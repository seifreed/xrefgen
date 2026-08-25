"""
Performance & Scalability Module
Implements caching, incremental analysis, and parallel processing
"""

import os
import json
import hashlib
import time
from typing import Dict, List, Tuple, Any, Optional, Set, Callable
from functools import lru_cache
import idautils
import idc
import ida_funcs
import ida_bytes
import ida_segment
import ida_kernwin
import ida_nalt
try:
    import idaapi
except ImportError:
    idaapi = None
from modules import __version__
from modules.domain.analyzer import XrefAnalyzer
from modules.domain.results import AnalysisResult, deserialize_result, serialize_result
from modules.infrastructure.ida.base import IDAXrefAnalyzer
from modules.infrastructure.ida.utils.function_cache import FunctionBoundsCache


class PerformanceOptimizer:
    """Performance optimization and caching system"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.use_cache = config.get("use_cache", True)
        self.cache_dir = self._resolve_cache_dir(config.get("cache_dir", ".xrefgen_cache"))
        self.incremental = config.get("incremental", True)
        self.cache_ttl = config.get("cache_ttl_seconds", 3600)
        self.xrefgen_version = __version__
        self.ida_version = getattr(idaapi, "IDA_SDK_VERSION", "unknown")
        self.max_function_ms = int(config.get("max_function_ms", 0))
        self.skip_slow_functions = bool(config.get("skip_slow_functions", False))

        # Create cache directory
        if self.use_cache:
            os.makedirs(self.cache_dir, exist_ok=True)

        # Cache structures
        self.function_cache = {}
        self.analysis_cache = {}
        self.config_hash = self._calculate_config_hash(self.config)
        self.binary_hash = self._calculate_binary_hash()
        self._func_bounds = FunctionBoundsCache()
        self.last_profile = {}
        self._slow_functions = set()
        self._pending_function_hashes = None
        self.last_run_success = True
        self._active_analyzer = None

        # Load existing cache
        self._load_cache()

        # Track modifications
        self.modified_functions = set()
        self.last_analysis_time = time.time()
        # Optional logger callable
        self.logger = None

    def _log(self, msg: str):
        try:
            if callable(self.logger):
                self.logger(msg)
        except (TypeError, ValueError, AttributeError, RuntimeError):
            pass

    def _calculate_binary_hash(self) -> str:
        """Calculate a robust hash of the current IDA database state"""
        hasher = hashlib.sha256()

        # Keep the binary identity stable while the IDB changes; function hashes
        # are responsible for incremental invalidation.
        input_path = ida_nalt.get_input_file_path()
        hasher.update(input_path.encode("utf-8"))
        try:
            with open(input_path, "rb") as binary:
                for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                    hasher.update(chunk)
        except (OSError, TypeError):
            for seg_ea in idautils.Segments():
                hasher.update(str(idc.get_segm_name(seg_ea)).encode())
                hasher.update(str(idc.get_segm_start(seg_ea)).encode())
                hasher.update(str(idc.get_segm_end(seg_ea)).encode())

        return hasher.hexdigest()

    def _resolve_cache_dir(self, configured: str) -> str:
        if os.path.isabs(configured):
            return configured
        try:
            idb_path = idc.get_idb_path()
        except (AttributeError, TypeError, ValueError, RuntimeError):
            idb_path = ida_nalt.get_input_file_path()
        return os.path.join(os.path.dirname(idb_path), configured)

    def _calculate_config_hash(self, config: Dict) -> str:
        try:
            payload = json.dumps(config, sort_keys=True, default=str).encode()
        except (TypeError, ValueError, AttributeError, RuntimeError):
            payload = repr(config).encode()
        return hashlib.sha256(payload).hexdigest()

    def _load_cache(self):
        """Load cached analysis results using secure JSON format"""
        if not self.use_cache:
            return

        cache_file = os.path.join(self.cache_dir, f"{self.binary_hash}.cache")

        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)

                    # Validate cache version and config
                    if (
                        cache_data.get("version") == "4.0"
                        and cache_data.get("config_hash") == self.config_hash
                        and cache_data.get("xrefgen_version") == self.xrefgen_version
                        and cache_data.get("ida_version") == self.ida_version
                    ):
                        # Convert string keys back to ints for JSON compatibility
                        self.function_cache = {
                            int(k): v
                            for k, v in cache_data.get("functions", {}).items()
                        }
                        raw_analysis = cache_data.get("analysis", {})
                        self.analysis_cache = {
                            int(k): v for k, v in raw_analysis.items()
                        }
                        print(
                            f"[XrefGen] Loaded JSON cache with {len(self.function_cache)} functions"
                        )
                    else:
                        print("[XrefGen] Cache version/config mismatch, starting fresh")
            except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
                print(f"[XrefGen] Cache load error: {e}")
                pass

    def save_cache(self):
        """Save analysis results to JSON cache"""
        if not self.use_cache:
            return

        cache_file = os.path.join(self.cache_dir, f"{self.binary_hash}.cache")
        temporary_file = None

        try:
            cache_data = {
                "version": "4.0",
                "binary_hash": self.binary_hash,
                "config_hash": self.config_hash,
                "xrefgen_version": self.xrefgen_version,
                "ida_version": self.ida_version,
                "timestamp": time.time(),
                # JSON requires string keys
                "functions": {str(k): v for k, v in self.function_cache.items()},
                "analysis": {str(k): v for k, v in self.analysis_cache.items()},
            }

            temporary_file = f"{cache_file}.tmp"
            with open(temporary_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary_file, cache_file)

            print(
                f"[XrefGen] Saved JSON cache with {len(self.function_cache)} functions"
            )
        except (IOError, OSError, TypeError, ValueError) as e:
            print(f"[XrefGen] Error saving cache: {e}")
            try:
                if temporary_file and os.path.exists(temporary_file):
                    os.remove(temporary_file)
            except OSError:
                pass

    def get_modified_functions(self) -> Set[int]:
        """Detect functions modified since last analysis using reliable hashing"""
        modified = set()
        current_funcs = list(idautils.Functions())

        if not self.incremental:
            return set(current_funcs)

        current_hashes = {}
        for func_ea in current_funcs:
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_hash = self._hash_function(func)

            current_hashes[func_ea] = func_hash
            if func_ea in self.function_cache:
                if self.function_cache[func_ea] != func_hash:
                    modified.add(func_ea)
            else:
                modified.add(func_ea)

        # Cleanup deleted functions
        cached_funcs_set = set(self.function_cache.keys())
        current_funcs_set = set(current_funcs)
        for func_ea in cached_funcs_set - current_funcs_set:
            modified.add(func_ea)

        self._pending_function_hashes = current_hashes
        for func_ea in modified:
            self.analysis_cache.pop(func_ea, None)

        print(f"[XrefGen] Found {len(modified)} modified functions for analysis")
        return modified

    def commit_cache(self) -> None:
        if not self.last_run_success:
            self._pending_function_hashes = None
            return
        if self._pending_function_hashes is not None and self.last_run_success:
            self.function_cache = dict(self._pending_function_hashes)
            self._pending_function_hashes = None
        self.save_cache()

    def _hash_function(self, func) -> str:
        """Calculate hash of a function's state (code and attributes)"""
        hasher = hashlib.sha256()

        # Hash instruction bytes efficiently
        func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
        if func_bytes:
            hasher.update(func_bytes)

        # Include critical metadata
        hasher.update(str(func.flags).encode())
        hasher.update(str(func.start_ea).encode())
        hasher.update(str(func.end_ea).encode())

        return hasher.hexdigest()

    def cache_analysis_result(self, func_ea: int, module_name: str, results: List):
        if not self.use_cache:
            return

        if func_ea not in self.analysis_cache:
            self.analysis_cache[func_ea] = {}

        self.analysis_cache[func_ea][module_name] = {
            "timestamp": time.time(),
            "results": [serialize_result(result) for result in results],
        }

    def cache_semantic_result(
        self, func_ea: int, module_name: str, results: List, semantic: Optional[Dict] = None
    ):
        self.cache_analysis_result(func_ea, module_name, results)
        if self.use_cache and semantic is not None:
            self.analysis_cache[func_ea][module_name]["semantic"] = semantic

    def get_cached_result(self, func_ea: int, module_name: str) -> Optional[List]:
        if not self.use_cache:
            return None

        if func_ea in self.analysis_cache:
            if module_name in self.analysis_cache[func_ea]:
                entry = self.analysis_cache[func_ea][module_name]
                if (
                    self.cache_ttl
                    and time.time() - entry.get("timestamp", 0) > self.cache_ttl
                ):
                    return None
                analyzer = getattr(self, "_active_analyzer", None)
                if analyzer is not None and hasattr(analyzer, "restore_cached_semantic"):
                    analyzer.restore_cached_semantic(func_ea, entry.get("semantic"))
                return [deserialize_result(result) for result in entry.get("results", [])]

        return None

    def invalidate_module_cache(self, module_name: str, functions: Set[int]):
        for func_ea in functions:
            module_cache = self.analysis_cache.get(func_ea, {})
            module_cache.pop(module_name, None)
            if not module_cache:
                self.analysis_cache.pop(func_ea, None)

    def analyze_sequential(
        self,
        analyzers: List[XrefAnalyzer],
        modified_only: bool = True,
        selected_modules: Optional[List[str]] = None,
        modified_functions: Optional[Set[int]] = None,
    ) -> Dict[str, List]:
        """Run analyzers sequentially, properly handling global vs incremental modules."""
        results: Dict[str, List] = {}
        profile: Dict[str, Dict[str, Any]] = {}

        # Pre-calculate modified functions if needed
        if modified_only and self.incremental and modified_functions is None:
            modified_functions = self.get_modified_functions()
        modified_functions = modified_functions or set()
        self.last_run_success = True

        for analyzer in analyzers:
            if not getattr(analyzer, "enabled", True):
                continue
            name = analyzer.get_name()
            if selected_modules and name not in selected_modules:
                continue
            supports_inc = getattr(analyzer, "supports_incremental", False)
            scope = getattr(analyzer, "analysis_scope", "global")

            # Decision logic:
            # 1. If we are NOT in modified_only mode, run on everything.
            # 2. If we ARE in modified_only, but module DOES NOT support incremental (it's global), run it anyway!
            # 3. If we ARE in modified_only and module DOES support it, run on modified set.
            if not (modified_only and self.incremental):
                target_funcs = set(idautils.Functions())
            elif not supports_inc or scope != "function":
                # Critical fix: global analyzers must run if incrementality isn't supported by them
                target_funcs = set(idautils.Functions())
            else:
                target_funcs = modified_functions

            try:
                if hasattr(analyzer, "set_slow_functions"):
                    analyzer.set_slow_functions(self._slow_functions)

                self._log(f"Starting {name}")
                start_t = time.time()

                # Execute with caching and thread-safe IDA orchestration
                self._active_analyzer = analyzer
                if (
                    modified_only
                    and self.incremental
                    and hasattr(analyzer, "prepare_incremental")
                    and hasattr(analyzer, "run_incremental")
                ):
                    invalidated = analyzer.prepare_incremental(
                        modified_functions,
                        set(idautils.Functions()),
                        self.analysis_cache,
                    )
                    self.invalidate_module_cache(name, invalidated)
                    module_results, func_profile = analyzer.run_incremental(
                        set(idautils.Functions()),
                        invalidated,
                        lambda ea: self.get_cached_result(ea, name),
                        lambda ea, values, semantic: self.cache_semantic_result(
                            ea, name, values, semantic
                        ),
                    )
                else:
                    module_results, func_profile = self._run_analyzer_orchestrated(
                        analyzer, target_funcs
                    )

                elapsed = max(0.0, time.time() - start_t)
                results[name] = module_results
                profile[name] = {
                    "duration_sec": elapsed,
                    "results": len(module_results),
                    "functions": len(target_funcs),
                    "per_function": func_profile,
                }
                print(f"[XrefGen] {name} completed: {len(module_results)} results")
            except (TypeError, ValueError, AttributeError, RuntimeError) as e:
                self.last_run_success = False
                print(f"[XrefGen] Error in {name}: {e}")
                results[name] = []
                profile[name] = {"duration_sec": 0.0, "error": str(e)}

        self.last_profile = profile
        self._active_analyzer = None
        return results

    def _run_analyzer_orchestrated(
        self, analyzer: XrefAnalyzer, target_functions: Set[int]
    ) -> Tuple[List, Dict[str, float]]:
        """Securely run analysis on IDA's main thread with results isolated from the wrapper."""
        all_results: List = []
        module_name = analyzer.get_name()
        func_profile: Dict[str, float] = {}

        def safe_execute(target_callable: Callable):
            holder = {}

            def wrapper():
                try:
                    holder["data"] = target_callable()
                except (TypeError, ValueError, AttributeError, RuntimeError) as ex:
                    holder["err"] = ex

            ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_READ)
            if "err" in holder:
                raise holder["err"]
            return holder.get("data")

        if (
            hasattr(analyzer, "analyze_function")
            and getattr(analyzer, "analysis_scope", "global") == "function"
        ):
            for func_ea in sorted(target_functions):
                if self.skip_slow_functions and func_ea in self._slow_functions:
                    continue

                cached = self.get_cached_result(func_ea, module_name)
                if cached is not None:
                    all_results.extend(cached)
                    continue

                def _do_analyze():
                    func = ida_funcs.get_func(func_ea)
                    return analyzer.analyze_function(func) if func else []

                start_t = time.time()
                func_results = safe_execute(_do_analyze)
                duration = max(0.0, time.time() - start_t)

                func_profile[f"0x{func_ea:x}"] = duration
                if self.max_function_ms and duration * 1000.0 > self.max_function_ms:
                    self._slow_functions.add(func_ea)

                all_results.extend(func_results or [])
                semantic = None
                if hasattr(analyzer, "get_semantic_cache"):
                    semantic = analyzer.get_semantic_cache(func_ea)
                self.cache_semantic_result(
                    func_ea, module_name, func_results or [], semantic
                )
        else:
            # Global analysis
            all_results = safe_execute(analyzer.analyze)

        return all_results, func_profile

    @lru_cache(maxsize=1024)
    def is_valid_reference_cached(self, target: int) -> bool:
        """Cached version of reference validation"""
        seg = ida_segment.getseg(target)
        if not seg:
            return False

        if not idc.is_code(idc.get_full_flags(target)):
            return False

        func = ida_funcs.get_func(target)
        if func:
            return True

        return self._func_bounds.near_function_start(target, radius=32)

    def optimize_memory(self):
        """Optimize memory usage by clearing unnecessary caches"""
        self.is_valid_reference_cached.cache_clear()

        current_time = time.time()
        max_age = 3600

        for func_ea in list(self.analysis_cache.keys()):
            for module_name in list(self.analysis_cache[func_ea].keys()):
                entry = self.analysis_cache[func_ea][module_name]
                if current_time - entry["timestamp"] > max_age:
                    del self.analysis_cache[func_ea][module_name]

            if not self.analysis_cache[func_ea]:
                del self.analysis_cache[func_ea]

        print("[XrefGen] Memory optimization completed")

    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics"""
        stats = {
            "cache_enabled": self.use_cache,
            "incremental_enabled": self.incremental,
            "cached_functions": len(self.function_cache),
            "cached_analyses": sum(len(v) for v in self.analysis_cache.values()),
            "binary_hash": self.binary_hash[:8] + "...",
            "cache_size_mb": self._get_cache_size() / (1024 * 1024),
        }
        return stats

    def _get_cache_size(self) -> int:
        if not self.use_cache:
            return 0
        total_size = 0
        for root, dirs, files in os.walk(self.cache_dir):
            for file in files:
                total_size += os.path.getsize(os.path.join(root, file))
        return total_size

    def clear_cache(self):
        self.function_cache.clear()
        self.analysis_cache.clear()
        if self.use_cache:
            for file in os.listdir(self.cache_dir):
                try:
                    os.remove(os.path.join(self.cache_dir, file))
                except OSError:
                    pass
        print("[XrefGen] Cache cleared")


class IncrementalAnalyzer(IDAXrefAnalyzer):
    """Base class for analyzers that support incremental analysis"""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.supports_incremental = True
        self.analysis_scope = "function"
        self.modified_functions = set()

    def set_modified_functions(self, modified: Set[int]):
        self.modified_functions = modified

    def set_slow_functions(self, slow: Set[int]):
        self._slow_functions = set(slow or [])

    def analyze_function(self, func) -> List[AnalysisResult]:
        raise NotImplementedError("Subclasses must implement analyze_function")

    def analyze(self) -> List[AnalysisResult]:
        results = []
        for func_ea in sorted(idautils.Functions()):
            if self.modified_functions and func_ea not in self.modified_functions:
                continue
            get_func = getattr(ida_funcs, "get_func", None)
            func = get_func(func_ea) if callable(get_func) else None
            if func:
                results.extend(self.analyze_function(func))
        return results
