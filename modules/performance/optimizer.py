"""
Performance & Scalability Module
Implements caching, incremental analysis, and parallel processing
"""

import os
import json
import pickle
import hashlib
import time
from typing import Dict, List, Tuple, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import idaapi
import idautils
import idc
import ida_funcs
import ida_bytes
from modules.core.base import XrefAnalyzer

class PerformanceOptimizer:
    """Performance optimization and caching system"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.use_cache = config.get('use_cache', True)
        self.cache_dir = config.get('cache_dir', '.xrefgen_cache')
        self.incremental = config.get('incremental', True)
        self.max_workers = config.get('max_workers', 4)
        
        # Create cache directory
        if self.use_cache:
            os.makedirs(self.cache_dir, exist_ok=True)
        
        # Cache structures
        self.function_cache = {}
        self.analysis_cache = {}
        self.binary_hash = self._calculate_binary_hash()
        
        # Load existing cache
        self._load_cache()
        
        # Track modifications
        self.modified_functions = set()
        self.last_analysis_time = time.time()
        
    def _calculate_binary_hash(self) -> str:
        """Calculate hash of the binary for cache invalidation"""
        hasher = hashlib.sha256()
        
        # Hash first 10KB and last 10KB of each segment
        for seg_ea in idautils.Segments():
            seg_start = seg_ea
            seg_end = idc.get_segm_end(seg_ea)
            
            # Hash beginning
            for ea in range(seg_start, min(seg_start + 10240, seg_end)):
                byte = ida_bytes.get_byte(ea)
                hasher.update(bytes([byte]))
            
            # Hash end
            if seg_end - seg_start > 20480:
                for ea in range(max(seg_end - 10240, seg_start + 10240), seg_end):
                    byte = ida_bytes.get_byte(ea)
                    hasher.update(bytes([byte]))
        
        return hasher.hexdigest()
    
    def _load_cache(self):
        """Load cached analysis results"""
        if not self.use_cache:
            return
        
        cache_file = os.path.join(self.cache_dir, f"{self.binary_hash}.cache")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'rb') as f:
                    cache_data = pickle.load(f)
                    
                    # Validate cache version
                    if cache_data.get('version') == '2.0':
                        self.function_cache = cache_data.get('functions', {})
                        self.analysis_cache = cache_data.get('analysis', {})
                        print(f"[XrefGen] Loaded cache with {len(self.function_cache)} functions")
                    else:
                        print("[XrefGen] Cache version mismatch, starting fresh")
            except Exception as e:
                print(f"[XrefGen] Error loading cache: {e}")
    
    def save_cache(self):
        """Save analysis results to cache"""
        if not self.use_cache:
            return
        
        cache_file = os.path.join(self.cache_dir, f"{self.binary_hash}.cache")
        
        try:
            cache_data = {
                'version': '2.0',
                'binary_hash': self.binary_hash,
                'timestamp': time.time(),
                'functions': self.function_cache,
                'analysis': self.analysis_cache
            }
            
            with open(cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
            
            print(f"[XrefGen] Saved cache with {len(self.function_cache)} functions")
        except Exception as e:
            print(f"[XrefGen] Error saving cache: {e}")
    
    def get_modified_functions(self) -> Set[int]:
        """Detect functions that have been modified since last analysis"""
        modified = set()
        
        if not self.incremental:
            # Full analysis - all functions are "modified"
            return set(idautils.Functions())
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # Calculate function hash
            func_hash = self._hash_function(func)
            
            # Check if function is in cache and unchanged
            if func_ea in self.function_cache:
                if self.function_cache[func_ea] != func_hash:
                    modified.add(func_ea)
            else:
                # New function
                modified.add(func_ea)
            
            # Update cache
            self.function_cache[func_ea] = func_hash
        
        # Also check for deleted functions
        cached_funcs = set(self.function_cache.keys())
        current_funcs = set(idautils.Functions())
        deleted_funcs = cached_funcs - current_funcs
        
        # Remove deleted functions from cache
        for func_ea in deleted_funcs:
            del self.function_cache[func_ea]
            if func_ea in self.analysis_cache:
                del self.analysis_cache[func_ea]
        
        print(f"[XrefGen] Found {len(modified)} modified functions for incremental analysis")
        return modified
    
    def _hash_function(self, func) -> str:
        """Calculate hash of a function for change detection"""
        hasher = hashlib.md5()
        
        # Hash function bytes
        for ea in idautils.Heads(func.start_ea, func.end_ea):
            # Hash instruction bytes
            insn_len = idc.get_item_size(ea)
            for i in range(insn_len):
                byte = ida_bytes.get_byte(ea + i)
                hasher.update(bytes([byte]))
        
        # Include function flags and attributes
        hasher.update(str(func.flags).encode())
        hasher.update(str(func.start_ea).encode())
        hasher.update(str(func.end_ea).encode())
        
        return hasher.hexdigest()
    
    def cache_analysis_result(self, func_ea: int, module_name: str, results: List):
        """Cache analysis results for a function"""
        if not self.use_cache:
            return
        
        if func_ea not in self.analysis_cache:
            self.analysis_cache[func_ea] = {}
        
        self.analysis_cache[func_ea][module_name] = {
            'timestamp': time.time(),
            'results': results
        }
    
    def get_cached_result(self, func_ea: int, module_name: str) -> Optional[List]:
        """Get cached analysis results for a function"""
        if not self.use_cache:
            return None
        
        if func_ea in self.analysis_cache:
            if module_name in self.analysis_cache[func_ea]:
                return self.analysis_cache[func_ea][module_name]['results']
        
        return None
    
    def parallel_analyze(self, analyzers: List[XrefAnalyzer], 
                        modified_only: bool = True) -> Dict[str, List]:
        """Run analyzers in parallel for better performance"""
        results = {}
        
        # Get functions to analyze
        if modified_only and self.incremental:
            target_functions = self.get_modified_functions()
        else:
            target_functions = set(idautils.Functions())
        
        print(f"[XrefGen] Analyzing {len(target_functions)} functions with {len(analyzers)} modules")
        
        # Create work items
        work_items = []
        for analyzer in analyzers:
            # Check if analyzer supports incremental analysis
            if hasattr(analyzer, 'supports_incremental') and analyzer.supports_incremental:
                funcs = target_functions
            else:
                funcs = set(idautils.Functions())  # Full analysis for this module
            
            work_items.append((analyzer, funcs))
        
        # Execute in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for analyzer, funcs in work_items:
                future = executor.submit(self._run_analyzer_cached, analyzer, funcs)
                futures[future] = analyzer.get_name()
            
            # Collect results
            for future in as_completed(futures):
                module_name = futures[future]
                try:
                    module_results = future.result(timeout=300)  # 5 minute timeout
                    results[module_name] = module_results
                    print(f"[XrefGen] {module_name} completed with {len(module_results)} results")
                except Exception as e:
                    print(f"[XrefGen] Error in {module_name}: {e}")
                    results[module_name] = []
        
        # Save cache after analysis
        self.save_cache()
        
        return results
    
    def _run_analyzer_cached(self, analyzer: XrefAnalyzer, 
                            target_functions: Set[int]) -> List:
        """Run analyzer with caching support"""
        all_results = []
        module_name = analyzer.get_name()
        
        # Check if analyzer has function-level granularity
        if hasattr(analyzer, 'analyze_function'):
            # Function-level analysis with caching
            for func_ea in target_functions:
                # Check cache first
                cached = self.get_cached_result(func_ea, module_name)
                if cached is not None:
                    all_results.extend(cached)
                else:
                    # Run analysis
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        func_results = analyzer.analyze_function(func)
                        all_results.extend(func_results)
                        
                        # Cache results
                        self.cache_analysis_result(func_ea, module_name, func_results)
        else:
            # Module-level analysis (can't cache per function)
            all_results = analyzer.analyze()
        
        return all_results
    
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
        
        for func in idautils.Functions():
            if abs(target - func) < 32:
                return True
        
        return False
    
    def optimize_memory(self):
        """Optimize memory usage by clearing unnecessary caches"""
        # Clear LRU caches
        self.is_valid_reference_cached.cache_clear()
        
        # Compact analysis cache (remove old entries)
        current_time = time.time()
        max_age = 3600  # 1 hour
        
        for func_ea in list(self.analysis_cache.keys()):
            for module_name in list(self.analysis_cache[func_ea].keys()):
                entry = self.analysis_cache[func_ea][module_name]
                if current_time - entry['timestamp'] > max_age:
                    del self.analysis_cache[func_ea][module_name]
            
            # Remove empty function entries
            if not self.analysis_cache[func_ea]:
                del self.analysis_cache[func_ea]
        
        print("[XrefGen] Memory optimization completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics"""
        stats = {
            'cache_enabled': self.use_cache,
            'incremental_enabled': self.incremental,
            'cached_functions': len(self.function_cache),
            'cached_analyses': sum(len(v) for v in self.analysis_cache.values()),
            'binary_hash': self.binary_hash[:8] + '...',
            'cache_size_mb': self._get_cache_size() / (1024 * 1024)
        }
        
        return stats
    
    def _get_cache_size(self) -> int:
        """Get total cache size in bytes"""
        if not self.use_cache:
            return 0
        
        total_size = 0
        for root, dirs, files in os.walk(self.cache_dir):
            for file in files:
                file_path = os.path.join(root, file)
                total_size += os.path.getsize(file_path)
        
        return total_size
    
    def clear_cache(self):
        """Clear all cached data"""
        self.function_cache.clear()
        self.analysis_cache.clear()
        
        # Remove cache files
        if self.use_cache:
            for file in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, file)
                try:
                    os.remove(file_path)
                except:
                    pass
        
        print("[XrefGen] Cache cleared")


class IncrementalAnalyzer(XrefAnalyzer):
    """Base class for analyzers that support incremental analysis"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.supports_incremental = True
        self.modified_functions = set()
    
    def set_modified_functions(self, modified: Set[int]):
        """Set the list of modified functions for incremental analysis"""
        self.modified_functions = modified
    
    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        """Analyze a single function - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement analyze_function")
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Full analysis - calls analyze_function for each function"""
        results = []
        
        for func_ea in idautils.Functions():
            if self.modified_functions and func_ea not in self.modified_functions:
                continue  # Skip unmodified functions
            
            func = ida_funcs.get_func(func_ea)
            if func:
                func_results = self.analyze_function(func)
                results.extend(func_results)
        
        return results