#!/usr/bin/env python3
"""
XrefGen - Advanced Cross-Reference Generator for IDA Pro
Main orchestrator script that executes all analysis modules

Author: Marc Rivero | @seifreed
Version: 0.5.0-alpha.1
"""

import sys
import os
import time
import argparse
from uuid import uuid4
from typing import List

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import ida_auto
import ida_nalt
import idc

try:
    import ida_ida
except ImportError:
    ida_ida = None

# Import core modules
from modules.application.module_manager import ModuleManager
from modules.application.registry import build_modules
from modules.application.config import Config

# Import performance optimizer
from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer
from modules.presentation.cli import XrefGenPresenter
from modules import observability as logger
from modules.observability import info as _info, warn as _warn, error as _error
from modules.domain.results import RESULT_TYPES, ResultStore, is_control_flow_mnemonic
from modules import __version__

class XrefGen:
    """Main XrefGen orchestrator"""

    def __init__(self, config_file: str = None):
        """Initialize XrefGen with configuration"""
        logger.configure(None)

        # Load configuration
        self.config = Config(config_file)
        logger.configure(
            self.config.get("general.log_file"),
            self.config.get("general.log_level", "info"),
            self.config.get("general.log_format", "json"),
        )
        logger.info(
            "XrefGen initialized",
            event_name="service.started",
            version=__version__,
        )

        # Initialize performance optimizer
        self.optimizer = PerformanceOptimizer(
            self.config.get_module_config("performance")
        )

        # Initialize module manager
        self.manager = ModuleManager(self.config.config)
        self.presenter = XrefGenPresenter(self.config, self.optimizer, self.manager)

        # Register all modules
        self._register_modules()
        # Keep graph-based control-flow resolution enabled when slow insights are skipped.
        if self.config.get("modules.performance.skip_slow_graph", False):
            for module in self.manager.modules:
                if getattr(module, "get_name", lambda: "")() == "GraphAnalyzer":
                    module.skip_slow_graph = True

        # Statistics
        self.start_time = None
        self.end_time = None
        self.total_xrefs = 0

    def _register_modules(self):
        """Register all analysis modules"""
        _info("Registering analysis modules")
        for module in build_modules(self.config.config):
            self.manager.register_module(module)

        _info(f"Registered {len(self.manager.modules)} modules")

    def run(self, modules: List[str] = None, incremental: bool = None):
        """Run one correlated analysis operation."""
        with logger.operation_context("analysis", uuid4().hex):
            started = time.perf_counter()
            logger.info("Analysis started", event_name="analysis.started", status="started")
            try:
                result = self._run(modules, incremental)
                logger.info(
                    "Analysis finished",
                    event_name="analysis.finished",
                    status="completed",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    result_count=self.total_xrefs,
                )
                return result
            except Exception:
                logger.exception(
                    "Analysis operation failed",
                    event_name="analysis.failed",
                    status="failed",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                )
                raise

    def _run(self, modules: List[str] = None, incremental: bool = None):
        """Run the cross-reference generation"""
        self.start_time = time.time()
        try:
            bin_path = ida_nalt.get_input_file_path()
        except (TypeError, ValueError, AttributeError):
            bin_path = None
        _info("Analysis started")
        _info(f"Binary: {os.path.basename(ida_nalt.get_input_file_path())}")
        _info(f"Architecture: {self._get_arch_name()}")

        # Wait for auto-analysis to complete
        if not self._wait_for_analysis():
            _warn("IDA analysis not complete, results may be incomplete")

        # Refresh caches for IDA-backed analyzers (function ranges, validation cache)
        for module in self.manager.modules:
            if hasattr(module, "refresh_caches"):
                try:
                    module.refresh_caches()
                except (TypeError, ValueError, AttributeError, RuntimeError):
                    _warn(f"Cache refresh failed for {module.get_name()}")

        # Check for incremental analysis
        if incremental is None:
            incremental = self.config.get("modules.performance.incremental", True)

        # Get modified functions if incremental
        modified_functions = set()
        if incremental:
            modified_functions = self.optimizer.get_modified_functions()
            if not modified_functions:
                _info("No modified functions detected, skipping analysis")
                return

        # Run analysis with performance optimization (sequential and main-thread safe)
        if self.config.get("modules.performance.enabled"):
            _info("Running analysis...")
            results_by_module = self.optimizer.analyze_sequential(
                self.manager.modules,
                modified_only=incremental,
                selected_modules=modules,
                modified_functions=modified_functions,
            )

            # Combine results from modules
            all_results = []
            for module_results in results_by_module.values():
                all_results.extend(module_results)
            profile = getattr(self.optimizer, "last_profile", {})
        else:
            _info("Running analysis without performance optimizer...")
            all_results = self.manager.run_analysis(modules)
            profile = {}

        result_store = ResultStore(
            source_is_control_flow=self._is_control_flow_source,
            target_is_executable=self._is_valid_target,
            already_exists=self._xref_exists,
        )
        raw_results_by_module = (
            results_by_module
            if self.config.get("modules.performance.enabled")
            else self.manager.results_by_module
        )
        for module_name, module_results in raw_results_by_module.items():
            for result in module_results:
                if not isinstance(result, RESULT_TYPES):
                    raise TypeError(
                        f"{module_name} returned an untyped analysis result: {result!r}"
                    )
                result_store.add_result(
                    result, module=module_name, evidence=(module_name,)
                )

        # Export only validated control-flow candidates.
        min_confidence = self.config.get("general.min_confidence", 0.5)
        filtered_results = result_store.xrefs(min_confidence)

        self.total_xrefs = len(filtered_results)

        evidence_counts = {}
        evidence_types = {}
        taint_kinds = {}
        try:
            if self.config.get("modules.performance.enabled"):
                for mod_name, mod_results in results_by_module.items():
                    for result in mod_results:
                        if isinstance(result, RESULT_TYPES):
                            evidence_types.setdefault(
                                (result.source, result.target), set()
                            ).add(mod_name)
            evidence_types.update(result_store.evidence())
            for module in self.manager.modules:
                counts = getattr(module, "evidence_counts", None)
                types = getattr(module, "evidence_types", None)
                tkinds = getattr(module, "taint_kind_xrefs", None)
                if not counts:
                    counts = {}
                for key, val in counts.items():
                    evidence_counts[key] = evidence_counts.get(key, 0) + int(val)
                if types:
                    for key, val in types.items():
                        evidence_types.setdefault(key, set()).update(val)
                if tkinds:
                    for key, val in tkinds.items():
                        taint_kinds[key] = val
        except (TypeError, ValueError, AttributeError, KeyError):
            evidence_counts = {}
            evidence_types = {}
            taint_kinds = {}

        # Save results
        output_file = self.config.get("general.output_file", "_user_xrefs.txt")
        if not self.config.get("general.include_taint_kind", True):
            taint_kinds = {}
        self.presenter.save_results(
            filtered_results,
            evidence_counts,
            evidence_types,
            profile,
            taint_kinds,
            findings=result_store.findings,
            relationships=result_store.relationships,
            rejections=result_store.rejections,
        )
        try:
            slow_path = self.config.get("general.slow_functions_report")
            if slow_path and profile:
                import json

                base_dir = os.path.dirname(ida_nalt.get_input_file_path())
                full = os.path.join(base_dir, slow_path)
                with open(full, "w", encoding="utf-8") as f_slow:
                    json.dump(profile, f_slow, indent=2)
        except (IOError, OSError, KeyError, TypeError) as exc:
            _error("Slow-function report could not be written", error_type=type(exc).__name__)

        # Save cache if enabled
        if self.config.get("modules.performance.use_cache"):
            self.optimizer.commit_cache()
        self.end_time = time.time()

        # Print statistics
        self._print_statistics()

    def _is_control_flow_source(self, ea: int) -> bool:
        try:
            return is_control_flow_mnemonic(idc.print_insn_mnem(ea))
        except (TypeError, ValueError, AttributeError, RuntimeError):
            return False

    def _is_valid_target(self, ea: int) -> bool:
        for module in self.manager.modules:
            validator = getattr(module, "is_valid_reference", None)
            if callable(validator):
                if validator(ea):
                    return True
        return False

    def _xref_exists(self, source: int, target: int) -> bool:
        for module in self.manager.modules:
            checker = getattr(module, "is_already_in_ida", None)
            if callable(checker):
                return bool(checker(source, target))
        return False

    def _wait_for_analysis(self, timeout: int = 60) -> bool:
        """Wait for IDA auto-analysis to complete"""
        _info("Waiting for IDA auto-analysis to complete...")
        try:
            if not ida_auto.auto_is_ok() and hasattr(ida_auto, "auto_wait"):
                ida_auto.auto_wait()
            ready = bool(ida_auto.auto_is_ok())
        except (TypeError, ValueError, AttributeError, RuntimeError):
            ready = False
        if ready:
            _info("Auto-analysis complete")
        return ready

    def _get_arch_name(self) -> str:
        """Get architecture name"""
        # Use IDA 9.1 API only
        procname = ida_ida.inf_get_procname().lower()
        is_64 = ida_ida.inf_is_64bit()

        if "arm" in procname:
            return "ARM64" if is_64 else "ARM"
        elif "mips" in procname:
            return "MIPS"
        elif "wasm" in procname:
            return "WebAssembly"
        elif is_64:
            return "x64"
        else:
            return "x86"

    def _print_statistics(self):
        """Print analysis statistics"""
        if not self.start_time or not self.end_time:
            return

        elapsed = self.end_time - self.start_time

        _info(f"Analysis completed: xrefs={self.total_xrefs}, duration_sec={elapsed:.3f}, modules={len(self.manager.modules)}")

        if self.config.get("modules.performance.enabled"):
            stats = self.optimizer.get_statistics()
            _info(f"Performance statistics: cache_enabled={stats['cache_enabled']}, incremental={stats['incremental_enabled']}, cached_functions={stats['cached_functions']}, cache_size_mb={stats['cache_size_mb']:.2f}")

    def interactive_mode(self):
        """Run in interactive mode with preview"""
        _info("Interactive mode started")
        choice = self.presenter.show_main_menu()

        if choice == 0:  # Run full analysis
            self.run(incremental=False)
        elif choice == 1:  # Run incremental
            self.run(incremental=True)
        elif choice == 2:  # Select modules
            self._select_modules_dialog()
        elif choice == 3:  # Configure
            self._configure_dialog()
        elif choice == 4:  # Clear cache
            self.optimizer.clear_cache()
            _info("Cache cleared")
        elif choice == 5:  # View statistics
            self._show_statistics()
        elif choice == 6:  # Exit
            return

    def _select_modules_dialog(self):
        """Show module selection dialog"""
        selected_names = self.presenter.select_modules_dialog()
        if selected_names:
            self.run(modules=selected_names)

    def _configure_dialog(self):
        """Show configuration dialog"""
        self.presenter.configure_dialog()

    def _show_statistics(self):
        """Show analysis statistics"""
        self.presenter.show_statistics()


def main():
    """Main entry point"""
    # Check if running in IDA
    try:
        import importlib.util

        if importlib.util.find_spec("idaapi") is None:
            _warn("XrefGen must be run from within IDA Pro")
            return
    except (ImportError, ModuleNotFoundError):
        _warn("XrefGen must be run from within IDA Pro")
        return
    # Parse arguments (if any)
    parser = argparse.ArgumentParser(
        description="XrefGen - Advanced Cross-Reference Generator"
    )
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument(
        "-i", "--incremental", action="store_true", help="Run incremental analysis"
    )
    parser.add_argument("-m", "--modules", nargs="+", help="Specific modules to run")
    parser.add_argument(
        "--interactive", action="store_true", help="Run in interactive mode"
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear cache before running"
    )

    # IDA doesn't pass sys.argv properly, so we'll use defaults
    args = parser.parse_args([])  # Empty args for IDA context

    # Create XrefGen instance
    xrefgen = XrefGen(config_file=args.config)
    # Keep optimizer diagnostics on the same configured logging pipeline.
    xrefgen.optimizer.logger = logger.debug

    # Clear cache if requested
    if args.clear_cache:
        xrefgen.optimizer.clear_cache()

    # Run analysis
    if args.interactive:
        xrefgen.interactive_mode()
    else:
        xrefgen.run(modules=args.modules, incremental=args.incremental)

    _info("XrefGen entry point finished")


if __name__ == "__main__":
    main()
