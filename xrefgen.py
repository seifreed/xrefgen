#!/usr/bin/env python3
"""
XrefGen - Advanced Cross-Reference Generator for IDA Pro
Main orchestrator script that executes all analysis modules

Author: Marc Rivero | @seifreed
Version: 2.0
"""

import sys
import builtins
import os
import time
import argparse
from datetime import datetime
from typing import List

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import ida_auto
import ida_nalt
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
from modules.presentation import logger
from modules.presentation.logger import info as _info, warn as _warn

_DEBUG_LOG_PATH = None


def _set_debug_log_from_binary(bin_path: str):
    global _DEBUG_LOG_PATH
    try:
        base_dir = os.path.dirname(bin_path) if bin_path else os.getcwd()
        _DEBUG_LOG_PATH = os.path.join(base_dir, "_xrefgen_debug.log")
    except Exception:
        _DEBUG_LOG_PATH = None


def _dbg_log(msg: str):
    try:
        if _DEBUG_LOG_PATH:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(_DEBUG_LOG_PATH, 'a', encoding='utf-8', errors='ignore') as _f:
                _f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass




def _install_safe_print():
    """Install a print() shim that avoids MSVCRT format pitfalls in IDA.
    Routes through ida_kernwin.msg("%s") to prevent stray %% interpretation
    and mitigates codepage issues with non-ASCII by best-effort str().
    """
    try:
        import idaapi as _ia
    except Exception:
        return

    def _safe_print(*args, sep=' ', end='\n', file=None, flush=False):
        try:
            s = sep.join(str(a) for a in args)
        except Exception:
            try:
                s = sep.join(repr(a) for a in args)
            except Exception:
                s = "<print failure>"
        try:
            _ia.msg("%s", s)
            if end:
                _ia.msg("%s", end)
        except Exception:
            # Last resort: write to original stdout if available
            try:
                sys.__stdout__.write(s + end)
            except Exception:
                pass

    builtins.print = _safe_print


class XrefGen:
    """Main XrefGen orchestrator"""
    
    def __init__(self, config_file: str = None):
        """Initialize XrefGen with configuration"""
        print("XrefGen v2.0 - Advanced Cross-Reference Generator for IDA Pro")
        print("Author: Marc Rivero (@seifreed)")
        
        # Load configuration
        self.config = Config(config_file)
        logger.configure(
            self.config.get("general.log_file"),
            self.config.get("general.log_level", "info"),
        )
        
        # Initialize performance optimizer
        self.optimizer = PerformanceOptimizer(self.config.get_module_config('performance'))
        
        # Initialize module manager
        self.manager = ModuleManager(self.config.config)
        self.presenter = XrefGenPresenter(self.config, self.optimizer, self.manager)
        
        # Register all modules
        self._register_modules()
        # Optional throttling for heavy modules
        if self.config.get("modules.performance.skip_slow_graph", False):
            for module in self.manager.modules:
                if hasattr(module, "get_name") and module.get_name() == "GraphAnalyzer":
                    try:
                        module.enabled = False
                    except Exception:
                        pass
        
        # Statistics
        self.start_time = None
        self.end_time = None
        self.total_xrefs = 0
        
    def _register_modules(self):
        """Register all analysis modules"""
        print("\n[XrefGen] Registering analysis modules...")
        for module in build_modules(self.config.config):
            self.manager.register_module(module)

        _info(f"Registered {len(self.manager.modules)} modules")
    
    def run(self, modules: List[str] = None, incremental: bool = None):
        """Run the cross-reference generation"""
        self.start_time = time.time()
        try:
            bin_path = ida_nalt.get_input_file_path()
        except Exception:
            bin_path = None
        _set_debug_log_from_binary(bin_path)
        _dbg_log("run() started")

        print("\n[XrefGen] Starting analysis...")
        _info(f"Binary: {ida_nalt.get_input_file_path()}")
        _info(f"Architecture: {self._get_arch_name()}")
        _dbg_log("after header")
        
        # Wait for auto-analysis to complete
        if not self._wait_for_analysis():
            _warn("IDA analysis not complete, results may be incomplete")
        _dbg_log("auto-analysis ready")

        # Refresh caches for IDA-backed analyzers (function ranges, validation cache)
        for module in self.manager.modules:
            if hasattr(module, "refresh_caches"):
                try:
                    module.refresh_caches()
                except Exception:
                    pass
        
        # Check for incremental analysis
        if incremental is None:
            incremental = self.config.get('modules.performance.incremental', True)
        
        # Get modified functions if incremental
        modified_functions = set()
        if incremental:
            modified_functions = self.optimizer.get_modified_functions()
            if not modified_functions:
                _info("No modified functions detected, skipping analysis")
                return
        
        # Run analysis with performance optimization (sequential and main-thread safe)
        if self.config.get('modules.performance.enabled'):
            _info("Running analysis...")
            _dbg_log("starting optimizer.analyze_sequential")
            results_by_module = self.optimizer.analyze_sequential(
                self.manager.modules,
                modified_only=incremental
            )
            _dbg_log("optimizer.analyze_sequential finished")

            # Combine results from modules
            all_results = []
            for module_results in results_by_module.values():
                all_results.extend(module_results)
            profile = getattr(self.optimizer, "last_profile", {})
        else:
            _info("Running analysis without performance optimizer...")
            all_results = self.manager.run_analysis(modules)
            profile = {}
        
        # Filter by confidence
        min_confidence = self.config.get('general.min_confidence', 0.5)
        filtered_results = [(s, t, typ, conf) for s, t, typ, conf in all_results 
                           if conf >= min_confidence]

        self.total_xrefs = len(filtered_results)

        evidence_counts = {}
        evidence_types = {}
        taint_kinds = {}
        try:
            if self.config.get('modules.performance.enabled'):
                for mod_name, mod_results in results_by_module.items():
                    for s, t, _typ, _conf in mod_results:
                        evidence_types.setdefault((s, t), set()).add(mod_name)
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
        except Exception:
            evidence_counts = {}
            evidence_types = {}
            taint_kinds = {}
        
        # Save results
        output_file = self.config.get('general.output_file', '_user_xrefs.txt')
        _dbg_log(f"saving results to {output_file}")
        if not self.config.get("general.include_taint_kind", True):
            taint_kinds = {}
        self.presenter.save_results(filtered_results, evidence_counts, evidence_types, profile, taint_kinds)
        try:
            slow_path = self.config.get("general.slow_functions_report")
            if slow_path and profile:
                import json
                base_dir = os.path.dirname(ida_nalt.get_input_file_path())
                full = os.path.join(base_dir, slow_path)
                with open(full, "w", encoding="utf-8") as f_slow:
                    json.dump(profile, f_slow, indent=2)
        except Exception:
            pass
        
        # Save cache if enabled
        if self.config.get('modules.performance.use_cache'):
            self.optimizer.save_cache()
        _dbg_log("run() finished successfully")
        
        self.end_time = time.time()
        
        # Print statistics
        self._print_statistics()
    
    def _wait_for_analysis(self, timeout: int = 60) -> bool:
        """Wait for IDA auto-analysis to complete"""
        _info("Waiting for IDA auto-analysis to complete...")
        
        start = time.time()
        while time.time() - start < timeout:
            if ida_auto.auto_is_ok():
                _info("Auto-analysis complete")
                return True
            time.sleep(1)
        
        return False
    
    def _get_arch_name(self) -> str:
        """Get architecture name"""
        # Use IDA 9.1 API only
        procname = ida_ida.inf_get_procname().lower()
        is_64 = ida_ida.inf_is_64bit()
        
        if 'arm' in procname:
            return 'ARM64' if is_64 else 'ARM'
        elif 'mips' in procname:
            return 'MIPS'
        elif 'wasm' in procname:
            return 'WebAssembly'
        elif is_64:
            return 'x64'
        else:
            return 'x86'
    
    def _print_statistics(self):
        """Print analysis statistics"""
        if not self.start_time or not self.end_time:
            return
        
        elapsed = self.end_time - self.start_time
        
        print("\n" + "="*60)
        print("                    ANALYSIS COMPLETE")
        print("="*60)
        print(f"  Total cross-references found: {self.total_xrefs}")
        print(f"  Analysis time: {elapsed:.2f} seconds")
        print(f"  Modules executed: {len(self.manager.modules)}")
        
        if self.config.get('modules.performance.enabled'):
            stats = self.optimizer.get_statistics()
            print("\n  Performance Statistics:")
            print(f"    Cache enabled: {stats['cache_enabled']}")
            print(f"    Incremental analysis: {stats['incremental_enabled']}")
            print(f"    Cached functions: {stats['cached_functions']}")
            print(f"    Cache size: {stats['cache_size_mb']:.2f} MB")
        
        print("="*60)
        print("\n[XrefGen] Use these references with Mandiant XRefer plugin")
    
    def interactive_mode(self):
        """Run in interactive mode with preview"""
        print("\n[XrefGen] Interactive mode")
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
            print("Error: This script must be run from within IDA Pro")
            return
    except Exception:
        print("Error: This script must be run from within IDA Pro")
        return
    # Suppress MSVCRT invalid parameter popups on Windows to avoid disruptive dialogs
    try:
        if os.name == 'nt':
            import ctypes
            PVF = ctypes.WINFUNCTYPE(None, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint)
            def _noop_invalid_param_handler(expr, func, file, line, pReserved):
                return
            _cb = PVF(_noop_invalid_param_handler)
            ctypes.cdll.msvcrt._set_invalid_parameter_handler(_cb)
            try:
                # Disable abort message box/report fault
                ctypes.cdll.msvcrt._set_abort_behavior(0, 0x1 | 0x2)
            except Exception:
                pass
    except Exception:
        pass
    # Install safe print shim early so all subsequent prints are safe
    _install_safe_print()
    
    # Parse arguments (if any)
    parser = argparse.ArgumentParser(description="XrefGen - Advanced Cross-Reference Generator")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("-i", "--incremental", action="store_true", help="Run incremental analysis")
    parser.add_argument("-m", "--modules", nargs="+", help="Specific modules to run")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--clear-cache", action="store_true", help="Clear cache before running")
    
    # IDA doesn't pass sys.argv properly, so we'll use defaults
    args = parser.parse_args([])  # Empty args for IDA context
    
    # Create XrefGen instance
    xrefgen = XrefGen(config_file=args.config)
    # Wire optimizer logger to file logger
    try:
        xrefgen.optimizer.logger = _dbg_log
    except Exception:
        pass
    
    # Clear cache if requested
    if args.clear_cache:
        xrefgen.optimizer.clear_cache()
    
    # Run analysis
    if args.interactive:
        xrefgen.interactive_mode()
    else:
        xrefgen.run(
            modules=args.modules,
            incremental=args.incremental
        )
    
    print("\n[XrefGen] Analysis complete!")


if __name__ == "__main__":
    main()
