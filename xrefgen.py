#!/usr/bin/env python3
"""
XrefGen - Advanced Cross-Reference Generator for IDA Pro
Main orchestrator script that executes all analysis modules

Author: Marc Rivero | @seifreed
Version: 2.0
"""

import sys
import os
import time
import argparse
from typing import Dict, List, Any

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import idaapi
import idautils
import idc
import ida_auto
import ida_kernwin

# Import core modules
from modules.core.base import ModuleManager
from modules.core.config import Config

# Import analysis modules
from modules.analysis.data_flow import DataFlowAnalyzer
from modules.obfuscation.detector import ObfuscationDetector
from modules.architecture.cross_arch import CrossArchAnalyzer
from modules.graph.analyzer import GraphAnalyzer
from modules.performance.optimizer import PerformanceOptimizer

# Import modules that will be stubs for now (can be implemented later)
# from modules.ml.similarity import MLSimilarityAnalyzer
# from modules.ida_features.ida91 import IDA91Analyzer
# from modules.interactive.preview import InteractiveAnalyzer

class XrefGen:
    """Main XrefGen orchestrator"""
    
    def __init__(self, config_file: str = None):
        """Initialize XrefGen with configuration"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    XrefGen v2.0                              ║
║     Advanced Cross-Reference Generator for IDA Pro           ║
║            Author: Marc Rivero | @seifreed                   ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        # Load configuration
        self.config = Config(config_file)
        
        # Initialize performance optimizer
        self.optimizer = PerformanceOptimizer(self.config.get_module_config('performance'))
        
        # Initialize module manager
        self.manager = ModuleManager(self.config.config)
        
        # Register all modules
        self._register_modules()
        
        # Statistics
        self.start_time = None
        self.end_time = None
        self.total_xrefs = 0
        
    def _register_modules(self):
        """Register all analysis modules"""
        print("\n[XrefGen] Registering analysis modules...")
        
        # Data Flow Analysis
        if self.config.get('modules.data_flow.enabled'):
            data_flow = DataFlowAnalyzer(self.config.get_module_config('data_flow'))
            self.manager.register_module(data_flow)
        
        # Obfuscation Detection
        if self.config.get('modules.obfuscation.enabled'):
            obfuscation = ObfuscationDetector(self.config.get_module_config('obfuscation'))
            self.manager.register_module(obfuscation)
        
        # Cross-Architecture Support
        if self.config.get('modules.architecture.enabled'):
            cross_arch = CrossArchAnalyzer(self.config.get_module_config('architecture'))
            self.manager.register_module(cross_arch)
        
        # Graph-Based Analysis
        if self.config.get('modules.graph.enabled'):
            graph = GraphAnalyzer(self.config.get_module_config('graph'))
            self.manager.register_module(graph)
        
        # ML-based Analysis (stub for now)
        if self.config.get('modules.ml.enabled'):
            try:
                from modules.ml.similarity import MLSimilarityAnalyzer
                ml_analyzer = MLSimilarityAnalyzer(self.config.get_module_config('ml'))
                self.manager.register_module(ml_analyzer)
            except ImportError:
                print("[XrefGen] ML module not available, skipping...")
        
        # IDA Pro 9.1 Features (stub for now)
        if self.config.get('modules.ida_features.enabled'):
            try:
                from modules.ida_features.ida91 import IDA91Analyzer
                ida91 = IDA91Analyzer(self.config.get_module_config('ida_features'))
                self.manager.register_module(ida91)
            except ImportError:
                print("[XrefGen] IDA 9.1 features module not available, skipping...")
        
        # Interactive Features (stub for now)
        if self.config.get('modules.interactive.enabled'):
            try:
                from modules.interactive.preview import InteractiveAnalyzer
                interactive = InteractiveAnalyzer(self.config.get_module_config('interactive'))
                self.manager.register_module(interactive)
            except ImportError:
                print("[XrefGen] Interactive module not available, skipping...")
        
        print(f"[XrefGen] Registered {len(self.manager.modules)} modules")
    
    def run(self, modules: List[str] = None, incremental: bool = None):
        """Run the cross-reference generation"""
        self.start_time = time.time()
        
        print("\n[XrefGen] Starting analysis...")
        print(f"[XrefGen] Binary: {ida_nalt.get_input_file_path()}")
        print(f"[XrefGen] Architecture: {self._get_arch_name()}")
        
        # Wait for auto-analysis to complete
        if not self._wait_for_analysis():
            print("[XrefGen] Warning: IDA analysis not complete, results may be incomplete")
        
        # Check for incremental analysis
        if incremental is None:
            incremental = self.config.get('modules.performance.incremental', True)
        
        # Get modified functions if incremental
        modified_functions = set()
        if incremental:
            modified_functions = self.optimizer.get_modified_functions()
            if not modified_functions:
                print("[XrefGen] No modified functions detected, skipping analysis")
                return
        
        # Run analysis with performance optimization
        if self.config.get('modules.performance.enabled') and self.config.get('general.parallel_processing'):
            # Parallel execution
            print("[XrefGen] Running parallel analysis...")
            results_by_module = self.optimizer.parallel_analyze(
                self.manager.modules,
                modified_only=incremental
            )
            
            # Combine results
            all_results = []
            for module_results in results_by_module.values():
                all_results.extend(module_results)
        else:
            # Sequential execution
            print("[XrefGen] Running sequential analysis...")
            all_results = self.manager.run_analysis(modules)
        
        # Filter by confidence
        min_confidence = self.config.get('general.min_confidence', 0.5)
        filtered_results = [(s, t, typ, conf) for s, t, typ, conf in all_results 
                           if conf >= min_confidence]
        
        self.total_xrefs = len(filtered_results)
        
        # Save results
        output_file = self.config.get('general.output_file', '_user_xrefs.txt')
        self._save_results(filtered_results, output_file)
        
        # Save cache if enabled
        if self.config.get('modules.performance.use_cache'):
            self.optimizer.save_cache()
        
        self.end_time = time.time()
        
        # Print statistics
        self._print_statistics()
    
    def _wait_for_analysis(self, timeout: int = 60) -> bool:
        """Wait for IDA auto-analysis to complete"""
        print("[XrefGen] Waiting for IDA auto-analysis to complete...")
        
        start = time.time()
        while time.time() - start < timeout:
            if ida_auto.auto_is_ok():
                print("[XrefGen] Auto-analysis complete")
                return True
            time.sleep(1)
        
        return False
    
    def _get_arch_name(self) -> str:
        """Get architecture name"""
        info = idaapi.get_inf_structure()
        procname = info.procname.lower()
        
        if 'arm' in procname:
            return 'ARM64' if info.is_64bit() else 'ARM'
        elif 'mips' in procname:
            return 'MIPS'
        elif 'wasm' in procname:
            return 'WebAssembly'
        elif info.is_64bit():
            return 'x64'
        else:
            return 'x86'
    
    def _save_results(self, results: List[Tuple[int, int, str, float]], output_file: str):
        """Save cross-references to file"""
        # Get binary directory
        binary_path = ida_nalt.get_input_file_path()
        output_path = os.path.join(os.path.dirname(binary_path), output_file)
        
        print(f"\n[XrefGen] Saving {len(results)} cross-references to {output_path}")
        
        with open(output_path, 'w') as f:
            # Write header
            f.write("# XrefGen v2.0 - Cross-Reference Analysis Results\n")
            f.write(f"# Binary: {os.path.basename(binary_path)}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total xrefs: {len(results)}\n")
            f.write("#\n")
            f.write("# Format: source,target # type (confidence)\n")
            f.write("#\n\n")
            
            # Group by type for better readability
            results_by_type = {}
            for source, target, xref_type, confidence in sorted(results):
                if xref_type not in results_by_type:
                    results_by_type[xref_type] = []
                results_by_type[xref_type].append((source, target, confidence))
            
            # Write grouped results
            for xref_type in sorted(results_by_type.keys()):
                f.write(f"\n# {xref_type} ({len(results_by_type[xref_type])} refs)\n")
                for source, target, confidence in results_by_type[xref_type]:
                    f.write(f"0x{source:x},0x{target:x} # {xref_type} ({confidence:.2f})\n")
        
        print(f"[XrefGen] Results written to: {output_path}")
    
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
            print(f"\n  Performance Statistics:")
            print(f"    Cache enabled: {stats['cache_enabled']}")
            print(f"    Incremental analysis: {stats['incremental_enabled']}")
            print(f"    Cached functions: {stats['cached_functions']}")
            print(f"    Cache size: {stats['cache_size_mb']:.2f} MB")
        
        print("="*60)
        print("\n[XrefGen] Use these references with Mandiant XRefer plugin")
    
    def interactive_mode(self):
        """Run in interactive mode with preview"""
        print("\n[XrefGen] Interactive mode")
        
        # Show menu
        choices = [
            "Run full analysis",
            "Run incremental analysis",
            "Select specific modules",
            "Configure settings",
            "Clear cache",
            "View statistics",
            "Exit"
        ]
        
        choice = ida_kernwin.choose_choose(
            choices,
            "XrefGen - Select Action",
            1
        )
        
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
            print("[XrefGen] Cache cleared")
        elif choice == 5:  # View statistics
            self._show_statistics()
        elif choice == 6:  # Exit
            return
    
    def _select_modules_dialog(self):
        """Show module selection dialog"""
        module_names = [m.get_name() for m in self.manager.modules]
        
        # Create checkboxes for each module
        selected = ida_kernwin.choose_choose(
            module_names,
            "Select modules to run",
            ida_kernwin.CH_MULTI
        )
        
        if selected:
            selected_names = [module_names[i] for i in selected]
            self.run(modules=selected_names)
    
    def _configure_dialog(self):
        """Show configuration dialog"""
        # This would show a configuration UI
        print("[XrefGen] Configuration dialog not yet implemented")
        print("[XrefGen] Edit xrefgen_config.json manually")
    
    def _show_statistics(self):
        """Show analysis statistics"""
        stats = self.optimizer.get_statistics()
        
        msg = f"""XrefGen Statistics
        
Binary Hash: {stats['binary_hash']}
Cached Functions: {stats['cached_functions']}
Cached Analyses: {stats['cached_analyses']}
Cache Size: {stats['cache_size_mb']:.2f} MB

Modules Registered: {len(self.manager.modules)}
        """
        
        ida_kernwin.info(msg)


def main():
    """Main entry point"""
    # Check if running in IDA
    try:
        import idaapi
    except ImportError:
        print("Error: This script must be run from within IDA Pro")
        return
    
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