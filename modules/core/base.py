"""
Base classes and interfaces for XrefGen modules
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Set, Any
import idaapi
import idautils
import idc
import ida_funcs
import ida_segment

class XrefAnalyzer(ABC):
    """Base class for all xref analysis modules"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.xrefs: Dict[Tuple[int, int], str] = {}
        self.confidence_scores: Dict[Tuple[int, int], float] = {}
        self.enabled = self.config.get('enabled', True)
        
    @abstractmethod
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """
        Perform analysis and return cross-references
        Returns: List of (source, target, type, confidence) tuples
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Return module name"""
        pass
    
    def is_valid_reference(self, target: int) -> bool:
        """Validate if a reference target is reasonable"""
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
    
    def is_already_in_ida(self, source: int, target: int) -> bool:
        """Check if the reference is already known to IDA"""
        for xref in idautils.XrefsFrom(source, 0):
            if xref.to == target:
                return True
        return False
    
    def add_xref(self, source: int, target: int, xref_type: str, confidence: float = 1.0):
        """Add a cross-reference with confidence score"""
        if self.is_valid_reference(target) and not self.is_already_in_ida(source, target):
            self.xrefs[(source, target)] = xref_type
            self.confidence_scores[(source, target)] = confidence
            
    def get_results(self) -> List[Tuple[int, int, str, float]]:
        """Get all discovered xrefs with confidence scores"""
        results = []
        for (source, target), xref_type in self.xrefs.items():
            confidence = self.confidence_scores.get((source, target), 1.0)
            results.append((source, target, xref_type, confidence))
        return results


class ModuleManager:
    """Manages all analysis modules"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.modules: List[XrefAnalyzer] = []
        self.results: List[Tuple[int, int, str, float]] = []
        
    def register_module(self, module: XrefAnalyzer):
        """Register an analysis module"""
        if module.enabled:
            self.modules.append(module)
            print(f"[XrefGen] Registered module: {module.get_name()}")
            
    def run_analysis(self, selected_modules: List[str] = None) -> List[Tuple[int, int, str, float]]:
        """Run analysis on all or selected modules"""
        self.results = []
        
        for module in self.modules:
            if selected_modules and module.get_name() not in selected_modules:
                continue
                
            print(f"[XrefGen] Running {module.get_name()}...")
            try:
                module_results = module.analyze()
                self.results.extend(module_results)
                print(f"[XrefGen] {module.get_name()} found {len(module_results)} xrefs")
            except Exception as e:
                print(f"[XrefGen] Error in {module.get_name()}: {e}")
                
        return self.results
    
    def get_filtered_results(self, min_confidence: float = 0.5) -> List[Tuple[int, int, str, float]]:
        """Get results filtered by confidence score"""
        return [(s, t, typ, conf) for s, t, typ, conf in self.results if conf >= min_confidence]
    
    def save_results(self, output_file: str, min_confidence: float = 0.5):
        """Save results to file"""
        filtered_results = self.get_filtered_results(min_confidence)
        
        with open(output_file, 'w') as f:
            for source, target, xref_type, confidence in sorted(filtered_results):
                f.write(f"0x{source:x},0x{target:x} # {xref_type} (conf: {confidence:.2f})\n")
                
        print(f"[XrefGen] Saved {len(filtered_results)} xrefs to {output_file}")