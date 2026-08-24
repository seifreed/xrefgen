"""Application layer: module orchestration (IDA-agnostic)."""

from typing import Dict, List, Tuple, Any
from modules.domain.analyzer import XrefAnalyzer


class ModuleManager:
    """Manages all analysis modules."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.modules: List[XrefAnalyzer] = []
        self.results: List[Tuple[int, int, str, float]] = []
        self.results_by_module: Dict[str, List[Tuple[int, int, str, float]]] = {}

    def register_module(self, module: XrefAnalyzer):
        """Register an analysis module."""
        if module.enabled:
            self.modules.append(module)
            print(f"[XrefGen] Registered module: {module.get_name()}")

    def run_analysis(
        self, selected_modules: List[str] = None
    ) -> List[Tuple[int, int, str, float]]:
        """Run analysis on all or selected modules."""
        self.results = []
        self.results_by_module = {}

        for module in self.modules:
            if selected_modules and module.get_name() not in selected_modules:
                continue

            print(f"[XrefGen] Running {module.get_name()}...")
            try:
                module_results = module.analyze()
                self.results_by_module[module.get_name()] = module_results
                self.results.extend(module_results)
                print(
                    f"[XrefGen] {module.get_name()} found {len(module_results)} xrefs"
                )
            except (TypeError, ValueError, AttributeError, RuntimeError) as e:
                print(f"[XrefGen] Error in {module.get_name()}: {e}")
                self.results_by_module[module.get_name()] = []

        return self.results

    def get_filtered_results(
        self, min_confidence: float = 0.5
    ) -> List[Tuple[int, int, str, float]]:
        """Get results filtered by confidence score."""
        return [
            (s, t, typ, conf)
            for s, t, typ, conf in self.results
            if conf >= min_confidence
        ]
