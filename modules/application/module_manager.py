"""Application layer: module orchestration (IDA-agnostic)."""

from typing import Any, Dict, List
from modules.domain.analyzer import XrefAnalyzer
from modules.domain.results import AnalysisResult, RESULT_TYPES


class ModuleManager:
    """Manages all analysis modules."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.modules: List[XrefAnalyzer] = []
        self.results: List[AnalysisResult] = []
        self.results_by_module: Dict[str, List[AnalysisResult]] = {}

    def register_module(self, module: XrefAnalyzer):
        """Register an analysis module."""
        if module.enabled:
            self.modules.append(module)
            print(f"[XrefGen] Registered module: {module.get_name()}")

    def run_analysis(
        self, selected_modules: List[str] = None
    ) -> List[AnalysisResult]:
        """Run analysis on all or selected modules."""
        self.results = []
        self.results_by_module = {}

        for module in self.modules:
            if selected_modules and module.get_name() not in selected_modules:
                continue

            print(f"[XrefGen] Running {module.get_name()}...")
            try:
                module_results = module.analyze()
                if any(not isinstance(result, RESULT_TYPES) for result in module_results):
                    raise TypeError(
                        f"{module.get_name()} returned an untyped analysis result"
                    )
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
    ) -> List[AnalysisResult]:
        """Get results filtered by confidence score."""
        return [result for result in self.results if result.confidence >= min_confidence]
