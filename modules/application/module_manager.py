"""Application layer: module orchestration (IDA-agnostic)."""

from typing import Any, Dict, List
import time
from modules.domain.analyzer import XrefAnalyzer
from modules.domain.results import AnalysisResult, RESULT_TYPES
from modules.presentation.logger import info, exception


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
            info(f"Registered module: {module.get_name()}")

    def run_analysis(
        self, selected_modules: List[str] = None
    ) -> List[AnalysisResult]:
        """Run analysis on all or selected modules."""
        self.results = []
        self.results_by_module = {}

        for module in self.modules:
            if selected_modules and module.get_name() not in selected_modules:
                continue

            module_name = module.get_name()
            started = time.perf_counter()
            info("Analysis module started", event_name="module.started", module=module_name, status="started")
            try:
                module_results = module.analyze()
                if any(not isinstance(result, RESULT_TYPES) for result in module_results):
                    raise TypeError(
                        f"{module.get_name()} returned an untyped analysis result"
                    )
                self.results_by_module[module.get_name()] = module_results
                self.results.extend(module_results)
                info(
                    "Analysis module completed", event_name="module.finished",
                    module=module_name, status="completed",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    result_count=len(module_results),
                )
            except (TypeError, ValueError, AttributeError, RuntimeError) as e:
                exception(
                    "Analysis module failed", event_name="module.failed",
                    module=module_name, status="failed",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                )
                self.results_by_module[module.get_name()] = []

        return self.results

    def get_filtered_results(
        self, min_confidence: float = 0.5
    ) -> List[AnalysisResult]:
        """Get results filtered by confidence score."""
        return [result for result in self.results if result.confidence >= min_confidence]
