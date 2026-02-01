"""Data-driven module registry for XrefGen."""

from dataclasses import dataclass
from importlib import import_module
from typing import Dict, Tuple, Any


@dataclass(frozen=True)
class ModuleSpec:
    key: str
    import_path: str
    class_name: str
    optional: bool = False


DEFAULT_REGISTRY: Tuple[ModuleSpec, ...] = (
    ModuleSpec("data_flow", "modules.infrastructure.ida.analysis.data_flow", "DataFlowAnalyzer"),
    ModuleSpec("obfuscation", "modules.infrastructure.ida.obfuscation.detector", "ObfuscationDetector"),
    ModuleSpec("architecture", "modules.infrastructure.ida.architecture.cross_arch", "CrossArchAnalyzer"),
    ModuleSpec("graph", "modules.infrastructure.ida.graph.analyzer", "GraphAnalyzer"),
    ModuleSpec("ml", "modules.infrastructure.ida.ml.similarity", "MLSimilarityAnalyzer", optional=True),
    ModuleSpec("ida_features", "modules.infrastructure.ida.ida_features.ida91", "IDA91Analyzer", optional=True),
    ModuleSpec("interactive", "modules.infrastructure.ida.interactive.preview", "InteractiveAnalyzer", optional=True),
)


def _load_class(import_path: str, class_name: str):
    module = import_module(import_path)
    return getattr(module, class_name)


def build_modules(config: Dict[str, Any], registry: Tuple[ModuleSpec, ...] = DEFAULT_REGISTRY):
    """Instantiate modules based on config and registry."""
    instances = []

    for spec in registry:
        enabled = bool(config.get("modules", {}).get(spec.key, {}).get("enabled", False))
        if not enabled:
            continue
        try:
            cls = _load_class(spec.import_path, spec.class_name)
            instances.append(cls(config.get("modules", {}).get(spec.key, {})))
        except Exception as exc:
            if spec.optional:
                print(f"[XrefGen] Optional module {spec.key} not available: {exc}")
            else:
                raise

    return instances
