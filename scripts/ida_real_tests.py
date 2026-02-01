"""Run real analysis tests inside IDA (no mocks).
Usage: In IDA Python console -> exec(open('scripts/ida_real_tests.py').read())
"""
import ida_nalt
from modules.application.config import Config
from modules.application.registry import build_modules
from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer

cfg = Config().config
modules = build_modules(cfg)
optimizer = PerformanceOptimizer(cfg.get("modules", {}).get("performance", {}))

print("[IDA Real Tests] Binary:", ida_nalt.get_input_file_path())

# Run a minimal analysis pass and assert basic invariants
results_by_module = optimizer.analyze_sequential(modules, modified_only=False)

# Basic checks: each module returns a list
for name, res in results_by_module.items():
    assert isinstance(res, list), f"Module {name} did not return a list"

# Sanity: total results list can be empty, but structure must be tuples
all_results = []
for res in results_by_module.values():
    all_results.extend(res)
for item in all_results:
    assert isinstance(item, tuple) and len(item) == 4, "Invalid xref tuple"

print("[IDA Real Tests] OK: modules executed, results validated")
