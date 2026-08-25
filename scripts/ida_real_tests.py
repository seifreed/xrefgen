"""Run real analysis checks inside IDA (no mocks).
Usage: In the IDA console, execute this file from the repository root.
"""
import json
import os
import copy
import sys
import idautils
import ida_nalt
import idc

ROOT = os.environ.get("XREFGEN_ROOT", os.getcwd())
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules.application.config import Config
from modules.application.registry import build_modules
from modules.domain.results import (
    RESULT_TYPES,
    ResultStore,
    is_control_flow_mnemonic,
)
from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer

cfg = Config().config
modules = build_modules(cfg)
optimizer = PerformanceOptimizer(cfg.get("modules", {}).get("performance", {}))

print("[IDA Real Tests] Binary:", ida_nalt.get_input_file_path())

# Run a minimal analysis pass and assert basic invariants
results_by_module = optimizer.analyze_sequential(modules, modified_only=False)

# Basic checks: each module returns a list
for name, res in results_by_module.items():
    if not isinstance(res, list):
        raise ValueError(f"Module {name} did not return a list (got {type(res)})")

# Validate the same export contract used by the production orchestrator.
all_results = []
for res in results_by_module.values():
    all_results.extend(res)

for item in all_results:
    if not isinstance(item, RESULT_TYPES):
        raise ValueError(f"Invalid analysis result: expected typed result, got {item}")

store = ResultStore(
    source_is_control_flow=lambda ea: is_control_flow_mnemonic(idc.print_insn_mnem(ea)),
    target_is_executable=lambda ea: any(
        getattr(module, "is_valid_reference", lambda _ea: False)(ea)
        for module in modules
    ),
    already_exists=lambda source, target: any(
        getattr(module, "is_already_in_ida", lambda _source, _target: False)(source, target)
        for module in modules
    ),
)
for item in all_results:
    if isinstance(item, RESULT_TYPES):
        store.add_result(item)
    else:
        store.add(*item)

expected_path = os.environ.get("XREFGEN_EXPECTED_JSON")
if expected_path:
    with open(expected_path, encoding="utf-8") as expected_file:
        expected = json.load(expected_file)
    actual = {(f"0x{s:x}", f"0x{t:x}", kind) for s, t, kind, _ in store.xrefs()}
    wanted = {
        (entry["source"], entry["target"], entry["kind"])
        for entry in expected.get("expected_xrefs", [])
    }
    forbidden = {
        (entry["source"], entry["target"], entry["kind"])
        for entry in expected.get("forbidden_xrefs", [])
    }
    if not wanted.issubset(actual):
        raise ValueError(f"Missing expected xrefs: {sorted(wanted - actual)}")
    if actual.intersection(forbidden):
        raise ValueError(f"Forbidden xrefs emitted: {sorted(actual.intersection(forbidden))}")

print("[IDA Real Tests] OK: modules executed, results validated")

if os.environ.get("XREFGEN_ASSERT_EQUIVALENCE"):
    equivalence_cfg = copy.deepcopy(cfg)
    performance_cfg = equivalence_cfg.setdefault("modules", {}).setdefault("performance", {})
    performance_cfg["use_cache"] = False
    performance_cfg["incremental"] = True

    full_optimizer = PerformanceOptimizer(performance_cfg)
    full_results = full_optimizer.analyze_sequential(
        build_modules(equivalence_cfg), modified_only=False
    )
    incremental_optimizer = PerformanceOptimizer(performance_cfg)
    incremental_results = incremental_optimizer.analyze_sequential(
        build_modules(equivalence_cfg),
        modified_only=True,
        modified_functions=set(idautils.Functions()),
    )
    if full_results != incremental_results:
        raise ValueError("full and incremental analysis results differ")
    print("[IDA Real Tests] OK: full/incremental results are equivalent")
