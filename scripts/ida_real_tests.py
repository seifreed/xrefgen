"""Run real analysis checks inside IDA (no mocks).
Usage: In the IDA console, execute this file from the repository root.
"""
import json
import os
import copy
import sys
import io
import logging
import time
import tempfile
from uuid import uuid4
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
from modules import observability
from xrefgen import XrefGen

observability.configure(None)
cfg = Config().config
observability.configure(
    cfg.get("general", {}).get("log_file"),
    cfg.get("general", {}).get("log_level", "info"),
)
modules = build_modules(cfg)
optimizer = PerformanceOptimizer(cfg.get("modules", {}).get("performance", {}))

print("[IDA Real Tests] Binary:", ida_nalt.get_input_file_path())

# Run real module analysis and assert that JSON events share one correlation ID.
capture = io.StringIO()
capture_handler = logging.StreamHandler(capture)
capture_handler.setFormatter(observability._logger.handlers[0].formatter)
observability._logger.addHandler(capture_handler)
correlation_id = uuid4().hex
started = time.perf_counter()
try:
    with observability.operation_context("ida.integration_validation", correlation_id):
        observability.info(
            "IDA integration analysis started",
            event_name="ida.validation.started",
            status="started",
        )
        results_by_module = optimizer.analyze_sequential(modules, modified_only=False)
        observability.info(
            "IDA integration analysis finished",
            event_name="analysis.finished",
            status="completed",
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            module_count=len(results_by_module),
        )
except Exception:
    observability.exception(
        "IDA integration analysis failed",
        event_name="ida.validation.failed",
        status="failed",
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
    )
    raise
finally:
    observability._logger.removeHandler(capture_handler)
    capture_handler.close()

captured_events = [json.loads(line) for line in capture.getvalue().splitlines()]
if not any(
    event.get("event_name") == "analysis.finished"
    and event.get("correlation_id") == correlation_id
    and event.get("operation") == "ida.integration_validation"
    for event in captured_events
):
    raise AssertionError("Analysis completion event lacked the expected correlation context")

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
    store.add_result(item)

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

# Exercise the production orchestrator and artifact-writing path with isolated outputs.
with tempfile.TemporaryDirectory(prefix="xrefgen-observability-") as output_dir:
    orchestrator_cfg = copy.deepcopy(cfg)
    general = orchestrator_cfg.setdefault("general", {})
    general.update({
        "log_file": os.path.join(output_dir, "xrefgen.jsonl"),
        "output_name_mode": "custom",
        "output_file": os.path.join(output_dir, "xrefs.txt"),
        "details_output_file": os.path.join(output_dir, "details.txt"),
        "json_output_file": os.path.join(output_dir, "xrefs.json"),
        "csv_output_file": os.path.join(output_dir, "xrefs.csv"),
        "profile_output_file": os.path.join(output_dir, "profile.json"),
        "findings_output_file": os.path.join(output_dir, "findings.json"),
        "relationships_output_file": os.path.join(output_dir, "relationships.json"),
        "rejections_output_file": os.path.join(output_dir, "rejections.json"),
        "taint_kind_output_file": os.path.join(output_dir, "taint.txt"),
    })
    performance = orchestrator_cfg.setdefault("modules", {}).setdefault("performance", {})
    performance.update({"enabled": True, "use_cache": False})
    config_path = os.path.join(output_dir, "xrefgen_config.json")
    with open(config_path, "w", encoding="utf-8") as config_file:
        json.dump(orchestrator_cfg, config_file)

    app = XrefGen(config_file=config_path)
    capture = io.StringIO()
    capture_handler = logging.StreamHandler(capture)
    capture_handler.setFormatter(observability._logger.handlers[0].formatter)
    observability._logger.addHandler(capture_handler)
    try:
        app.run(incremental=False)
    finally:
        observability._logger.removeHandler(capture_handler)
        capture_handler.close()

    orchestrator_events = [
        json.loads(line) for line in capture.getvalue().splitlines()
    ]
    started_event = next(
        event for event in orchestrator_events
        if event.get("event_name") == "analysis.started"
    )
    finished_event = next(
        event for event in orchestrator_events
        if event.get("event_name") == "analysis.finished"
    )
    if not started_event.get("correlation_id") or any(
        event.get("correlation_id") != started_event["correlation_id"]
        for event in (finished_event,)
    ):
        raise AssertionError("Orchestrator lifecycle events were not correlated")
    if finished_event.get("duration_ms", -1) < 0:
        raise AssertionError("Orchestrator completion event lacked duration")
    for artifact in ("xrefs.txt", "details.txt", "xrefs.json", "xrefs.csv"):
        if not os.path.exists(os.path.join(output_dir, artifact)):
            raise AssertionError(f"Orchestrator did not write {artifact}")
    if not any(event.get("event_name") == "results.artifact_written" for event in orchestrator_events):
        raise AssertionError("Artifact output events were not emitted")
    with open(general["log_file"], encoding="utf-8") as log_file:
        file_events = [json.loads(line) for line in log_file]
    if not any(
        event.get("event_name") == "analysis.finished"
        and event.get("correlation_id") == started_event["correlation_id"]
        for event in file_events
    ):
        raise AssertionError("Configured JSONL sink omitted the correlated completion event")

print("[IDA Real Tests] OK: orchestrator events correlated and artifacts written")

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
