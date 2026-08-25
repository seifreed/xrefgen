"""Verify DataFlow equivalence across a real callee patch and IDB reopen.

Run this script twice inside IDA with XREFGEN_INCREMENTAL_STAGE set to
``mutate`` and then ``reopen``. The first stage writes the patched IDB and
cache; the second stage proves the persisted cache can be reused after IDA
starts again.
"""

import copy
import json
import os
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_loader
import idautils
import idc

ROOT = os.environ.get("XREFGEN_ROOT", os.getcwd())
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules.application.config import Config
from modules.application.registry import build_modules
from modules.domain.results import serialize_result
from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer


def _config(cache_dir, use_cache=True):
    path = os.environ.get("XREFGEN_CONFIG", os.path.join(ROOT, "xrefgen_config.json"))
    config = copy.deepcopy(Config(path).config)
    for name, module_config in config.setdefault("modules", {}).items():
        if isinstance(module_config, dict):
            module_config["enabled"] = name == "data_flow"
    config["modules"].setdefault("performance", {}).update(
        {
            "enabled": True,
            "use_cache": use_cache,
            "incremental": True,
            "cache_dir": cache_dir,
        }
    )
    return config


def _results(values):
    return sorted(
        (serialize_result(value) for value in values),
        key=lambda value: json.dumps(value, sort_keys=True),
    )


def _run(config, modified_only, modified_functions):
    optimizer = PerformanceOptimizer(config["modules"]["performance"])
    modules = build_modules(config)
    values = optimizer.analyze_sequential(
        modules,
        modified_only=modified_only,
        selected_modules=["DataFlowAnalyzer"],
        modified_functions=modified_functions,
    ).get("DataFlowAnalyzer", [])
    optimizer.commit_cache()
    return _results(values), optimizer


def _resolve(name):
    for candidate in (name, f"_{name}"):
        address = idc.get_name_ea_simple(candidate)
        if address != idc.BADADDR:
            return address
    raise ValueError(f"symbol not found: {name}")


def _caller_of(callee):
    for xref in idautils.XrefsTo(callee, 0):
        function = ida_funcs.get_func(xref.frm)
        if function and function.start_ea != callee:
            return function.start_ea
    raise ValueError(f"caller not found for 0x{callee:x}")


def _save_database():
    ida_loader.save_database(idc.get_idb_path(), 0)


def _write_report(report):
    output = os.environ.get("XREFGEN_EQUIVALENCE_OUTPUT")
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps(report, sort_keys=True))
    return report


def _mutate(cache_dir):
    callee = _resolve(os.environ.get("XREFGEN_CALLEE", "add"))
    caller = _caller_of(callee)
    full_before, _ = _run(
        _config(cache_dir), modified_only=False, modified_functions=set()
    )

    original = ida_bytes.get_byte(callee)
    ida_bytes.patch_byte(callee, original ^ 1)
    if ida_bytes.get_byte(callee) == original:
        raise RuntimeError("callee patch did not change the IDB")

    config = _config(cache_dir)
    all_functions = set(idautils.Functions())
    analyzer = next(
        module
        for module in build_modules(config)
        if module.get_name() == "DataFlowAnalyzer"
    )
    cache_optimizer = PerformanceOptimizer(config["modules"]["performance"])
    invalidated = analyzer.prepare_incremental(
        {callee}, all_functions, cache_optimizer.analysis_cache
    )
    incremental, _ = _run(
        config, modified_only=True, modified_functions={callee}
    )
    full_after, _ = _run(
        _config(os.path.join(cache_dir, "full-after"), use_cache=False),
        modified_only=False,
        modified_functions=set(),
    )
    _save_database()
    return _write_report(
        {
            "stage": "mutate",
            "caller": f"0x{caller:x}",
            "callee": f"0x{callee:x}",
            "patched_byte": True,
            "caller_invalidated": caller in invalidated,
            "callee_invalidated": callee in invalidated,
            "full_before_results": len(full_before),
            "incremental_results": len(incremental),
            "full_after_results": len(full_after),
            "incremental_equals_full_after": incremental == full_after,
        }
    )


def _reopen(cache_dir):
    warm, _ = _run(
        _config(cache_dir), modified_only=True, modified_functions=set()
    )
    full, _ = _run(
        _config(os.path.join(cache_dir, "full-reopen"), use_cache=False),
        modified_only=False,
        modified_functions=set(),
    )
    return _write_report(
        {
            "stage": "reopen",
            "warm_results": len(warm),
            "full_results": len(full),
            "warm_equals_full": warm == full,
        }
    )


def run():
    ida_auto.auto_wait()
    stage = os.environ.get("XREFGEN_INCREMENTAL_STAGE", "mutate")
    cache_dir = os.environ.get("XREFGEN_INCREMENTAL_CACHE", ".xrefgen-reopen-cache")
    if stage == "mutate":
        report = _mutate(cache_dir)
        return 0 if report["caller_invalidated"] and report["incremental_equals_full_after"] else 1
    if stage == "reopen":
        report = _reopen(cache_dir)
        return 0 if report["warm_equals_full"] else 1
    raise ValueError(f"unsupported stage: {stage}")


if __name__ == "__main__":
    idc.qexit(run())
