"""Verify full, cold-incremental, and warm-incremental DataFlow results in IDA."""

import copy
import json
import os
import shutil
import tempfile

import ida_auto
import idautils
import idc

ROOT = os.environ.get("XREFGEN_ROOT", os.getcwd())
os.sys.path.insert(0, ROOT)

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
    performance = config["modules"].setdefault("performance", {})
    performance.update(
        {
            "enabled": True,
            "use_cache": use_cache,
            "incremental": True,
            "cache_dir": cache_dir,
        }
    )
    return config


def _run(config, modified_only, modified_functions):
    performance = config["modules"]["performance"]
    optimizer = PerformanceOptimizer(performance)
    modules = build_modules(config)
    results = optimizer.analyze_sequential(
        modules,
        modified_only=modified_only,
        selected_modules=["DataFlowAnalyzer"],
        modified_functions=modified_functions,
    )
    optimizer.commit_cache()
    values = results.get("DataFlowAnalyzer", [])
    return sorted(
        (serialize_result(value) for value in values),
        key=lambda value: json.dumps(value, sort_keys=True),
    )


def run():
    ida_auto.auto_wait()
    all_functions = set(idautils.Functions())
    cache_dir = tempfile.mkdtemp(prefix="xrefgen-equivalence-")
    try:
        full = _run(
            _config(cache_dir),
            modified_only=False,
            modified_functions=all_functions,
        )
        cold = _run(
            _config(os.path.join(cache_dir, "cold"), use_cache=False),
            modified_only=True,
            modified_functions=all_functions,
        )
        warm = _run(
            _config(cache_dir),
            modified_only=True,
            modified_functions=set(),
        )
        report = {
            "functions": len(all_functions),
            "full_results": len(full),
            "cold_incremental_results": len(cold),
            "warm_incremental_results": len(warm),
            "full_equals_cold_incremental": full == cold,
            "full_equals_warm_incremental": full == warm,
        }
        output = os.environ.get("XREFGEN_EQUIVALENCE_OUTPUT")
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)
                handle.write("\n")
        print(json.dumps(report, sort_keys=True))
        return 0 if all(
            (report["full_equals_cold_incremental"], report["full_equals_warm_incremental"])
        ) else 1
    finally:
        shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
    idc.qexit(run())
