"""Run a symbolic ground-truth fixture inside IDA without saving the IDB."""

import copy
import json
import os
import sys

import ida_xref
import ida_auto
import idautils
import idc


ROOT = os.environ.get("XREFGEN_ROOT", os.getcwd())
sys.path.insert(0, ROOT)

from modules.application.config import Config
from modules.application.registry import build_modules
from modules.domain.results import RESULT_TYPES, ResultStore, is_control_flow_mnemonic
from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer


def _resolve(name):
    candidates = (name, f"_{name}")
    for candidate in candidates:
        ea = idc.get_name_ea_simple(candidate)
        if ea != idc.BADADDR:
            return ea
    raise ValueError(f"symbol not found in IDA: {name}")


def _symbolic_refs(payload):
    refs = []
    for entry in payload.get("expected_symbols", []):
        source = entry.get("source_address")
        if source is None:
            source = _resolve(entry["source"])
        else:
            source = int(source, 0) if isinstance(source, str) else source
        source += entry.get("source_offset", 0)
        mnemonic = entry.get("source_mnemonic")
        if mnemonic and "source_offset" not in entry:
            matches = [
                head
                for head in idautils.FuncItems(source)
                if idc.print_insn_mnem(head).lower() == mnemonic.lower()
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"expected one {mnemonic} in {entry['source']}, found {len(matches)}"
                )
            source = matches[0]
        target = entry.get("target_address")
        if target is None:
            target = _resolve(entry["target"])
        else:
            target = int(target, 0) if isinstance(target, str) else target
        if entry.get("resolve_source_by_target"):
            matches = [
                head
                for head in idautils.FuncItems(_resolve(entry["source"]))
                if (not mnemonic or idc.print_insn_mnem(head).lower() == mnemonic.lower())
                and (
                    target in idautils.CodeRefsFrom(head, False)
                    or idc.get_operand_value(head, 0) == target
                )
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"expected one call to {entry['target']} in {entry['source']}, found {len(matches)}"
                )
            source = matches[0]
        refs.append(
            {
                "source": f"0x{source:x}",
                "target": f"0x{target:x}",
                "kind": entry["kind"],
            }
        )
    return refs


def _refs(entries):
    return {
        (entry["source"], entry["target"], entry.get("kind", entry.get("type", "")))
        for entry in entries
    }


def run(expected_path):
    ida_auto.auto_wait()
    with open(expected_path, encoding="utf-8") as handle:
        expected_payload = json.load(handle)
    expected_entries = list(expected_payload.get("expected_xrefs", []))
    expected_entries.extend(_symbolic_refs(expected_payload))
    forbidden = _refs(expected_payload.get("forbidden_xrefs", []))
    expected = _refs(expected_entries)

    removed = {(int(source, 16), int(target, 16)) for source, target, _kind in expected}
    if expected_payload.get("remove_existing", False):
        for source, target in removed:
            ida_xref.del_cref(source, target, 0)

    config_path = os.environ.get("XREFGEN_CONFIG", os.path.join(ROOT, "xrefgen_config.json"))
    cfg = copy.deepcopy(Config(config_path).config)
    modules_cfg = cfg.setdefault("modules", {})
    enabled_modules = {"graph", "performance", *expected_payload.get("enabled_modules", [])}
    for name, module_cfg in modules_cfg.items():
        if name not in enabled_modules and isinstance(module_cfg, dict):
            module_cfg["enabled"] = False
    modules_cfg.setdefault("graph", {})["skip_slow_graph"] = True
    performance_cfg = modules_cfg.setdefault("performance", {})
    performance_cfg["enabled"] = True
    performance_cfg["use_cache"] = False
    performance_cfg["incremental"] = False

    modules = build_modules(cfg)
    optimizer = PerformanceOptimizer(performance_cfg)
    by_module = optimizer.analyze_sequential(modules, modified_only=False)
    all_results = [item for values in by_module.values() for item in values]
    store = ResultStore(
        source_is_control_flow=lambda ea: is_control_flow_mnemonic(idc.print_insn_mnem(ea)),
        target_is_executable=lambda ea: any(
            getattr(module, "is_valid_reference", lambda _ea: False)(ea) for module in modules
        ),
        already_exists=lambda source, target: (
            False
            if (source, target) in removed
            else any(xref.to == target for xref in idautils.XrefsFrom(source, 0))
        ),
    )
    for item in all_results:
        if not isinstance(item, RESULT_TYPES):
            raise ValueError(f"Invalid typed corpus result: {item!r}")
        store.add_result(item)

    actual = {
        (f"0x{source:x}", f"0x{target:x}", kind)
        for source, target, kind, _confidence in store.xrefs()
    }
    false_positives = actual - expected
    false_negatives = expected - actual
    precision = len(actual & expected) / len(actual) if actual else 1.0
    recall = len(actual & expected) / len(expected) if expected else 1.0
    report = {
        "precision": precision,
        "recall": recall,
        "true_positives": sorted(actual & expected),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "forbidden_emitted": sorted(actual & forbidden),
    }
    output_path = os.environ.get("XREFGEN_CORPUS_ACTUAL")
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(
                [
                    {"source": source, "target": target, "kind": kind}
                    for source, target, kind in sorted(actual)
                ],
                handle,
                indent=2,
            )
    print(json.dumps(report, indent=2))
    if false_negatives or report["forbidden_emitted"] or false_positives:
        raise SystemExit(1)
    print("[IDA Corpus] OK")


if __name__ == "__main__":
    expected_path = os.environ.get("XREFGEN_EXPECTED_JSON")
    if not expected_path:
        raise SystemExit("XREFGEN_EXPECTED_JSON is required")
    run(expected_path)
