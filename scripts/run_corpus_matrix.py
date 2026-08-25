"""Run every built corpus artifact against declared IDA installations."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.compare_ground_truth import compare


DEFAULT_MATRIX = ROOT / "tests" / "fixtures" / "corpus" / "validation_matrix.json"


def _run_target(target, manifest, corpus_root, script, strict):
    executable = os.environ.get(target["executable_env"])
    if not executable:
        return [{"target": target, "status": "missing_executable"}]

    reports = []
    for artifact in manifest["artifacts"]:
        actual = corpus_root / "reports" / target["id"] / (
            artifact["fixture"] + "-" + artifact["variant"] + ".json"
        )
        actual.parent.mkdir(parents=True, exist_ok=True)
        metrics = actual.with_name(actual.stem + ".metrics.json")
        expected = corpus_root / artifact["ground_truth"]
        if not expected.is_file():
            expected = ROOT / "tests" / "fixtures" / "corpus" / artifact["ground_truth"]
        environment = dict(os.environ)
        environment.update({
            "XREFGEN_ROOT": str(ROOT),
            "XREFGEN_EXPECTED_JSON": str(expected),
            "XREFGEN_CORPUS_ACTUAL": str(actual),
            "XREFGEN_CORPUS_METRICS": str(metrics),
        })
        binary = corpus_root / artifact["path"]
        for suffix in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
            binary.with_name(binary.name + suffix).unlink(missing_ok=True)
        command = [executable, "-A", f"-S{script}", str(binary)]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        report = {
            "target": target,
            "fixture": artifact["fixture"],
            "variant": artifact["variant"],
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
        if actual.exists():
            if metrics.exists():
                report.update(json.loads(metrics.read_text(encoding="utf-8")))
            expected_payload = json.loads(expected.read_text(encoding="utf-8"))
            if expected_payload.get("expected_symbols"):
                report["ground_truth_mode"] = "symbolic_ida"
                report["expected_symbol_count"] = len(
                    expected_payload["expected_symbols"]
                )
                report["validated_by_ida"] = completed.returncode == 0
            else:
                report.update(compare(actual, expected))
        reports.append(report)
        if completed.returncode and strict:
            raise RuntimeError(
                f"{target['id']} failed on {artifact['fixture']}/{artifact['variant']}"
            )
    return reports


def _summary(reports):
    completed = [report for report in reports if "fixture" in report]
    symbolic = [
        report for report in completed if report.get("ground_truth_mode") == "symbolic_ida"
    ]
    explicit = [report for report in completed if "precision" in report]
    true_positives = sum(len(report.get("true_positives", ())) for report in completed)
    false_positives = sum(len(report.get("false_positives", ())) for report in completed)
    false_negatives = sum(len(report.get("false_negatives", ())) for report in completed)
    actual = true_positives + false_positives
    expected = true_positives + false_negatives
    return {
        "version": 1,
        "runs": len(reports),
        "completed_runs": len(completed),
        "missing_targets": sum(report.get("status") == "missing_executable" for report in reports),
        "failed_runs": sum(report.get("returncode", 0) != 0 for report in completed),
        "symbolic_runs": len(symbolic),
        "symbolic_validated": sum(report.get("validated_by_ida", False) for report in symbolic),
        "explicit_runs": len(explicit),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": true_positives / actual if actual else 1.0,
        "recall": true_positives / expected if expected else 1.0,
    }


def run(corpus_root, matrix_path, strict=False, target_ids=None):
    manifest_path = corpus_root / "validation-manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"missing {manifest_path}; run build_corpus.py first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    targets = [
        target for target in matrix["ida"]
        if not target_ids or target["id"] in target_ids
    ]
    script = ROOT / "scripts" / "ida_corpus_tests.py"
    reports = []
    for target in targets:
        reports.extend(_run_target(target, manifest, corpus_root, script, strict))
    output = corpus_root / "matrix-report.json"
    output.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (corpus_root / "matrix-summary.json").write_text(
        json.dumps(_summary(reports), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return reports


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    reports = run(args.corpus, args.matrix, args.strict, set(args.targets or ()))
    summary = _summary(reports)
    print(json.dumps(summary, sort_keys=True))
    raise SystemExit(
        1
        if summary["failed_runs"] or (args.strict and summary["missing_targets"])
        else 0
    )
