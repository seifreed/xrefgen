"""Compare an XrefGen JSON export with a corpus ground-truth file."""

import argparse
import json


def _refs(payload):
    return {
        (item["source"], item["target"], item.get("kind", item.get("type", "")))
        for item in payload
    }


def compare(actual_path, expected_path):
    with open(actual_path, encoding="utf-8") as actual_file:
        actual = _refs(json.load(actual_file))
    with open(expected_path, encoding="utf-8") as expected_file:
        expected_payload = json.load(expected_file)
    expected = _refs(expected_payload.get("expected_xrefs", []))
    forbidden = _refs(expected_payload.get("forbidden_xrefs", []))
    true_positives = actual & expected
    false_positives = actual - expected
    false_negatives = expected - actual
    precision = len(true_positives) / len(actual) if actual else 1.0
    recall = len(true_positives) / len(expected) if expected else 1.0
    return {
        "precision": precision,
        "recall": recall,
        "true_positives": sorted(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "forbidden_emitted": sorted(actual & forbidden),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("actual_json")
    parser.add_argument("expected_json")
    parser.add_argument("--min-precision", type=float, default=None)
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--fail-on-false-positive", action="store_true")
    args = parser.parse_args()
    report = compare(args.actual_json, args.expected_json)
    print(json.dumps(report, indent=2))
    failures = []
    if report["forbidden_emitted"]:
        failures.append("forbidden xrefs emitted")
    if report["false_negatives"]:
        failures.append("expected xrefs missing")
    if args.fail_on_false_positive and report["false_positives"]:
        failures.append("false positives emitted")
    if args.min_precision is not None and report["precision"] < args.min_precision:
        failures.append("precision below threshold")
    if args.min_recall is not None and report["recall"] < args.min_recall:
        failures.append("recall below threshold")
    if failures:
        print("Ground truth gate failed: " + "; ".join(failures))
        raise SystemExit(1)
