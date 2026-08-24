import json
import subprocess
import sys

from scripts.compare_ground_truth import compare


def test_compare_ground_truth_reports_precision_and_recall(tmp_path):
    actual = tmp_path / "actual.json"
    expected = tmp_path / "expected.json"
    actual.write_text(
        json.dumps([{"source": "0x1000", "target": "0x2000", "type": "indirect_call"}]),
        encoding="utf-8",
    )
    expected.write_text(
        json.dumps(
            {
                "expected_xrefs": [
                    {"source": "0x1000", "target": "0x2000", "kind": "indirect_call"}
                ],
                "forbidden_xrefs": [],
            }
        ),
        encoding="utf-8",
    )

    report = compare(actual, expected)

    assert report["precision"] == 1.0
    assert report["recall"] == 1.0


def test_compare_ground_truth_cli_enforces_thresholds(tmp_path):
    actual = tmp_path / "actual.json"
    expected = tmp_path / "expected.json"
    actual.write_text(
        json.dumps([
            {"source": "0x1000", "target": "0x2000", "type": "indirect_call"},
            {"source": "0x3000", "target": "0x4000", "type": "indirect_call"},
        ]),
        encoding="utf-8",
    )
    expected.write_text(
        json.dumps({
            "expected_xrefs": [
                {"source": "0x1000", "target": "0x2000", "kind": "indirect_call"}
            ],
            "forbidden_xrefs": [],
        }),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/compare_ground_truth.py",
            str(actual),
            str(expected),
            "--min-precision",
            "0.75",
            "--fail-on-false-positive",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "false positives emitted" in proc.stdout
