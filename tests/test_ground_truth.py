import json

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
