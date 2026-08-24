import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "corpus"


def test_corpus_manifest_covers_real_fixture_families_and_variants():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    fixtures = manifest["fixtures"]
    languages = {fixture["language"] for fixture in fixtures}
    variants = sum(len(fixture.get("variants", manifest["variants"])) for fixture in fixtures)

    assert len(fixtures) >= 15
    assert variants >= 20
    assert {"c", "cpp", "rust", "go"}.issubset(languages)
    assert any(fixture.get("target", "").startswith("mips") for fixture in fixtures)
    assert any("opaque" in fixture["name"] for fixture in fixtures)
    assert all((CORPUS / fixture["source"]).is_file() for fixture in fixtures)
    assert all(
        (CORPUS / fixture.get("ground_truth", "negative_no_new_xrefs.ground_truth.json")).is_file()
        for fixture in fixtures
    )
    assert (CORPUS / "arm64_function_pointer_positive.ground_truth.json").is_file()
