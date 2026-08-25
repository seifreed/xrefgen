"""Build the versioned XrefGen source corpus with available local toolchains."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "corpus"
MANIFEST = CORPUS / "manifest.json"


def _toolchain(language):
    names = {
        "c": (os.environ.get("XREFGEN_CC"), "clang", "cc"),
        "cpp": (os.environ.get("XREFGEN_CXX"), "clang++", "c++"),
        "rust": (os.environ.get("XREFGEN_RUSTC"), "rustc"),
        "go": (os.environ.get("XREFGEN_GO"), "go"),
    }[language]
    return next((path for name in names if name and (path := shutil.which(name))), None)


def _command(fixture, source, output, variant, compiler):
    language = fixture["language"]
    level = variant.removeprefix("O")
    common = ["-g", f"-O{level}"]
    if language == "c":
        command = [compiler, *common, "-fno-omit-frame-pointer"]
        if fixture.get("target"):
            command.extend([f"--target={fixture['target']}", "-c"])
        command.extend([str(source), "-o", str(output)])
        return command
    if language == "cpp":
        return [compiler, *common, "-fno-omit-frame-pointer", str(source), "-o", str(output)]
    if language == "rust":
        return [compiler, str(source), "-C", f"opt-level={level}", "-C", "debuginfo=2", "-o", str(output)]
    if language == "go":
        flags = ["-gcflags=all=-N -l"] if variant == "O0" else []
        return [compiler, "build", *flags, "-o", str(output), str(source)]
    raise ValueError(f"unsupported corpus language: {language}")


def build_fixture(fixture, output_root, variants, report=None):
    compiler = _toolchain(fixture["language"])
    if not compiler:
        message = f"SKIP {fixture['name']}: {fixture['language']} toolchain unavailable"
        if fixture.get("required"):
            raise RuntimeError(message)
        print(message)
        if report is not None:
            report["skipped"].append({"fixture": fixture["name"], "reason": message})
        return 0

    source = CORPUS / fixture["source"]
    built = 0
    for variant in variants:
        output_dir = output_root / fixture["name"] / variant
        output_dir.mkdir(parents=True, exist_ok=True)
        suffix = ".o" if fixture.get("artifact") == "object" else ""
        output = output_dir / f"{fixture['name']}{suffix}"
        command = _command(fixture, source, output, variant, compiler)
        print("BUILD", fixture["name"], variant)
        subprocess.run(command, check=True)
        built += 1
        if report is not None:
            report["artifacts"].append({
                "fixture": fixture["name"],
                "variant": variant,
                "path": str(output.relative_to(output_root)),
                "ground_truth": fixture.get(
                    "ground_truth", "negative_no_new_xrefs.ground_truth.json"
                ),
                "target": fixture.get("target"),
            })
    return built


def build(output_root, selected=None, strict=False):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    variants = manifest.get("variants", ["O0", "O1", "O2", "O3"])
    report = {"version": 1, "source_manifest": str(MANIFEST), "artifacts": [], "skipped": []}
    total = 0
    for fixture in manifest["fixtures"]:
        if selected and fixture["name"] not in selected:
            continue
        fixture = dict(fixture)
        if strict:
            fixture["required"] = True
        total += build_fixture(
            fixture, output_root, fixture.get("variants", variants), report
        )
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "validation-manifest.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "corpus")
    parser.add_argument("--fixture", action="append", dest="fixtures")
    parser.add_argument("--strict", action="store_true", help="fail when a toolchain is unavailable")
    args = parser.parse_args()
    count = build(args.output, set(args.fixtures or ()), args.strict)
    print(f"Built {count} corpus artifacts in {args.output}")
