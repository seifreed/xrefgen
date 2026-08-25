"""Run the persisted incremental DataFlow check over several IDA binaries."""

import argparse
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_incremental_reopen.py"
SIDECARS = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")


def _clean(binary):
    for suffix in SIDECARS:
        binary.with_name(binary.name + suffix).unlink(missing_ok=True)


def run(binaries, ida, callee, cache_root, expect_nonempty):
    reports = []
    for binary in binaries:
        binary = binary.resolve()
        _clean(binary)
        cache = cache_root / binary.stem
        for path in (cache,):
            if path.exists():
                for child in sorted(path.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                path.rmdir()
        stages = {}
        for stage in ("mutate", "reopen"):
            output = cache_root / f"{binary.stem}-{stage}.json"
            environment = dict(os.environ)
            environment.update(
                {
                    "XREFGEN_ROOT": str(ROOT),
                    "XREFGEN_INCREMENTAL_STAGE": stage,
                    "XREFGEN_INCREMENTAL_CACHE": str(cache),
                    "XREFGEN_CALLEE": callee,
                    "XREFGEN_EQUIVALENCE_OUTPUT": str(output),
                    "XREFGEN_EXPECT_NONEMPTY": "1" if expect_nonempty else "0",
                }
            )
            completed = subprocess.run(
                [str(ida), "-A", f"-S{SCRIPT}", str(binary)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            stages[stage] = {
                "returncode": completed.returncode,
                "report": json.loads(output.read_text()) if output.exists() else None,
            }
        reports.append({"binary": str(binary), "stages": stages})
    return reports


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida", default=os.environ.get("XREFGEN_IDA_9_3_MACOS"))
    parser.add_argument("--binary", action="append", required=True)
    parser.add_argument("--callee", default="flow")
    parser.add_argument("--cache-root", type=Path, default=Path("/tmp/xrefgen-reopen-matrix"))
    parser.add_argument("--expect-nonempty", action="store_true")
    args = parser.parse_args()
    if not args.ida:
        parser.error("--ida or XREFGEN_IDA_9_3_MACOS is required")
    args.cache_root.mkdir(parents=True, exist_ok=True)
    reports = run(
        [Path(path) for path in args.binary],
        Path(args.ida),
        args.callee,
        args.cache_root,
        args.expect_nonempty,
    )
    print(json.dumps(reports, indent=2, sort_keys=True))
    raise SystemExit(
        1
        if any(
            stage["returncode"]
            for report in reports
            for stage in report["stages"].values()
        )
        else 0
    )
