"""Build a deterministic ZIP containing the installable IDA plugin."""

import argparse
import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import __version__


FILES = (
    "xrefgen.py",
    "xrefgen_plugin.py",
    "xrefgen_config.json",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "SECURITY.md",
    "docs/compatibility.md",
    "scripts/compare_ground_truth.py",
    "scripts/build_corpus.py",
    "scripts/ida_real_tests.py",
    "scripts/install_ida.py",
)


def build(output: pathlib.Path) -> pathlib.Path:
    root = ROOT
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [root / name for name in FILES]
    files.extend(sorted((root / "modules").rglob("*.py")))
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            relative = pathlib.Path("xrefgen") / path.relative_to(root)
            info = zipfile.ZipInfo(str(relative), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", default=f"dist/xrefgen-{__version__}.zip")
    args = parser.parse_args()
    print(build(pathlib.Path(args.output)))
