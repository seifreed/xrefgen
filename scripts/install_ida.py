"""Install XrefGen into an IDA user directory without deleting existing files."""

import argparse
import os
import pathlib
import shutil
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE_FILES = ("xrefgen.py", "xrefgen_config.json")


def install(ida_user_dir: pathlib.Path, source_root: pathlib.Path = ROOT) -> pathlib.Path:
    scripts_dir = ida_user_dir / "scripts" / "xrefgen"
    plugins_dir = ida_user_dir / "plugins"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    plugins_dir.mkdir(parents=True, exist_ok=True)

    for name in CORE_FILES:
        shutil.copy2(source_root / name, scripts_dir / name)
    shutil.copytree(source_root / "modules", scripts_dir / "modules", dirs_exist_ok=True)
    shutil.copy2(source_root / "xrefgen_plugin.py", plugins_dir / "xrefgen_plugin.py")
    return scripts_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ida-user-dir",
        default=os.environ.get("IDAUSR"),
        help="IDA user directory (also read from IDAUSR)",
    )
    parser.add_argument("--source-root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args(argv)
    if not args.ida_user_dir:
        parser.error("--ida-user-dir or IDAUSR is required")
    scripts_dir = install(pathlib.Path(args.ida_user_dir).expanduser(), args.source_root)
    print(f"Installed XrefGen core to {scripts_dir}")
    print(f"Installed plugin to {scripts_dir.parent.parent / 'plugins' / 'xrefgen_plugin.py'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
