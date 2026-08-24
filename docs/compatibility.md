# Compatibility

The independent code is tested with Python 3.9 through 3.12 in CI. IDA-backed execution uses
the `ida_ida.inf_*` APIs and is intended for:

| IDA | Hex-Rays | Status |
| --- | --- | --- |
| 9.1 | optional | compatibility target |
| 9.2 | optional | primary target |
| 9.3 | optional | primary target |
| Home | unavailable | controlled degradation |

This repository does not contain IDA Pro or Hex-Rays, so these entries are
targets rather than a certification claim. Run `scripts/ida_real_tests.py`
inside each installation and compare the exported JSON with a corpus fixture.
WebAssembly support is planned/experimental and is not enabled by default.
The source corpus is described by `tests/fixtures/corpus/manifest.json` and can
be built with `python scripts/build_corpus.py`; MIPS and cross-target entries
require a matching local compiler target.
