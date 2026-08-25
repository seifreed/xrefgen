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
WebAssembly support is experimental and parser-level: it covers static
`call_indirect` table entries and `br_table` block targets when IDA exposes a
matching WASM input. Dynamic table indices remain findings rather than XRefer
candidates, and WASM is not currently covered by the certified corpus matrix.
The optional Similarity Analyzer is a deterministic mnemonic-set Jaccard
heuristic. It emits relationship metadata; it is not an ML or embeddings
implementation and should not be presented as one.
The source corpus is described by `tests/fixtures/corpus/manifest.json` and can
be built with `python scripts/build_corpus.py`; MIPS and cross-target entries
require a matching local compiler target.

The maintained portable corpus lives in the separate `xrefgen-corpus` repository
and exports the same `validation-manifest.json` contract. `run_corpus_matrix.py`
accepts either that external build or the legacy in-repository corpus.
