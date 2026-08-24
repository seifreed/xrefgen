# XrefGen Corpus

Each fixture has a ground-truth JSON file consumed by
`scripts/compare_ground_truth.py`. Fixtures without a calibrated positive
mapping use `negative_no_new_xrefs.ground_truth.json` as a duplicate-xref
baseline; the ARM64 fixture is also retained as a concrete negative regression.

The symbolic positive fixture can be run inside IDA with
`XREFGEN_ROOT=/path/to/xrefgen XREFGEN_EXPECTED_JSON=... scripts/ida_corpus_tests.py`;
it removes the known direct call edge in the temporary IDB copy and checks
that GraphAnalyzer reconstructs the real call instruction and target.

Build it for an IDA integration run with:

```bash
clang -O0 -fno-pie -no-pie -g \
  -o arm64_function_pointer tests/fixtures/corpus/arm64_function_pointer.c
```

Run `scripts/ida_real_tests.py` inside IDA with
`XREFGEN_EXPECTED_JSON` pointing at the matching ground-truth file, then gate
the export with precision and recall thresholds. Additional compiler,
architecture, and obfuscation fixtures should be added before beta claims.
