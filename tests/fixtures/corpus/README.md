# XrefGen Corpus

Each fixture has a ground-truth JSON file consumed by
`scripts/compare_ground_truth.py`. The current fixture is a negative ARM64
regression: IDA already records the indirect function-pointer reference, so
XrefGen must export no duplicate xref.

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
