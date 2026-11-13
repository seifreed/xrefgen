# Changelog

## 1.0.0

- First stable release of XrefGen.
- Export validated indirect control-flow candidates in XRefer-compatible format;
  keep data-flow findings, similarity relationships, and rejected candidates in
  separate detailed exports.
- Analyze data flow, call graphs, wrappers, callbacks, vtables, and common
  obfuscation patterns, with ABI-aware cross-architecture support.
- Add deterministic incremental analysis, transactional JSON caches, and
  interactive controls for full, incremental, and module-selected runs.
- Export evidence in text, JSON, and CSV formats and provide configurable
  output naming and formatting.
- Include deterministic mnemonic similarity as relationship metadata, optional
  Hex-Rays evidence, and experimental parser-level WASM support.
- Harden logging and private file creation, and add structured observability
  with correlation for analysis operations.
- Add real-IDA integration checks, symbolic corpus validation, precision/recall
  gates, and reproducible plugin ZIP packaging.
