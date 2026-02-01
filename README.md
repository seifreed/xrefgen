<p align="center">
  <img src="https://img.shields.io/badge/XrefGen-IDA%20Pro%20Plugin-blue?style=for-the-badge" alt="XrefGen">
</p>

<h1 align="center">XrefGen</h1>

<p align="center">
  <strong>Advanced cross-reference generation for IDA Pro, designed to extend Mandiant XRefer</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/IDA%20Pro-9.2%2B-orange?style=flat-square" alt="IDA Pro 9.2+">
  <img src="https://img.shields.io/badge/Output-XRefer%20Compatible-brightgreen?style=flat-square" alt="XRefer Compatible">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://github.com/mandiant/xrefer"><img src="https://img.shields.io/badge/Powered%20by-XRefer-black?style=flat-square" alt="XRefer"></a>
  <a href="https://github.com/mandiant"><img src="https://img.shields.io/badge/Thanks-Mandiant-blue?style=flat-square" alt="Mandiant"></a>
</p>

---

## Overview

**XrefGen** is a professional-grade cross-reference generator that detects indirect references and complex control-flow patterns that IDA Pro may miss. It is designed to feed **Mandiant XRefer** with additional user xrefs in the exact format the plugin expects.

It is especially useful for:
- Modern compiled languages (Rust, Go, C++)
- Obfuscated malware (CFF, opaque predicates, string tricks)
- Packed or heavily optimized binaries
- Multi-architecture targets

## Key Features

| Feature | Description |
|---------|-------------|
| **XRefer-Compatible Output** | Writes `0xSRC,0xDST` lines matching XRefer parser |
| **Modular Analyzer System** | Enable/disable analyzers individually |
| **Incremental & Cached Analysis** | Only re-analyze modified functions |
| **Confidence Scoring** | Each xref has a confidence score |
| **Evidence Tracking** | Evidence is exported in detailed/JSON/CSV formats |
| **Multi-Architecture** | x86, x64, ARM, ARM64, MIPS, WASM |

## Supported Architectures

- x86 / x64
- ARM / ARM64
- MIPS
- WebAssembly (WASM)

## Modules (What It Analyzes)

- **Data Flow Analyzer**
  - Taint tracking from sources to sinks
  - Pointer chains and indirect call propagation
  - Reaching-defs and CFG-based heuristics

- **Graph Analyzer**
  - Call-graph edges
  - Hubs, cycles, wrapper detection
  - Vtable and callback patterns

- **Obfuscation Analyzer**
  - Control-flow flattening (CFF)
  - Opaque predicates
  - String encryption patterns
  - Anti-analysis heuristics

- **Architecture Analyzer**
  - Cross-architecture register resolution
  - ABI-aware calling convention logic

- **Hex-Rays / Decompiler Evidence**
  - Extracts high-confidence refs from decompiled views (when available)

## Output Files (XRefer-Compatible)

XRefer expects user xrefs at:
```
<IDB_PATH>_user_xrefs.txt
```

XrefGen now writes outputs with the **IDB prefix** by default, matching XRefer’s expectations.

### Primary output (XRefer compatible)
```
<IDB_PATH>_user_xrefs.txt
```
Format (strict):
```
0xSRC,0xDST
```

### Additional exports
```
<IDB_PATH>_user_xrefs_details.txt
<IDB_PATH>_user_xrefs.json
<IDB_PATH>_user_xrefs.csv
<IDB_PATH>_user_xrefs_taint.txt
```

## Installation

1. Copy the `xrefgen` folder into your IDA scripts directory.
2. Open your binary in **IDA Pro 9.2+**.
3. Run:
   - Script mode: `File > Script file...` or `Alt+F7` on `xrefgen.py`
   - Plugin mode: copy `xrefgen_plugin.py` into IDA `plugins/` and run **XrefGen** from `Edit > Plugins`.

## Quick Start

```python
# Run full analysis
exec(open("path/to/xrefgen.py").read())
```

## Configuration

Configuration lives in `xrefgen_config.json`.

Important output keys:
```json
"general": {
  "output_name_mode": "idb",
  "txt_format": "xrefer",
  "txt_include_evidence": false
}
```

- `output_name_mode: "idb"` → uses `<IDB_PATH>_user_xrefs.txt`
- `txt_format: "xrefer"` → strict `0xSRC,0xDST`
- Set `txt_format: "extended"` if you want extra columns

## Thanks

Huge thanks to **Mandiant** for building **XRefer** and open-sourcing it. This project is specifically designed to augment XRefer workflows and would not exist without their excellent work.

---

## Support the Project

If you find XrefGen useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

<p align="center">
  <sub>Made to extend IDA Pro analysis and supercharge XRefer workflows</sub>
</p>
