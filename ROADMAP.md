# XrefGen Analysis Roadmap

This roadmap groups the remaining analysis improvements into phases. Each phase is incremental and safe to ship.

## Phase 1 — Accuracy & Evidence
- [x] RTTI/vtable exactness
  - Validate method offsets using full class typeinfo (not just UDT layout).
- [x] Reaching-defs full dataflow
  - Compute GEN/KILL per block with per-instruction defs per register.
- [x] Strong string evidence gating
  - Only elevate confidence with real string evidence (stack/heap/literal).
- [x] Evidence detail in TXT
  - Include ordered evidence list with weights for each xref.
- [x] Interprocedural summaries
  - Model arg→arg, arg→ret, arg→mem with real typeinfo.

## Phase 2 — Heap Precision
- [x] Deep heap aliasing
  - Propagate ranges and offsets through chains of memcpy/memmove, not just single hops.
- [x] Heap region sizing
  - Use malloc/new sizes and propagate through copy APIs and sanitizers.
- [x] Mem-to-mem tracking
  - Follow taint for memcpy between buffers with offsets.
- [x] Structure-aware taint
  - Propagate through typed fields/offsets when typeinfo is available.

## Phase 3 — Auto-Tuning & Performance
- [x] Noise score tuning
  - Adjust thresholds using combined CFG density, loops, and fan-out metrics.
- [x] Profiling-driven throttling
  - Disable expensive heuristics per function when time exceeds thresholds.
- [x] Control-flow sanity
  - Avoid taint propagation through unreachable/dead blocks.
- [x] Architecture-specific models
  - ABI/ISA-specific rules for ARM/MIPS/ARM64 in taint/indirect resolution.

## Phase 4 — Final Polish
- [x] Report slow functions
  - Export a ranked list to guide tuning.
- [x] Expand evidence taxonomy
  - Unify evidence tags across modules (dataflow/hexrays/strings/heuristic/rtti).
- [x] Global alias resolution
  - Handle IAT/GOT/global pointer tables for indirect targets.
- [x] String context classification
  - Distinguish format strings vs data to refine sink confidence.
- [x] Analysis test suite
  - Real IDA-run tests via scripts/ida_real_tests.py to validate module outputs.
- [x] Wrapper intent heuristic
  - Detect thin wrappers and inherit evidence to reduce noise.
- [x] Exception/SEH flows
  - Consider exception handlers in CFG to avoid missing paths.
- [x] Chain confidence decay
  - Reduce confidence based on length of propagation chains.
- [x] API alias normalization
  - Identify wrapper aliases for better source/sink matching.
- [x] Pointer target disambiguation
  - Distinguish code vs data targets to reduce indirect-call false positives.
- [x] Modern obfuscation heuristics
  - Lightweight handling for control-flow flattening/opaque predicates in dataflow.
- [x] Hash-resolved API calls
  - Detect hashed/obfuscated API resolution patterns (e.g., Win32 hashing).
- [x] Callback analysis
  - Detect callback registrations (qsort, CreateThread, Enum*) to enrich call graph.
