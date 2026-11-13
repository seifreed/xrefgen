# Observability audit

This is an in-progress audit, not a release sign-off. Scores are 0–10 and the overall score is the arithmetic mean. HTTP, database, messaging, authentication, and distributed tracing do not apply to this IDA Pro plugin: it analyzes the currently loaded database in-process and writes local artifacts/cache.

## Baseline

The baseline is the repository state before commit `00a57e0` (logger source in its parent). `modules/presentation/logger.py` printed text with local time, appended to an unbounded file by reopening it per event, accepted unknown levels by silently choosing INFO, and swallowed file errors. The orchestrator also wrote `_xrefgen_debug.log` independently. Application and analysis layers had direct `print` calls, and no structured event, correlation, redaction, or logger-specific test contract existed.

| Dimension | Baseline | Evidence |
|---|---:|---|
| Architecture and decoupling | 3 | One helper module existed, but orchestrator had a parallel file writer and components printed directly. |
| Functional coverage | 2 | Startup and some operation messages existed; component paths and failures were inconsistently visible. |
| Event quality | 2 | Mostly free-form messages; errors often omitted context or used direct prints. |
| Structure and consistency | 1 | Plain text, local timestamps, inconsistent prefixes and destinations. |
| Context and correlation | 0 | No correlation identifiers or propagation. |
| Security and privacy | 1 | No sanitization or credential redaction. |
| Performance and resilience | 1 | Unbounded file, open/write per event, swallowed destination failures. |
| Configuration and portability | 2 | Optional file and level existed, but invalid level silently fell back. |
| Error handling | 2 | Some errors printed; others swallowed without useful record. |
| Testing and verification | 1 | Basic helper tests only; no structured/security/concurrency/sink failure contracts. |
| **Mean** | **1.5** | **15 / 10 dimensions** |

The first progress reply used a rough `3/10` estimate before scoring each dimension. The required dimension-by-dimension mean above corrects that preliminary estimate to `1.5/10`.

## Current in-progress score

Evidence through commit `2cb541f` plus the current working changes: standard-library logging moved below presentation, UTC structured JSON/text records, caller-module attribution, TRACE–FATAL levels, bounded rotating file output, 16,384-character field and 64-field caps, quoted/unquoted credential and private-key redaction, owner-only POSIX log files, observable configuration fallback, concurrent and sink-failure tests, filtered-event fast path, sanitized exception type/stack, scoped analysis correlation, plugin shutdown and launch failure logging, structured artifact events with path minimization, module/analysis lifecycle events, observable cache load/save/invalidation/clear outcomes, omission of raw exception text from failure profiles, observable fallbacks for CFG/profile failures and UI errors, and successful IDA 9.5 execution of module analysis plus `XrefGen.run()` with isolated artifact assertions, JSONL file-sink readback, service startup, and plugin shutdown flush. The maintained selection passed 46 tests, including rotation and both output formats. Many locally present test files are untracked and should not be treated as repository-owned baseline tests.

| Dimension | Current | Remaining evidence/gap |
|---|---:|---|
| Architecture and decoupling | 7 | Shared logger moved to neutral `modules.observability`, avoiding application/infrastructure imports from presentation; validate lifecycle inside IDA and component attribution. |
| Functional coverage | 8 | Application and optimized module executions emit lifecycle events; full `XrefGen.run()` verified under IDA 9.5 on a real Mach-O fixture. Remaining best-effort catches and broader corpus runs need review. |
| Event quality | 9 | Analysis, module, cache and artifact events carry stable names, outcomes, durations/counts where useful; some low-level diagnostic messages remain free-form. |
| Structure and consistency | 9 | UTC events have normalized JSON or text output, scalar structured fields, and component attribution to the emitting module. |
| Context and correlation | 5 | A per-run correlation ID and operation are scoped with `ContextVar`; no distributed tracing is justified for the current single-process design. |
| Security and privacy | 9 | Quoted/unquoted credentials, bearer values, private keys, controls and nested objects are covered; raw exception messages from best-effort paths are omitted; local files are owner-only on POSIX. Stack redaction remains pattern-based. |
| Performance and resilience | 9 | 20,000-event in-memory benchmark: JSON INFO ~48,987 events/s, filtered DEBUG ~3,901,328 calls/s; IDA 9.5 A/B on 301 functions (five runs per level) measured median 0.790 s at INFO vs 0.784 s at CRITICAL, 0.77% difference, with equal outputs. This remains a small synthetic workload. |
| Configuration and portability | 8 | Config selects level, JSON/text format, optional rotating file plus always-on console; invalid values/sinks warn and fall back. Rotation size/count remain fixed. |
| Error handling | 8 | Analysis boundary logs exception type and sanitized stack; cache fallback/error states are explicit and profile artifacts omit raw exception messages. Remaining best-effort catches require review. |
| Testing and verification | 8 | 46 maintained tests pass; IDA 9.5 smoke test ran module analysis and production orchestration, checked correlated lifecycle/artifact events, JSONL file-sink readback and output files. The entire repository test suite still includes conflicting untracked tests. |
| **Provisional mean** | **8.0** | **80 / 10 dimensions; not final or release-ready** |

Do not use the provisional score as a completion claim. A final score requires resolving the remaining gaps, running the maintained test suite, and verifying the plugin lifecycle in IDA or documenting a genuine environment limitation.

The throughput figures above are a local CPython 3.14 microbenchmark writing JSON to `io.StringIO`; they are comparative evidence for the formatter/filter path only. The IDA A/B uses the same synthetic Mach-O database, fresh optimizer/modules per run, five alternating repetitions per level, and compares result counts for equality. Its 0.77% difference is below the measurement noise expected for this sample and is not a customer-workload certification.
