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

Evidence through commit `d8f1f9a` plus current verification: standard-library logging moved below presentation, UTC structured JSON/text records, caller-module attribution, TRACE–FATAL levels, bounded rotating file output with configurable limits, 16,384-character field and 64-field caps, quoted/unquoted credential, URL credential, access-key and private-key redaction, owner-only POSIX log files, observable configuration fallback, concurrent and sink-failure tests, filtered-event fast path, exception type chains and bounded source-free frames, scoped analysis correlation, plugin shutdown and launch failure logging, structured artifact events with path minimization, module/analysis lifecycle events, named events across configuration, module registration/execution, graph/taint fallbacks, cache, IDA auto-analysis and UI (AST scan: zero unnamed production logger calls), accurate `partial` outcome and failed-module count, observable cache load/save/invalidation/clear outcomes, and successful IDA 9.5 execution of module analysis plus `XrefGen.run()` with isolated artifact assertions, JSONL file-sink readback, service startup, a deliberately failing analyzer producing a redacted partial outcome, and plugin shutdown flush. The 50 maintained tests pass. A strict IDA 9.5 matrix passed 43/43 C, C++, Rust, Go, ARM64, MIPS, and obfuscation artifacts (zero false positives/negatives; all five symbolic cases validated). Many locally present test files are untracked and should not be treated as repository-owned baseline tests.

| Dimension | Current | Remaining evidence/gap |
|---|---:|---|
| Architecture and decoupling | 9 | Standard-library logger is isolated in neutral `modules.observability`; business/application/infrastructure code depends on its small function API, and the presentation shim preserves old imports. No logging dependency cycles. |
| Functional coverage | 10 | Startup, analysis/module success and failure, partial overall outcome, cache operations, artifact writes, configuration, plugin shutdown and UI fallbacks are instrumented; 43 IDA artifacts across C/C++/Rust/Go/ARM64/MIPS/obfuscation passed strict validation. |
| Event quality | 10 | Every production logger call has a stable `event_name`; lifecycle/cache/artifact events include outcomes and relevant counts/durations, while low-level fallbacks remain DEBUG or WARN. |
| Structure and consistency | 9 | UTC events have normalized JSON or text output, scalar structured fields, and component attribution to the emitting module. |
| Context and correlation | 9 | A per-run correlation ID and operation propagate through synchronous module, cache, artifact, success and failure events via `ContextVar`; thread isolation is tested. No distributed trace context applies to this single-process plugin. |
| Security and privacy | 9 | Quoted/unquoted credentials, URL credentials, access keys, bearer values, private keys, controls and nested objects are covered; exception messages/source lines/absolute paths are omitted; local files are owner-only on POSIX. Free-form message redaction remains pattern-based. |
| Performance and resilience | 9 | CPython 3.15.2 20,000-event in-memory benchmark: JSON INFO ~51,954 events/s, filtered DEBUG ~3,707,033 calls/s; two IDA 9.5 A/B sets on 301 functions measured INFO/CRITICAL medians 0.9156/0.9078 s (+0.86%) and 0.8019/0.8090 s (-0.87%), with equal outputs. The direction varies within measurement noise. |
| Configuration and portability | 10 | Config selects level, JSON/text, console plus optional file, file size (2–50 MB) and backups (0–5); invalid values/sinks warn and fall back to safe defaults. |
| Error handling | 9 | Analysis boundaries retain original exception propagation where fatal; recoverable module/cache failures emit sanitized types/stacks and produce accurate partial outcomes. |
| Testing and verification | 10 | 50 maintained tests pass; IDA 9.5 normal/injected-failure smoke, strict 43-artifact matrix, JSONL/shutdown assertions, compileall, AST event-name scan, and wheel build all passed. |
| **Provisional mean** | **9.4** | **94 / 10 dimensions; not final or release-ready** |

Do not use the provisional score as a completion claim. A final score requires resolving the remaining gaps, running the maintained test suite, and verifying the plugin lifecycle in IDA or documenting a genuine environment limitation.

The throughput figures above are a local CPython 3.15.2 microbenchmark writing JSON to `io.StringIO`; they are comparative evidence for the formatter/filter path only. The IDA A/B uses the same synthetic Mach-O database, fresh optimizer/modules per run, five alternating repetitions per level, and compares result counts for equality. Its 0.86% difference is below the measurement noise expected for this sample and is not a customer-workload certification.
