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

Evidence includes commit `18761f4` and subsequent clean-archive verification: standard-library logging moved below presentation, UTC structured JSON/text records, caller-module attribution, TRACE–FATAL levels, bounded rotating file output with configurable limits, 16,384-character field and 64-field caps, quoted/unquoted credential, complete authorization/cookie header, URL credential, access-key and private-key redaction, ASCII/C1 and Unicode line/bidi control suppression, owner-only POSIX log files, observable configuration fallback without echoing untrusted keys, concurrent and sink-failure tests, filtered-event fast path, exception type chains and bounded source-free frames, scoped analysis correlation protected from field override, plugin shutdown and launch failure logging, artifact events without user-selected filenames or absolute paths, module/analysis lifecycle events, named events across configuration, module registration/execution, graph/taint fallbacks, cache, IDA auto-analysis and UI (AST scan: zero unnamed production logger calls or dynamic log messages), accurate `partial` outcome and failed-module count, observable cache load/save/invalidation/clear outcomes, safe console sink suppression and a one-time sanitized warning for file sink write/flush/close failures (with repetition and secret-leak tests). Installed IDA Pro 9.5.261026.365f1f33 ran `scripts/ida_real_tests.py` from a clean tracked archive; the smoke verified module analysis, correlated lifecycle events, `XrefGen.run()` artifacts, JSONL sink readback, redacted failure simulation, no user-selected filename/path in artifact events, and plugin shutdown flush. The current 57 maintained tests pass in clean tracked archives on macOS with CPython 3.9 and 3.15, Linux/aarch64 with CPython 3.9, and Windows CPython 3.12.10 under Wine 11.0 on macOS; Wine is emulation evidence only. The original 51-test suite also passed on macOS CPython 3.10–3.14. A strict IDA 9.5 matrix passed 43/43 C, C++, Rust, Go, ARM64, MIPS, and obfuscation artifacts (zero false positives/negatives; all five symbolic cases validated).

| Dimension | Current | Remaining evidence/gap |
|---|---:|---|
| Architecture and decoupling | 9 | Standard-library logger is isolated in neutral `modules.observability`; business/application/infrastructure code depends on its small function API, and the presentation shim preserves old imports. No logging dependency cycles. |
| Functional coverage | 10 | Startup, analysis/module success and failure, partial overall outcome, cache operations, artifact writes, configuration, plugin shutdown and UI fallbacks are instrumented; 43 IDA artifacts across C/C++/Rust/Go/ARM64/MIPS/obfuscation passed strict validation. |
| Event quality | 10 | Every production logger call has a stable `event_name`; lifecycle/cache/artifact events include outcomes and relevant counts/durations, while low-level fallbacks remain DEBUG or WARN. |
| Structure and consistency | 9 | UTC events have normalized JSON or text output, scalar structured fields, and component attribution to the emitting module. |
| Context and correlation | 9 | A per-run correlation ID and operation propagate through synchronous module, cache, artifact, success and failure events via `ContextVar`; thread isolation is tested. No distributed trace context applies to this single-process plugin. |
| Security and privacy | 9 | Quoted/unquoted credentials, URL credentials, access keys, bearer values, private keys, controls and nested objects are covered; exception messages/source lines/absolute paths are omitted; local files are owner-only on POSIX. Free-form message redaction remains pattern-based. |
| Performance and resilience | 10 | CPython 3.15.2 20,000-event in-memory benchmark: JSON INFO ~51,954 events/s, filtered DEBUG ~3,707,033 calls/s; two IDA 9.5 A/B sets on 301 functions measured INFO/CRITICAL medians 0.9156/0.9078 s (+0.86%) and 0.8019/0.8090 s (-0.87%), with equal outputs. The direction varies within measurement noise. Console failures are isolated; file sink write/flush/close failures emit one sanitized warning to console and suppress repeats; file rotation is bounded. |
| Configuration and portability | 9 | Config selects level, JSON/text, console plus optional file, file size (2–50 MB) and backups (0–5); invalid values/sinks warn and fall back to safe defaults. The suite passed on macOS and Linux/aarch64; Windows jobs and IDA integration outside macOS remain unverified. |
| Error handling | 9 | Analysis boundaries retain original exception propagation where fatal; recoverable module/cache failures emit sanitized types/stacks and produce accurate partial outcomes. |
| Testing and verification | 9 | 57 maintained tests pass on macOS CPython 3.9/3.15, Linux/aarch64 CPython 3.9 and Windows CPython 3.12 under Wine; installed IDA 9.5 smoke and strict 43-artifact matrix pass. Native Windows CI and documented IDA 9.1–9.3 targets remain unverified. |
| **Provisional mean** | **9.3** | **93 / 10 dimensions; not final or release-ready** |

Do not use the provisional score as a completion claim. This machine has IDA Pro 9.5 for macOS only; supported older IDA versions and Windows plugin hosts were not available for validation. The full maintained suite passes under Wine emulation, but this cannot verify native Windows behavior. The current 57-test suite passed on Linux/aarch64 through a local Docker container and on macOS CPython 3.9/3.15; untracked tests were left untouched. Native cross-OS GitHub logger jobs remain queued without runner assignment when checked, so those results are not counted. GitHub currently reports Actions as operational while those jobs remain queued. A previous full `pytest -q` run on the shared worktree emitted failures from untracked tests and remained CPU-bound at 33% after more than four minutes, so it was stopped; do not treat the full worktree suite as passing. The wheel build passes but emits a setuptools deprecation warning for the existing table-form `project.license` metadata. These leave the audit at 9.3/10 rather than a verified 10/10.

The throughput figures above are a local CPython 3.15.2 microbenchmark writing JSON to `io.StringIO`; they are comparative evidence for the formatter/filter path only. The IDA A/B uses the same synthetic Mach-O database, fresh optimizer/modules per run, five alternating repetitions per level, and compares result counts for equality. Its 0.86% difference is below the measurement noise expected for this sample and is not a customer-workload certification.
