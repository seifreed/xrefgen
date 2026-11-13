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

## Current in-progress score

Evidence through commit `0f5b3cb` plus follow-up commits `e2594d7` and `b9c2df1`: standard-library logging, JSON UTC records, TRACE–FATAL levels, bounded rotating file output, basic credential/control-character/private-key redaction, file-sink fallback, concurrent event test, sanitized exception type/stack, plugin shutdown flush, and broader lifecycle/module/cache/analyzer instrumentation. The explicitly selected tracked test set passed 29 tests. Many locally present test files are untracked and should not be treated as repository-owned baseline tests.

| Dimension | Current | Remaining evidence/gap |
|---|---:|---|
| Architecture and decoupling | 6 | Shared logger used broadly; validate layering/import behavior inside IDA and component attribution. |
| Functional coverage | 6 | Most diagnostics migrated; audit all error paths and run representative IDA analyses. |
| Event quality | 5 | Lifecycle, counts and durations exist; some events remain free-form and not consistently named. |
| Structure and consistency | 7 | JSON UTC schema exists; component is currently always `xrefgen`, and operation/status fields are not normalized. |
| Context and correlation | 5 | A per-run correlation ID and operation are scoped with `ContextVar`; no distributed tracing is justified for the current single-process design. |
| Security and privacy | 6 | Common credentials, bearer values, private keys and controls are redacted; broader sensitive-data review remains. |
| Performance and resilience | 7 | Standard handler locking and bounded rotation; no benchmark or IDA-thread impact measurement. |
| Configuration and portability | 5 | Level and file sink supported; no environment selector or retention configuration beyond fixed bounds. |
| Error handling | 6 | Several swallowed operational failures now warn/error; remaining best-effort catches require review. |
| Testing and verification | 5 | Logger contracts and tracked subset pass; global suite is polluted by untracked tests, and IDA runtime tests are not run. |
| **Provisional mean** | **5.8** | **58 / 10 dimensions; not final or release-ready** |

Do not use the provisional score as a completion claim. A final score requires resolving the remaining gaps, running the maintained test suite, and verifying the plugin lifecycle in IDA or documenting a genuine environment limitation.
