# Changelog

## 0.5.0-alpha.1

- Export only validated control-flow candidates to XRefer.
- Separate findings, relationships, and rejected candidates.
- Make incremental cache updates transactional and JSON-only.
- Respect selected and disabled modules in optimized execution.
- Mark unverified ML, interactive, and IDA feature modules disabled by default.
- Rebuild global data-flow and graph summaries deterministically instead of
  serving stale incremental state.
- Add precision/recall thresholds and false-positive gates to ground-truth
  comparison tooling.
