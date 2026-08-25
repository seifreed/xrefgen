# Changelog

## 0.5.0-alpha.1

- Export only validated control-flow candidates to XRefer.
- Separate findings, relationships, and rejected candidates.
- Make incremental cache updates transactional and JSON-only.
- Respect selected and disabled modules in optimized execution.
- Replace heuristic ML naming with deterministic similarity relationships;
  make IDA type evidence and the interactive configuration menu functional.
- Rebuild global data-flow and graph summaries deterministically instead of
  serving stale incremental state.
- Add precision/recall thresholds and false-positive gates to ground-truth
  comparison tooling.
