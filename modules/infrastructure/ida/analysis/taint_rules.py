"""Taint rules and policies."""
from modules.infrastructure.ida.utils import abi


class TaintRules:
    def __init__(self, analyzer):
        self.a = analyzer

    def source_kind(self, name: str) -> str:
        if any(s in name for s in self.a.numeric_parsers):
            return "control"
        if any(s in name for s in self.a.string_sources):
            return "string"
        return "ptr"

    def adjust_sink_confidence(self, sink: str, kind: str, call_ea: int, source_ea: int) -> float:
        conf = 1.0
        sink = sink.lower()
        if kind == "num" and any(k in sink for k in self.a.sink_exec_keywords):
            conf *= 0.7
        if kind == "string" and any(k in sink for k in self.a.sink_string_keywords):
            conf *= 1.1
        if kind == "ptr" and any(k in sink for k in self.a.sink_string_keywords):
            conf *= 0.85
        if kind == "control" and any(k in sink for k in self.a.sink_exec_keywords):
            conf *= 0.6
        if any(k in sink for k in self.a.sink_exec_keywords) and kind == "string":
            if not self.a.string_evidence.arg_points_to_string(call_ea, abi.arg_registers()[0] if abi.arg_registers() else ""):
                conf *= 0.5
            if self.a.evidence_types.get((source_ea, call_ea), set()) and "strings" not in self.a.evidence_types.get((source_ea, call_ea), set()):
                conf *= 0.5
            if self.a.string_evidence.is_format_string(call_ea):
                conf *= 0.8
        return conf
