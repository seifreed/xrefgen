"""Sink policy helpers."""


class SinkPolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def should_emit(self, source_ea: int, call_ea: int, sink: str, kind: str, confidence: float) -> bool:
        if confidence < self.a.sink_min_confidence:
            return False
        return True
