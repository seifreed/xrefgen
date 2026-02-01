"""Domain entities for XrefGen (IDA-agnostic)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Xref:
    source: int
    target: int
    xref_type: str
    confidence: float = 1.0

    def as_tuple(self):
        return (self.source, self.target, self.xref_type, self.confidence)
