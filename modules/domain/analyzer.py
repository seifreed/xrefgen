"""Domain-level analyzer abstractions (IDA-agnostic)."""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any, Iterable
from modules.domain.evidence import EvidenceCollector
from modules.domain.results import XrefCandidate, Finding, Relationship


class XrefAnalyzer(ABC):
    """Base class for all xref analysis modules (no IDA dependencies)."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.xrefs: Dict[Tuple[int, int], str] = {}
        self.confidence_scores: Dict[Tuple[int, int], float] = {}
        self._evidence = EvidenceCollector()
        self.enabled = self.config.get('enabled', True)

    @abstractmethod
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform analysis and return (source, target, type, confidence) tuples."""
        raise NotImplementedError

    @abstractmethod
    def get_name(self) -> str:
        """Return module name."""
        raise NotImplementedError

    def add_xref(self, source: int, target: int, xref_type: str, confidence: float = 1.0):
        """Add a cross-reference with confidence score (no IDA filtering here)."""
        key = (source, target)
        self.xrefs[key] = xref_type
        prev_conf = self.confidence_scores.get(key, 0.0)
        # We maintain the highest confidence seen for this xref
        new_conf = min(1.0, max(prev_conf, confidence))
        self.confidence_scores[key] = new_conf
        self._evidence.add_count(source, target)
        return True

    def add_evidence(self, source: int, target: int, etype: str):
        self._evidence.add(source, target, etype)

    def emit_control_flow(
        self,
        source: int,
        target: int,
        kind: str,
        confidence: float,
        evidence: Iterable[str] = (),
    ) -> XrefCandidate:
        self.add_xref(source, target, kind, confidence)
        for etype in evidence:
            self.add_evidence(source, target, etype)
        return XrefCandidate(source, target, kind, confidence, self.get_name(), tuple(evidence))

    def emit_finding(
        self,
        source: int,
        target: int,
        kind: str,
        confidence: float,
        evidence: Iterable[str] = (),
    ) -> Finding:
        return Finding(source, target, kind, confidence, self.get_name(), tuple(evidence))

    def emit_relationship(
        self,
        source: int,
        target: int,
        kind: str,
        confidence: float,
        evidence: Iterable[str] = (),
    ) -> Relationship:
        return Relationship(source, target, kind, confidence, self.get_name(), tuple(evidence))

    @property
    def evidence_counts(self):
        return self._evidence.counts()

    @property
    def evidence_types(self):
        return self._evidence.types()

    def get_results(self) -> List[Tuple[int, int, str, float]]:
        """Get all discovered xrefs with confidence scores."""
        results = []
        for (source, target), xref_type in self.xrefs.items():
            confidence = self.confidence_scores.get((source, target), 1.0)
            results.append((source, target, xref_type, confidence))
        return results
