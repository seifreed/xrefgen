"""Domain-level analyzer abstractions (IDA-agnostic)."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List
from modules.domain.evidence import EvidenceCollector
from modules.domain.results import AnalysisResult, XrefCandidate, Finding, Relationship


class XrefAnalyzer(ABC):
    """Base class for all xref analysis modules (no IDA dependencies)."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._evidence = EvidenceCollector()
        self.enabled = self.config.get('enabled', True)

    @abstractmethod
    def analyze(self) -> List[AnalysisResult]:
        """Perform analysis and return explicitly classified results."""
        raise NotImplementedError

    @abstractmethod
    def get_name(self) -> str:
        """Return module name."""
        raise NotImplementedError

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
