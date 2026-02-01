"""Domain-level analyzer abstractions (IDA-agnostic)."""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any
from modules.domain.evidence import EvidenceCollector


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
        prev_count = self._evidence.counts().get(key, 0)
        new_count = prev_count + 1
        boosted = min(1.0, max(prev_conf, confidence) + 0.05 * new_count)
        self.confidence_scores[key] = boosted
        self._evidence.add_count(source, target)

    def add_evidence(self, source: int, target: int, etype: str):
        self._evidence.add(source, target, etype)

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
