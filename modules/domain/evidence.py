"""Evidence collection utilities (IDA-agnostic)."""

from typing import Dict, Set, Tuple


class EvidenceCollector:
    def __init__(self):
        self._counts: Dict[Tuple[int, int], int] = {}
        self._types: Dict[Tuple[int, int], Set[str]] = {}

    def add(self, source: int, target: int, etype: str):
        key = (source, target)
        self._counts[key] = self._counts.get(key, 0) + 1
        self._types.setdefault(key, set()).add(etype)

    def add_count(self, source: int, target: int):
        key = (source, target)
        self._counts[key] = self._counts.get(key, 0) + 1

    def counts(self) -> Dict[Tuple[int, int], int]:
        return dict(self._counts)

    def types(self) -> Dict[Tuple[int, int], Set[str]]:
        return {k: set(v) for k, v in self._types.items()}
