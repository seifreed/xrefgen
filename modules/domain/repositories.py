"""Repository interfaces (IDA-agnostic)."""

from abc import ABC, abstractmethod
from typing import Iterable, Tuple


class XrefRepository(ABC):
    @abstractmethod
    def save(self, xrefs: Iterable[Tuple[int, int, str, float]]):
        raise NotImplementedError


class ReferenceValidator(ABC):
    @abstractmethod
    def is_valid(self, target: int) -> bool:
        raise NotImplementedError
