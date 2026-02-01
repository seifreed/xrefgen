"""IDA-specific function boundary cache to speed reference validation."""

from bisect import bisect_left
from typing import List, Tuple
import idautils
import ida_funcs


class FunctionBoundsCache:
    def __init__(self):
        self._ranges: List[Tuple[int, int]] = []
        self._starts: List[int] = []

    def refresh(self):
        ranges: List[Tuple[int, int]] = []
        for start_ea in idautils.Functions():
            func = ida_funcs.get_func(start_ea)
            if not func:
                continue
            ranges.append((func.start_ea, func.end_ea))
        ranges.sort()
        self._ranges = ranges
        self._starts = [start for start, _ in ranges]

    def ensure(self):
        if not self._ranges:
            self.refresh()

    def contains(self, ea: int) -> bool:
        self.ensure()
        if not self._ranges:
            return False
        idx = bisect_left(self._starts, ea)
        candidates = []
        if idx < len(self._ranges):
            candidates.append(self._ranges[idx])
        if idx > 0:
            candidates.append(self._ranges[idx - 1])
        for start, end in candidates:
            if start <= ea < end:
                return True
        return False

    def near_function_start(self, ea: int, radius: int = 32) -> bool:
        self.ensure()
        if not self._ranges:
            return False
        idx = bisect_left(self._starts, ea)
        candidates = []
        if idx < len(self._starts):
            candidates.append(self._starts[idx])
        if idx > 0:
            candidates.append(self._starts[idx - 1])
        for start in candidates:
            if abs(ea - start) < radius:
                return True
        return False
