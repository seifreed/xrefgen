"""IDA-specific analyzer base and adapters."""

from typing import Dict, Any
import idautils
import idc
import ida_funcs
import ida_segment
from modules.domain.analyzer import XrefAnalyzer
from modules.infrastructure.ida.utils.function_cache import FunctionBoundsCache


class IDAXrefAnalyzer(XrefAnalyzer):
    """XrefAnalyzer with IDA-specific validation helpers."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._func_bounds = FunctionBoundsCache()
        self._valid_ref_cache = {}

    def _is_already_in_ida(self, source: int, target: int) -> bool:
        for xref in idautils.XrefsFrom(source, 0):
            if xref.to == target:
                return True
        return False

    def _is_valid_reference(self, target: int) -> bool:
        seg = ida_segment.getseg(target)
        if not seg:
            return False
        if hasattr(seg, "perm") and hasattr(ida_segment, "SEGPERM_EXEC"):
            if not (seg.perm & ida_segment.SEGPERM_EXEC):
                return False
        if not idc.is_code(idc.get_full_flags(target)):
            return False
        func = ida_funcs.get_func(target)
        if func:
            return True
        # Fast boundary check instead of iterating all functions per call
        return self._func_bounds.near_function_start(target, radius=32)

    def is_valid_reference(self, target: int) -> bool:
        """Public validation helper for analyzers."""
        if target in self._valid_ref_cache:
            return self._valid_ref_cache[target]
        valid = self._is_valid_reference(target)
        self._valid_ref_cache[target] = valid
        return valid

    def is_already_in_ida(self, source: int, target: int) -> bool:
        """Public helper to check existing IDA xrefs."""
        return self._is_already_in_ida(source, target)

    def refresh_caches(self):
        """Refresh internal caches after analysis changes."""
        self._valid_ref_cache.clear()
        self._func_bounds.refresh()

    def add_xref(self, source: int, target: int, xref_type: str, confidence: float = 1.0):
        """Add xref with IDA validation + dedup against existing IDA xrefs."""
        valid = self.is_valid_reference(target)
        if not valid:
            return
        if self._is_already_in_ida(source, target):
            return
        super().add_xref(source, target, xref_type, confidence)

    def combine_confidence(self, source_conf: float, target_conf: float) -> float:
        """Combine source/target confidence into a final score."""
        try:
            return max(0.0, min(1.0, float(source_conf) * float(target_conf)))
        except Exception:
            return max(0.0, min(1.0, float(source_conf)))
