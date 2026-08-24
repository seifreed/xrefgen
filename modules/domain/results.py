"""Typed result collection for analysis modules."""

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple


CONTROL_FLOW_TYPES = frozenset(
    {
        "indirect_call",
        "indirect_jump",
        "call_edge",
        "callback_arg",
        "wrapper_call",
        "cff_resolved",
        "mips_jalr",
        "mips_jr",
        "mips_plt_call",
        "wasm_call_indirect",
        "x86_fastcall",
        "x86_thiscall",
        "x64_convention_call",
        "x64_rip_relative",
        "arm64_blr",
        "arm64_br",
        "arm_blx_indirect",
        "arm_bx_indirect",
        "arm_ldr_pc_call",
        "arm_vtable_call",
        "arm64_brx",
        "arm64_adrp_add",
        "return_value_call",
    }
)


@dataclass(frozen=True)
class XrefCandidate:
    source: int
    target: int
    kind: str
    confidence: float
    module: str = ""
    evidence: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    source: int
    target: int
    kind: str
    confidence: float
    module: str = ""
    evidence: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Relationship:
    source: int
    target: int
    kind: str
    confidence: float
    module: str = ""
    evidence: Tuple[str, ...] = ()


@dataclass
class _StoredXref:
    source: int
    target: int
    kind: str
    confidence: float
    evidence: set = field(default_factory=set)


class ResultStore:
    """Validate, deduplicate, and classify raw module results."""

    def __init__(
        self,
        source_is_control_flow: Optional[Callable[[int], bool]] = None,
        target_is_executable: Optional[Callable[[int], bool]] = None,
        already_exists: Optional[Callable[[int, int], bool]] = None,
    ):
        self._source_is_control_flow = source_is_control_flow or (lambda _ea: True)
        self._target_is_executable = target_is_executable or (lambda _ea: True)
        self._already_exists = already_exists or (lambda _source, _target: False)
        self._xrefs: Dict[Tuple[int, int], _StoredXref] = {}
        self.findings: List[Finding] = []
        self.relationships: List[Relationship] = []
        self.rejections: List[Dict[str, object]] = []

    def add(
        self,
        source: int,
        target: int,
        kind: str,
        confidence: float,
        module: str = "",
        evidence: Iterable[str] = (),
    ) -> bool:
        try:
            source = int(source)
            target = int(target)
            confidence = max(0.0, min(1.0, float(confidence)))
            kind = str(kind)
        except (TypeError, ValueError):
            self._reject(source, target, kind, "invalid_result")
            return False

        evidence = tuple(sorted(set(evidence or ())))
        if kind in CONTROL_FLOW_TYPES:
            reason = self._xref_rejection_reason(source, target)
            if reason:
                self._reject(source, target, kind, reason)
                return False
            key = (source, target)
            stored = self._xrefs.get(key)
            if stored is None:
                self._xrefs[key] = _StoredXref(
                    source, target, kind, confidence, set(evidence)
                )
            else:
                stored.confidence = max(stored.confidence, confidence)
                stored.evidence.update(evidence)
            return True

        record = (source, target, kind, confidence, module, evidence)
        if kind.startswith(("ml_", "cluster_", "call_chain_", "complex_func_")):
            self.relationships.append(Relationship(*record))
        else:
            self.findings.append(Finding(*record))
        return False

    def xrefs(self, min_confidence: float = 0.0) -> List[Tuple[int, int, str, float]]:
        return [
            (item.source, item.target, item.kind, item.confidence)
            for item in sorted(self._xrefs.values(), key=lambda item: (item.source, item.target, item.kind))
            if item.confidence >= min_confidence
        ]

    def evidence(self) -> Dict[Tuple[int, int], set]:
        return {key: set(item.evidence) for key, item in self._xrefs.items()}

    def _xref_rejection_reason(self, source: int, target: int) -> Optional[str]:
        if source == target:
            return "self_reference"
        if not self._source_is_control_flow(source):
            return "source_not_control_flow"
        if not self._target_is_executable(target):
            return "target_not_executable"
        if self._already_exists(source, target):
            return "already_in_ida"
        return None

    def _reject(self, source: object, target: object, kind: object, reason: str) -> None:
        self.rejections.append(
            {"source": source, "target": target, "kind": kind, "reason": reason}
        )
