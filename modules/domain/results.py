"""Typed result collection for analysis modules."""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


CONTROL_FLOW_TYPES = frozenset(
    {
        "indirect_call",
        "indirect_jump",
        "call_edge",
        "callback_arg",
        "wrapper_call",
        "trampoline",
        "mips_jalr",
        "mips_jr",
        "bal",
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
        "return_value_call",
        "tainted_indirect_call",
    }
)

CONTROL_FLOW_MNEMONICS = frozenset(
    {
        "call", "bl", "blx", "jal", "jalr", "bal", "jmp", "b", "br", "blr",
        "bx", "jr", "cbz", "cbnz", "tbz", "tbnz", "tbb", "tbh",
        "call_indirect", "br_table",
    }
)


def is_control_flow_mnemonic(mnemonic: str) -> bool:
    return str(mnemonic or "").lower() in CONTROL_FLOW_MNEMONICS


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

AnalysisResult = Union[XrefCandidate, Finding, Relationship]
RESULT_TYPES = (XrefCandidate, Finding, Relationship)


def serialize_result(result: Any) -> Any:
    """Serialize an explicitly typed analysis result for the JSON cache."""
    if not isinstance(result, RESULT_TYPES):
        return result
    role = {
        XrefCandidate: "candidate",
        Finding: "finding",
        Relationship: "relationship",
    }[type(result)]
    return {
        "role": role,
        "source": result.source,
        "target": result.target,
        "kind": result.kind,
        "confidence": result.confidence,
        "module": result.module,
        "evidence": list(result.evidence),
    }


def deserialize_result(payload: Any) -> Any:
    """Restore a cached typed result; preserve non-result test metadata."""
    if not isinstance(payload, dict) or payload.get("role") not in {
        "candidate", "finding", "relationship"
    }:
        return payload
    result_type = {
        "candidate": XrefCandidate,
        "finding": Finding,
        "relationship": Relationship,
    }[payload["role"]]
    return result_type(
        int(payload["source"]),
        int(payload["target"]),
        str(payload["kind"]),
        float(payload["confidence"]),
        str(payload.get("module", "")),
        tuple(payload.get("evidence", ())),
    )


@dataclass
class _StoredXref:
    source: int
    target: int
    kind: str
    confidence: float
    kinds: set = field(default_factory=set)
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
        self._finding_keys = set()
        self._relationship_keys = set()

    def add_result(
        self,
        result: AnalysisResult,
        module: str = "",
        evidence: Iterable[str] = (),
    ) -> bool:
        """Add an explicitly classified result without inferring its role from kind."""
        if isinstance(result, XrefCandidate):
            return self._add_candidate(
                result.source,
                result.target,
                result.kind,
                result.confidence,
                module or result.module,
                tuple(evidence) + tuple(result.evidence),
            )
        if isinstance(result, Finding):
            record = Finding(
                result.source,
                result.target,
                result.kind,
                result.confidence,
                module or result.module,
                tuple(sorted(set(tuple(evidence) + tuple(result.evidence)))),
            )
            key = (record.source, record.target, record.kind)
            if key not in self._finding_keys:
                self._finding_keys.add(key)
                self.findings.append(record)
            return False
        if isinstance(result, Relationship):
            record = Relationship(
                result.source,
                result.target,
                result.kind,
                result.confidence,
                module or result.module,
                tuple(sorted(set(tuple(evidence) + tuple(result.evidence)))),
            )
            key = (record.source, record.target, record.kind)
            if key not in self._relationship_keys:
                self._relationship_keys.add(key)
                self.relationships.append(record)
            return False
        self._reject(result, None, "unknown", "invalid_result")
        return False

    def _add_candidate(
        self,
        source: int,
        target: int,
        kind: str,
        confidence: float,
        module: str = "",
        evidence: Iterable[str] = (),
    ) -> bool:
        """Store an explicitly typed candidate after applying common validation."""
        try:
            source = int(source)
            target = int(target)
            confidence = max(0.0, min(1.0, float(confidence)))
            kind = str(kind)
        except (TypeError, ValueError):
            self._reject(source, target, kind, "invalid_result")
            return False

        reason = self._xref_rejection_reason(source, target)
        if reason:
            self._reject(source, target, kind, reason)
            return False
        evidence = tuple(sorted(set(evidence or ())))
        key = (source, target)
        stored = self._xrefs.get(key)
        if stored is None:
            self._xrefs[key] = _StoredXref(
                source, target, kind, confidence, {kind}, set(evidence)
            )
        else:
            stored.confidence = max(stored.confidence, confidence)
            stored.kinds.add(kind)
            stored.evidence.update(evidence)
        return True

    def xrefs(self, min_confidence: float = 0.0) -> List[Tuple[int, int, str, float]]:
        return [
            (item.source, item.target, item.kind, item.confidence)
            for item in sorted(self._xrefs.values(), key=lambda item: (item.source, item.target, item.kind))
            if item.confidence >= min_confidence
        ]

    def evidence(self) -> Dict[Tuple[int, int], set]:
        return {key: set(item.evidence) for key, item in self._xrefs.items()}

    def xref_types(self) -> Dict[Tuple[int, int], set]:
        """Return every control-flow type observed for each accepted pair."""
        return {key: set(item.kinds) for key, item in self._xrefs.items()}

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
        try:
            key = (int(source), int(target), str(kind), reason)
            if key not in self._finding_keys:
                self._finding_keys.add(key)
                self.findings.append(
                    Finding(
                        int(source),
                        int(target),
                        f"rejected_{kind}",
                        0.0,
                        evidence=(reason,),
                    )
                )
        except (TypeError, ValueError):
            pass
