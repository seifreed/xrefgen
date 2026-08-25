"""
IDA Pro 9.1 Specific Features Module
Lumina integration, type library matching, and microcode analysis
"""

from typing import Dict, List, Tuple
from modules.infrastructure.ida.base import IDAXrefAnalyzer
from modules.domain.results import AnalysisResult
import idaapi
import idc
import idautils
import ida_ida
import ida_funcs

try:
    import ida_typeinf
except ImportError:
    ida_typeinf = None
try:
    import ida_struct
except ImportError:
    ida_struct = None


class IDA91Analyzer(IDAXrefAnalyzer):
    """IDA Pro 9.1+ specific features"""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.use_lumina = (config or {}).get("use_lumina", False)
        self.use_microcode = (config or {}).get("use_microcode", True)
        self.use_type_libraries = (config or {}).get("use_type_libraries", True)

        # Check IDA version
        self.ida_version = idaapi.IDA_SDK_VERSION
        self.is_compatible = self.ida_version >= 910  # IDA 9.1+

    def get_name(self) -> str:
        return "IDAFeatures"

    def analyze(self) -> List[AnalysisResult]:
        """Perform IDA 9.1 specific analysis"""
        if not self.is_compatible:
            print(f"[XrefGen] IDA 9.1+ required (current: {self.ida_version})")
            return []

        results = []

        # Microcode analysis
        if self.use_microcode:
            microcode_refs = self._analyze_microcode()
            results.extend(microcode_refs)

        # Type library matching
        if self.use_type_libraries:
            type_refs = self._match_type_libraries()
            results.extend(type_refs)

        # Lumina metadata
        if self.use_lumina:
            lumina_refs = self._query_lumina()
            results.extend(lumina_refs)

        return results

    def _analyze_microcode(self) -> List[AnalysisResult]:
        """Analyze using Hex-Rays (ctree) to find direct/indirect calls."""
        results: List[AnalysisResult] = []

        try:
            import ida_hexrays

            if not ida_hexrays.init_hexrays_plugin():
                return results

            # Iterate all functions and decompile
            for func_ea in idautils.Functions():
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        continue

                    # Walk ctree to collect calls and resolve indirects via simple assignment tracking
                    class CallVisitor(ida_hexrays.ctree_visitor_t):
                        def __init__(self):
                            super().__init__(ida_hexrays.CV_FAST)
                            self.calls = []
                            self.data_refs = []
                            self.funcptr_map = {}  # lvar.idx -> ea

                        def _resolve_obj_ea(self, ex):
                            try:
                                if ex.op == ida_hexrays.cot_obj:
                                    return ex.obj_ea
                                if (
                                    ex.op == ida_hexrays.cot_ref
                                    and ex.x.op == ida_hexrays.cot_obj
                                ):
                                    return ex.x.obj_ea
                                if ex.op == ida_hexrays.cot_cast:
                                    return self._resolve_obj_ea(ex.x)
                            except (
                                TypeError,
                                ValueError,
                                AttributeError,
                                RuntimeError,
                            ):
                                return None
                            return None

                        def visit_expr(self, e):
                            if e.op == ida_hexrays.cot_call:
                                callsite_ea = getattr(e, "ea", func_ea)
                                if callsite_ea in (None, idaapi.BADADDR):
                                    callsite_ea = func_ea
                                # Direct callee
                                callee_ea = idaapi.BADADDR
                                if e.x.op == ida_hexrays.cot_obj:
                                    callee_ea = e.x.obj_ea
                                    if callee_ea != idaapi.BADADDR:
                                        self.calls.append(
                                            (callsite_ea, callee_ea, "hexrays_call", 0.9)
                                        )
                                else:
                                    # Indirect call; try to resolve from lvar mapping, array-of-fptr, or member ptr
                                    try:
                                        target = None
                                        if e.x.op == ida_hexrays.cot_lvar:
                                            idx = e.x.v.idx
                                            target = self.funcptr_map.get(idx)
                                        elif (
                                            e.x.op == ida_hexrays.cot_ptr
                                            and e.x.x.op == ida_hexrays.cot_lvar
                                        ):
                                            idx = e.x.x.v.idx
                                            target = self.funcptr_map.get(idx)
                                        # Try array-of-function-pointers: vtable[idx]
                                        if not target:
                                            target = self._resolve_array_of_funcptr(e.x)
                                        # Try member pointer chains (best-effort)
                                        if not target:
                                            target = self._resolve_member_funcptr(e.x)
                                        if target and target != idaapi.BADADDR:
                                            self.calls.append(
                                                (
                                                    callsite_ea,
                                                    target,
                                                    "hexrays_indirect_resolved",
                                                    0.85,
                                                )
                                            )
                                        else:
                                            self.calls.append(
                                                (
                                                    callsite_ea,
                                                    callsite_ea,
                                                    "hexrays_indirect_call",
                                                    0.5,
                                                )
                                            )
                                    except (
                                        TypeError,
                                        ValueError,
                                        AttributeError,
                                        RuntimeError,
                                    ):
                                        self.calls.append(
                                            (
                                                callsite_ea,
                                                callsite_ea,
                                                "hexrays_indirect_call",
                                                0.5,
                                            )
                                        )
                            # Collect string/data refs via objects
                            if e.op == ida_hexrays.cot_obj:
                                obj = e.obj_ea
                                if obj != idaapi.BADADDR:
                                    try:
                                        s = idc.get_strlit_contents(obj)
                                        if s:
                                            self.data_refs.append(
                                                (
                                                    func_ea,
                                                    obj,
                                                    "hexrays_string_ref",
                                                    0.8,
                                                )
                                            )
                                    except (
                                        TypeError,
                                        ValueError,
                                        AttributeError,
                                        RuntimeError,
                                    ):
                                        pass
                            # Track simple assignments: lvar = &obj or lvar = obj
                            if e.op == ida_hexrays.cot_asg:
                                try:
                                    lhs = e.x
                                    rhs = e.y
                                    if lhs.op == ida_hexrays.cot_lvar:
                                        idx = lhs.v.idx
                                        tgt = self._resolve_obj_ea(rhs)
                                        if tgt and tgt != idaapi.BADADDR:
                                            self.funcptr_map[idx] = tgt
                                except (
                                    TypeError,
                                    ValueError,
                                    AttributeError,
                                    RuntimeError,
                                ):
                                    pass
                            return 0

                        def _ptr_size(self) -> int:
                            return 8 if ida_ida.inf_is_64bit() else 4

                        def _is_code(self, ea: int) -> bool:
                            try:
                                if ida_funcs.get_func(ea):
                                    return True
                                flags = idc.get_full_flags(ea)
                                if flags == idc.BADADDR:
                                    return False
                                return idc.is_code(flags)
                            except (
                                TypeError,
                                ValueError,
                                AttributeError,
                                RuntimeError,
                            ):
                                return False

                        def _resolve_array_of_funcptr(self, ex):
                            # Handle patterns like: call vtable[idx], possibly with cast/ref/ptr wrappers
                            try:
                                import ida_hexrays as hx

                                # Unwrap common wrappers
                                while ex.op in (hx.cot_cast, hx.cot_ref, hx.cot_ptr):
                                    ex = ex.x
                                if ex.op == hx.cot_idx:
                                    base = ex.x
                                    idx = ex.y
                                    # Base must resolve to data address
                                    base_ea = self._resolve_obj_ea(base)
                                    if base_ea and base_ea != idaapi.BADADDR:
                                        # Index must be constant for static resolution
                                        if idx.op == hx.cot_num:
                                            i = int(idx.n._value)
                                            entry = base_ea + i * self._ptr_size()
                                            try:
                                                val = (
                                                    idc.get_qword(entry)
                                                    if self._ptr_size() == 8
                                                    else idc.get_wide_dword(entry)
                                                )
                                                if (
                                                    val
                                                    and val != idc.BADADDR
                                                    and self._is_code(val)
                                                ):
                                                    return val
                                            except (
                                                TypeError,
                                                ValueError,
                                                AttributeError,
                                                RuntimeError,
                                            ):
                                                pass
                                return None
                            except (
                                TypeError,
                                ValueError,
                                AttributeError,
                                RuntimeError,
                            ):
                                return None

                        def _resolve_member_funcptr(self, ex):
                            # Best-effort: unwrap and try to find base obj + constant offset
                            try:
                                import ida_hexrays as hx

                                # Peel casts/pointers/refs
                                node = ex
                                base_ea = None
                                offset = None
                                for _ in range(4):  # limited depth
                                    if node.op in (hx.cot_cast, hx.cot_ptr, hx.cot_ref):
                                        node = node.x
                                        continue
                                    if node.op == hx.cot_obj:
                                        base_ea = node.obj_ea
                                        break
                                    if node.op == hx.cot_idx:
                                        # Treat like array
                                        return self._resolve_array_of_funcptr(node)
                                    if node.op in (hx.cot_memref, hx.cot_memptr):
                                        # Try to capture member offset if available on the node
                                        try:
                                            mem = getattr(node, "m", None)
                                            # Different IDA builds may expose different attr names
                                            for attr in (
                                                "soff",
                                                "moff",
                                                "off",
                                                "offset",
                                            ):
                                                if mem is not None and hasattr(
                                                    mem, attr
                                                ):
                                                    offset = int(getattr(mem, attr))
                                                    break
                                        except (
                                            TypeError,
                                            ValueError,
                                            AttributeError,
                                            RuntimeError,
                                        ):
                                            offset = offset
                                        # Proceed to base expression
                                        node = node.x
                                        continue
                                    break
                                if base_ea and base_ea != idaapi.BADADDR:
                                    # If we recovered a field offset, try base+offset
                                    if isinstance(offset, int) and offset >= 0:
                                        addr = base_ea + offset
                                        try:
                                            val = (
                                                idc.get_qword(addr)
                                                if self._ptr_size() == 8
                                                else idc.get_wide_dword(addr)
                                            )
                                            if (
                                                val
                                                and val != idc.BADADDR
                                                and self._is_code(val)
                                            ):
                                                return val
                                        except (
                                            TypeError,
                                            ValueError,
                                            AttributeError,
                                            RuntimeError,
                                        ):
                                            pass
                                    # Heuristic: vtable-like bases
                                    try:
                                        name = idc.get_name(base_ea) or ""
                                        if (
                                            "vtable" in name.lower()
                                            or "vfptr" in name.lower()
                                            or "vftable" in name.lower()
                                        ):
                                            val = (
                                                idc.get_qword(base_ea)
                                                if self._ptr_size() == 8
                                                else idc.get_wide_dword(base_ea)
                                            )
                                            if (
                                                val
                                                and val != idc.BADADDR
                                                and self._is_code(val)
                                            ):
                                                return val
                                    except (
                                        TypeError,
                                        ValueError,
                                        AttributeError,
                                        RuntimeError,
                                    ):
                                        pass
                                return None
                            except (
                                TypeError,
                                ValueError,
                                AttributeError,
                                RuntimeError,
                            ):
                                return None

                    v = CallVisitor()
                    v.apply_to(cfunc.body, None)
                    for source, target, kind, confidence in v.calls:
                        if kind in ("hexrays_call", "hexrays_indirect_resolved"):
                            results.append(self.emit_control_flow(
                                source, target, kind, confidence, ("hexrays",)
                            ))
                        else:
                            results.append(self.emit_finding(
                                source, target, kind, confidence, ("hexrays",)
                            ))
                    for source, target, kind, confidence in v.data_refs:
                        results.append(self.emit_finding(
                            source, target, kind, confidence, ("hexrays",)
                        ))

                except (TypeError, ValueError, AttributeError, RuntimeError):
                    continue

        except ImportError:
            print("[XrefGen] Hex-Rays decompiler not available")

        return results

    def _match_type_libraries(self) -> List[AnalysisResult]:
        """Record functions for which IDA resolved a library-backed type."""
        results = []
        if ida_typeinf is None:
            return results
        for func_ea in idautils.Functions():
            try:
                tinfo = ida_typeinf.tinfo_t()
                if not ida_typeinf.get_tinfo(tinfo, func_ea):
                    continue
                type_name = tinfo.get_type_name() if hasattr(tinfo, "get_type_name") else ""
                if type_name:
                    results.append(self.emit_finding(
                        func_ea,
                        func_ea,
                        "type_library_match",
                        0.75,
                        ("ida_typeinf", type_name),
                    ))
            except (TypeError, ValueError, AttributeError, RuntimeError):
                continue
        return results

    def _query_lumina(self) -> List[AnalysisResult]:
        """Query Lumina metadata service if available, attach names/types."""
        results: List[AnalysisResult] = []
        try:
            import ida_lumina
        except ImportError:
            print("[XrefGen] Lumina module not available; skipping")
            return results

        # Attempt to fetch metadata; keep it non-destructive and optional
        try:
            # Refresh metadata for current database; APIs differ by version.
            # Use a conservative call that exists in 9.x
            if hasattr(ida_lumina, "apply_metadata"):  # newer
                ida_lumina.apply_metadata()
            elif hasattr(ida_lumina, "refresh_metadata"):
                ida_lumina.refresh_metadata()
            # Metadata is useful to IDA but is not an xref candidate.
        except (TypeError, ValueError, AttributeError, RuntimeError):
            # Best-effort; do not fail the analysis if Lumina unreachable
            pass

        return results
