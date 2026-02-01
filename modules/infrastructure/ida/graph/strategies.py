"""Graph analyzer strategies."""
from typing import List, Tuple, Optional
import idaapi
import idautils
import idc
import ida_segment
from modules.infrastructure.ida.utils import abi
from modules.infrastructure.ida.utils.names import normalize_name
from modules.infrastructure.ida.utils.insn import scan_back_for_reg_source


class WrapperDetector:
    def __init__(self, analyzer):
        self.a = analyzer

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for func_ea, func in self.a._iter_functions():
            if (func.end_ea - func.start_ea) > self.a.skip_trivial_size * 2:
                continue
            call_target = None
            call_count = 0
            for head in self.a._iter_heads(func):
                mnem = idc.print_insn_mnem(head).lower()
                if mnem in self.a.CALL_MNEMS:
                    call_count += 1
                    if idc.get_operand_type(head, 0) == idc.o_near:
                        call_target = idc.get_operand_value(head, 0)
            if call_count == 1 and call_target and self.a.is_valid_reference(call_target):
                conf = self.a.confidence("wrapper_call")
                self.a.add_xref(func_ea, call_target, "wrapper_call", conf)
                try:
                    self.a.add_evidence(func_ea, call_target, "wrapper")
                except Exception:
                    pass
                results.append((func_ea, call_target, "wrapper_call", conf))
        return results


class CallbackResolver:
    def __init__(self, analyzer):
        self.a = analyzer

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        callbacks = self.a.callback_targets or {}
        regs = abi.arg_registers()
        for func_ea, func in self.a._iter_functions():
            for head in self.a._iter_heads(func):
                if idc.print_insn_mnem(head).lower() not in self.a.CALL_MNEMS:
                    continue
                if idc.get_operand_type(head, 0) != idc.o_near:
                    continue
                target = idc.get_operand_value(head, 0)
                name = normalize_name(idc.get_func_name(target))
                if name not in callbacks:
                    continue
                arg_idx = callbacks[name]
                if arg_idx >= len(regs):
                    continue
                cb_reg = regs[arg_idx]
                cb = self._resolve_recent_reg_imm(head, cb_reg)
                if cb and self.a.is_valid_reference(cb):
                    conf = self.a.confidence("callback_arg")
                    self.a.add_xref(head, cb, "callback_arg", conf)
                    try:
                        self.a.add_evidence(head, cb, "callback")
                    except Exception:
                        pass
                    results.append((head, cb, "callback_arg", conf))
        return results

    def _resolve_recent_reg_imm(self, call_ea: int, reg: str) -> Optional[int]:
        res = scan_back_for_reg_source(call_ea, reg, max_back=6)
        if not res:
            return None
        _ea, src_type, src_val = res
        if src_type in (idc.o_imm, idc.o_mem, idc.o_displ):
            return src_val
        return None


class SEHResolver:
    def __init__(self, analyzer):
        self.a = analyzer

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for seg_ea in idautils.Segments():
            name = idc.get_segm_name(seg_ea).lower()
            if name not in (".pdata", ".xdata"):
                continue
            seg_end = idc.get_segm_end(seg_ea)
            ea = seg_ea
            ptr = 8 if idaapi.get_inf_structure().is_64bit() else 4
            while ea < seg_end:
                try:
                    handler = idc.get_qword(ea) if ptr == 8 else idc.get_wide_dword(ea)
                except Exception:
                    handler = 0
                if handler and self.a.is_valid_reference(handler):
                    conf = self.a.confidence("seh_handler")
                    self.a.add_xref(ea, handler, "seh_handler", conf)
                    try:
                        self.a.add_evidence(ea, handler, "seh")
                    except Exception:
                        pass
                    results.append((ea, handler, "seh_handler", conf))
                ea += ptr
        return results


class VTableResolver:
    def __init__(self, analyzer):
        self.a = analyzer

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        seen_entries = set()
        try:
            ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
        except Exception:
            ptr_size = 4
        for vt_start, is_rtti in self.a._find_named_vtables():
            run = []
            ea = vt_start
            for _ in range(512):
                try:
                    target = idc.get_qword(ea) if ptr_size == 8 else idc.get_wide_dword(ea)
                except Exception:
                    break
                if target and self.a.is_valid_reference(target):
                    run.append((ea, target))
                    ea += ptr_size
                else:
                    break
            if len(run) >= self.a.vtable_min_len:
                for entry_ea, func_ptr in run:
                    if entry_ea in seen_entries:
                        continue
                    seen_entries.add(entry_ea)
                    conf = self.a.confidence("vtable_named")
                    self.a.add_xref(entry_ea, func_ptr, "vtable_entry", conf)
                    if is_rtti:
                        try:
                            self.a.add_evidence(entry_ea, func_ptr, "rtti_vtable")
                        except Exception:
                            pass
                    results.append((entry_ea, func_ptr, "vtable_entry", conf))
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            if hasattr(seg, "perm") and hasattr(ida_segment, "SEGPERM_EXEC"):
                if seg.perm & ida_segment.SEGPERM_EXEC:
                    continue
            seg_end = idc.get_segm_end(seg_ea)
            run = []
            ea = seg_ea
            while ea < seg_end:
                try:
                    target = idc.get_qword(ea) if ptr_size == 8 else idc.get_wide_dword(ea)
                except Exception:
                    target = 0
                if target and self.a.is_valid_reference(target):
                    run.append((ea, target))
                else:
                    if len(run) >= self.a.vtable_min_len:
                        for entry_ea, func_ptr in run:
                            if entry_ea in seen_entries:
                                continue
                            seen_entries.add(entry_ea)
                            conf = self.a.confidence("vtable_scan")
                            self.a.add_xref(entry_ea, func_ptr, "vtable_entry", conf)
                            results.append((entry_ea, func_ptr, "vtable_entry", conf))
                    run = []
                ea += ptr_size
            if len(run) >= self.a.vtable_min_len:
                for entry_ea, func_ptr in run:
                    if entry_ea in seen_entries:
                        continue
                    seen_entries.add(entry_ea)
                    conf = self.a.confidence("vtable_scan")
                    self.a.add_xref(entry_ea, func_ptr, "vtable_entry", conf)
                    results.append((entry_ea, func_ptr, "vtable_entry", conf))
        return results
