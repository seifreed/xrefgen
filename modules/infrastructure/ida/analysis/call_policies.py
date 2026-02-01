"""Policies for handling call-side taint effects."""
from typing import List
from modules.infrastructure.ida.utils import abi


class CallInfo:
    def __init__(self, call_ea: int, target_ea: int, name: str, arg_regs: List[str]):
        self.call_ea = call_ea
        self.target_ea = target_ea
        self.name = name
        self.arg_regs = arg_regs


class TaintSourcePolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self, info: CallInfo, regs: dict):
        if any(src in info.name for src in self.a.taint_sources):
            ret_reg = abi.return_reg()
            regs[ret_reg] = (info.call_ea, self.a._ret_taint_confidence(info.target_ea))
            self.a.taint_kinds_regs.setdefault(self.a._current_func_ea, {})[ret_reg] = self.a.taint_rules.source_kind(info.name)
            try:
                self.a.add_evidence(info.call_ea, info.call_ea, "dataflow")
            except Exception:
                pass


class NumericParserPolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self, info: CallInfo, regs: dict):
        if any(p in info.name for p in self.a.numeric_parsers):
            ret_reg = abi.return_reg()
            regs[ret_reg] = (info.call_ea, 0.8)
            self.a.taint_kinds_regs.setdefault(self.a._current_func_ea, {})[ret_reg] = "control"


class HeapAllocPolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self, info: CallInfo, regs: dict):
        if not any(a in info.name for a in self.a.heap_alloc_apis):
            return
        heap_id = f"heap_{info.call_ea:x}"
        ret_reg = abi.return_reg()
        self.a._heap_aliases.setdefault(self.a._current_func_ea, {})[ret_reg] = heap_id
        size_val = None
        arg_regs = info.arg_regs
        if arg_regs:
            if "calloc" in info.name and len(arg_regs) >= 2:
                n = self.a._resolve_arg_immediate(info.call_ea, arg_regs[0])
                s = self.a._resolve_arg_immediate(info.call_ea, arg_regs[1])
                if n is not None and s is not None:
                    size_val = n * s
            else:
                size_val = self.a._resolve_arg_immediate(info.call_ea, arg_regs[0])
        if size_val:
            prefix = f"heap:{heap_id}"
            self.a._record_mem_interval(prefix, 0, size_val, "ptr", 0.7)


class SanitizerPolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self, info: CallInfo, regs: dict, mem: dict) -> bool:
        if not any(s in info.name for s in self.a.sanitizers):
            return False
        if self.a.sanitizer_scoped:
            self.a._apply_scoped_sanitizer(regs, mem, info.call_ea)
        else:
            regs.clear()
            mem.clear()
        return True


class TaintCarryPolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self, info: CallInfo, regs: dict, mem: dict):
        if any(a in info.name for a in self.a.taint_carrying_apis):
            self.a._apply_taint_carry(regs, mem, info.call_ea, info.name)
