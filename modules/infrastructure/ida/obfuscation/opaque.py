"""Opaque predicate detection helpers."""

from typing import List, Tuple, Optional
import idautils
import ida_funcs
import idc
from modules.infrastructure.ida.base import IDAXrefAnalyzer


class OpaquePredicateDetector:
    def __init__(self, analyzer: IDAXrefAnalyzer):
        self.analyzer = analyzer
        self.opaque_predicates = []
        self.always_taken_branches = set()
        self.never_taken_branches = set()

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for _func_ea, func in self._iter_functions():
            results.extend(self.analyze_function(func))
        return results

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        results = []
        mnem_cache = {}
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = self._mnem(head, mnem_cache)
            if mnem in ["je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", "jge", "jle"]:
                if self._is_opaque_predicate(head, mnem_cache):
                    always_taken = self._get_always_taken_branch(head, mnem_cache)
                    if always_taken:
                        self.always_taken_branches.add(head)
                        target = idc.get_operand_value(head, 0)
                        self.analyzer.add_xref(head, target, "opaque_always_taken", 0.95)
                        results.append((head, target, "opaque_always_taken", 0.95))
                    else:
                        self.never_taken_branches.add(head)
                        next_ea = idc.next_head(head)
                        if next_ea != idc.BADADDR:
                            self.analyzer.add_xref(head, next_ea, "opaque_never_taken", 0.95)
                            results.append((head, next_ea, "opaque_never_taken", 0.95))
        return results

    def _iter_functions(self):
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func

    def _is_opaque_predicate(self, jmp_ea: int, mnem_cache: Optional[dict] = None) -> bool:
        prev_ea = idc.prev_head(jmp_ea)
        if prev_ea == idc.BADADDR:
            return False
        prev_mnem = self._mnem(prev_ea, mnem_cache)
        if prev_mnem not in ["cmp", "test"]:
            return False
        pattern_ea = prev_ea
        for _ in range(10):
            pattern_ea = idc.prev_head(pattern_ea)
            if pattern_ea == idc.BADADDR:
                break
            pattern_mnem = self._mnem(pattern_ea, mnem_cache)
            if pattern_mnem == "imul":
                next_ea = idc.next_head(pattern_ea)
                if next_ea != idc.BADADDR:
                    next_mnem = idc.print_insn_mnem(next_ea).lower()
                    if next_mnem in ["sub", "dec"]:
                        return True
            elif pattern_mnem == "xor":
                op1 = idc.print_operand(pattern_ea, 0)
                op2 = idc.print_operand(pattern_ea, 1)
                if op1 == op2:
                    return True
            elif pattern_mnem == "and":
                op2_type = idc.get_operand_type(pattern_ea, 1)
                if op2_type == idc.o_imm and idc.get_operand_value(pattern_ea, 1) == 1:
                    return True
        return False

    def _get_always_taken_branch(self, jmp_ea: int, mnem_cache: Optional[dict] = None) -> bool:
        mnem = self._mnem(jmp_ea, mnem_cache)
        prev_ea = idc.prev_head(jmp_ea)
        if prev_ea == idc.BADADDR:
            return True
        prev_mnem = self._mnem(prev_ea, mnem_cache)
        if prev_mnem == "test":
            op1 = idc.print_operand(prev_ea, 0)
            op2 = idc.print_operand(prev_ea, 1)
            if op1 == op2:
                if mnem in ["jz", "je"]:
                    return True
                if mnem in ["jnz", "jne"]:
                    return False
        return mnem in ["je", "jz", "jge", "jle"]

    def _mnem(self, ea: int, cache: Optional[dict]) -> str:
        if cache is None:
            return idc.print_insn_mnem(ea).lower()
        if ea in cache:
            return cache[ea]
        val = idc.print_insn_mnem(ea).lower()
        cache[ea] = val
        return val
