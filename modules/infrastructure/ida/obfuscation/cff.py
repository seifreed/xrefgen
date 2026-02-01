"""Control Flow Flattening detection helpers."""

from typing import List, Tuple, Set, Optional
import idautils
import ida_funcs
import idc
from modules.infrastructure.ida.base import IDAXrefAnalyzer
from modules.infrastructure.ida.utils.insn import mnem_cached
from modules.infrastructure.ida.obfuscation.cff_utils import (
    is_compare_mnem,
    is_cond_jump_mnem,
    is_indirect_jump,
    is_state_var_compare,
    is_reg_assignment,
    imm_assignment_value,
)


class CFFDetector:
    def __init__(self, analyzer: IDAXrefAnalyzer):
        self.analyzer = analyzer
        cfg = getattr(analyzer, "config", {}) if analyzer else {}
        obf = cfg.get("modules", {}).get("obfuscation", {})
        tuning = obf.get("tuning_table", {}) if isinstance(obf.get("tuning_table", {}), dict) else {}
        self.max_dispatcher_size = int(tuning.get("max_dispatcher_size", 1000))
        self.min_block_refs = int(tuning.get("cff_min_block_refs", 5))
        self.min_comparisons = int(tuning.get("cff_min_comparisons", 3))
        self.min_jumps = int(tuning.get("cff_min_jumps", 3))
        self.dispatcher_scan_limit = int(tuning.get("cff_dispatcher_scan_limit", 20))
        self.dispatcher_scan_window = int(tuning.get("cff_dispatcher_scan_window", 256))
        self.resolved_confidence = float(tuning.get("cff_resolved_confidence", 0.7))
        self.dispatcher_blocks = {}
        self.flattened_functions = set()

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for func_ea, func in self._iter_functions():
            results.extend(self.analyze_function(func_ea, func))
        return results

    def analyze_function(self, func_ea: int, func) -> List[Tuple[int, int, str, float]]:
        results = []
        mnem_cache = {}
        dispatcher = self._find_dispatcher_block(func, mnem_cache)
        if dispatcher:
            self.flattened_functions.add(func_ea)
            self.dispatcher_blocks[func_ea] = dispatcher
            real_flow = self._resolve_flattened_flow(func, dispatcher)
            for source, target, conf in real_flow:
                conf_val = min(conf, self.resolved_confidence) if conf is not None else self.resolved_confidence
                self.analyzer.add_xref(source, target, "cff_resolved", conf_val)
                results.append((source, target, "cff_resolved", conf_val))
        return results

    def _iter_functions(self):
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func

    def _find_dispatcher_block(self, func, mnem_cache: Optional[dict] = None) -> Optional[int]:
        block_refs = {}
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsTo(head):
                if func.start_ea <= xref.frm < func.end_ea:
                    block_refs[head] = block_refs.get(head, 0) + 1
        if not block_refs:
            return None
        dispatcher_candidate = max(block_refs.items(), key=lambda x: x[1])
        if dispatcher_candidate[1] > self.min_block_refs:
            if self._has_dispatcher_pattern(dispatcher_candidate[0], func.end_ea, mnem_cache):
                return dispatcher_candidate[0]
        return None

    def _has_dispatcher_pattern(self, ea: int, end_ea: int, mnem_cache: Optional[dict] = None) -> bool:
        comparisons = 0
        jumps = 0
        curr_ea = ea
        checked = 0
        while curr_ea < end_ea and checked < self.max_dispatcher_size:
            mnem = mnem_cached(curr_ea, mnem_cache)
            if is_compare_mnem(mnem):
                comparisons += 1
            elif is_cond_jump_mnem(mnem):
                jumps += 1
            elif mnem == "jmp":
                if is_indirect_jump(curr_ea):
                    return True
            curr_ea = idc.next_head(curr_ea)
            checked += 1
        return comparisons > self.min_comparisons and jumps > self.min_jumps

    def _resolve_flattened_flow(self, func, dispatcher: int) -> List[Tuple[int, int, float]]:
        resolved_flow = []
        state_vars = self._find_state_variables(func, dispatcher)
        state_map = {}
        for state_var in state_vars:
            assignments = self._find_state_assignments(func, state_var)
            for ea, value in assignments:
                state_map[value] = ea
        for value, block in state_map.items():
            next_blocks = self._find_next_blocks(block, func.end_ea, dispatcher)
            for next_block in next_blocks:
                if next_block in state_map.values():
                    resolved_flow.append((block, next_block, self.resolved_confidence))
        return resolved_flow

    def _find_state_variables(self, func, dispatcher: int) -> Set[int]:
        state_vars = set()
        curr_ea = dispatcher
        for _ in range(self.dispatcher_scan_limit):
            if curr_ea >= func.end_ea:
                break
            mnem = idc.print_insn_mnem(curr_ea).lower()
            if mnem == "cmp" and is_state_var_compare(curr_ea):
                op1_type = idc.get_operand_type(curr_ea, 0)
                if op1_type == idc.o_reg:
                    state_vars.add(idc.get_operand_value(curr_ea, 0))
                elif op1_type == idc.o_displ:
                    state_vars.add(curr_ea)
            curr_ea = idc.next_head(curr_ea)
        return state_vars

    def _find_state_assignments(self, func, state_var: int) -> List[Tuple[int, int]]:
        assignments = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "mov":
                if is_reg_assignment(head, state_var):
                    value = imm_assignment_value(head)
                    if value is not None:
                        assignments.append((head, value))
        return assignments

    def _find_next_blocks(self, block_ea: int, end_ea: int, dispatcher: int) -> List[int]:
        next_blocks = []
        curr_ea = block_ea
        scanned = 0
        while curr_ea < end_ea and scanned < self.dispatcher_scan_window:
            mnem = idc.print_insn_mnem(curr_ea).lower()
            if mnem == "jmp":
                target = idc.get_operand_value(curr_ea, 0)
                if target == dispatcher:
                    prev_ea = idc.prev_head(curr_ea)
                    if prev_ea != idc.BADADDR:
                        prev_mnem = idc.print_insn_mnem(prev_ea).lower()
                        if prev_mnem == "mov":
                            src_type = idc.get_operand_type(prev_ea, 1)
                            if src_type == idc.o_imm:
                                next_state = idc.get_operand_value(prev_ea, 1)
                                next_blocks.append(dispatcher + (next_state * 0x10))
                    break
            curr_ea = idc.next_head(curr_ea)
            scanned += 1
        return next_blocks
