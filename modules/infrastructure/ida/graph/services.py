"""Graph analysis services."""
from typing import List, Tuple
import idaapi
import idautils
import idc
try:
    import ida_ida
except ImportError:
    ida_ida = None


class EntryPointFinder:
    def __init__(self, analyzer):
        self.a = analyzer

    def find_entry_points(self) -> List[int]:
        entry_points = []
        main_ea = idc.get_name_ea_simple("main")
        if main_ea != idc.BADADDR:
            entry_points.append(main_ea)
        if ida_ida is not None and hasattr(ida_ida, "inf_get_start_ea"):
            start_ea = ida_ida.inf_get_start_ea()
            if start_ea != idc.BADADDR:
                entry_points.append(start_ea)
        for idx in range(idc.get_entry_qty()):
            ordinal = idc.get_entry_ordinal(idx)
            ea = idc.get_entry(ordinal)
            if ea != idc.BADADDR:
                entry_points.append(ea)
        entry_points.extend(self._find_tls_callbacks())
        entry_points.extend(self._find_ctors_dtors())
        return list(set(entry_points))

    def _find_tls_callbacks(self) -> List[int]:
        callbacks = []
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if ".tls" in seg_name.lower():
                pass
        return callbacks

    def _find_ctors_dtors(self) -> List[int]:
        ctors = []
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if any(name in seg_name.lower() for name in [".init", ".ctor", ".dtor", ".fini"]):
                seg_end = idc.get_segm_end(seg_ea)
                is64 = False
                if ida_ida is not None and hasattr(ida_ida, 'inf_is_64bit'):
                    try:
                        is64 = ida_ida.inf_is_64bit()
                    except Exception:
                        is64 = False
                ptr_size = 8 if is64 else 4
                ea = seg_ea
                while ea < seg_end:
                    func_ptr = idc.get_qword(ea) if ptr_size == 8 else idc.get_wide_dword(ea)
                    if func_ptr and self.a.is_valid_reference(func_ptr):
                        ctors.append(func_ptr)
                    ea += ptr_size
        return ctors


class ComplexityAnalyzer:
    def __init__(self, analyzer):
        self.a = analyzer

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for func_ea, func in self.a._iter_functions():
            complexity = self._calculate_cyclomatic_complexity(func)
            self.a.function_complexity[func_ea] = complexity
            if complexity > self.a.complexity_threshold:
                hidden_refs = self._analyze_complex_function(func, complexity)
                for source, target, confidence in hidden_refs:
                    self.a.add_xref(source, target, f"complex_func_cc_{complexity}", confidence)
                    results.append((source, target, f"complex_func_cc_{complexity}", confidence))
        return results

    def _calculate_cyclomatic_complexity(self, func) -> int:
        cfg_nodes, cfg_edges = self._build_cfg(func)
        nodes = len(cfg_nodes)
        edges = len(cfg_edges)
        complexity = edges - nodes + 2
        exit_points = self._count_exit_points(func)
        if exit_points > 1:
            complexity += exit_points - 1
        return max(1, complexity)

    def _build_cfg(self, func):
        cfg_nodes = set()
        cfg_edges = set()
        for head in self.a._iter_heads(func):
            cfg_nodes.add(head)
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in self.a.JMP_MNEMS | self.a.COND_JMPS:
                target = idc.get_operand_value(head, 0)
                if func.start_ea <= target < func.end_ea:
                    cfg_edges.add((head, target))
                if mnem not in self.a.JMP_MNEMS:
                    self._add_fallthrough_edge(head, func, cfg_edges)
            elif mnem in self.a.RET_MNEMS:
                cfg_edges.add((head, head))
            else:
                self._add_fallthrough_edge(head, func, cfg_edges)
        return cfg_nodes, cfg_edges

    def _add_fallthrough_edge(self, head, func, cfg_edges):
        next_ea = idc.next_head(head)
        if next_ea != idc.BADADDR and next_ea < func.end_ea:
            cfg_edges.add((head, next_ea))

    def _count_exit_points(self, func) -> int:
        exits = 0
        for head in self.a._iter_heads(func):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in self.a.EXIT_MNEMS:
                exits += 1
        return max(1, exits)

    def _analyze_complex_function(self, func, complexity: int) -> List[Tuple[int, int, float]]:
        refs = []
        for head in self.a._iter_heads(func):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in self.a.JMP_MNEMS:
                op_type = idc.get_operand_type(head, 0)
                if op_type in [idc.o_reg, idc.o_mem, idc.o_displ]:
                    targets = self._resolve_computed_targets(head, func)
                    for target, base_conf in targets:
                        confidence = base_conf - (complexity / 100.0)
                        refs.append((head, target, max(0.3, confidence)))
        return refs

    def _resolve_computed_targets(self, jmp_ea: int, func) -> List[Tuple[int, float]]:
        targets: List[Tuple[int, float]] = []
        targets.extend(self._resolve_switch_targets(jmp_ea, func))
        if targets:
            return targets
        max_value = self._find_bounds_check(jmp_ea)
        if max_value is not None:
            for i in range(max_value + 1):
                potential_target = func.start_ea + (i * 0x10)
                if self.a.is_valid_reference(potential_target):
                    targets.append((potential_target, 0.6))
        return targets

    def _resolve_switch_targets(self, jmp_ea: int, func) -> List[Tuple[int, float]]:
        if not hasattr(idaapi, "get_switch_info_ex"):
            return []
        try:
            si = idaapi.get_switch_info_ex(jmp_ea)
        except Exception:
            return []
        if not si:
            return []
        try:
            jtable = si.jumps
            size = si.get_jtable_size() if hasattr(si, "get_jtable_size") else 0
            esize = si.get_jtable_element_size() if hasattr(si, "get_jtable_element_size") else 4
        except Exception:
            return []
        if not jtable or size <= 0:
            return []
        results: List[Tuple[int, float]] = []
        for i in range(size):
            ea = jtable + i * esize
            try:
                target = idc.get_qword(ea) if esize == 8 else idc.get_wide_dword(ea)
            except Exception:
                continue
            if target and self._valid_jump_target(func, target):
                results.append((target, 0.75))
        return results

    def _valid_jump_target(self, func, target: int) -> bool:
        if not self.a.is_valid_reference(target):
            return False
        return func.start_ea <= target < func.end_ea

    def _find_bounds_check(self, jmp_ea: int) -> int:
        prev_ea = jmp_ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem == "cmp":
                op_type = idc.get_operand_type(prev_ea, 1)
                if op_type == idc.o_imm:
                    return idc.get_operand_value(prev_ea, 1)
        return None
