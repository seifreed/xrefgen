"""Helper components for DataFlowAnalyzer."""
from typing import Optional, Tuple, List
import idaapi
import idautils
import idc
import ida_funcs
try:
    import ida_frame
except Exception:
    ida_frame = None
try:
    import ida_struct
except Exception:
    ida_struct = None
try:
    import ida_typeinf
except Exception:
    ida_typeinf = None
try:
    import ida_bytes
except Exception:
    ida_bytes = None

from modules.infrastructure.ida.utils import abi
from modules.infrastructure.ida.utils.insn import scan_back_for_reg_source


class ArgumentResolver:
    def __init__(self, analyzer):
        self.a = analyzer

    def get_call_arg_regs(self, call_ea: int) -> List[str]:
        arg_regs = abi.arg_registers()
        callee_ea = None
        try:
            callee_ea = idc.get_operand_value(call_ea, 0)
        except Exception:
            callee_ea = None
        if callee_ea is None or callee_ea == idc.BADADDR or ida_typeinf is None:
            return arg_regs
        try:
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.get_tinfo(tinfo, callee_ea):
                ftd = ida_typeinf.func_type_data_t()
                if tinfo.get_func_details(ftd):
                    argc = ftd.size()
                    return arg_regs[: max(0, argc)]
        except Exception:
            return arg_regs
        return arg_regs

    def expected_arg_kind(self, call_ea: int, arg_index: int) -> Optional[str]:
        if ida_typeinf is None:
            return None
        try:
            callee_ea = idc.get_operand_value(call_ea, 0)
            if callee_ea in (None, idc.BADADDR):
                return None
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.get_tinfo(tinfo, callee_ea):
                ftd = ida_typeinf.func_type_data_t()
                if tinfo.get_func_details(ftd):
                    if arg_index >= ftd.size():
                        return None
                    arg_t = ftd[arg_index].type
                    if arg_t.is_ptr() or arg_t.is_array():
                        return "ptr"
                    if arg_t.is_integral() or arg_t.is_enum():
                        return "num"
        except Exception:
            return None
        return None

    def arg_reg_index(self, reg: str) -> Optional[int]:
        try:
            regs = abi.arg_registers()
            return regs.index(reg) if reg in regs else None
        except Exception:
            return None

    def func_arg_is_ptr(self, func_ea: int, arg_index: int) -> bool:
        if ida_typeinf is None:
            return False
        try:
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.get_tinfo(tinfo, func_ea):
                ftd = ida_typeinf.func_type_data_t()
                if tinfo.get_func_details(ftd):
                    if arg_index >= ftd.size():
                        return False
                    arg_t = ftd[arg_index].type
                    return arg_t.is_ptr() or arg_t.is_array()
        except Exception:
            return False
        return False

    def resolve_arg_immediate(self, call_ea: int, reg: str, max_back: int = 8) -> Optional[int]:
        res = scan_back_for_reg_source(call_ea, reg, max_back=max_back)
        if not res:
            return None
        _ea, src_type, src_val = res
        if src_type == idc.o_imm:
            try:
                return int(src_val)
            except Exception:
                return None
        return None


class StringEvidence:
    def __init__(self, analyzer):
        self.a = analyzer

    def arg_points_to_string(self, call_ea: int, reg: str) -> bool:
        res = scan_back_for_reg_source(call_ea, reg, max_back=6)
        if not res:
            return False
        _ea, src_type, src_val = res
        if src_type in (idc.o_imm, idc.o_mem, idc.o_displ):
            addr = src_val
            if ida_bytes is not None and addr and ida_bytes.is_strlit(ida_bytes.get_flags(addr)):
                return True
        return False

    def is_format_string(self, call_ea: int) -> bool:
        ea = call_ea
        for _ in range(6):
            ea = idc.prev_head(ea)
            if ea == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem in ("mov", "lea"):
                try:
                    src_type = idc.get_operand_type(ea, 1)
                except Exception:
                    continue
                if src_type in (idc.o_imm, idc.o_mem):
                    addr = idc.get_operand_value(ea, 1)
                    try:
                        s = idc.get_strlit_contents(addr)
                        if s and b"%" in s:
                            return True
                    except Exception:
                        continue
        return False


class HeapTracker:
    def __init__(self, analyzer):
        self.a = analyzer

    def heap_mem_key(self, lower: str) -> Optional[str]:
        func_ea = self.a._current_func_ea
        if not func_ea:
            return None
        aliases = self.a._heap_aliases.get(func_ea, {})
        base, offset = self.parse_mem_base_offset(lower)
        if base and base in aliases:
            suffix = ""
            if offset is not None:
                sign = "+" if offset >= 0 else "-"
                suffix = f"{sign}{abs(offset):#x}"
            return f"heap:{aliases[base]}{suffix}"
        return None

    def parse_mem_base_offset(self, lower: str) -> Tuple[Optional[str], Optional[int]]:
        if "[" not in lower or "]" not in lower:
            return None, None
        inside = lower.split("[", 1)[1].split("]", 1)[0]
        inside = inside.replace("#", "")
        parts = __import__("re").split(r"[,+\-\s]", inside)
        base = parts[0].strip() if parts else None
        offset = None
        m = __import__("re").search(r"([+-])\s*(0x[0-9a-f]+|\d+)", inside)
        if m:
            val = int(m.group(2), 0)
            offset = val if m.group(1) == "+" else -val
        return base, offset

    def heap_key_offset(self, key: str) -> Optional[int]:
        m = __import__("re").search(r"([+-])0x([0-9a-f]+)$", key)
        if not m:
            return 0
        val = int(m.group(2), 16)
        return val if m.group(1) == "+" else -val

    def record_mem_interval(self, prefix: str, start: int, size: int, kind: str, conf: float):
        func_ea = self.a._current_func_ea
        if not func_ea:
            return
        self.a._mem_intervals.setdefault(func_ea, []).append((prefix, start, size, kind, conf))

    def stack_var_key(self, ea: int, op_idx: int) -> Optional[str]:
        try:
            if hasattr(idc, "get_stkvar"):
                sv = idc.get_stkvar(ea, op_idx)
                if not sv:
                    return None
                size = self.stack_var_size(ea, sv)
                member = self.stack_var_member_name(ea, sv, op_idx)
                if size:
                    return f"stk:{sv}:{size}{member}"
                return f"stk:{sv}{member}"
        except Exception:
            return None
        return None

    def stack_var_size(self, ea: int, name: str) -> Optional[int]:
        if ida_frame is None or ida_struct is None:
            return None
        func = ida_funcs.get_func(ea)
        if not func:
            return None
        try:
            fr = ida_frame.get_frame(func)
            if not fr:
                return None
            m = ida_struct.get_member_by_name(fr, name)
            if not m:
                return None
            return ida_struct.get_member_size(m)
        except Exception:
            return None

    def stack_var_member_name(self, ea: int, name: str, op_idx: int) -> str:
        if ida_struct is None or ida_frame is None:
            return ""
        try:
            func = ida_funcs.get_func(ea)
            if not func:
                return ""
            fr = ida_frame.get_frame(func)
            if not fr:
                return ""
            m = ida_struct.get_member_by_name(fr, name)
            if not m:
                return ""
            op = self.a._safe_print_operand(ea, op_idx).lower()
            _base, offset = self.parse_mem_base_offset(op)
            if offset is None:
                return ""
            sub = ida_struct.get_member(fr, m.soff + offset)
            if not sub:
                return ""
            sub_name = ida_struct.get_member_name(sub.id)
            return f".{sub_name}" if sub_name else ""
        except Exception:
            return ""


class CFGWalker:
    def __init__(self, analyzer):
        self.a = analyzer

    def iter_basic_blocks(self, func):
        try:
            for block in idaapi.FlowChart(func, flags=idaapi.FC_PREDS):
                yield block
        except Exception:
            return

    def reachable_block_ids(self, entry_block):
        seen = set()
        stack = [entry_block]
        while stack:
            b = stack.pop()
            if b.id in seen:
                continue
            seen.add(b.id)
            for s in b.succs():
                stack.append(s)
        return seen

    def merge_pred_states(self, block, out_states):
        regs = {}
        mem = {}
        preds = list(block.preds())
        if not preds:
            return regs, mem
        for pred in preds:
            state = out_states.get(pred.id)
            if not state:
                continue
            pre_regs, pre_mem = state
            for reg, (src, conf) in pre_regs.items():
                if reg not in regs or conf > regs[reg][1]:
                    regs[reg] = (src, conf)
            for key, (src, conf) in pre_mem.items():
                if key not in mem or conf > mem[key][1]:
                    mem[key] = (src, conf)
        return regs, mem

    def merge_pred_kinds(self, block, out_kinds):
        kinds = {}
        preds = list(block.preds())
        if not preds:
            return kinds
        for pred in preds:
            state = out_kinds.get(pred.id)
            if not state:
                continue
            for reg, kind in state.items():
                if reg not in kinds:
                    kinds[reg] = kind
        return kinds

    def merge_pred_defs(self, block, out_defs):
        defs = {}
        preds = list(block.preds())
        if not preds:
            return defs
        for pred in preds:
            state = out_defs.get(pred.id)
            if not state:
                continue
            for reg, eas in state.items():
                if reg not in defs:
                    defs[reg] = set()
                defs[reg].update(eas)
        return defs

    def compute_reaching_defs(self, func, out_defs):
        rd_in = {}
        rd_out = {}
        try:
            blocks = list(self.iter_basic_blocks(func))
        except Exception:
            return rd_in
        gen = {}
        kill = {}
        for b in blocks:
            g = {}
            k = set()
            for head in idautils.Heads(b.start_ea, b.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                if mnem in self.a._mov_mnems() | {"mov"}:
                    try:
                        dst_type = idc.get_operand_type(head, 0)
                    except Exception:
                        dst_type = idc.o_void
                    if dst_type == idc.o_reg:
                        reg = idc.print_operand(head, 0).lower()
                        g.setdefault(reg, set()).add(head)
                        k.add(reg)
            gen[b.id] = g
            kill[b.id] = k
            rd_in[b.id] = {}
            rd_out[b.id] = {k: set(v) for k, v in g.items()}
        changed = True
        while changed:
            changed = False
            for b in blocks:
                in_set = {}
                for p in b.preds():
                    out_p = rd_out.get(p.id, {})
                    for reg, defs in out_p.items():
                        in_set.setdefault(reg, set()).update(defs)
                out_set = {k: set(v) for k, v in gen[b.id].items()}
                for reg, defs in in_set.items():
                    if reg in kill[b.id]:
                        continue
                    out_set.setdefault(reg, set()).update(defs)
                if rd_in[b.id] != in_set or rd_out[b.id] != out_set:
                    rd_in[b.id] = in_set
                    rd_out[b.id] = out_set
                    changed = True
        return rd_in


class TaintMovement:
    def __init__(self, analyzer):
        self.a = analyzer

    def track_mov(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str):
        try:
            dst_type = op_type(ea, 0)
            src_type = op_type(ea, 1)
        except Exception:
            return
        if dst_type == idc.o_reg:
            self._mov_to_reg(ea, func_ea, regs, mem, src_type, op_str)
        if dst_type in [idc.o_displ, idc.o_mem] and src_type == idc.o_reg:
            self._mov_to_mem(ea, func_ea, regs, mem, op_str)

    def _mov_to_reg(self, ea: int, func_ea: int, regs: dict, mem: dict, src_type, op_str):
        dst_reg = op_str(ea, 0).lower()
        if not dst_reg:
            return
        if src_type == idc.o_reg:
            src_reg = op_str(ea, 1).lower()
            if not src_reg:
                return
            if src_reg in regs:
                source, conf = regs[src_reg]
                regs[dst_reg] = (source, conf * 0.95)
                self.a.taint_kinds_regs.setdefault(func_ea, {})[dst_reg] = \
                    self.a.taint_kinds_regs.get(func_ea, {}).get(src_reg, "ptr")
                arg_regs = abi.arg_registers()
                if src_reg in arg_regs and dst_reg in arg_regs:
                    self.a.interprocedural.record_arg_to_arg(func_ea, src_reg, dst_reg)
        elif src_type in [idc.o_displ, idc.o_mem]:
            mem_key = self.a._mem_key(ea, 1, op_str)
            if mem_key and mem_key in mem:
                source, conf = mem[mem_key]
                regs[dst_reg] = (source, conf * 0.9)
                self.a.taint_kinds_regs.setdefault(func_ea, {})[dst_reg] = \
                    self.a.taint_kinds_mem.get(func_ea, {}).get(mem_key, "ptr")

    def _mov_to_mem(self, ea: int, func_ea: int, regs: dict, mem: dict, op_str):
        src_reg = op_str(ea, 1).lower()
        if src_reg in regs:
            mem_key = self.a._mem_key(ea, 0, op_str)
            if mem_key:
                mem[mem_key] = regs[src_reg]
                self.a.taint_kinds_mem.setdefault(func_ea, {})[mem_key] = \
                    self.a.taint_kinds_regs.get(func_ea, {}).get(src_reg, "ptr")
            arg_idx = self.a._arg_reg_index(src_reg)
            if arg_idx is not None and self.a._func_arg_is_ptr(func_ea, arg_idx):
                self.a.interprocedural.record_arg_to_mem(func_ea, src_reg)


class StackTaint:
    def __init__(self, analyzer):
        self.a = analyzer

    def track_stack(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str):
        mnem = idc.print_insn_mnem(ea).lower()
        if not hasattr(self.a, '_lifo_stacks'):
            self.a._lifo_stacks = {}
        lifo = self.a._lifo_stacks.setdefault(func_ea, [])
        if mnem == "push":
            self._handle_push(ea, func_ea, regs, mem, op_type, op_str, lifo)
        elif mnem == "pop":
            self._handle_pop(ea, func_ea, regs, mem, op_type, op_str, lifo)

    def _handle_push(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str, lifo):
        opt = op_type(ea, 0)
        if opt == idc.o_reg:
            reg = op_str(ea, 0).lower()
            if reg in regs:
                if self.a._has_get_sp_val:
                    sp = idc.get_sp_val(ea)
                    if sp != idc.BADADDR:
                        mem[sp] = regs[reg]
                        self.a.taint_kinds_mem.setdefault(func_ea, {})[sp] = \
                            self.a.taint_kinds_regs.get(func_ea, {}).get(reg, "ptr")
                else:
                    lifo.append(regs[reg])

    def _handle_pop(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str, lifo):
        opt = op_type(ea, 0)
        if opt == idc.o_reg:
            reg_name = op_str(ea, 0).lower()
            if self.a._has_get_sp_val:
                sp = idc.get_sp_val(ea)
                if sp != idc.BADADDR and sp in mem:
                    regs[reg_name] = mem[sp]
                    self.a.taint_kinds_regs.setdefault(func_ea, {})[reg_name] = \
                        self.a.taint_kinds_mem.get(func_ea, {}).get(sp, "ptr")
            else:
                if lifo:
                    regs[reg_name] = lifo.pop()


class ArithmeticTaint:
    def __init__(self, analyzer):
        self.a = analyzer

    def track_arithmetic(self, ea: int, func_ea: int, regs: dict, op_type, op_str):
        dst_type = op_type(ea, 0)
        if dst_type != idc.o_reg:
            return
        dst_reg = op_str(ea, 0).lower()
        for i in range(1, 3):
            opt = op_type(ea, i)
            if opt == idc.o_reg:
                src_reg = op_str(ea, i).lower()
                if src_reg in regs:
                    source, conf = regs[src_reg]
                    regs[dst_reg] = (source, conf * 0.9)
                    self.a.taint_kinds_regs.setdefault(func_ea, {})[dst_reg] = \
                        self.a.taint_kinds_regs.get(func_ea, {}).get(src_reg, "ptr")
                    break


class RegisterForwardTracker:
    def __init__(self, analyzer):
        self.a = analyzer

    def track(self, start_ea: int, reg: str, source: int):
        func = ida_funcs.get_func(start_ea)
        if not func:
            return
        ea = idc.next_head(start_ea)
        depth = 0
        max_depth = self.a._max_depth_override or self.a.max_taint_depth
        while ea < func.end_ea and depth < max_depth:
            mnem = idc.print_insn_mnem(ea).lower()
            for i in range(2):
                op_type = idc.get_operand_type(ea, i)
                if op_type == idc.o_reg:
                    op_reg = idc.print_operand(ea, i).lower()
                    if op_reg == reg:
                        if mnem in ["call", "jmp"] and i == 0:
                            target = self.a._resolve_register_value(ea, reg)
                            if target and self.a.is_valid_reference(target):
                                self.a.add_xref(source, target, "tainted_indirect_call", 0.8)
                            if self.a.jump_table_taint:
                                for tgt in self.a._resolve_switch_targets(ea, func):
                                    if self.a.is_valid_reference(tgt):
                                        self.a.add_xref(source, tgt, "tainted_indirect_call", 0.7)
                        break
            ea = idc.next_head(ea)
            depth += 1


class RegisterResolver:
    def __init__(self, analyzer):
        self.a = analyzer

    def resolve_immediate(self, ea: int, reg: str) -> Optional[int]:
        res = scan_back_for_reg_source(
            ea,
            str(reg).lower(),
            max_back=self.a.register_resolve_back_depth,
            mnems=("mov",),
        )
        if not res:
            return None
        _prev_ea, src_type, src_val = res
        if src_type == idc.o_imm:
            return src_val
        return None


class ArgumentTaintChecker:
    def __init__(self, analyzer):
        self.a = analyzer

    def check(self, call_ea: int) -> Optional[Tuple[int, float, str]]:
        func = ida_funcs.get_func(call_ea)
        if not func or func.start_ea not in self.a.tainted_regs:
            return None
        arg_regs = self.a._get_call_arg_regs(call_ea)
        for idx, reg_name in enumerate(arg_regs):
            if reg_name in self.a.tainted_regs[func.start_ea]:
                if self.a.cf_sensitive_sinks and not self.a._is_reg_tainted_near_call(call_ea, reg_name, func):
                    continue
                kind = self.a.taint_kinds_regs.get(func.start_ea, {}).get(reg_name, "ptr")
                source_ea, conf = self.a.tainted_regs[func.start_ea][reg_name]
                exp_kind = self.a._expected_arg_kind(call_ea, idx)
                if exp_kind and exp_kind != kind:
                    conf *= 0.85
                if kind == "ptr" and self.a._arg_points_to_string(call_ea, reg_name):
                    kind = "string"
                    conf = min(1.0, conf * 1.1)
                return source_ea, conf, kind
        return None


class StackArgScanner:
    def __init__(self, analyzer):
        self.a = analyzer

    def scan(self, call_ea: int, func, reg_arg_count: int) -> Optional[Tuple[int, float]]:
        max_back = self.a.stack_arg_scan_max_back
        win64 = (abi.calling_convention() == 'win64')
        win_slots = set(self.a.stack_arg_win_slots or [0, 8, 16, 24])
        shadow_size = 0
        if reg_arg_count >= len(abi.arg_registers()):
            return None
        ea = call_ea
        for _ in range(max_back):
            ea = idc.prev_head(ea)
            if ea == idc.BADADDR or ea < func.start_ea:
                break
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem == 'sub':
                d0 = idc.get_operand_type(ea, 0)
                d1 = idc.get_operand_type(ea, 1)
                if d0 == idc.o_reg and d1 == idc.o_imm:
                    if idc.print_operand(ea, 0).lower() in ('rsp', 'esp'):
                        try:
                            shadow_size = int(idc.get_operand_value(ea, 1))
                        except Exception:
                            shadow_size = 0
            if mnem == 'mov':
                dst_type = idc.get_operand_type(ea, 0)
                src_type = idc.get_operand_type(ea, 1)
                if dst_type == idc.o_displ:
                    op = idc.print_operand(ea, 0).lower()
                    if op.startswith('[rsp+') or op.startswith('[esp+'):
                        try:
                            off_str = op.split('+', 1)[1].rstrip(']')
                            off = int(off_str, 0) if off_str.startswith('0x') or off_str.isdigit() else -1
                        except Exception:
                            off = -1
                        accept_win64 = (off in win_slots) or (shadow_size and 0 <= off < shadow_size and off % 8 == 0)
                        if off >= 0 and ((not win64) or accept_win64):
                            if src_type == idc.o_reg:
                                src_reg = idc.print_operand(ea, 1).lower()
                                if src_reg in self.a.tainted_regs.get(func.start_ea, {}):
                                    return self.a.tainted_regs[func.start_ea][src_reg]
                            if src_type == idc.o_imm:
                                val = idc.get_operand_value(ea, 1)
                                if self.a.is_valid_reference(val):
                                    return (ea, 0.5)
            if mnem == 'push':
                op_type = idc.get_operand_type(ea, 0)
                if op_type == idc.o_reg:
                    src_reg = idc.print_operand(ea, 0).lower()
                    if src_reg in self.a.tainted_regs.get(func.start_ea, {}):
                        return self.a.tainted_regs[func.start_ea][src_reg]
                elif op_type == idc.o_imm:
                    val = idc.get_operand_value(ea, 0)
                    if self.a.is_valid_reference(val):
                        return (ea, 0.5)
        return None


class ReturnValueTracker:
    def __init__(self, analyzer):
        self.a = analyzer

    def get_return_value(self, ret_ea: int, func_ea: int) -> Optional[Tuple[int, float]]:
        ea = idc.prev_head(ret_ea)
        depth = 0
        while ea >= func_ea and depth < self.a.return_value_back_depth:
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem == "mov":
                dst_type = idc.get_operand_type(ea, 0)
                if dst_type == idc.o_reg:
                    dst_reg = idc.print_operand(ea, 0).lower()
                    ret_reg = abi.return_reg()
                    if dst_reg == ret_reg:
                        src_type = idc.get_operand_type(ea, 1)
                        if src_type == idc.o_imm:
                            value = idc.get_operand_value(ea, 1)
                            if self.a.is_valid_reference(value):
                                return (value, 0.9)
                        break
            ea = idc.prev_head(ea)
            depth += 1
        return None

    def check_return_usage(self, call_ea: int, called_func: int) -> Optional[Tuple[int, float]]:
        ea = idc.next_head(call_ea)
        depth = 0
        func = ida_funcs.get_func(call_ea)
        if not func or called_func not in self.a.return_values:
            return None
        ret_value, ret_conf = self.a.return_values[called_func]
        while ea < func.end_ea and depth < self.a.return_value_forward_depth:
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem == "call":
                op_type = idc.get_operand_type(ea, 0)
                if op_type == idc.o_reg:
                    op_reg = idc.print_operand(ea, 0).lower()
                    ret_reg = abi.return_reg()
                    if op_reg == ret_reg:
                        return (ret_value, ret_conf * 0.85)
            ea = idc.next_head(ea)
            depth += 1
        return None
