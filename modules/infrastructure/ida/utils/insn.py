"""Instruction-level helpers."""
from typing import Optional, Tuple, Iterable
import idc


def mnem_cached(ea: int, cache: Optional[dict]) -> str:
    if cache is None:
        return idc.print_insn_mnem(ea).lower()
    if ea in cache:
        return cache[ea]
    val = idc.print_insn_mnem(ea).lower()
    cache[ea] = val
    return val


def extract_bracket_base_offset(op_str: str):
    """Extract base register and offset from strings like '[reg, #0x10]' or '[reg+0x10]'."""
    lower = op_str.lower().strip()
    if "[" not in lower or "]" not in lower:
        return None, None
    inner = lower.split("[", 1)[1].split("]", 1)[0]
    inner = inner.replace("#", "").replace(" ", "")
    if "+" in inner:
        base, off = inner.split("+", 1)
        try:
            return base, int(off, 0)
        except Exception:
            return base, None
    if "," in inner:
        parts = inner.split(",", 1)
        base = parts[0]
        try:
            return base, int(parts[1], 0)
        except Exception:
            return base, None
    return inner, 0


def has_mem_bracket(op_str: str) -> bool:
    lower = op_str.lower()
    return "[" in lower and "]" in lower


def scan_back(ea: int, max_back: int = 6, mnems: Optional[Iterable[str]] = None):
    """Yield (ea, mnem) scanning backwards up to max_back instructions."""
    cur = ea
    for _ in range(max_back):
        cur = idc.prev_head(cur)
        if cur == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur).lower()
        if mnems is None or mnem in mnems:
            yield cur, mnem


def scan_back_for_reg_source(call_ea: int, reg: str, max_back: int = 6, mnems=("mov", "lea")) -> Optional[Tuple[int, int, int]]:
    """Scan backwards for the last assignment to reg via mov/lea.

    Returns (ea, src_type, src_val) for the first match.
    """
    for ea, _mnem in scan_back(call_ea, max_back=max_back, mnems=mnems):
        try:
            dst_type = idc.get_operand_type(ea, 0)
            src_type = idc.get_operand_type(ea, 1)
        except Exception:
            continue
        if dst_type == idc.o_reg and idc.print_operand(ea, 0).lower() == reg:
            try:
                src_val = idc.get_operand_value(ea, 1)
            except Exception:
                src_val = None
            return ea, src_type, src_val
    return None
