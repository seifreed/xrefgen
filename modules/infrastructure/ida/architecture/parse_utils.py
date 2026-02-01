"""Operand parsing helpers for architecture-specific analysis."""
from typing import Optional
import idc
import ida_segment
from modules.infrastructure.ida.utils.insn import extract_bracket_base_offset


def parse_gp_offset(op_str: str) -> Optional[int]:
    lower = op_str.lower()
    if "$gp" not in lower:
        return None
    try:
        offset_str = op_str.split("(")[0].strip()
        if offset_str in ("", "0"):
            return 0
        return int(offset_str, 0)
    except Exception:
        return None


def operand_str(ea: int, idx: int) -> str:
    try:
        return idc.print_operand(ea, idx)
    except Exception:
        return ""


def is_in_segment(ea: int, substr: str) -> bool:
    try:
        seg = ida_segment.getseg(ea)
        if not seg:
            return False
        name = idc.get_segm_name(seg.start_ea).lower()
        return substr in name
    except Exception:
        return False


def segment_name(ea: int) -> str:
    try:
        seg = ida_segment.getseg(ea)
        if not seg:
            return ""
        return idc.get_segm_name(seg.start_ea).lower()
    except Exception:
        return ""


def is_rip_relative(op_str: str) -> bool:
    return "rip" in op_str.lower()


def has_reg(op_str: str, reg: str) -> bool:
    return reg.lower() in op_str.lower()


def is_got_access(op_str: str) -> bool:
    lower = op_str.lower()
    return "$gp" in lower or "%got" in lower


def has_mem_bracket(op_str: str) -> bool:
    lower = op_str.lower()
    return "[" in lower and "]" in lower


def has_mem_offset(op_str: str) -> bool:
    base, off = extract_bracket_base_offset(op_str)
    return base is not None and off is not None
