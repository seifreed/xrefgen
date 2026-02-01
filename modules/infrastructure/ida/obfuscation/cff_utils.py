"""Helpers for control-flow flattening pattern parsing."""
import idc


def is_compare_mnem(mnem: str) -> bool:
    return mnem in ("cmp", "test")


def is_cond_jump_mnem(mnem: str) -> bool:
    return mnem in ("je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns")


def is_indirect_jump(ea: int) -> bool:
    op_type = idc.get_operand_type(ea, 0)
    return op_type in (idc.o_mem, idc.o_displ)


def is_state_var_compare(ea: int) -> bool:
    op1_type = idc.get_operand_type(ea, 0)
    return op1_type in (idc.o_reg, idc.o_displ)


def is_reg_assignment(ea: int, reg_id: int) -> bool:
    dst_type = idc.get_operand_type(ea, 0)
    if dst_type != idc.o_reg:
        return False
    return idc.get_operand_value(ea, 0) == reg_id


def imm_assignment_value(ea: int):
    src_type = idc.get_operand_type(ea, 1)
    if src_type == idc.o_imm:
        return idc.get_operand_value(ea, 1)
    return None
