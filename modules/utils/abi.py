"""
ABI/Calling convention utilities for IDA 9.1+
Detects platform and exposes argument/return register sets
"""

from typing import List
import ida_ida
import ida_loader


def is_64bit() -> bool:
    return bool(ida_ida.inf_is_64bit())


def procname() -> str:
    return ida_ida.inf_get_procname().lower()


def platform() -> str:
    """Return 'windows' | 'linux' | 'mac' | 'unknown' based on file type."""
    try:
        ftn = ida_loader.get_file_type_name().lower()
    except AttributeError:
        # Fallback for older IDA versions or API changes
        try:
            import ida_nalt
            ftn = ida_nalt.get_file_type_name().lower()
        except (AttributeError, ImportError):
            # If both fail, try to determine from other sources
            try:
                import idaapi
                ftn = idaapi.get_file_type_name().lower()
            except (AttributeError, ImportError):
                return 'unknown'
    
    if 'pe' in ftn or 'portable executable' in ftn:
        return 'windows'
    if 'elf' in ftn:
        return 'linux'
    if 'mach-o' in ftn or 'mach-o' in ftn:
        return 'mac'
    return 'unknown'


def calling_convention() -> str:
    arch = procname()
    plat = platform()
    if 'arm' in arch:
        return 'aarch64' if is_64bit() else 'arm'
    if is_64bit():
        return 'win64' if plat == 'windows' else 'sysv64'
    return 'cdecl'


def return_reg() -> str:
    arch = procname()
    if 'arm' in arch:
        return 'x0' if is_64bit() else 'r0'
    return 'rax' if is_64bit() else 'eax'


def arg_registers() -> List[str]:
    arch = procname()
    cc = calling_convention()
    if 'arm' in arch:
        return ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'] if is_64bit() else ['r0', 'r1', 'r2', 'r3']
    if cc == 'win64':
        return ['rcx', 'rdx', 'r8', 'r9']
    if cc == 'sysv64':
        return ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    # 32-bit cdecl: arguments on stack
    return []

