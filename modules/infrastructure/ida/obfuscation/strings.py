"""Encrypted string detection helpers."""

from typing import List, Tuple, Optional
import idautils
import ida_funcs
import idc
import ida_bytes
from modules.infrastructure.ida.base import IDAXrefAnalyzer
from modules.infrastructure.ida.utils.insn import scan_back, mnem_cached
from modules.infrastructure.ida.obfuscation.string_utils import (
    bytes_map_to_bytes,
    add_imm_to_map,
    extract_mem_offset,
    looks_like_utf16le,
    looks_like_utf16be,
    printable_ratio,
)


class EncryptedStringDetector:
    def __init__(self, analyzer: IDAXrefAnalyzer):
        self.analyzer = analyzer
        self.encrypted_strings = {}
        self.decryption_functions = set()
        self._decrypt_funcs_built = False
        self._seen_normalized = set()
        if not hasattr(self.analyzer, "string_map"):
            self.analyzer.string_map = {}

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for _func_ea, func in self._iter_functions():
            results.extend(self.analyze_function(func))
        return results

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        results = []
        if not self._decrypt_funcs_built:
            self._find_decryption_functions()
            self._decrypt_funcs_built = True
        mnem_cache = {}
        encrypted_refs = self._find_encrypted_string_refs(func, mnem_cache)
        for source, string_addr, decrypted in encrypted_refs:
            if decrypted:
                norm = self._normalize_string(decrypted)
                if norm in self._seen_normalized:
                    continue
                self._seen_normalized.add(norm)
                self.analyzer.add_xref(source, string_addr, "decrypted_string", 0.8)
                try:
                    self.analyzer.add_evidence(source, string_addr, "strings")
                except Exception:
                    pass
                results.append((source, string_addr, "decrypted_string", 0.8))
                self.encrypted_strings[string_addr] = norm
                self.analyzer.string_map[string_addr] = norm
        results.extend(self._find_stack_string_calls(func))
        results.extend(self._find_heap_string_calls(func))
        return results

    def _iter_functions(self):
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func

    def _find_decryption_functions(self):
        for func_ea, func in self._iter_functions():
            xor_count = 0
            loop_count = 0
            string_ops = 0
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                if mnem == "xor":
                    xor_count += 1
                elif mnem in ["loop", "loopne", "loope"]:
                    loop_count += 1
                elif mnem in ["movs", "stos", "lods", "scas"]:
                    string_ops += 1
                elif mnem in ["je", "jne", "jz", "jnz"]:
                    target = idc.get_operand_value(head, 0)
                    if target < head:
                        loop_count += 1
            if xor_count > 2 and (loop_count > 0 or string_ops > 0):
                self.decryption_functions.add(func_ea)

    def _find_encrypted_string_refs(self, func, mnem_cache: Optional[dict] = None) -> List[Tuple[int, int, Optional[str]]]:
        refs = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = mnem_cached(head, mnem_cache)
            if mnem == "call":
                target = idc.get_operand_value(head, 0)
                if target in self.decryption_functions:
                    string_arg = self._get_decryption_argument(head)
                    if string_arg:
                        decrypted = self._try_decrypt_string(string_arg)
                        refs.append((head, string_arg, decrypted))
            elif mnem == "xor":
                if self._is_string_xor(head):
                    string_addr = self._get_xor_string_address(head)
                    if string_addr:
                        decrypted = self._try_decrypt_inline(head, string_addr)
                        refs.append((head, string_addr, decrypted))
        return refs

    def _get_decryption_argument(self, call_ea: int) -> Optional[int]:
        for prev_ea, _mnem in scan_back(call_ea, max_back=5, mnems=("lea", "mov")):
            src_type = idc.get_operand_type(prev_ea, 1)
            if src_type in [idc.o_mem, idc.o_imm]:
                addr = idc.get_operand_value(prev_ea, 1)
                if ida_bytes.is_data(ida_bytes.get_flags(addr)):
                    return addr
        return None

    def _try_decrypt_string(self, string_addr: int) -> Optional[str]:
        encrypted = self._read_encrypted_bytes(string_addr)
        if not encrypted:
            return None
        return self._try_decrypt_algorithms(encrypted)

    def _read_encrypted_bytes(self, string_addr: int, max_len: int = 256) -> List[int]:
        encrypted: List[int] = []
        ea = string_addr
        for _ in range(max_len):
            byte = ida_bytes.get_byte(ea)
            if byte == 0:
                break
            encrypted.append(byte)
            ea += 1
        return encrypted

    def _try_decrypt_algorithms(self, encrypted: List[int]) -> Optional[str]:
        for decryptor in (self._try_single_byte_xor, self._try_rolling_xor, self._try_index_xor):
            result = decryptor(encrypted)
            if result:
                return result
        return None

    def _try_index_xor(self, encrypted: List[int]) -> Optional[str]:
        for key in range(1, 256):
            decrypted = []
            for i, b in enumerate(encrypted):
                decrypted.append(b ^ (key ^ (i & 0xFF)))
            decrypted_bytes = bytes(decrypted)
            if self._is_valid_string(decrypted_bytes):
                return self._decode_string(decrypted_bytes)
        return None

    def _try_single_byte_xor(self, encrypted: List[int]) -> Optional[str]:
        for key in range(1, 256):
            decrypted = bytes([b ^ key for b in encrypted])
            if self._is_valid_string(decrypted):
                return self._decode_string(decrypted)
        return None

    def _try_rolling_xor(self, encrypted: List[int]) -> Optional[str]:
        for key_start in range(1, 256):
            key = key_start
            decrypted = []
            for b in encrypted:
                decrypted.append(b ^ key)
                key = (key + 1) % 256
            decrypted_bytes = bytes(decrypted)
            if self._is_valid_string(decrypted_bytes):
                return self._decode_string(decrypted_bytes)
        return None

    def _is_valid_string(self, data: bytes) -> bool:
        if not data:
            return False
        if looks_like_utf16le(data):
            return True
        if printable_ratio(data) < 0.7:
            return False
        try:
            text = data.decode('utf-8', errors='ignore')
            if any(pattern in text.lower() for pattern in [
                'http', 'https', '.exe', '.dll', 'system', 'process',
                'file', 'registry', 'windows', 'program', 'error'
            ]):
                return True
            if '\\' in text or '/' in text or '.' in text:
                return True
        except Exception:
            pass
        return printable_ratio(data) == 1.0

    def _is_string_xor(self, ea: int) -> bool:
        op1_type = idc.get_operand_type(ea, 0)
        if op1_type in [idc.o_displ, idc.o_mem]:
            return True
        return False

    def _get_xor_string_address(self, xor_ea: int) -> Optional[int]:
        op_type = idc.get_operand_type(xor_ea, 0)
        if op_type == idc.o_mem:
            return idc.get_operand_value(xor_ea, 0)
        if op_type == idc.o_displ:
            return xor_ea
        return None

    def _try_decrypt_inline(self, xor_ea: int, string_addr: int) -> Optional[str]:
        op2_type = idc.get_operand_type(xor_ea, 1)
        if op2_type == idc.o_imm:
            key = idc.get_operand_value(xor_ea, 1)
            encrypted = []
            ea = string_addr
            for _ in range(256):
                byte = ida_bytes.get_byte(ea)
                if byte == 0:
                    break
                encrypted.append(byte ^ key)
                ea += 1
            if encrypted:
                decrypted = bytes(encrypted)
                if self._is_valid_string(decrypted):
                    return self._decode_string(decrypted)
        return None

    def _decode_string(self, data: bytes) -> str:
        if data.startswith(b"\xff\xfe"):
            data = data[2:]
        elif data.startswith(b"\xfe\xff"):
            data = data[2:]
        if looks_like_utf16le(data):
            try:
                return data.decode("utf-16le", errors="ignore")
            except Exception:
                pass
        if looks_like_utf16be(data):
            try:
                return data.decode("utf-16be", errors="ignore")
            except Exception:
                pass
        return data.decode("utf-8", errors="ignore")

    # Backward-compatible wrappers for tests/external callers
    def _looks_like_utf16le(self, data: bytes) -> bool:
        return looks_like_utf16le(data)

    def _looks_like_utf16be(self, data: bytes) -> bool:
        return looks_like_utf16be(data)

    def _normalize_string(self, text: str) -> str:
        text = text.replace("\x00", "")
        return text.strip()

    def _find_stack_string_calls(self, func) -> List[Tuple[int, int, str, float]]:
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem != "call":
                continue
            target = idc.get_operand_value(head, 0)
            s = self._extract_stack_string(head, func)
            if s and self.analyzer.is_valid_reference(target):
                self.analyzer.add_xref(head, target, "stack_string_arg", 0.6)
                try:
                    self.analyzer.add_evidence(head, target, "strings")
                except Exception:
                    pass
                results.append((head, target, "stack_string_arg", 0.6))
        return results

    def _find_heap_string_calls(self, func) -> List[Tuple[int, int, str, float]]:
        results = []
        ret_reg = "rax"
        try:
            import ida_ida
            ret_reg = "rax" if ida_ida.inf_is_64bit() else "eax"
        except Exception:
            pass
        alloc_names = ["malloc", "calloc", "HeapAlloc", "operator new"]
        copy_names = ["memcpy", "strcpy", "strncpy", "memmove"]
        last_alloc_ea = None
        bytes_map = {}
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "call":
                try:
                    target = idc.get_operand_value(head, 0)
                    name = idc.get_func_name(target).lower()
                except Exception:
                    name = ""
                if any(a in name for a in alloc_names):
                    last_alloc_ea = head
                    bytes_map = {}
                    continue
                if last_alloc_ea is not None:
                    # call uses heap string if ret_reg moved/pushed shortly before
                    if self._uses_register_as_arg(head, ret_reg) or any(c in name for c in copy_names):
                        data = bytes_map_to_bytes(bytes_map)
                        if data and self._is_valid_string(data):
                            self.analyzer.add_xref(head, target, "heap_string_arg", 0.6)
                            try:
                                self.analyzer.add_evidence(head, target, "strings")
                            except Exception:
                                pass
                            results.append((head, target, "heap_string_arg", 0.6))
                    last_alloc_ea = None
                    bytes_map = {}
            elif last_alloc_ea is not None:
                # collect stores into [ret_reg+off]
                if mnem == "mov":
                    dst_type = idc.get_operand_type(head, 0)
                    src_type = idc.get_operand_type(head, 1)
                    if dst_type == idc.o_displ and src_type == idc.o_imm:
                        dst = idc.print_operand(head, 0).lower()
                        if ret_reg in dst:
                            off = extract_mem_offset(dst)
                            if off is None:
                                continue
                            val = idc.get_operand_value(head, 1)
                            add_imm_to_map(bytes_map, off, val)
        return results

    def _uses_register_as_arg(self, call_ea: int, reg: str) -> bool:
        for ea, mnem in scan_back(call_ea, max_back=6):
            if mnem in ("mov", "lea"):
                dst = idc.print_operand(ea, 0).lower()
                src = idc.print_operand(ea, 1).lower()
                if reg in src and dst in ["rdi", "rsi", "rcx", "rdx", "r8", "r9", "ecx", "edx"]:
                    return True
            if mnem == "push":
                op = idc.print_operand(ea, 0).lower()
                if reg in op:
                    return True
        return False

    def _extract_stack_string(self, call_ea: int, func) -> Optional[str]:
        bytes_map = {}
        base_reg = None
        for ea, mnem in scan_back(call_ea, max_back=16, mnems=("mov", "lea")):
            if ea < func.start_ea:
                break
            if mnem == "lea":
                dst = idc.print_operand(ea, 0).lower()
                src = idc.print_operand(ea, 1).lower()
                if "[rsp+" in src or "[esp+" in src:
                    base_reg = dst
                continue
            dst_type = idc.get_operand_type(ea, 0)
            src_type = idc.get_operand_type(ea, 1)
            if dst_type != idc.o_displ or src_type != idc.o_imm:
                continue
            dst = idc.print_operand(ea, 0).lower()
            if "[rsp+" in dst or "[esp+" in dst or (base_reg and base_reg in dst):
                off = extract_mem_offset(dst)
                if off is None:
                    continue
                val = idc.get_operand_value(ea, 1)
                add_imm_to_map(bytes_map, off, val)
        if not bytes_map:
            return None
        data = bytes_map_to_bytes(bytes_map)
        if self._is_valid_string(data):
            return self._decode_string(data)
        return None
