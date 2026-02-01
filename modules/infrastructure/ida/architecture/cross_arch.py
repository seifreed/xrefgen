"""
Cross-Architecture Support Module
Handles architecture-specific patterns for ARM, MIPS, and WebAssembly
"""

from typing import Dict, List, Tuple, Optional
import idautils
import idc
import ida_funcs
import ida_bytes
import ida_segregs
from modules.infrastructure.ida.utils.insn import scan_back, extract_bracket_base_offset
from modules.infrastructure.ida.architecture.parse_utils import parse_gp_offset, is_in_segment, segment_name, is_rip_relative, is_got_access, has_mem_offset, has_reg, operand_str
try:
    import ida_ida
except ImportError:
    ida_ida = None
from modules.infrastructure.ida.performance.optimizer import IncrementalAnalyzer
from modules.infrastructure.ida.utils.insn import scan_back_for_reg_source

class CrossArchAnalyzer(IncrementalAnalyzer):
    """Architecture-specific xref analysis"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.supported_archs = config.get('architectures', 
            ['x86', 'x64', 'arm', 'arm64', 'mips', 'wasm'])
        
        # Detect current architecture
        self.arch = self._detect_architecture()
        # Get 64-bit flag (use new API when available)
        self.is_64bit = bool(ida_ida.inf_is_64bit())
        
        # Architecture-specific handlers
        self.arch_handlers = {
            'arm': self._analyze_arm,
            'arm64': self._analyze_arm64,
            'mips': self._analyze_mips,
            'wasm': self._analyze_wasm,
            'x86': self._analyze_x86,
            'x64': self._analyze_x64
        }

    def _iter_functions(self):
        """Yield (func_ea, func) for all valid functions."""
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func
        
    def get_name(self) -> str:
        return "CrossArchAnalyzer"
    
    def _detect_architecture(self) -> str:
        """Detect the current binary architecture"""
        # Try IDA 9.x API first, then fall back
        procname = ''
        is_64 = False
        procname = ida_ida.inf_get_procname().lower()
        is_64 = bool(ida_ida.inf_is_64bit())
        
        if 'arm' in procname:
            if is_64:
                return 'arm64'
            else:
                return 'arm'
        elif 'mips' in procname:
            return 'mips'
        elif 'wasm' in procname:
            return 'wasm'
        elif is_64:
            return 'x64'
        else:
            return 'x86'
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform architecture-specific analysis"""
        if self.arch not in self.supported_archs:
            print(f"[XrefGen] Architecture {self.arch} not in supported list")
            return []
        return super().analyze()

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        handler = self.arch_handlers.get(self.arch)
        if not handler:
            return []
        return handler(func)
    
    def _analyze_arm(self, func) -> List[Tuple[int, int, str, float]]:
        """ARM-specific analysis"""
        results = []
        results.extend(self._find_arm_indirect_calls(func))
        results.extend(self._find_arm_vtables(func))
        results.extend(self._find_arm_switch_tables(func))
            
        return results
    
    def _find_arm_indirect_calls(self, func) -> List[Tuple[int, int, str, float]]:
        """Find ARM indirect call patterns"""
        refs = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.GetDisasm(head)
            mnem = idc.print_insn_mnem(head).upper()
            
            # ARM indirect calls
            if mnem == "BLX":
                # Branch with link and exchange (indirect call)
                op_type = idc.get_operand_type(head, 0)
                if op_type == idc.o_reg:
                    # BLX register - indirect call
                    target = self._resolve_arm_register(head)
                    if target and self.is_valid_reference(target):
                        self.add_xref(head, target, "arm_blx_indirect", 0.85)
                        refs.append((head, target, "arm_blx_indirect", 0.85))
                        
            elif mnem == "BX":
                # Branch and exchange (indirect jump)
                op_type = idc.get_operand_type(head, 0)
                if op_type == idc.o_reg:
                    target = self._resolve_arm_register(head)
                    if target and self.is_valid_reference(target):
                        self.add_xref(head, target, "arm_bx_indirect", 0.85)
                        refs.append((head, target, "arm_bx_indirect", 0.85))
                        
            elif mnem == "LDR":
                # Load register - check for function pointer loads
                if "PC" in disasm:
                    # PC-relative load, common for function pointers
                    target = self._get_arm_ldr_target(head)
                    if target:
                        # Check if next instruction is BLX/BX
                        next_ea = idc.next_head(head)
                        if next_ea != idc.BADADDR:
                            next_mnem = idc.print_insn_mnem(next_ea).upper()
                            if next_mnem in ["BLX", "BX"]:
                                self.add_xref(head, target, "arm_ldr_pc_call", 0.8)
                                refs.append((head, target, "arm_ldr_pc_call", 0.8))
        
        return refs
    
    def _resolve_arm_register(self, ea: int) -> Optional[int]:
        """Resolve ARM register value at given address"""
        reg_name = idc.print_operand(ea, 0)

        def resolver(prev_ea: int, mnem: str) -> Optional[int]:
            if mnem == "ldr":
                return self._get_arm_ldr_target(prev_ea)
            if mnem in ["mov", "movw"]:
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_imm:
                    return idc.get_operand_value(prev_ea, 1)
            return None

        return self._resolve_register_via_backtrace(
            ea,
            reg_name,
            {"ldr", "mov", "movw", "movt"},
            resolver,
        )
    
    def _get_arm_ldr_target(self, ldr_ea: int) -> Optional[int]:
        """Get target address from ARM LDR instruction"""
        # Parse LDR instruction for PC-relative or literal pool access
        op_type = idc.get_operand_type(ldr_ea, 1)
        
        if op_type == idc.o_mem:
            # Direct memory reference
            return idc.get_operand_value(ldr_ea, 1)
        elif op_type == idc.o_displ:
            # Displacement - calculate effective address
            base = idc.get_operand_value(ldr_ea, 1)
            # In ARM, PC-relative addressing uses PC+8 in ARM mode, PC+4 in Thumb
            if self._is_thumb_mode(ldr_ea):
                pc_offset = 4
            else:
                pc_offset = 8
            
            effective_addr = ldr_ea + pc_offset + base
            
            # Read the value at this address
            value = idc.get_wide_dword(effective_addr)
            if value and self.is_valid_reference(value):
                return value
        
        return None
    
    def _is_thumb_mode(self, ea: int) -> bool:
        """Check if address is in Thumb mode"""
        # Check the T flag in the status register
        sreg_val = ida_segregs.get_sreg(ea, ida_segregs.sr_t)
        return sreg_val == 1
    
    def _find_arm_vtables(self, func) -> List[Tuple[int, int, str, float]]:
        """Find ARM virtual table calls"""
        refs = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).upper()
            
            # Look for vtable access pattern:
            # LDR R0, [R1, #offset] ; Load vtable entry
            # BLX R0                ; Call virtual function
            
            if mnem == "LDR":
                op_str = operand_str(head, 1)
                if has_mem_offset(op_str):
                    # Potential vtable access
                    next_ea = head
                    for _ in range(3):
                        next_ea = idc.next_head(next_ea)
                        if next_ea == idc.BADADDR:
                            break
                        
                        next_mnem = idc.print_insn_mnem(next_ea).upper()
                        if next_mnem == "BLX":
                            # Found vtable call pattern
                            # Try to resolve vtable entry
                            vtable_entry = self._resolve_arm_vtable_entry(head)
                            if vtable_entry:
                                self.add_xref(next_ea, vtable_entry, "arm_vtable_call", 0.75)
                                refs.append((next_ea, vtable_entry, "arm_vtable_call", 0.75))
                            break
        
        return refs
    
    def _resolve_arm_vtable_entry(self, ldr_ea: int) -> Optional[int]:
        """Resolve ARM vtable entry address"""
        op_str = operand_str(ldr_ea, 1)
        base_reg, offset = extract_bracket_base_offset(op_str)
        if base_reg and offset is not None:
            base_value = self._find_register_value(ldr_ea, base_reg)
            if base_value:
                entry_addr = base_value + offset
                func_ptr = idc.get_wide_dword(entry_addr)
                if func_ptr and self.is_valid_reference(func_ptr):
                    return func_ptr
        
        return None
    
    def _find_register_value(self, ea: int, reg_name: str) -> Optional[int]:
        """Find value loaded into a register"""
        mnems = {"ldr", "mov", "movw", "adr"}
        for prev_ea, mnem in scan_back(ea, max_back=20, mnems=mnems):
            dst = idc.print_operand(prev_ea, 0)
            if dst.upper() == reg_name.upper():
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_imm:
                    return idc.get_operand_value(prev_ea, 1)
                if mnem == "adr":
                    return idc.get_operand_value(prev_ea, 1)
        return None
    
    def _find_arm_switch_tables(self, func) -> List[Tuple[int, int, str, float]]:
        """Find ARM switch table implementations"""
        refs = []
        
        # ARM switch tables often use TBB/TBH instructions or computed jumps
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).upper()
            
            if mnem in ["TBB", "TBH"]:
                # Table branch instructions
                table_base = self._get_arm_table_base(head)
                if table_base:
                    # Read table entries
                    entry_size = 1 if mnem == "TBB" else 2
                    for i in range(256):  # Max table size
                        entry_addr = table_base + (i * entry_size)
                        
                        if entry_size == 1:
                            offset = ida_bytes.get_byte(entry_addr)
                        else:
                            offset = ida_bytes.get_word(entry_addr)
                        
                        if offset == 0:
                            break  # End of table
                        
                        # Calculate target
                        target = head + 4 + (offset * 2)  # Thumb mode
                        if self.is_valid_reference(target) and func.start_ea <= target < func.end_ea:
                            self.add_xref(head, target, f"arm_switch_case_{i}", 0.9)
                            refs.append((head, target, f"arm_switch_case_{i}", 0.9))
        
        return refs
    
    def _get_arm_table_base(self, tbb_ea: int) -> Optional[int]:
        """Get base address of ARM switch table"""
        op_str = operand_str(tbb_ea, 0)
        base_reg, _offset = extract_bracket_base_offset(op_str)
        if base_reg:
            return self._find_register_value(tbb_ea, base_reg)
        
        return None
    
    def _analyze_arm64(self, func) -> List[Tuple[int, int, str, float]]:
        """ARM64/AArch64-specific analysis"""
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in ["br", "blr"]:
                op_type = idc.get_operand_type(head, 0)
                if op_type == idc.o_reg:
                    target = self._resolve_arm64_register(head)
                    if target and self.is_valid_reference(target):
                        xref_type = "arm64_blr" if mnem == "blr" else "arm64_br"
                        self.add_xref(head, target, xref_type, 0.85)
                        results.append((head, target, xref_type, 0.85))
            elif mnem == "adrp":
                page_addr = idc.get_operand_value(head, 1)
                next_ea = idc.next_head(head)
                if next_ea != idc.BADADDR:
                    next_mnem = idc.print_insn_mnem(next_ea).lower()
                    if next_mnem == "add":
                        if idc.get_operand_type(next_ea, 2) != idc.o_void:
                            offset = idc.get_operand_value(next_ea, 2)
                            full_addr = page_addr + offset
                            if self.is_valid_reference(full_addr):
                                self.add_xref(head, full_addr, "arm64_adrp_add", 0.9)
                                results.append((head, full_addr, "arm64_adrp_add", 0.9))
        
        return results
    
    def _resolve_arm64_register(self, ea: int) -> Optional[int]:
        """Resolve ARM64 register value"""
        reg_name = idc.print_operand(ea, 0)

        def resolver(prev_ea: int, mnem: str) -> Optional[int]:
            if mnem == "ldr":
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_mem:
                    addr = idc.get_operand_value(prev_ea, 1)
                    value = idc.get_qword(addr)
                    if value and self.is_valid_reference(value):
                        return value
            if mnem in ["mov", "movz"]:
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_imm:
                    return idc.get_operand_value(prev_ea, 1)
            if mnem in ["adr", "adrp"]:
                return idc.get_operand_value(prev_ea, 1)
            return None

        return self._resolve_register_via_backtrace(
            ea,
            reg_name,
            {"ldr", "mov", "movz", "movk", "adr", "adrp"},
            resolver,
        )
    
    def _analyze_mips(self, func) -> List[Tuple[int, int, str, float]]:
        """MIPS-specific analysis"""
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "jalr":
                op_type = idc.get_operand_type(head, 0)
                if op_type == idc.o_reg:
                    target = self._resolve_mips_register(head)
                    if target and self.is_valid_reference(target):
                        self.add_xref(head, target, "mips_jalr", 0.85)
                        results.append((head, target, "mips_jalr", 0.85))
                    delay_slot = idc.next_head(head)
                    if delay_slot != idc.BADADDR:
                        self.add_xref(delay_slot, target, "mips_delay_slot", 0.7)
            elif mnem == "jr":
                op_type = idc.get_operand_type(head, 0)
                if op_type == idc.o_reg:
                    reg_name = idc.print_operand(head, 0)
                    if reg_name != "$ra":
                        target = self._resolve_mips_register(head)
                        if target and self.is_valid_reference(target):
                            self.add_xref(head, target, "mips_jr", 0.85)
                            results.append((head, target, "mips_jr", 0.85))
            elif mnem in ["lw", "la"]:
                if self._is_mips_got_access(head):
                    target = self._resolve_mips_got_entry(head)
                    if target:
                        self.add_xref(head, target, "mips_got_ref", 0.8)
                        results.append((head, target, "mips_got_ref", 0.8))
            elif mnem in ["jal", "jalr"]:
                # Prefer PLT calls if in .plt
                target = idc.get_operand_value(head, 0)
                if self._is_plt_address(target):
                    self.add_xref(head, target, "mips_plt_call", 0.7)
                    results.append((head, target, "mips_plt_call", 0.7))
        
        return results
    
    def _resolve_mips_register(self, ea: int) -> Optional[int]:
        """Resolve MIPS register value"""
        # MIPS often uses LUI/ADDIU or LUI/ORI pairs for addresses
        lui_value = None
        mnems = {"lui", "addiu", "ori", "lw", "ld"}
        target_reg = idc.print_operand(ea, 0)
        for prev_ea, mnem in scan_back(ea, max_back=10, mnems=mnems):
            if mnem == "lui":
                dst = idc.print_operand(prev_ea, 0)
                if dst == target_reg:
                    lui_value = idc.get_operand_value(prev_ea, 1) << 16
            elif mnem in ("addiu", "ori") and lui_value is not None:
                dst = idc.print_operand(prev_ea, 0)
                if dst == target_reg and idc.get_operand_type(prev_ea, 2) != idc.o_void:
                    low_value = idc.get_operand_value(prev_ea, 2)
                    full_value = lui_value | low_value
                    if self.is_valid_reference(full_value):
                        return full_value
            elif mnem in ("lw", "ld"):
                dst = idc.print_operand(prev_ea, 0)
                if dst == target_reg:
                    src_type = idc.get_operand_type(prev_ea, 1)
                    if src_type == idc.o_mem:
                        addr = idc.get_operand_value(prev_ea, 1)
                        value = idc.get_wide_dword(addr) if mnem == "lw" else idc.get_qword(addr)
                        if value and self.is_valid_reference(value):
                            return value
        return None
    
    def _is_mips_got_access(self, ea: int) -> bool:
        """Check if instruction accesses MIPS GOT"""
        op_str = operand_str(ea, 1)
        # GOT access patterns: offset($gp), %got(symbol)
        return is_got_access(op_str)
    
    def _resolve_mips_got_entry(self, ea: int) -> Optional[int]:
        """Resolve MIPS GOT entry"""
        # Parse GOT offset
        op_str = operand_str(ea, 1)
        offset = parse_gp_offset(op_str)
        if offset is not None:
            gp_value = self._get_mips_gp_value()
            if gp_value:
                got_entry = gp_value + offset
                value = idc.get_wide_dword(got_entry)
                if value and self.is_valid_reference(value):
                    return value
        
        return None
    
    def _get_mips_gp_value(self) -> Optional[int]:
        """Get MIPS global pointer value"""
        # This would require proper MIPS ABI analysis
        # Simplified: look for .got section
        for seg_ea in idautils.Segments():
            if ".got" in segment_name(seg_ea):
                return seg_ea
        return None

    def _is_plt_address(self, ea: int) -> bool:
        return is_in_segment(ea, ".plt")
    
    def _analyze_wasm(self, func) -> List[Tuple[int, int, str, float]]:
        """WebAssembly-specific analysis"""
        results = []
        
        # WebAssembly has different instruction model
        # Function calls are via call_indirect instruction
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.GetDisasm(head).lower()
            if "call_indirect" in disasm:
                table_idx = self._get_wasm_table_index(head)
                if table_idx is not None:
                    target = self._resolve_wasm_table_entry(table_idx)
                    if target:
                        self.add_xref(head, target, "wasm_call_indirect", 0.8)
                        results.append((head, target, "wasm_call_indirect", 0.8))
            elif "br_table" in disasm:
                targets = self._get_wasm_br_table_targets(head)
                for i, target in enumerate(targets):
                    if self.is_valid_reference(target):
                        self.add_xref(head, target, f"wasm_br_table_{i}", 0.85)
                        results.append((head, target, f"wasm_br_table_{i}", 0.85))
        
        return results
    
    def _get_wasm_table_index(self, ea: int) -> Optional[int]:
        """Get WebAssembly table index from call_indirect"""
        # Parse WASM bytecode for table index
        # Simplified implementation
        return 0  # Would need proper WASM decoder
    
    def _resolve_wasm_table_entry(self, idx: int) -> Optional[int]:
        """Resolve WebAssembly table entry"""
        # Would need to parse WASM table section
        return None
    
    def _get_wasm_br_table_targets(self, ea: int) -> List[int]:
        """Get WebAssembly br_table targets"""
        # Would need to parse WASM br_table instruction
        return []
    
    def _analyze_x86(self, func) -> List[Tuple[int, int, str, float]]:
        """x86-specific analysis (32-bit)"""
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "call":
                if self._is_x86_thiscall(head):
                    target = self._resolve_x86_thiscall(head)
                    if target:
                        self.add_xref(head, target, "x86_thiscall", 0.8)
                        results.append((head, target, "x86_thiscall", 0.8))
            elif self._is_x86_fastcall(head):
                target = idc.get_operand_value(head, 0)
                if self.is_valid_reference(target):
                    self.add_xref(head, target, "x86_fastcall", 0.85)
                    results.append((head, target, "x86_fastcall", 0.85))
        
        return results
    
    def _is_x86_thiscall(self, call_ea: int) -> bool:
        """Check if call uses thiscall convention"""
        # Look for ECX being set before call
        return bool(scan_back_for_reg_source(call_ea, "ecx", max_back=5, mnems=("mov",)))
    
    def _resolve_x86_thiscall(self, call_ea: int) -> Optional[int]:
        """Resolve thiscall vtable call"""
        # Look for pattern: mov ecx, object; call [ecx+offset]
        op_type = idc.get_operand_type(call_ea, 0)
        if op_type == idc.o_displ:
            # Call through vtable
            op_str = idc.print_operand(call_ea, 0)
            if has_reg(op_str, "ecx"):
                _base, offset = extract_bracket_base_offset(op_str)
                if offset is not None:
                    return None  # Simplified

        return None
    
    def _is_x86_fastcall(self, ea: int) -> bool:
        """Check if using fastcall convention"""
        # Look for ECX and EDX being set before call
        ecx_set = scan_back_for_reg_source(ea, "ecx", max_back=10, mnems=("mov",)) is not None
        edx_set = scan_back_for_reg_source(ea, "edx", max_back=10, mnems=("mov",)) is not None
        return ecx_set and edx_set
    
    def _analyze_x64(self, func) -> List[Tuple[int, int, str, float]]:
        """x64-specific analysis"""
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "call":
                op_str = operand_str(head, 0)
                if is_rip_relative(op_str):
                    target = self._resolve_rip_relative(head)
                    if target:
                        self.add_xref(head, target, "x64_rip_relative", 0.9)
                        results.append((head, target, "x64_rip_relative", 0.9))
            elif mnem in ["call", "jmp"]:
                if self._uses_x64_calling_convention(head):
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_reg:
                        target = self._resolve_x64_register(head)
                        if target:
                            self.add_xref(head, target, "x64_convention_call", 0.85)
                            results.append((head, target, "x64_convention_call", 0.85))
        
        return results
    
    def _resolve_rip_relative(self, ea: int) -> Optional[int]:
        """Resolve RIP-relative address"""
        op_type = idc.get_operand_type(ea, 0)
        
        if op_type == idc.o_mem:
            # Direct RIP-relative
            return idc.get_operand_value(ea, 0)
        elif op_type == idc.o_displ:
            # RIP + displacement
            op_str = operand_str(ea, 0)
            if is_rip_relative(op_str):
                next_ea = idc.next_head(ea)
                if next_ea != idc.BADADDR:
                    _base, disp = extract_bracket_base_offset(op_str)
                    if disp is not None:
                        return next_ea + disp
        
        return None
    
    def _uses_x64_calling_convention(self, call_ea: int) -> bool:
        """Check if using x64 calling convention"""
        # Check if RCX, RDX, R8, R9 are set before call
        arg_regs = ["rcx", "rdx", "r8", "r9"]
        regs_set = []
        for reg in arg_regs:
            if scan_back_for_reg_source(call_ea, reg, max_back=20, mnems=("mov", "lea")):
                regs_set.append(reg)
        return len(regs_set) >= 2
    
    def _resolve_x64_register(self, ea: int) -> Optional[int]:
        """Resolve x64 register value"""
        reg_name = idc.print_operand(ea, 0)

        def resolver(prev_ea: int, mnem: str) -> Optional[int]:
            src_type = idc.get_operand_type(prev_ea, 1)
            if src_type == idc.o_imm:
                return idc.get_operand_value(prev_ea, 1)
            if mnem == "lea" and src_type == idc.o_mem:
                return idc.get_operand_value(prev_ea, 1)
            return None

        return self._resolve_register_via_backtrace(
            ea,
            reg_name,
            {"mov", "lea"},
            resolver,
        )

    def _resolve_register_via_backtrace(
        self,
        ea: int,
        reg_name: str,
        mnemonics: set,
        resolver,
        max_back: int = 10,
    ) -> Optional[int]:
        """Generic register backtrace resolver to reduce duplication."""
        for prev_ea, mnem in scan_back(ea, max_back=max_back, mnems=mnemonics):
            dst = idc.print_operand(prev_ea, 0)
            if dst.lower() != reg_name.lower():
                continue
            value = resolver(prev_ea, mnem)
            if value is not None:
                return value
        return None
