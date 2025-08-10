"""
Cross-Architecture Support Module
Handles architecture-specific patterns for ARM, MIPS, and WebAssembly
"""

from typing import Dict, List, Tuple, Optional
import idaapi
import idautils
import idc
import ida_funcs
import ida_ua
import ida_bytes
import ida_segregs
from modules.core.base import XrefAnalyzer

class CrossArchAnalyzer(XrefAnalyzer):
    """Architecture-specific xref analysis"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.supported_archs = config.get('architectures', 
            ['x86', 'x64', 'arm', 'arm64', 'mips', 'wasm'])
        
        # Detect current architecture
        info = idaapi.get_inf_structure()
        self.arch = self._detect_architecture(info)
        self.is_64bit = info.is_64bit()
        
        # Architecture-specific handlers
        self.arch_handlers = {
            'arm': self._analyze_arm,
            'arm64': self._analyze_arm64,
            'mips': self._analyze_mips,
            'wasm': self._analyze_wasm,
            'x86': self._analyze_x86,
            'x64': self._analyze_x64
        }
        
    def get_name(self) -> str:
        return "CrossArchAnalyzer"
    
    def _detect_architecture(self, info) -> str:
        """Detect the current binary architecture"""
        procname = info.procname.lower()
        
        if 'arm' in procname:
            if info.is_64bit():
                return 'arm64'
            else:
                return 'arm'
        elif 'mips' in procname:
            return 'mips'
        elif 'wasm' in procname:
            return 'wasm'
        elif info.is_64bit():
            return 'x64'
        else:
            return 'x86'
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform architecture-specific analysis"""
        if self.arch not in self.supported_archs:
            print(f"[XrefGen] Architecture {self.arch} not in supported list")
            return []
        
        handler = self.arch_handlers.get(self.arch)
        if handler:
            return handler()
        
        return []
    
    def _analyze_arm(self) -> List[Tuple[int, int, str, float]]:
        """ARM-specific analysis"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # ARM-specific patterns
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
        # Look backwards for register loads
        prev_ea = ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).upper()
            
            if mnem in ["LDR", "MOV", "MOVW", "MOVT"]:
                # Check if loading to same register
                dst_op = idc.print_operand(prev_ea, 0)
                call_op = idc.print_operand(ea, 0)
                
                if dst_op == call_op:
                    # Found load to our register
                    if mnem == "LDR":
                        return self._get_arm_ldr_target(prev_ea)
                    elif mnem in ["MOV", "MOVW"]:
                        src_type = idc.get_operand_type(prev_ea, 1)
                        if src_type == idc.o_imm:
                            return idc.get_operand_value(prev_ea, 1)
        
        return None
    
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
                op_str = idc.print_operand(head, 1)
                if '[' in op_str and '#' in op_str:
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
        # Parse the LDR instruction
        op_str = idc.print_operand(ldr_ea, 1)
        
        # Extract base register and offset
        if '[' in op_str and '#' in op_str:
            # Pattern: [Rn, #offset]
            parts = op_str.strip('[]').split(',')
            if len(parts) >= 2:
                offset_str = parts[1].strip()
                if offset_str.startswith('#'):
                    try:
                        offset = int(offset_str[1:], 0)
                        
                        # Look for base register value
                        base_reg = parts[0].strip()
                        base_value = self._find_register_value(ldr_ea, base_reg)
                        
                        if base_value:
                            # Calculate vtable entry address
                            entry_addr = base_value + offset
                            # Read function pointer from vtable
                            func_ptr = idc.get_wide_dword(entry_addr)
                            if func_ptr and self.is_valid_reference(func_ptr):
                                return func_ptr
                    except ValueError:
                        pass
        
        return None
    
    def _find_register_value(self, ea: int, reg_name: str) -> Optional[int]:
        """Find value loaded into a register"""
        prev_ea = ea
        for _ in range(20):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).upper()
            if mnem in ["LDR", "MOV", "MOVW", "ADR"]:
                dst = idc.print_operand(prev_ea, 0)
                if dst.upper() == reg_name.upper():
                    # Found load to our register
                    src_type = idc.get_operand_type(prev_ea, 1)
                    if src_type == idc.o_imm:
                        return idc.get_operand_value(prev_ea, 1)
                    elif mnem == "ADR":
                        # ADR loads PC-relative address
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
                        if self.is_valid_reference(target):
                            self.add_xref(head, target, f"arm_switch_case_{i}", 0.9)
                            refs.append((head, target, f"arm_switch_case_{i}", 0.9))
        
        return refs
    
    def _get_arm_table_base(self, tbb_ea: int) -> Optional[int]:
        """Get base address of ARM switch table"""
        op_str = idc.print_operand(tbb_ea, 0)
        
        # Parse [Rn, Rm] pattern
        if '[' in op_str:
            parts = op_str.strip('[]').split(',')
            if parts:
                base_reg = parts[0].strip()
                # Find where base register is loaded
                return self._find_register_value(tbb_ea, base_reg)
        
        return None
    
    def _analyze_arm64(self) -> List[Tuple[int, int, str, float]]:
        """ARM64/AArch64-specific analysis"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # ARM64-specific patterns
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                # BR/BLR - indirect branch/call
                if mnem in ["br", "blr"]:
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_reg:
                        target = self._resolve_arm64_register(head)
                        if target and self.is_valid_reference(target):
                            xref_type = "arm64_blr" if mnem == "blr" else "arm64_br"
                            self.add_xref(head, target, xref_type, 0.85)
                            results.append((head, target, xref_type, 0.85))
                
                # ADRP/ADD pattern for large addresses
                elif mnem == "adrp":
                    page_addr = idc.get_operand_value(head, 1)
                    # Look for following ADD instruction
                    next_ea = idc.next_head(head)
                    if next_ea != idc.BADADDR:
                        next_mnem = idc.print_insn_mnem(next_ea).lower()
                        if next_mnem == "add":
                            # Calculate full address
                            offset = idc.get_operand_value(next_ea, 2)
                            full_addr = page_addr + offset
                            if self.is_valid_reference(full_addr):
                                self.add_xref(head, full_addr, "arm64_adrp_add", 0.9)
                                results.append((head, full_addr, "arm64_adrp_add", 0.9))
        
        return results
    
    def _resolve_arm64_register(self, ea: int) -> Optional[int]:
        """Resolve ARM64 register value"""
        # Similar to ARM but with 64-bit registers
        prev_ea = ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            
            if mnem in ["ldr", "mov", "movz", "movk", "adr", "adrp"]:
                dst_op = idc.print_operand(prev_ea, 0)
                call_op = idc.print_operand(ea, 0)
                
                if dst_op == call_op:
                    if mnem == "ldr":
                        # Load from memory
                        src_type = idc.get_operand_type(prev_ea, 1)
                        if src_type == idc.o_mem:
                            addr = idc.get_operand_value(prev_ea, 1)
                            value = idc.get_qword(addr)
                            if value and self.is_valid_reference(value):
                                return value
                    elif mnem in ["mov", "movz"]:
                        src_type = idc.get_operand_type(prev_ea, 1)
                        if src_type == idc.o_imm:
                            return idc.get_operand_value(prev_ea, 1)
                    elif mnem in ["adr", "adrp"]:
                        return idc.get_operand_value(prev_ea, 1)
        
        return None
    
    def _analyze_mips(self) -> List[Tuple[int, int, str, float]]:
        """MIPS-specific analysis"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # MIPS delay slots require special handling
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                # JALR - jump and link register (indirect call)
                if mnem == "jalr":
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_reg:
                        target = self._resolve_mips_register(head)
                        if target and self.is_valid_reference(target):
                            self.add_xref(head, target, "mips_jalr", 0.85)
                            results.append((head, target, "mips_jalr", 0.85))
                        
                        # Handle delay slot
                        delay_slot = idc.next_head(head)
                        if delay_slot != idc.BADADDR:
                            # Mark delay slot instruction
                            self.add_xref(delay_slot, target, "mips_delay_slot", 0.7)
                
                # JR - jump register (indirect jump)
                elif mnem == "jr":
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_reg:
                        reg_name = idc.print_operand(head, 0)
                        if reg_name != "$ra":  # Not a return
                            target = self._resolve_mips_register(head)
                            if target and self.is_valid_reference(target):
                                self.add_xref(head, target, "mips_jr", 0.85)
                                results.append((head, target, "mips_jr", 0.85))
                
                # LW/LA for function pointer loads
                elif mnem in ["lw", "la"]:
                    # Check if loading from GOT or function pointer table
                    if self._is_mips_got_access(head):
                        target = self._resolve_mips_got_entry(head)
                        if target:
                            self.add_xref(head, target, "mips_got_ref", 0.8)
                            results.append((head, target, "mips_got_ref", 0.8))
        
        return results
    
    def _resolve_mips_register(self, ea: int) -> Optional[int]:
        """Resolve MIPS register value"""
        # MIPS often uses LUI/ADDIU or LUI/ORI pairs for addresses
        prev_ea = ea
        lui_value = None
        
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            
            if mnem == "lui":
                # Load upper immediate
                dst = idc.print_operand(prev_ea, 0)
                target_reg = idc.print_operand(ea, 0)
                if dst == target_reg:
                    lui_value = idc.get_operand_value(prev_ea, 1) << 16
            
            elif mnem in ["addiu", "ori"] and lui_value is not None:
                # Add immediate unsigned or OR immediate
                dst = idc.print_operand(prev_ea, 0)
                target_reg = idc.print_operand(ea, 0)
                if dst == target_reg:
                    low_value = idc.get_operand_value(prev_ea, 2)
                    full_value = lui_value | low_value
                    if self.is_valid_reference(full_value):
                        return full_value
            
            elif mnem in ["lw", "ld"]:
                # Load word/doubleword
                dst = idc.print_operand(prev_ea, 0)
                target_reg = idc.print_operand(ea, 0)
                if dst == target_reg:
                    # Get memory address
                    src_type = idc.get_operand_type(prev_ea, 1)
                    if src_type == idc.o_mem:
                        addr = idc.get_operand_value(prev_ea, 1)
                        value = idc.get_wide_dword(addr) if mnem == "lw" else idc.get_qword(addr)
                        if value and self.is_valid_reference(value):
                            return value
        
        return None
    
    def _is_mips_got_access(self, ea: int) -> bool:
        """Check if instruction accesses MIPS GOT"""
        op_str = idc.print_operand(ea, 1)
        # GOT access patterns: offset($gp), %got(symbol)
        return "$gp" in op_str or "%got" in op_str.lower()
    
    def _resolve_mips_got_entry(self, ea: int) -> Optional[int]:
        """Resolve MIPS GOT entry"""
        # Parse GOT offset
        op_str = idc.print_operand(ea, 1)
        
        if "$gp" in op_str:
            # Extract offset from pattern: offset($gp)
            try:
                offset_str = op_str.split('(')[0]
                offset = int(offset_str, 0)
                
                # Get GP value (would need proper MIPS analysis)
                gp_value = self._get_mips_gp_value()
                if gp_value:
                    got_entry = gp_value + offset
                    value = idc.get_wide_dword(got_entry)
                    if value and self.is_valid_reference(value):
                        return value
            except (ValueError, IndexError):
                pass
        
        return None
    
    def _get_mips_gp_value(self) -> Optional[int]:
        """Get MIPS global pointer value"""
        # This would require proper MIPS ABI analysis
        # Simplified: look for .got section
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if ".got" in seg_name.lower():
                return seg_ea
        return None
    
    def _analyze_wasm(self) -> List[Tuple[int, int, str, float]]:
        """WebAssembly-specific analysis"""
        results = []
        
        # WebAssembly has different instruction model
        # Function calls are via call_indirect instruction
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # WASM uses different instruction encoding
                # This is simplified - real implementation would need WASM decoder
                disasm = idc.GetDisasm(head).lower()
                
                if "call_indirect" in disasm:
                    # Indirect function call through table
                    table_idx = self._get_wasm_table_index(head)
                    if table_idx is not None:
                        # Resolve function from table
                        target = self._resolve_wasm_table_entry(table_idx)
                        if target:
                            self.add_xref(head, target, "wasm_call_indirect", 0.8)
                            results.append((head, target, "wasm_call_indirect", 0.8))
                
                elif "br_table" in disasm:
                    # Branch table (switch-like construct)
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
    
    def _analyze_x86(self) -> List[Tuple[int, int, str, float]]:
        """x86-specific analysis (32-bit)"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # x86-specific patterns
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                # Check for thiscall pattern (ECX as this pointer)
                if mnem == "call":
                    if self._is_x86_thiscall(head):
                        target = self._resolve_x86_thiscall(head)
                        if target:
                            self.add_xref(head, target, "x86_thiscall", 0.8)
                            results.append((head, target, "x86_thiscall", 0.8))
                
                # Check for fastcall pattern (ECX, EDX for first two args)
                elif self._is_x86_fastcall(head):
                    target = idc.get_operand_value(head, 0)
                    if self.is_valid_reference(target):
                        self.add_xref(head, target, "x86_fastcall", 0.85)
                        results.append((head, target, "x86_fastcall", 0.85))
        
        return results
    
    def _is_x86_thiscall(self, call_ea: int) -> bool:
        """Check if call uses thiscall convention"""
        # Look for ECX being set before call
        prev_ea = call_ea
        for _ in range(5):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem == "mov":
                dst = idc.print_operand(prev_ea, 0).lower()
                if dst == "ecx":
                    return True
        
        return False
    
    def _resolve_x86_thiscall(self, call_ea: int) -> Optional[int]:
        """Resolve thiscall vtable call"""
        # Look for pattern: mov ecx, object; call [ecx+offset]
        op_type = idc.get_operand_type(call_ea, 0)
        
        if op_type == idc.o_displ:
            # Call through vtable
            op_str = idc.print_operand(call_ea, 0)
            if "ecx" in op_str.lower():
                # Extract offset
                if '+' in op_str:
                    try:
                        offset = int(op_str.split('+')[1].strip(']'), 0)
                        # Would need to track ECX value to resolve
                        return None  # Simplified
                    except ValueError:
                        pass
        
        return None
    
    def _is_x86_fastcall(self, ea: int) -> bool:
        """Check if using fastcall convention"""
        # Look for ECX and EDX being set before call
        ecx_set = False
        edx_set = False
        
        prev_ea = ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem == "mov":
                dst = idc.print_operand(prev_ea, 0).lower()
                if dst == "ecx":
                    ecx_set = True
                elif dst == "edx":
                    edx_set = True
        
        return ecx_set and edx_set
    
    def _analyze_x64(self) -> List[Tuple[int, int, str, float]]:
        """x64-specific analysis"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # x64 uses RIP-relative addressing
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                # RIP-relative calls
                if mnem == "call":
                    op_str = idc.print_operand(head, 0)
                    if "rip" in op_str.lower():
                        target = self._resolve_rip_relative(head)
                        if target:
                            self.add_xref(head, target, "x64_rip_relative", 0.9)
                            results.append((head, target, "x64_rip_relative", 0.9))
                
                # Check for x64 calling conventions (RCX, RDX, R8, R9)
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
            op_str = idc.print_operand(ea, 0)
            if "rip" in op_str.lower():
                # Calculate target
                # Next instruction address + displacement
                next_ea = idc.next_head(ea)
                if next_ea != idc.BADADDR:
                    # Extract displacement
                    if '+' in op_str:
                        try:
                            disp = int(op_str.split('+')[1].strip(']'), 0)
                            return next_ea + disp
                        except ValueError:
                            pass
        
        return None
    
    def _uses_x64_calling_convention(self, call_ea: int) -> bool:
        """Check if using x64 calling convention"""
        # Check if RCX, RDX, R8, R9 are set before call
        arg_regs = ["rcx", "rdx", "r8", "r9"]
        regs_set = []
        
        prev_ea = call_ea
        for _ in range(20):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem in ["mov", "lea"]:
                dst = idc.print_operand(prev_ea, 0).lower()
                if dst in arg_regs:
                    regs_set.append(dst)
        
        # At least 2 argument registers should be set
        return len(regs_set) >= 2
    
    def _resolve_x64_register(self, ea: int) -> Optional[int]:
        """Resolve x64 register value"""
        reg_name = idc.print_operand(ea, 0)
        
        prev_ea = ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            
            if mnem in ["mov", "lea"]:
                dst = idc.print_operand(prev_ea, 0)
                if dst.lower() == reg_name.lower():
                    src_type = idc.get_operand_type(prev_ea, 1)
                    if src_type == idc.o_imm:
                        return idc.get_operand_value(prev_ea, 1)
                    elif mnem == "lea" and src_type == idc.o_mem:
                        return idc.get_operand_value(prev_ea, 1)
        
        return None