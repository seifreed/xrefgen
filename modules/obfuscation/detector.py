"""
Advanced Obfuscation Detection Module
Detects control flow flattening, opaque predicates, and encrypted strings
"""

from typing import Dict, List, Tuple, Set, Optional
import idaapi
import idautils
import idc
import ida_funcs
import ida_bytes
import ida_nalt
from modules.core.base import XrefAnalyzer
import struct
import re

class ObfuscationDetector(XrefAnalyzer):
    """Detects and resolves various obfuscation techniques"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.detect_cff = config.get('detect_cff', True)
        self.detect_opaque = config.get('detect_opaque_predicates', True)
        self.detect_encryption = config.get('detect_string_encryption', True)
        self.max_dispatcher_size = config.get('max_dispatcher_size', 1000)
        
        # Control flow flattening patterns
        self.dispatcher_blocks = {}
        self.flattened_functions = set()
        
        # Opaque predicate patterns
        self.opaque_predicates = []
        self.always_taken_branches = set()
        self.never_taken_branches = set()
        
        # String encryption patterns
        self.encrypted_strings = {}
        self.decryption_functions = set()
        
    def get_name(self) -> str:
        return "ObfuscationDetector"
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform obfuscation detection and resolution"""
        results = []
        
        if self.detect_cff:
            cff_refs = self._detect_control_flow_flattening()
            results.extend(cff_refs)
        
        if self.detect_opaque:
            opaque_refs = self._detect_opaque_predicates()
            results.extend(opaque_refs)
        
        if self.detect_encryption:
            string_refs = self._detect_encrypted_strings()
            results.extend(string_refs)
        
        return results
    
    def _detect_control_flow_flattening(self) -> List[Tuple[int, int, str, float]]:
        """Detect and resolve control flow flattening"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # Check if function has CFF characteristics
            dispatcher = self._find_dispatcher_block(func)
            if dispatcher:
                self.flattened_functions.add(func_ea)
                self.dispatcher_blocks[func_ea] = dispatcher
                
                # Resolve flattened control flow
                real_flow = self._resolve_flattened_flow(func, dispatcher)
                for source, target, conf in real_flow:
                    self.add_xref(source, target, "cff_resolved", conf)
                    results.append((source, target, "cff_resolved", conf))
        
        return results
    
    def _find_dispatcher_block(self, func) -> Optional[int]:
        """Find the dispatcher block in a potentially flattened function"""
        # CFF characteristics:
        # 1. Central dispatcher block with many incoming edges
        # 2. Switch/if-else chain dispatching to real blocks
        # 3. State variable controlling flow
        
        block_refs = {}
        
        # Count incoming references for each block
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsTo(head):
                if func.start_ea <= xref.frm < func.end_ea:
                    if head not in block_refs:
                        block_refs[head] = 0
                    block_refs[head] += 1
        
        # Find block with most incoming edges (likely dispatcher)
        if not block_refs:
            return None
        
        dispatcher_candidate = max(block_refs.items(), key=lambda x: x[1])
        
        # Validate it's a dispatcher
        if dispatcher_candidate[1] > 5:  # Threshold for dispatcher detection
            # Check for switch or comparison chain
            if self._has_dispatcher_pattern(dispatcher_candidate[0], func.end_ea):
                return dispatcher_candidate[0]
        
        return None
    
    def _has_dispatcher_pattern(self, ea: int, end_ea: int) -> bool:
        """Check if address has dispatcher-like pattern"""
        # Look for switch statement or comparison chain
        comparisons = 0
        jumps = 0
        
        curr_ea = ea
        checked = 0
        
        while curr_ea < end_ea and checked < self.max_dispatcher_size:
            mnem = idc.print_insn_mnem(curr_ea).lower()
            
            if mnem in ["cmp", "test"]:
                comparisons += 1
            elif mnem in ["je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"]:
                jumps += 1
            elif mnem == "jmp":
                # Check for jump table
                op_type = idc.get_operand_type(curr_ea, 0)
                if op_type in [idc.o_mem, idc.o_displ]:
                    # Likely a switch jump table
                    return True
            
            curr_ea = idc.next_head(curr_ea)
            checked += 1
        
        # Heuristic: dispatcher has many comparisons and conditional jumps
        return comparisons > 3 and jumps > 3
    
    def _resolve_flattened_flow(self, func, dispatcher: int) -> List[Tuple[int, int, float]]:
        """Resolve the real control flow in a flattened function"""
        resolved_flow = []
        
        # Find state variable assignments
        state_vars = self._find_state_variables(func, dispatcher)
        
        # Map state values to real blocks
        state_map = {}
        for state_var in state_vars:
            assignments = self._find_state_assignments(func, state_var)
            for ea, value in assignments:
                state_map[value] = ea
        
        # Reconstruct real flow
        for value, block in state_map.items():
            # Find where this block would naturally flow
            next_blocks = self._find_next_blocks(block, func.end_ea, dispatcher)
            for next_block in next_blocks:
                if next_block in state_map.values():
                    resolved_flow.append((block, next_block, 0.7))
        
        return resolved_flow
    
    def _find_state_variables(self, func, dispatcher: int) -> Set[int]:
        """Find variables used as state in control flow flattening"""
        state_vars = set()
        
        # Look for variables compared in dispatcher
        curr_ea = dispatcher
        for _ in range(20):  # Check first 20 instructions
            if curr_ea >= func.end_ea:
                break
            
            mnem = idc.print_insn_mnem(curr_ea).lower()
            if mnem == "cmp":
                # Get compared operands
                op1_type = idc.get_operand_type(curr_ea, 0)
                if op1_type == idc.o_reg:
                    state_vars.add(idc.get_operand_value(curr_ea, 0))
                elif op1_type == idc.o_displ:
                    # Stack variable
                    state_vars.add(curr_ea)  # Use address as identifier
            
            curr_ea = idc.next_head(curr_ea)
        
        return state_vars
    
    def _find_state_assignments(self, func, state_var: int) -> List[Tuple[int, int]]:
        """Find assignments to state variable"""
        assignments = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            
            if mnem == "mov":
                dst_type = idc.get_operand_type(head, 0)
                src_type = idc.get_operand_type(head, 1)
                
                # Check if assigning to state variable
                if dst_type == idc.o_reg and idc.get_operand_value(head, 0) == state_var:
                    if src_type == idc.o_imm:
                        value = idc.get_operand_value(head, 1)
                        assignments.append((head, value))
        
        return assignments
    
    def _find_next_blocks(self, block_ea: int, end_ea: int, dispatcher: int) -> List[int]:
        """Find blocks that would naturally follow in unflattened code"""
        next_blocks = []
        
        # Find end of current block
        curr_ea = block_ea
        while curr_ea < end_ea:
            mnem = idc.print_insn_mnem(curr_ea).lower()
            
            # Look for jumps back to dispatcher (end of real block)
            if mnem == "jmp":
                target = idc.get_operand_value(curr_ea, 0)
                if target == dispatcher:
                    # This block ends here, look for state assignment before jump
                    prev_ea = idc.prev_head(curr_ea)
                    if prev_ea != idc.BADADDR:
                        prev_mnem = idc.print_insn_mnem(prev_ea).lower()
                        if prev_mnem == "mov":
                            src_type = idc.get_operand_type(prev_ea, 1)
                            if src_type == idc.o_imm:
                                # This value indicates next block
                                next_state = idc.get_operand_value(prev_ea, 1)
                                # Map state to block (simplified)
                                next_blocks.append(dispatcher + (next_state * 0x10))
                    break
            
            curr_ea = idc.next_head(curr_ea)
        
        return next_blocks
    
    def _detect_opaque_predicates(self) -> List[Tuple[int, int, str, float]]:
        """Detect and resolve opaque predicates"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                # Check conditional jumps
                if mnem in ["je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", "jge", "jle"]:
                    if self._is_opaque_predicate(head):
                        # Determine which branch is always/never taken
                        always_taken = self._get_always_taken_branch(head)
                        
                        if always_taken:
                            self.always_taken_branches.add(head)
                            target = idc.get_operand_value(head, 0)
                            self.add_xref(head, target, "opaque_always_taken", 0.95)
                            results.append((head, target, "opaque_always_taken", 0.95))
                        else:
                            self.never_taken_branches.add(head)
                            # Add xref to fall-through
                            next_ea = idc.next_head(head)
                            if next_ea != idc.BADADDR:
                                self.add_xref(head, next_ea, "opaque_never_taken", 0.95)
                                results.append((head, next_ea, "opaque_never_taken", 0.95))
        
        return results
    
    def _is_opaque_predicate(self, jmp_ea: int) -> bool:
        """Check if a conditional jump is an opaque predicate"""
        # Look for common opaque predicate patterns
        
        # Pattern 1: x*(x-1) % 2 == 0 (always true for integers)
        # Pattern 2: (x^2) >= 0 (always true)
        # Pattern 3: 7y^2 - 1 == x^2 (never true for integers)
        
        # Look back for the comparison
        prev_ea = idc.prev_head(jmp_ea)
        if prev_ea == idc.BADADDR:
            return False
        
        prev_mnem = idc.print_insn_mnem(prev_ea).lower()
        if prev_mnem not in ["cmp", "test"]:
            return False
        
        # Check for mathematical patterns
        pattern_ea = prev_ea
        for _ in range(10):  # Look back up to 10 instructions
            pattern_ea = idc.prev_head(pattern_ea)
            if pattern_ea == idc.BADADDR:
                break
            
            pattern_mnem = idc.print_insn_mnem(pattern_ea).lower()
            
            # Check for multiplication followed by subtraction (x*(x-1) pattern)
            if pattern_mnem == "imul":
                # Check if multiplying register by itself-1
                next_ea = idc.next_head(pattern_ea)
                if next_ea != idc.BADADDR:
                    next_mnem = idc.print_insn_mnem(next_ea).lower()
                    if next_mnem in ["sub", "dec"]:
                        # Likely opaque predicate
                        return True
            
            # Check for XOR with same register (always zero)
            elif pattern_mnem == "xor":
                op1 = idc.print_operand(pattern_ea, 0)
                op2 = idc.print_operand(pattern_ea, 1)
                if op1 == op2:
                    # XOR reg, reg always produces zero
                    return True
        
        return False
    
    def _get_always_taken_branch(self, jmp_ea: int) -> bool:
        """Determine if opaque predicate branch is always or never taken"""
        # Analyze the condition
        mnem = idc.print_insn_mnem(jmp_ea).lower()
        
        # Look at previous comparison
        prev_ea = idc.prev_head(jmp_ea)
        if prev_ea == idc.BADADDR:
            return True  # Default to always taken
        
        prev_mnem = idc.print_insn_mnem(prev_ea).lower()
        
        # Check for always-zero comparisons
        if prev_mnem == "test":
            op1 = idc.print_operand(prev_ea, 0)
            op2 = idc.print_operand(prev_ea, 1)
            if op1 == op2:
                # TEST reg, reg after XOR reg, reg
                if mnem == "jz" or mnem == "je":
                    return True  # Always zero, so JZ always taken
                elif mnem == "jnz" or mnem == "jne":
                    return False  # Never taken
        
        # Default heuristic based on jump type
        return mnem in ["je", "jz", "jge", "jle"]
    
    def _detect_encrypted_strings(self) -> List[Tuple[int, int, str, float]]:
        """Detect and resolve encrypted string references"""
        results = []
        
        # Find potential string decryption functions
        self._find_decryption_functions()
        
        # Find encrypted string references
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            encrypted_refs = self._find_encrypted_string_refs(func)
            for source, string_addr, decrypted in encrypted_refs:
                if decrypted:
                    # Create reference to decrypted string location
                    self.add_xref(source, string_addr, "decrypted_string", 0.8)
                    results.append((source, string_addr, "decrypted_string", 0.8))
                    
                    # Store decrypted string
                    self.encrypted_strings[string_addr] = decrypted
        
        return results
    
    def _find_decryption_functions(self):
        """Identify functions that decrypt strings"""
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # Characteristics of decryption functions:
            # 1. XOR operations in loops
            # 2. Byte-by-byte processing
            # 3. String manipulation instructions
            
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
                    # Check for loop via conditional jump
                    target = idc.get_operand_value(head, 0)
                    if target < head:  # Backward jump
                        loop_count += 1
            
            # Heuristic: function with XOR in loops is likely decryption
            if xor_count > 2 and (loop_count > 0 or string_ops > 0):
                self.decryption_functions.add(func_ea)
    
    def _find_encrypted_string_refs(self, func) -> List[Tuple[int, int, Optional[str]]]:
        """Find references to encrypted strings in a function"""
        refs = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            # Look for calls to decryption functions
            mnem = idc.print_insn_mnem(head).lower()
            
            if mnem == "call":
                target = idc.get_operand_value(head, 0)
                if target in self.decryption_functions:
                    # Found call to decryption function
                    # Try to find the encrypted string argument
                    string_arg = self._get_decryption_argument(head)
                    if string_arg:
                        # Try to decrypt the string
                        decrypted = self._try_decrypt_string(string_arg)
                        refs.append((head, string_arg, decrypted))
            
            # Also look for inline decryption patterns
            elif mnem == "xor":
                # Check if XORing string bytes
                if self._is_string_xor(head):
                    string_addr = self._get_xor_string_address(head)
                    if string_addr:
                        decrypted = self._try_decrypt_inline(head, string_addr)
                        refs.append((head, string_addr, decrypted))
        
        return refs
    
    def _get_decryption_argument(self, call_ea: int) -> Optional[int]:
        """Get the string argument passed to decryption function"""
        # Look for string address loaded before call
        prev_ea = call_ea
        
        for _ in range(5):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            
            # Check for loading string address
            if mnem in ["lea", "mov"]:
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_mem or src_type == idc.o_imm:
                    addr = idc.get_operand_value(prev_ea, 1)
                    # Check if it points to data
                    if ida_bytes.is_data(ida_bytes.get_flags(addr)):
                        return addr
        
        return None
    
    def _try_decrypt_string(self, string_addr: int) -> Optional[str]:
        """Try to decrypt a string using common algorithms"""
        # Read encrypted bytes
        encrypted = []
        ea = string_addr
        
        for _ in range(256):  # Max string length
            byte = ida_bytes.get_byte(ea)
            if byte == 0:
                break
            encrypted.append(byte)
            ea += 1
        
        if not encrypted:
            return None
        
        # Try common decryption methods
        
        # Method 1: Single-byte XOR
        for key in range(1, 256):
            decrypted = bytes([b ^ key for b in encrypted])
            if self._is_valid_string(decrypted):
                return decrypted.decode('utf-8', errors='ignore')
        
        # Method 2: Rolling XOR
        for key_start in range(1, 256):
            key = key_start
            decrypted = []
            for b in encrypted:
                decrypted.append(b ^ key)
                key = (key + 1) % 256
            
            decrypted_bytes = bytes(decrypted)
            if self._is_valid_string(decrypted_bytes):
                return decrypted_bytes.decode('utf-8', errors='ignore')
        
        # Method 3: Simple substitution
        # (Would need more context to implement)
        
        return None
    
    def _is_valid_string(self, data: bytes) -> bool:
        """Check if decrypted data looks like a valid string"""
        if not data:
            return False
        
        # Check for printable ASCII characters
        printable_count = sum(1 for b in data if 32 <= b < 127)
        
        # At least 70% should be printable
        if printable_count / len(data) < 0.7:
            return False
        
        # Check for common string patterns
        try:
            text = data.decode('utf-8', errors='ignore')
            # Look for common patterns
            if any(pattern in text.lower() for pattern in [
                'http', 'https', '.exe', '.dll', 'system', 'process',
                'file', 'registry', 'windows', 'program', 'error'
            ]):
                return True
            
            # Check if it looks like a path or URL
            if '\\' in text or '/' in text or '.' in text:
                return True
                
        except:
            pass
        
        return printable_count == len(data)  # All printable is likely a string
    
    def _is_string_xor(self, ea: int) -> bool:
        """Check if XOR instruction is operating on string data"""
        # Check operands
        op1_type = idc.get_operand_type(ea, 0)
        
        if op1_type == idc.o_displ or op1_type == idc.o_mem:
            # XORing memory location
            return True
        elif op1_type == idc.o_reg:
            # Check if register points to string
            # Would need data flow analysis
            pass
        
        return False
    
    def _get_xor_string_address(self, xor_ea: int) -> Optional[int]:
        """Get address of string being XORed"""
        op_type = idc.get_operand_type(xor_ea, 0)
        
        if op_type == idc.o_mem:
            return idc.get_operand_value(xor_ea, 0)
        elif op_type == idc.o_displ:
            # Need to calculate effective address
            # Simplified - would need full calculation
            return xor_ea
        
        return None
    
    def _try_decrypt_inline(self, xor_ea: int, string_addr: int) -> Optional[str]:
        """Try to decrypt string with inline XOR"""
        # Get XOR key
        op2_type = idc.get_operand_type(xor_ea, 1)
        
        if op2_type == idc.o_imm:
            key = idc.get_operand_value(xor_ea, 1)
            
            # Read and decrypt string
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
                    return decrypted.decode('utf-8', errors='ignore')
        
        return None