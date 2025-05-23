#!/usr/bin/env python3
"""
IDA Pro Cross-Reference Generator for Mandiant XRefer
Author: Marc Rivero | @seifreed
Version: 1.2
Description: Generates additional cross-references for IDA Pro that aren't automatically detected.
"""

import idaapi
import idautils
import idc
import ida_funcs
import ida_xref
import ida_ua
import ida_nalt
import ida_segment
import os
from typing import Tuple, List, Optional, Set, Dict

class XrefGenerator:
    def __init__(self):
        self.xrefs: Dict[Tuple[int, int], str] = {}  # (source, target) -> type_description
        self.log_file = None
        self.binary_path = ida_nalt.get_input_file_path()
        
    def log(self, message: str) -> None:
        """Log a message to both IDA console and log file."""
        print(f"[XrefGen] {message}")
        if self.log_file:
            self.log_file.write(f"{message}\n")
            
    def is_valid_reference(self, target: int) -> bool:
        """
        Validate if a reference target is reasonable.
        Returns True if the target is within a function or code segment.
        """
        # Check if target is in a code segment
        seg = ida_segment.getseg(target)
        if not seg:
            return False
            
        # Check if segment is a code segment
        if not idc.is_code(idc.get_full_flags(target)):
            return False
            
        # Check if target is within a function
        func = ida_funcs.get_func(target)
        if func:
            return True
            
        # Check if target is near a function (within 32 bytes)
        for func in idautils.Functions():
            if abs(target - func) < 32:
                return True
                
        return False
    
    def is_trivial_jump(self, source: int, target: int) -> bool:
        """
        Check if a jump is trivial (e.g., to the next instruction or within the same basic block).
        """
        # Check if target is the next instruction
        next_ea = idc.next_head(source)
        if next_ea == target:
            return True
            
        # Check if source and target are within the same function
        source_func = ida_funcs.get_func(source)
        target_func = ida_funcs.get_func(target)
        if source_func and target_func and source_func.start_ea == target_func.start_ea:
            # Check if it's a short jump within 16 bytes
            if abs(target - source) < 16:
                return True
                
        return False
    
    def is_already_in_ida(self, source: int, target: int) -> bool:
        """
        Check if the reference is already known to IDA.
        """
        for xref in idautils.XrefsFrom(source, 0):
            if xref.to == target:
                return True
        return False
        
    def find_constant_loads(self, ea: int, prev_limit: int = 8) -> Optional[int]:
        """
        Look for constant values loaded into registers before the current instruction.
        This is useful for resolving function pointers loaded before calls.
        """
        # Look backwards for up to prev_limit instructions
        curr_ea = ea
        seen_regs = set()
        
        for _ in range(prev_limit):
            curr_ea = idc.prev_head(curr_ea)
            if curr_ea == idc.BADADDR:
                break
                
            # Check if this is a mov instruction with an immediate value
            mnemonic = idc.print_insn_mnem(curr_ea).lower()
            if mnemonic in ["mov", "lea"]:
                # Check destination register
                dest_op_type = idc.get_operand_type(curr_ea, 0)
                if dest_op_type == idc.o_reg:
                    dest_reg = idc.get_operand_value(curr_ea, 0)
                    
                    # If we've already seen instructions modifying this register, skip
                    if dest_reg in seen_regs:
                        continue
                    
                    # Add this register to seen list
                    seen_regs.add(dest_reg)
                    
                    # Check source operand
                    src_op_type = idc.get_operand_type(curr_ea, 1)
                    if src_op_type == idc.o_imm:
                        target = idc.get_operand_value(curr_ea, 1)
                        if self.is_valid_reference(target):
                            return target
                        
        return None
        
    def resolve_indirect_target(self, ea: int, depth: int = 1) -> Optional[int]:
        """
        Resolve the target of an indirect call/jump instruction with improved heuristics.
        Returns the resolved target address or None if not resolvable.
        """
        if depth > 2:  # Prevent excessive recursion
            return None
            
        mnemonic = idc.print_insn_mnem(ea).lower()
        if mnemonic in ["call", "jmp"]:
            # Get operand type
            op_type = idc.get_operand_type(ea, 0)
            
            # Handle memory-based indirect calls/jumps
            if op_type == idc.o_mem:
                addr = idc.get_operand_value(ea, 0)
                
                # Try to read the value at that memory location
                value = idc.get_qword(addr)
                if value and self.is_valid_reference(value):
                    return value
                
                # Check if the memory address itself is a function
                if self.is_valid_reference(addr):
                    return addr
                
                # Try to recursively resolve the memory location
                mem_ea = idc.get_first_cref_to(addr)
                if mem_ea != idc.BADADDR:
                    return self.resolve_indirect_target(mem_ea, depth + 1)
                    
                return addr
                
            # Handle register-based indirect calls/jumps
            elif op_type == idc.o_reg or op_type == idc.o_displ:
                # Try to find constant loads before this instruction
                return self.find_constant_loads(ea, 8)  # Increased search depth
                
        return None
        
    def get_function_end(self, func_ea: int) -> int:
        """Get the end address of a function using alternative methods."""
        func = ida_funcs.get_func(func_ea)
        if func:
            return func.end_ea
            
        # If we can't get the function object, try to find the next function
        next_func = idc.next_func(func_ea)
        if next_func != idc.BADADDR:
            return next_func
            
        # If no next function, try to find the next code segment
        next_seg = idc.next_seg(func_ea)
        if next_seg != idc.BADADDR:
            return next_seg
            
        # If all else fails, return the current segment end
        seg = ida_segment.getseg(func_ea)
        if seg:
            return seg.end_ea
            
        return idc.BADADDR
        
    def detect_trampolines_or_vtables(self) -> List[Tuple[int, int, str]]:
        """
        Detects advanced patterns of indirect control flow in modern languages:
        - Small trampoline functions
        - Vtable-like dispatches
        - Register-based indirect calls
        - Complex switch patterns
        
        Returns:
            List of tuples (source_addr, target_addr, pattern_type)
        """
        self.log("Analyzing advanced dispatch patterns...")
        advanced_refs = []
        
        # Track processed addresses to avoid duplicates
        processed_addrs = set()
        
        # Process all functions
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Get function size and check if it's a small trampoline
            func_size = func.end_ea - func.start_ea
            
            # 1. Small trampoline functions (5 or fewer instructions)
            if func_size <= 20:
                # Count instructions
                instr_count = 0
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    instr_count += 1
                    if instr_count > 5:
                        break
                
                # If 5 or fewer instructions, check for jumps
                if instr_count <= 5:
                    # Look for jump/call patterns
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        mnemonic = idc.print_insn_mnem(head).lower()
                        
                        # Skip if already processed
                        if head in processed_addrs:
                            continue
                            
                        processed_addrs.add(head)
                        
                        # Check for direct jumps/calls
                        if mnemonic in ["jmp", "call"]:
                            op_type = idc.get_operand_type(head, 0)
                            
                            # Direct jump/call
                            if op_type == idc.o_near:
                                target = idc.get_operand_value(head, 0)
                                if self.is_valid_reference(target) and not self.is_trivial_jump(head, target):
                                    if not self.is_already_in_ida(head, target):
                                        advanced_refs.append((head, target, "small_trampoline"))
            
            # 2. For all functions, check for vtable-like dispatches and other patterns
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Skip if already processed
                if head in processed_addrs:
                    continue
                    
                processed_addrs.add(head)
                
                # Get instruction details
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Handle call and jump instructions
                if mnemonic in ["call", "jmp"]:
                    op_type = idc.get_operand_type(head, 0)
                    
                    # 2.1 Complex vtable-like dispatch: jmp/call [reg + offset]
                    if op_type == idc.o_displ:
                        # This is a pattern like call [rax+0x18]
                        op_str = idc.print_operand(head, 0)
                        
                        # Look backward for register loading
                        target = None
                        curr_ea = head
                        base_reg = None
                        
                        # Extract base register from operand string
                        if '[' in op_str and '+' in op_str:
                            reg_part = op_str[op_str.find('[')+1:op_str.find('+')]
                            base_reg = reg_part.strip()
                        
                        # If we identified a base register, track it backwards
                        if base_reg:
                            # Look for instruction that loads this register
                            for i in range(10):  # Look back up to 10 instructions
                                curr_ea = idc.prev_head(curr_ea)
                                if curr_ea == idc.BADADDR:
                                    break
                                    
                                if idc.print_insn_mnem(curr_ea).lower() in ["mov", "lea"]:
                                    # Check if this instruction loads our register
                                    if idc.print_operand(curr_ea, 0).lower() == base_reg.lower():
                                        # Found a load to our register
                                        src_type = idc.get_operand_type(curr_ea, 1)
                                        
                                        # If it's an immediate value that points to code
                                        if src_type == idc.o_imm:
                                            ptr_val = idc.get_operand_value(curr_ea, 1)
                                            if self.is_valid_reference(ptr_val):
                                                target = ptr_val
                                                break
                                                
                                        # Memory dereference
                                        elif src_type == idc.o_mem:
                                            mem_addr = idc.get_operand_value(curr_ea, 1)
                                            # Try to read a qword from this address
                                            ptr_val = idc.get_qword(mem_addr)
                                            if ptr_val and self.is_valid_reference(ptr_val):
                                                target = ptr_val
                                                break
                        
                        if target and not self.is_already_in_ida(head, target):
                            advanced_refs.append((head, target, "vtable_dispatch"))
                    
                    # 2.2 Simple register indirect calls: call rax
                    elif op_type == idc.o_reg:
                        # This is a pattern like "call rax"
                        # Analyze previous instructions to find where rax is loaded
                        target = self.find_constant_loads(head, 10)  # Look back deeper
                        if target and not self.is_already_in_ida(head, target):
                            advanced_refs.append((head, target, "reg_indirect_call"))
            
            # 3. Check for switch-case patterns (simple approach, without get_switch_info_ex)
            # This detects potential jumptable beginnings
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Skip if already processed
                if head in processed_addrs:
                    continue
                    
                processed_addrs.add(head)
                
                # Check for indirect jump instruction that could be a switch
                mnemonic = idc.print_insn_mnem(head).lower()
                if mnemonic == "jmp":
                    op_type = idc.get_operand_type(head, 0)
                    
                    if op_type == idc.o_mem:
                        # This could be a jump table beginning
                        # Look for previous instructions that might be setting up the jump table index
                        mov_found = False
                        add_found = False
                        imm_val = None
                        
                        curr_ea = head
                        for i in range(5):  # Look back 5 instructions for typical switch setup
                            curr_ea = idc.prev_head(curr_ea)
                            if curr_ea == idc.BADADDR:
                                break
                                
                            curr_mnem = idc.print_insn_mnem(curr_ea).lower()
                            
                            # Check for classic switch-case setup patterns
                            if curr_mnem in ["mov", "lea"] and not mov_found:
                                mov_found = True
                            elif curr_mnem in ["add", "shl"] and not add_found:
                                add_found = True
                                
                            # If we've found a typical pattern, mark this as a potential switch
                            if mov_found and add_found:
                                # Try to resolve potential targets from the memory address
                                jmp_addr = idc.get_operand_value(head, 0)
                                
                                # Add the jump table entry as a reference
                                if self.is_valid_reference(jmp_addr) and not self.is_already_in_ida(head, jmp_addr):
                                    advanced_refs.append((head, jmp_addr, "switch_jumptable"))
                                    
                                # Try to examine the jump table entries
                                for offset in range(0, 80, 8):  # Look at max 10 entries, assuming 64-bit
                                    entry_addr = jmp_addr + offset
                                    entry_val = idc.get_qword(entry_addr)
                                    
                                    if entry_val and self.is_valid_reference(entry_val):
                                        if not self.is_already_in_ida(head, entry_val):
                                            advanced_refs.append((head, entry_val, "switch_case_target"))
                                    else:
                                        # Stop when we hit an invalid entry
                                        break
                                        
                                break  # We've found and processed the switch pattern
        
        self.log(f"Found {len(advanced_refs)} advanced control flow references")
        return advanced_refs
    
    def get_indirect_calls(self) -> List[Tuple[int, int, str]]:
        """Detect significant indirect calls and jumps in the binary."""
        indirect_refs = []
        
        for func_ea in idautils.Functions():
            func_end = self.get_function_end(func_ea)
            if func_end == idc.BADADDR:
                continue
                
            for head in idautils.Heads(func_ea, func_end):
                # Check if this is a call or jump instruction
                mnemonic = idc.print_insn_mnem(head).lower()
                if mnemonic in ["call", "jmp"]:
                    # Check if this is an indirect call/jump
                    op_type = idc.get_operand_type(head, 0)
                    if op_type in [idc.o_reg, idc.o_mem, idc.o_displ]:
                        target = self.resolve_indirect_target(head)
                        
                        if target and self.is_valid_reference(target):
                            # Skip if it's a trivial jump
                            if mnemonic == "jmp" and self.is_trivial_jump(head, target):
                                continue
                                
                            # Skip if already in IDA
                            if self.is_already_in_ida(head, target):
                                continue
                                
                            ref_type = f"indirect_{mnemonic}"
                            indirect_refs.append((head, target, ref_type))
                            
        return indirect_refs
        
    def get_switch_cases(self) -> List[Tuple[int, int, str]]:
        """Detect significant switch-case jump tables."""
        switch_refs = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Check for jump table patterns - look for complex control flow
                flags = idc.get_full_flags(head)
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Only process jump instructions
                if mnemonic != "jmp":
                    continue
                    
                # Look for indirect jumps that might be switch cases
                op_type = idc.get_operand_type(head, 0)
                if op_type in [idc.o_mem, idc.o_displ]:
                    # Try to get the target directly
                    target = idc.get_operand_value(head, 0)
                    
                    if target and self.is_valid_reference(target):
                        # Skip trivial or already known references
                        if self.is_trivial_jump(head, target) or self.is_already_in_ida(head, target):
                            continue
                            
                        switch_refs.append((head, target, "switch_case"))
                            
                    # Look for table jumps by following memory references
                    for _ in range(10):  # Check a reasonable number of potential table entries
                        next_entry = target + (8 * _)  # Assuming 64-bit pointers
                        entry_value = idc.get_qword(next_entry)
                        
                        if entry_value and self.is_valid_reference(entry_value):
                            if not self.is_already_in_ida(head, entry_value):
                                switch_refs.append((head, entry_value, "jumptable_entry"))
                        else:
                            break  # Stop if we find an invalid entry
                                        
        return switch_refs
        
    def get_vtable_constructors(self) -> List[Tuple[int, int, str]]:
        """Detect vtable constructor references with improved filtering for Rust."""
        vtable_refs = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Look for vtable initialization patterns
            for head in idautils.Heads(func_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Only care about mov instructions that might set up vtables
                if mnemonic != "mov":
                    continue
                    
                # Check for immediate values that might be function pointers
                op_type = idc.get_operand_type(head, 1)
                if op_type == idc.o_imm:
                    target = idc.get_operand_value(head, 1)
                    
                    # Skip if already in IDA
                    if self.is_already_in_ida(head, target):
                        continue
                        
                    # Check if target is a plausible function pointer
                    if target and self.is_valid_reference(target):
                        # Check if target is in a data segment and points to code
                        if idc.is_loaded(target):
                            # Look if the target could be a function
                            if ida_funcs.get_func(target):
                                vtable_refs.append((head, target, "vtable_func_ptr"))
                            
        return vtable_refs
        
    def get_trampoline_refs(self) -> List[Tuple[int, int, str]]:
        """
        Detect significant trampoline functions (small functions that just jump to another location).
        Filters out trivial or already known references.
        """
        trampoline_refs = []
        
        for func_ea in idautils.Functions():
            # Get function size
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Only process very small functions (very likely trampolines)
            if func.end_ea - func.start_ea > 16:  # Reduced from 20 to 16 bytes to be more strict
                continue
                
            # Skip functions with more than 2 instructions (less likely to be simple trampolines)
            instr_count = 0
            for _ in idautils.Heads(func.start_ea, func.end_ea):
                instr_count += 1
                if instr_count > 2:
                    break
                    
            if instr_count > 2:
                continue
                
            # Look for the first and only jump/call
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                if mnemonic in ["jmp", "call"]:
                    # Get the target
                    op_type = idc.get_operand_type(head, 0)
                    
                    # Only care about direct jumps/calls
                    if op_type != idc.o_near:
                        continue
                        
                    target = idc.get_operand_value(head, 0)
                    
                    # Skip invalid, trivial or already known references
                    if not self.is_valid_reference(target):
                        continue
                        
                    if self.is_trivial_jump(head, target):
                        continue
                        
                    if self.is_already_in_ida(func.start_ea, target):
                        continue
                        
                    trampoline_refs.append((func.start_ea, target, "trampoline"))
                    break  # Only consider the first jump instruction
                    
        return trampoline_refs
        
    def detect_switch_cases(self) -> List[Tuple[int, int, str]]:
        """
        Detect switch-case structures using idaapi.get_switch_info_ex.
        
        This function analyzes the binary looking for jump tables generated by
        switch-case structures in languages like C, C++, Rust or Go. It uses IDA Pro's 
        native APIs (get_switch_info_ex and calc_switch_cases) to identify and extract
        the destinations of each switch case.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Looking for switch-case structures with get_switch_info_ex...")
        switch_refs = []
        
        # To avoid duplicates
        processed_switches = set()
        
        # Check if switch functions are available
        has_switch_info = hasattr(idaapi, 'get_switch_info_ex')
        has_calc_cases = hasattr(idaapi, 'calc_switch_cases')
        
        if not has_switch_info:
            self.log("Warning: get_switch_info_ex is not available in this IDA version")
            return switch_refs
        
        # Iterate through all functions in the binary
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Iterate through all instructions in the function
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Skip if we've already processed this switch
                if head in processed_switches:
                    continue
                    
                # Try to get switch information at this address
                try:
                    switch_info = idaapi.get_switch_info_ex(head)
                    
                    # If there's no switch at this address, continue
                    if not switch_info:
                        continue
                        
                    # Mark this switch as processed
                    processed_switches.add(head)
                    
                    # Get number of cases if available
                    jcases = 0
                    if hasattr(switch_info, 'ncases'):
                        jcases = switch_info.ncases
                    
                    self.log(f"Found switch at 0x{head:x} with {jcases} cases")
                    jumps = []
                    
                    # Method 1: Use calc_switch_cases if available
                    if has_calc_cases:
                        try:
                            results = idaapi.calc_switch_cases(head, switch_info)
                            
                            if results:
                                cases, targets = results
                                jumps = targets
                                self.log(f"  - Got {len(jumps)} targets using calc_switch_cases")
                        except Exception as e:
                            self.log(f"  - Error using calc_switch_cases: {str(e)}")
                    
                    # Method 2: Access the jumptable directly if available
                    if not jumps and hasattr(switch_info, 'jumps'):
                        try:
                            jtable_addr = switch_info.jumps
                            jumps = []
                            
                            # Try to determine entry size
                            entry_size = 8  # Default to 64 bits
                            if hasattr(switch_info, 'elbase') and switch_info.elbase > 0:
                                entry_size = switch_info.elbase
                            
                            # Limit the number of cases for safety
                            max_cases = min(jcases if jcases > 0 else 100, 200)
                            
                            # Read the jumptable
                            for i in range(max_cases):
                                entry_addr = jtable_addr + (i * entry_size)
                                
                                # Read according to entry size
                                if entry_size == 8:
                                    entry_value = idc.get_qword(entry_addr)
                                elif entry_size == 4:
                                    entry_value = idc.get_wide_dword(entry_addr)
                                elif entry_size == 2:
                                    entry_value = idc.get_wide_word(entry_addr)
                                else:
                                    entry_value = idc.get_wide_byte(entry_addr)
                                    
                                if entry_value and self.is_valid_reference(entry_value):
                                    jumps.append(entry_value)
                                elif i > 0:  # If we find an invalid entry after the first one, we're done
                                    break
                            
                            if jumps:
                                self.log(f"  - Got {len(jumps)} targets from the jump table")
                        except Exception as e:
                            self.log(f"  - Error reading jump table: {str(e)}")
                    
                    # Method 3: Look for code references
                    if not jumps:
                        self.log(f"  - Using alternative method to find targets")
                        
                        # Get the instruction's operand
                        for i in range(2):  # Check up to 2 operands
                            if idc.get_operand_type(head, i) == idc.o_mem:
                                mem_addr = idc.get_operand_value(head, i)
                                if mem_addr:
                                    # Look for code references from this address
                                    for xref in idautils.XrefsFrom(head, idautils.XREF_ALL):
                                        if xref.type == idautils.XrefTypeName.Code_Near_Jump or xref.type == idautils.XrefTypeName.Ordinary_Flow:
                                            target = xref.to
                                            if self.is_valid_reference(target) and not target in jumps:
                                                jumps.append(target)
                    
                    # Process each target found
                    for idx, target in enumerate(jumps):
                        # Validate the target
                        if self.is_valid_reference(target):
                            # Check it's not a duplicate and not already in IDA
                            if not self.is_already_in_ida(head, target):
                                ref_type = f"switch_case_{idx}"
                                switch_refs.append((head, target, ref_type))
                                
                except Exception as e:
                    self.log(f"Error processing switch at 0x{head:x}: {str(e)}")
                    continue
                
        self.log(f"Found {len(switch_refs)} switch-case references")
        return switch_refs
        
    def detect_stack_variable_refs(self) -> List[Tuple[int, int, str]]:
        """
        Track stack variables used as function pointers or indirect references.
        Common in malware and obfuscated code where function pointers are
        stored on the stack and called indirectly.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Analyzing stack variable references...")
        stack_refs = []
        
        # Track stack variable assignments and usage
        stack_vars = {}  # {func_ea: {offset: possible_target}}
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # Track stack variable assignments in this function
            func_stack_vars = {}
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Look for stack variable assignments: mov [rbp+var_XX], value
                if mnemonic == "mov":
                    # Get operands
                    op1_type = idc.get_operand_type(head, 0)
                    op2_type = idc.get_operand_type(head, 1)
                    
                    # Check if destination is stack variable (displacement from rbp/rsp)
                    if op1_type == idc.o_displ:
                        op1_str = idc.print_operand(head, 0)
                        
                        # Parse stack variable reference [rbp+var_XX] or [rsp+XX]
                        if '[' in op1_str and ('+' in op1_str or '-' in op1_str):
                            # Extract the offset
                            try:
                                if 'rbp' in op1_str or 'ebp' in op1_str:
                                    # Local variable
                                    if '+' in op1_str:
                                        offset_str = op1_str.split('+')[1].split(']')[0]
                                    else:
                                        offset_str = op1_str.split('-')[1].split(']')[0]
                                        
                                    # Check if source operand is a potential function address
                                    if op2_type == idc.o_imm:
                                        target = idc.get_operand_value(head, 1)
                                        if self.is_valid_reference(target):
                                            # Store this stack variable assignment
                                            func_stack_vars[offset_str] = (target, head)
                                            
                                    elif op2_type == idc.o_reg:
                                        # Register source - try to trace back the value
                                        target = self.find_constant_loads(head, 5)
                                        if target and self.is_valid_reference(target):
                                            func_stack_vars[offset_str] = (target, head)
                                            
                            except (IndexError, ValueError):
                                continue
                
                # Look for stack variable usage: call [rbp+var_XX] or jmp [rbp+var_XX]
                elif mnemonic in ["call", "jmp"]:
                    op1_type = idc.get_operand_type(head, 0)
                    
                    if op1_type == idc.o_displ:
                        op1_str = idc.print_operand(head, 0)
                        
                        # Parse stack variable reference
                        if '[' in op1_str and ('+' in op1_str or '-' in op1_str):
                            try:
                                if 'rbp' in op1_str or 'ebp' in op1_str:
                                    if '+' in op1_str:
                                        offset_str = op1_str.split('+')[1].split(']')[0]
                                    else:
                                        offset_str = op1_str.split('-')[1].split(']')[0]
                                    
                                    # Check if we have a stored value for this stack variable
                                    if offset_str in func_stack_vars:
                                        target, assign_addr = func_stack_vars[offset_str]
                                        if not self.is_already_in_ida(head, target):
                                            ref_type = f"stack_var_{mnemonic}"
                                            stack_refs.append((head, target, ref_type))
                                            
                            except (IndexError, ValueError):
                                continue
                
                # Look for lea instruction loading stack variable address
                elif mnemonic == "lea":
                    op1_type = idc.get_operand_type(head, 0)
                    op2_type = idc.get_operand_type(head, 1)
                    
                    if op1_type == idc.o_reg and op2_type == idc.o_displ:
                        op2_str = idc.print_operand(head, 1)
                        
                        # This loads the address of a stack variable
                        # Look for subsequent usage of this register
                        reg = idc.get_operand_value(head, 0)
                        
                        # Scan forward a few instructions to see if this register is used
                        next_ea = head
                        for _ in range(5):
                            next_ea = idc.next_head(next_ea)
                            if next_ea == idc.BADADDR:
                                break
                                
                            next_mnem = idc.print_insn_mnem(next_ea).lower()
                            if next_mnem in ["call", "jmp"]:
                                next_op_type = idc.get_operand_type(next_ea, 0)
                                if next_op_type == idc.o_reg:
                                    used_reg = idc.get_operand_value(next_ea, 0)
                                    if used_reg == reg:
                                        # This is an indirect call through stack variable address
                                        # Try to resolve the target
                                        target = self.resolve_indirect_target(next_ea)
                                        if target and not self.is_already_in_ida(next_ea, target):
                                            stack_refs.append((next_ea, target, "stack_var_lea_call"))
                                        break
            
        self.log(f"Found {len(stack_refs)} stack variable references")
        return stack_refs
    
    def analyze_hexrays_pseudocode(self) -> List[Tuple[int, int, str]]:
        """
        Analyze Hex-Rays decompiled pseudocode for hidden references.
        This can reveal function pointers, indirect calls, and data references
        that are obfuscated in assembly but visible in decompiled code.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Analyzing Hex-Rays pseudocode for hidden references...")
        pseudocode_refs = []
        
        try:
            import ida_hexrays
        except ImportError:
            self.log("Warning: Hex-Rays decompiler not available, skipping pseudocode analysis")
            return pseudocode_refs
        
        # Check if decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            self.log("Warning: Hex-Rays decompiler not initialized")
            return pseudocode_refs
        
        # Process all functions
        for func_ea in idautils.Functions():
            try:
                # Get function object
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                    
                # Try to decompile the function
                cfunc = ida_hexrays.decompile(func)
                if not cfunc:
                    continue
                    
                # Get the pseudocode text
                pseudocode_text = str(cfunc)
                if not pseudocode_text:
                    continue
                
                # Analyze pseudocode for patterns
                # Look for function pointer calls: func_ptr()
                import re
                
                # Pattern 1: Direct function pointer calls like "sub_401000()"
                func_call_pattern = r'sub_([0-9A-Fa-f]+)\s*\('
                for match in re.finditer(func_call_pattern, pseudocode_text):
                    try:
                        target_addr = int(match.group(1), 16)
                        # Convert to full address (assuming standard base)
                        if target_addr < 0x10000:  # Relative address
                            continue
                        
                        if self.is_valid_reference(target_addr):
                            if not self.is_already_in_ida(func_ea, target_addr):
                                pseudocode_refs.append((func_ea, target_addr, "pseudocode_func_call"))
                    except ValueError:
                        continue
                
                # Pattern 2: Function pointer dereferences like "(*func_ptr)()"
                func_ptr_pattern = r'\(\*[a-zA-Z_][a-zA-Z0-9_]*\)\s*\('
                matches = re.finditer(func_ptr_pattern, pseudocode_text)
                for match in matches:
                    # This indicates an indirect call through function pointer
                    # We need to find the actual address from the context
                    # Look for assignments to this variable
                    var_name = match.group(0).split('*')[1].split(')')[0]
                    assignment_pattern = f'{var_name}\\s*=\\s*([a-zA-Z_][a-zA-Z0-9_]*|0x[0-9A-Fa-f]+)'
                    
                    for assign_match in re.finditer(assignment_pattern, pseudocode_text):
                        try:
                            value = assign_match.group(1)
                            if value.startswith('0x'):
                                target_addr = int(value, 16)
                            elif value.startswith('sub_'):
                                target_addr = int(value[4:], 16)
                            else:
                                continue
                                
                            if self.is_valid_reference(target_addr):
                                if not self.is_already_in_ida(func_ea, target_addr):
                                    pseudocode_refs.append((func_ea, target_addr, "pseudocode_func_ptr"))
                        except (ValueError, IndexError):
                            continue
                
                # Pattern 3: Array/structure member function calls like "vtable->func()"
                vtable_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)->([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
                for match in re.finditer(vtable_pattern, pseudocode_text):
                    # This suggests vtable or structure function pointer access
                    # Mark this location for potential vtable analysis
                    pseudocode_refs.append((func_ea, func_ea, "pseudocode_vtable_access"))
                
            except Exception as e:
                # Decompilation can fail for various reasons
                continue
                
        self.log(f"Found {len(pseudocode_refs)} references from pseudocode analysis")
        return pseudocode_refs
        
    def analyze_string_references(self) -> List[Tuple[int, int, str]]:
        """
        Analyze string references that might indicate important functionality.
        Focuses on strings that suggest malicious behavior, API names, file paths,
        URLs, registry keys, and other indicators of interest.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Analyzing significant string references...")
        string_refs = []
        
        # Categories of interesting strings
        interesting_patterns = {
            'malware_indicator': [
                'createprocess', 'virtualalloc', 'virtualprotect', 'writeprocessmemory',
                'readprocessmemory', 'openprocess', 'getprocaddress', 'loadlibrary',
                'shellexecute', 'winexec', 'system', 'createthread', 'createremotethread',
                'setwindowshook', 'findwindow', 'enumprocesses', 'enummodules'
            ],
            'crypto_indicator': [
                'encrypt', 'decrypt', 'cipher', 'aes', 'des', 'rsa', 'md5', 'sha',
                'cryptapi', 'cryptgenkey', 'cryptcreatekey', 'bcrypt', 'crypto'
            ],
            'network_indicator': [
                'http', 'https', 'ftp', 'smtp', 'tcp', 'udp', 'socket', 'wsastartup',
                'connect', 'send', 'recv', 'inet_addr', 'gethostbyname', 'wininet'
            ],
            'file_indicator': [
                'createfile', 'readfile', 'writefile', 'deletefile', 'movefile',
                'copyfile', 'findfirstfile', 'findnextfile', 'setfileattributes'
            ],
            'registry_indicator': [
                'regopenkeyex', 'regclosekey', 'regqueryvalueex', 'regsetvalueex',
                'regcreatekey', 'regdeletekey', 'regdeletevalue', 'regenumkey'
            ],
            'persistence_indicator': [
                'createservice', 'openservice', 'startservice', 'controlservice',
                'taskscheduler', 'schtasks', 'startup', 'run', 'runonce'
            ]
        }
        
        # Collect all strings in the binary
        binary_strings = {}
        
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
                
            # Look for strings in data segments
            if seg.type in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]:
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    # Try to get string at this address
                    string_val = idc.get_strlit_contents(head)
                    if string_val:
                        try:
                            string_str = string_val.decode('utf-8', errors='ignore').lower()
                            if len(string_str) > 2:  # Only consider strings longer than 2 chars
                                binary_strings[head] = string_str
                        except:
                            continue
        
        # Analyze string references for interesting patterns
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Look for instructions that reference strings
                mnemonic = idc.print_insn_mnem(head).lower()
                
                if mnemonic in ["mov", "lea", "push"]:
                    # Check each operand for memory references
                    for op_idx in range(2):
                        op_type = idc.get_operand_type(head, op_idx)
                        if op_type == idc.o_mem:
                            addr = idc.get_operand_value(head, op_idx)
                            
                            # Check if this address contains an interesting string
                            if addr in binary_strings:
                                string_content = binary_strings[addr]
                                
                                # Categorize the string
                                for category, patterns in interesting_patterns.items():
                                    for pattern in patterns:
                                        if pattern in string_content:
                                            if not self.is_already_in_ida(head, addr):
                                                ref_type = f"string_{category}_{pattern}"
                                                string_refs.append((head, addr, ref_type))
                                            break
                                    else:
                                        continue
                                    break
                                
                                # Also check for file paths and URLs
                                if ('\\' in string_content or '/' in string_content) and len(string_content) > 5:
                                    if not self.is_already_in_ida(head, addr):
                                        string_refs.append((head, addr, "string_path"))
                                
                                if ('http://' in string_content or 'https://' in string_content or 
                                    'ftp://' in string_content):
                                    if not self.is_already_in_ida(head, addr):
                                        string_refs.append((head, addr, "string_url"))
                                
                                # Check for registry paths
                                if ('hkey_' in string_content or 'software\\' in string_content or
                                    'system\\' in string_content):
                                    if not self.is_already_in_ida(head, addr):
                                        string_refs.append((head, addr, "string_registry"))
                                
                                # Check for API names (strings that match function naming patterns)
                                if (string_content.replace('_', '').replace('.', '').isalnum() and
                                    len(string_content) > 4 and 
                                    (string_content[0].isupper() or string_content.startswith('_'))):
                                    if not self.is_already_in_ida(head, addr):
                                        string_refs.append((head, addr, "string_api_name"))
        
        # Look for indirect string references (strings loaded into registers then used)
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Track register assignments
            reg_strings = {}
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Track string loading into registers
                if mnemonic in ["mov", "lea"]:
                    dest_type = idc.get_operand_type(head, 0)
                    src_type = idc.get_operand_type(head, 1)
                    
                    if dest_type == idc.o_reg and src_type == idc.o_mem:
                        reg = idc.get_operand_value(head, 0)
                        addr = idc.get_operand_value(head, 1)
                        
                        if addr in binary_strings:
                            reg_strings[reg] = (addr, binary_strings[addr])
                
                # Look for usage of registers containing strings
                elif mnemonic in ["push", "call"]:
                    for op_idx in range(2):
                        op_type = idc.get_operand_type(head, op_idx)
                        if op_type == idc.o_reg:
                            reg = idc.get_operand_value(head, op_idx)
                            if reg in reg_strings:
                                str_addr, str_content = reg_strings[reg]
                                if not self.is_already_in_ida(head, str_addr):
                                    string_refs.append((head, str_addr, "string_indirect_ref"))
        
        self.log(f"Found {len(string_refs)} significant string references")
        return string_refs
    
    def detect_dynamic_imports(self) -> List[Tuple[int, int, str]]:
        """
        Detect dynamic import resolution patterns like GetProcAddress calls,
        dlsym usage, and other runtime function loading techniques.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Analyzing dynamic import patterns...")
        import_refs = []
        
        # API functions that indicate dynamic imports
        dynamic_apis = {
            "GetProcAddress", "GetProcAddressA", "GetProcAddressW",
            "dlsym", "dlopen", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
            "LdrGetProcedureAddress", "LdrLoadDll"
        }
        
        # String references that might be function names
        potential_api_strings = []
        
        # First pass: collect string references that could be API names
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
                
            # Check if this is a data segment
            if seg.type == ida_segment.SEG_DATA or seg.type == ida_segment.SEG_BSS:
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    # Look for strings
                    string_val = idc.get_strlit_contents(head)
                    if string_val:
                        string_str = string_val.decode('utf-8', errors='ignore')
                        
                        # Check if this looks like an API name
                        if (len(string_str) > 3 and 
                            string_str.isalnum() and 
                            (string_str[0].isupper() or string_str.startswith('_'))):
                            potential_api_strings.append((head, string_str))
        
        # Second pass: look for dynamic API resolution patterns
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Track potential API loading sequences
            api_calls = []
            string_loads = []
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Look for calls to dynamic loading APIs
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type == ida_xref.fl_CN:  # Call reference
                        target_name = idc.get_name(xref.to)
                        if any(api in target_name for api in dynamic_apis):
                            api_calls.append((head, target_name, xref.to))
                
                # Look for string loading before API calls
                mnemonic = idc.print_insn_mnem(head).lower()
                if mnemonic in ["mov", "lea", "push"]:
                    op_type = idc.get_operand_type(head, 1)
                    if op_type == idc.o_mem:
                        addr = idc.get_operand_value(head, 1)
                        # Check if this address corresponds to a potential API string
                        for str_addr, str_val in potential_api_strings:
                            if addr == str_addr:
                                string_loads.append((head, str_val, addr))
            
            # Correlate string loads with API calls
            for call_addr, api_name, api_target in api_calls:
                # Look for string loads before this API call
                for load_addr, string_val, string_addr in string_loads:
                    if load_addr < call_addr and (call_addr - load_addr) < 50:  # Within 50 instructions
                        # This is likely a dynamic import resolution
                        import_refs.append((call_addr, api_target, f"dynamic_import_{string_val}"))
                        
                        # Also add the string reference
                        import_refs.append((load_addr, string_addr, f"api_string_{string_val}"))
        
        # Third pass: look for manual dll loading and function resolution
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Look for patterns like:
            # 1. LoadLibrary call
            # 2. GetProcAddress call  
            # 3. Indirect call to resolved function
            
            library_loads = []
            proc_gets = []
            indirect_calls = []
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                # Collect different types of calls
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type == ida_xref.fl_CN:
                        target_name = idc.get_name(xref.to)
                        if "LoadLibrary" in target_name:
                            library_loads.append(head)
                        elif "GetProcAddress" in target_name:
                            proc_gets.append(head)
                
                # Look for indirect calls that might use resolved functions
                mnemonic = idc.print_insn_mnem(head).lower()
                if mnemonic in ["call", "jmp"]:
                    op_type = idc.get_operand_type(head, 0)
                    if op_type in [idc.o_reg, idc.o_mem]:
                        indirect_calls.append(head)
            
            # If we have LoadLibrary -> GetProcAddress -> indirect call pattern
            if library_loads and proc_gets and indirect_calls:
                # Find the sequence
                for lib_call in library_loads:
                    for proc_call in proc_gets:
                        if proc_call > lib_call:
                            for indirect_call in indirect_calls:
                                if indirect_call > proc_call and (indirect_call - proc_call) < 20:
                                    # This looks like a dynamic import resolution sequence
                                    target = self.resolve_indirect_target(indirect_call)
                                    if target and not self.is_already_in_ida(indirect_call, target):
                                        import_refs.append((indirect_call, target, "resolved_dynamic_import"))
                                    break
        
        self.log(f"Found {len(import_refs)} dynamic import references")
        return import_refs
        
    def detect_variable_references(self) -> List[Tuple[int, int, str]]:
        """
        Detect references to global variables, static data, and important local variables.
        This helps identify data flow that might not be obvious from function calls alone.
        
        Returns:
            List of tuples (source_address, target_address, reference_type)
        """
        self.log("Analyzing variable references...")
        var_refs = []
        
        # Collect global variables and static data locations
        global_vars = {}
        
        # First pass: identify potential global variables in data segments
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
                
            # Look for initialized data segments
            if seg.type in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]:
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    # Check if this looks like a variable (has a name and references)
                    var_name = idc.get_name(head)
                    if var_name and not var_name.startswith('unk_'):
                        # Check if this address is referenced by code
                        refs_to = list(idautils.XrefsTo(head))
                        if refs_to:
                            # This looks like a global variable
                            var_value = idc.get_qword(head)
                            if var_value and self.is_valid_reference(var_value):
                                global_vars[head] = (var_name, var_value)
        
        # Second pass: analyze function pointer tables and vtables
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
                
            if seg.type == ida_segment.SEG_DATA:
                curr_addr = seg.start_ea
                
                while curr_addr < seg.end_ea:
                    # Check for sequences of function pointers (potential vtables)
                    func_ptr_count = 0
                    table_start = curr_addr
                    
                    # Look for consecutive function pointers
                    for i in range(10):  # Check up to 10 consecutive entries
                        ptr_addr = curr_addr + (i * 8)  # Assuming 64-bit pointers
                        if ptr_addr >= seg.end_ea:
                            break
                            
                        ptr_value = idc.get_qword(ptr_addr)
                        if ptr_value and self.is_valid_reference(ptr_value):
                            func_ptr_count += 1
                        else:
                            break
                    
                    # If we found a table with multiple function pointers
                    if func_ptr_count >= 3:
                        # This looks like a vtable or function pointer table
                        for i in range(func_ptr_count):
                            ptr_addr = table_start + (i * 8)
                            ptr_value = idc.get_qword(ptr_addr)
                            
                            # Find references to this table entry
                            for xref in idautils.XrefsTo(ptr_addr):
                                if not self.is_already_in_ida(xref.frm, ptr_value):
                                    var_refs.append((xref.frm, ptr_value, f"vtable_entry_{i}"))
                    
                    curr_addr += max(8, func_ptr_count * 8)
        
        # Third pass: analyze local variable usage patterns
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Track local variable assignments that might contain function pointers
            local_vars = {}
            
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Look for global variable references
                for op_idx in range(2):
                    op_type = idc.get_operand_type(head, op_idx)
                    if op_type == idc.o_mem:
                        addr = idc.get_operand_value(head, op_idx)
                        
                        # Check if this is a global variable
                        if addr in global_vars:
                            var_name, var_value = global_vars[addr]
                            if not self.is_already_in_ida(head, var_value):
                                var_refs.append((head, var_value, f"global_var_{var_name}"))
                
                # Look for assignments to local variables that might be function pointers
                if mnemonic == "mov":
                    dest_type = idc.get_operand_type(head, 0)
                    src_type = idc.get_operand_type(head, 1)
                    
                    # mov [local_var], immediate_value
                    if dest_type == idc.o_displ and src_type == idc.o_imm:
                        target = idc.get_operand_value(head, 1)
                        if self.is_valid_reference(target):
                            dest_str = idc.print_operand(head, 0)
                            # Store this for later reference analysis
                            local_vars[dest_str] = target
                    
                    # mov register, [global_var] - loading global variable
                    elif dest_type == idc.o_reg and src_type == idc.o_mem:
                        addr = idc.get_operand_value(head, 1)
                        if addr in global_vars:
                            var_name, var_value = global_vars[addr]
                            if var_value != addr:  # The variable contains a different address
                                if not self.is_already_in_ida(head, var_value):
                                    var_refs.append((head, var_value, f"global_var_load_{var_name}"))
        
        # Fourth pass: analyze structure member accesses that might be function pointers
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnemonic = idc.print_insn_mnem(head).lower()
                
                # Look for structure member accesses: mov reg, [reg+offset]
                if mnemonic in ["mov", "call", "jmp"]:
                    for op_idx in range(2):
                        op_type = idc.get_operand_type(head, op_idx)
                        if op_type == idc.o_displ:
                            # This is a register + offset access
                            op_str = idc.print_operand(head, op_idx)
                            
                            # Try to resolve if this might be accessing a function pointer
                            if '[' in op_str and '+' in op_str:
                                # Look backwards to see if the base register was loaded with a data address
                                base_reg = op_str[op_str.find('[')+1:op_str.find('+')].strip()
                                
                                # Scan backwards to find where this register was loaded
                                curr_ea = head
                                for _ in range(10):
                                    curr_ea = idc.prev_head(curr_ea)
                                    if curr_ea == idc.BADADDR:
                                        break
                                        
                                    if idc.print_insn_mnem(curr_ea).lower() == "mov":
                                        dest_str = idc.print_operand(curr_ea, 0)
                                        if dest_str.lower() == base_reg.lower():
                                            # Found where the base register was loaded
                                            src_type = idc.get_operand_type(curr_ea, 1)
                                            if src_type == idc.o_mem:
                                                base_addr = idc.get_operand_value(curr_ea, 1)
                                                
                                                # Check if this base address + offset contains a function pointer
                                                try:
                                                    offset_str = op_str[op_str.find('+')+1:op_str.find(']')]
                                                    offset = int(offset_str, 0) if offset_str.isdigit() or offset_str.startswith('0x') else 0
                                                    
                                                    ptr_addr = base_addr + offset
                                                    ptr_value = idc.get_qword(ptr_addr)
                                                    
                                                    if ptr_value and self.is_valid_reference(ptr_value):
                                                        if not self.is_already_in_ida(head, ptr_value):
                                                            var_refs.append((head, ptr_value, f"struct_member_ptr"))
                                                except:
                                                    pass
                                                break
        
        self.log(f"Found {len(var_refs)} variable references")
        return var_refs
    
    def generate_xrefs(self) -> None:
        """Generate filtered cross-references and write them to file."""
        self.log("Starting cross-reference generation...")
        
        # Collect all types of references
        indirect_refs = self.get_indirect_calls()
        self.log(f"Found {len(indirect_refs)} significant indirect calls/jumps")
        
        switch_refs = self.get_switch_cases()
        self.log(f"Found {len(switch_refs)} significant switch case references")
        
        # Advanced switch-case detection with get_switch_info_ex
        advanced_switch_refs = self.detect_switch_cases()
        self.log(f"Found {len(advanced_switch_refs)} switch-case references using get_switch_info_ex")
        
        vtable_refs = self.get_vtable_constructors()
        self.log(f"Found {len(vtable_refs)} significant vtable constructor references")
        
        trampoline_refs = self.get_trampoline_refs()
        self.log(f"Found {len(trampoline_refs)} significant trampoline functions")
        
        # Get advanced detection patterns
        advanced_refs = self.detect_trampolines_or_vtables()
        self.log(f"Found {len(advanced_refs)} advanced dispatch patterns")
        
        # Analyze Hex-Rays pseudocode for hidden references
        pseudocode_refs = self.analyze_hexrays_pseudocode()
        self.log(f"Found {len(pseudocode_refs)} references from pseudocode analysis")
        
        # Analyze string references
        string_refs = self.analyze_string_references()
        self.log(f"Found {len(string_refs)} significant string references")
        
        # Analyze stack variable references  
        stack_refs = self.detect_stack_variable_refs()
        self.log(f"Found {len(stack_refs)} stack variable references")
        
        # Detect dynamic imports
        import_refs = self.detect_dynamic_imports()
        self.log(f"Found {len(import_refs)} dynamic import references")
        
        # Analyze variable references
        var_refs = self.detect_variable_references()
        self.log(f"Found {len(var_refs)} variable references")
        
        # Process all references
        for source, target, ref_type in (
            indirect_refs + switch_refs + vtable_refs + trampoline_refs + 
            advanced_refs + advanced_switch_refs + pseudocode_refs + string_refs +
            stack_refs + import_refs + var_refs
        ):
            # Skip self-references
            if source == target:
                continue
                
            # Validate reference target
            if not self.is_valid_reference(target):
                continue
                
            # Store in our dictionary (this automatically handles duplicates)
            self.xrefs[(source, target)] = ref_type
                
        # Write results to file
        output_file = os.path.join(os.path.dirname(self.binary_path), "_user_xrefs.txt")
        with open(output_file, 'w') as f:
            for (source, target), ref_type in sorted(self.xrefs.items()):
                f.write(f"0x{source:x},0x{target:x} # {ref_type}\n")
                
        self.log(f"Generated {len(self.xrefs)} significant cross-references")
        self.log(f"Results written to: {output_file}")
        self.log("Complete. Use these references with Mandiant XRefer plugin.")

def main():
    """Main entry point for the script."""
    generator = XrefGenerator()
    generator.generate_xrefs()

if __name__ == "__main__":
    main() 