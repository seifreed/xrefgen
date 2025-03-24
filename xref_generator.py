#!/usr/bin/env python3
"""
IDA Pro Cross-Reference Generator for Mandiant XRefer
Author: Marc Rivero | @seifreed
Version: 1.1
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
        
        # Process all references
        for source, target, ref_type in (
            indirect_refs + switch_refs + vtable_refs + trampoline_refs + 
            advanced_refs + advanced_switch_refs
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