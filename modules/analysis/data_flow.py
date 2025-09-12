"""
Enhanced Data Flow Analysis Module
Tracks data flow from sources to sinks, return value propagation, and pointer chains
"""

from typing import Dict, List, Tuple, Set, Optional
import idaapi
import idautils
import idc
import ida_funcs
import ida_ua
import ida_xref
from modules.core.base import XrefAnalyzer
from modules.utils import abi
try:
    import ida_ida
except ImportError:
    ida_ida = None

class DataFlowAnalyzer(XrefAnalyzer):
    """Enhanced data flow analysis for taint tracking and value propagation"""
    
    def _safe_get_operand_value(self, ea: int, op_idx: int) -> Optional[int]:
        """Safely get operand value with error handling"""
        try:
            if idc.get_operand_type(ea, op_idx) != idc.o_void:
                return idc.get_operand_value(ea, op_idx)
        except:
            pass
        return None
    
    def _safe_print_operand(self, ea: int, op_idx: int) -> str:
        """Safely get operand string with error handling"""
        try:
            if idc.get_operand_type(ea, op_idx) != idc.o_void:
                return idc.print_operand(ea, op_idx)
        except:
            pass
        return ""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.taint_sources = set(config.get('taint_sources', [
            'recv', 'read', 'fread', 'scanf', 'gets', 'getchar',
            'recvfrom', 'recvmsg', 'ReadFile', 'InternetReadFile',
            'fgets', 'getenv', 'getline', 'fscanf'
        ]))
        self.taint_sinks = set(config.get('taint_sinks', [
            'system', 'exec', 'strcpy', 'sprintf', 'memcpy',
            'execve', 'execl', 'ShellExecute', 'CreateProcess',
            'strcat', 'vsprintf', 'WinExec', 'popen'
        ]))
        self.max_taint_depth = config.get('max_taint_depth', 10)
        self.tainted_regs = {}  # func_ea -> {reg: (source_ea, confidence)}
        self.tainted_mem = {}   # func_ea -> {mem_addr: (source_ea, confidence)}
        self.return_values = {}  # func_ea -> (value, confidence)
        # Some IDA versions (including 9.1 Python API) do not expose idc.get_sp_val
        # Guard stack taint tracking accordingly
        self._has_get_sp_val = hasattr(idc, 'get_sp_val')
        
    def get_name(self) -> str:
        return "DataFlowAnalyzer"
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform comprehensive data flow analysis"""
        results = []
        
        try:
            # Analyze taint propagation
            taint_refs = self._analyze_taint_propagation()
            results.extend(taint_refs)
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in taint analysis: {e}")
        
        try:
            # Analyze return value propagation
            return_refs = self._analyze_return_values()
            results.extend(return_refs)
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in return value analysis: {e}")
        
        try:
            # Analyze multi-level pointer chains
            pointer_refs = self._analyze_pointer_chains()
            results.extend(pointer_refs)
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in pointer chain analysis: {e}")
        
        return results
    
    def _analyze_taint_propagation(self) -> List[Tuple[int, int, str, float]]:
        """Track data flow from taint sources to sinks"""
        results = []
        
        # Find all taint sources
        for func_ea in idautils.Functions():
            try:
                func_name = idc.get_func_name(func_ea)
                if not func_name:
                    continue
            except:
                continue
            
            # Check if this function is a taint source
            for source in self.taint_sources:
                if source in func_name.lower():
                    # Mark all callers as tainted
                    for xref in idautils.XrefsTo(func_ea):
                        if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                            self._propagate_taint_from_call(xref.frm, func_ea)
            
            # Analyze function for taint propagation
            self._analyze_function_taint(func_ea)
        
        # Find paths from sources to sinks
        for func_ea in idautils.Functions():
            try:
                func_name = idc.get_func_name(func_ea)
                if not func_name:
                    continue
            except:
                continue
            
            # Check if this function is a taint sink
            for sink in self.taint_sinks:
                if sink in func_name.lower():
                    # Check if any arguments are tainted
                    for xref in idautils.XrefsTo(func_ea):
                        if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                            taint_info = self._check_tainted_arguments(xref.frm)
                            if taint_info:
                                source_ea, confidence = taint_info
                                self.add_xref(source_ea, xref.frm, 
                                            f"taint_flow_{sink}", confidence * 0.9)
                                results.append((source_ea, xref.frm, 
                                              f"taint_flow_{sink}", confidence * 0.9))
        
        return results
    
    def _propagate_taint_from_call(self, call_ea: int, source_func: int):
        """Propagate taint from a function call"""
        func = ida_funcs.get_func(call_ea)
        if not func:
            return
            
        # Get return register name based on ABI
        ret_reg = abi.return_reg()
            
        # Mark return value as tainted
        if func.start_ea not in self.tainted_regs:
            self.tainted_regs[func.start_ea] = {}
        self.tainted_regs[func.start_ea][ret_reg] = (call_ea, 0.9)
        
        # Track forward from call
        self._track_register_forward(call_ea, ret_reg, source_func)
    
    def _analyze_function_taint(self, func_ea: int):
        """Analyze taint propagation within a function"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return
            
        for head in idautils.Heads(func.start_ea, func.end_ea):
            try:
                mnem = idc.print_insn_mnem(head).lower()
                if not mnem:
                    continue
            except:
                continue
            
            # Track MOV instructions for taint propagation
            if mnem == "mov":
                self._track_mov_taint(head, func_ea)
            # Track arithmetic operations that preserve taint
            elif mnem in ["add", "sub", "xor", "or", "and", "shl", "shr"]:
                self._track_arithmetic_taint(head, func_ea)
            # Track memory operations
            elif mnem in ["push", "pop"]:
                self._track_stack_taint(head, func_ea)
    
    def _track_mov_taint(self, ea: int, func_ea: int):
        """Track taint through MOV instructions"""
        try:
            dst_type = idc.get_operand_type(ea, 0)
            src_type = idc.get_operand_type(ea, 1)
        except:
            return
        
        # Get destination
        if dst_type == idc.o_reg:
            dst_reg = self._safe_print_operand(ea, 0).lower()
            if not dst_reg:
                return
            
            # Check if source is tainted
            if src_type == idc.o_reg:
                src_reg = self._safe_print_operand(ea, 1).lower()
                if not src_reg:
                    return
                if func_ea in self.tainted_regs and src_reg in self.tainted_regs[func_ea]:
                    # Propagate taint
                    source, conf = self.tainted_regs[func_ea][src_reg]
                    self.tainted_regs[func_ea][dst_reg] = (source, conf * 0.95)
    
    def _track_register_forward(self, start_ea: int, reg: str, source: int):
        """Track a tainted register forward through the code"""
        func = ida_funcs.get_func(start_ea)
        if not func:
            return
            
        ea = idc.next_head(start_ea)
        depth = 0
        
        while ea < func.end_ea and depth < self.max_taint_depth:
            mnem = idc.print_insn_mnem(ea).lower()
            
            # Check if register is used
            for i in range(2):
                op_type = idc.get_operand_type(ea, i)
                if op_type == idc.o_reg:
                    op_reg = idc.print_operand(ea, i).lower()
                    if op_reg == reg:
                        # Register is used
                        if mnem in ["call", "jmp"] and i == 0:
                            # Indirect call/jump through tainted register
                            target = self._resolve_register_value(ea, reg)
                            if target and self.is_valid_reference(target):
                                self.add_xref(source, target, "tainted_indirect_call", 0.8)
                        break
            
            ea = idc.next_head(ea)
            depth += 1
    
    def _check_tainted_arguments(self, call_ea: int) -> Optional[Tuple[int, float]]:
        """Check if any arguments to a call are tainted"""
        func = ida_funcs.get_func(call_ea)
        if not func or func.start_ea not in self.tainted_regs:
            return None
            
        # Argument registers based on ABI (supports SysV and Win64)
        arg_regs = abi.arg_registers()
        
        for reg_name in arg_regs:
            if reg_name in self.tainted_regs[func.start_ea]:
                return self.tainted_regs[func.start_ea][reg_name]
                
        # If no tainted registers, scan stack stores/pushes prior to call
        stack_taint = self._scan_stack_arguments(call_ea, func)
        if stack_taint:
            return stack_taint
        return None

    def _scan_stack_arguments(self, call_ea: int, func) -> Optional[Tuple[int, float]]:
        """Scan a window before call for stack-based argument setup.
        - Win64: detect home space stores to [rsp+0..24]
        - SysV: detect additional args via pushes or [rsp+offset] stores
        Returns (source_ea, confidence) if tainted data flows into an argument.
        """
        max_back = 16
        win64 = (abi.calling_convention() == 'win64')
        win_slots = {0, 8, 16, 24}
        shadow_size = 0  # detected SUB RSP, imm before call
        ea = call_ea
        for _ in range(max_back):
            ea = idc.prev_head(ea)
            if ea == idc.BADADDR or ea < func.start_ea:
                break
            mnem = idc.print_insn_mnem(ea).lower()
            # Detect stack reservation near call (Win64 shadow space or prologue sizing)
            if mnem == 'sub':
                d0 = idc.get_operand_type(ea, 0)
                d1 = idc.get_operand_type(ea, 1)
                if d0 == idc.o_reg and d1 == idc.o_imm:
                    if idc.print_operand(ea, 0).lower() in ('rsp', 'esp'):
                        try:
                            shadow_size = int(idc.get_operand_value(ea, 1))
                        except Exception:
                            shadow_size = 0
            # mov [rsp+imm], reg
            if mnem == 'mov':
                dst_type = idc.get_operand_type(ea, 0)
                src_type = idc.get_operand_type(ea, 1)
                if dst_type == idc.o_displ:
                    op = idc.print_operand(ea, 0).lower()
                    if op.startswith('[rsp+') or op.startswith('[esp+'):
                        # Extract offset
                        try:
                            off_str = op.split('+', 1)[1].rstrip(']')
                            off = int(off_str, 0) if off_str.startswith('0x') or off_str.isdigit() else -1
                        except Exception:
                            off = -1
                        # Accept canonical homes (0..24), or any 8-byte slot within locally detected reservation
                        accept_win64 = (off in win_slots) or (shadow_size and 0 <= off < shadow_size and off % 8 == 0)
                        if off >= 0 and ((not win64) or accept_win64):
                            # If source is a tainted reg, treat as tainted arg
                            if src_type == idc.o_reg:
                                src_reg = idc.print_operand(ea, 1).lower()
                                if src_reg in self.tainted_regs.get(func.start_ea, {}):
                                    return self.tainted_regs[func.start_ea][src_reg]
                            # If source is immediate/address (low confidence)
                            if src_type == idc.o_imm:
                                val = idc.get_operand_value(ea, 1)
                                if self.is_valid_reference(val):
                                    return (ea, 0.5)
            # push reg/imm (cdecl/SysV extras)
            if mnem == 'push':
                op_type = idc.get_operand_type(ea, 0)
                if op_type == idc.o_reg:
                    src_reg = idc.print_operand(ea, 0).lower()
                    if src_reg in self.tainted_regs.get(func.start_ea, {}):
                        return self.tainted_regs[func.start_ea][src_reg]
                elif op_type == idc.o_imm:
                    val = idc.get_operand_value(ea, 0)
                    if self.is_valid_reference(val):
                        return (ea, 0.5)
        return None
    
    def _analyze_return_values(self) -> List[Tuple[int, int, str, float]]:
        """Track function return values used as indirect call targets"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            # Look for return instructions
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                if mnem in ["ret", "retn"]:
                    # Track what value is in RAX/EAX at return
                    ret_value = self._get_return_value(head, func_ea)
                    if ret_value:
                        self.return_values[func_ea] = ret_value
            
            # Check callers of this function
            for xref in idautils.XrefsTo(func_ea):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    # Check if return value is used for indirect call
                    ret_usage = self._check_return_value_usage(xref.frm, func_ea)
                    if ret_usage:
                        target, confidence = ret_usage
                        self.add_xref(xref.frm, target, "return_value_call", confidence)
                        results.append((xref.frm, target, "return_value_call", confidence))
        
        return results
    
    def _get_return_value(self, ret_ea: int, func_ea: int) -> Optional[Tuple[int, float]]:
        """Get the value in the return register at a return instruction"""
        # Look backwards for RAX/EAX assignment
        ea = idc.prev_head(ret_ea)
        depth = 0
        
        while ea >= func_ea and depth < 20:
            mnem = idc.print_insn_mnem(ea).lower()
            
            if mnem == "mov":
                dst_type = idc.get_operand_type(ea, 0)
                if dst_type == idc.o_reg:
                    dst_reg = idc.print_operand(ea, 0).lower()
                    # Check if it's RAX/EAX
                    ret_reg = abi.return_reg()
                    
                    if dst_reg == ret_reg:
                        src_type = idc.get_operand_type(ea, 1)
                        if src_type == idc.o_imm:
                            value = idc.get_operand_value(ea, 1)
                            if self.is_valid_reference(value):
                                return (value, 0.9)
                        break
            
            ea = idc.prev_head(ea)
            depth += 1
            
        return None
    
    def _check_return_value_usage(self, call_ea: int, called_func: int) -> Optional[Tuple[int, float]]:
        """Check if return value from a call is used for indirect call"""
        # Look forward from the call
        ea = idc.next_head(call_ea)
        depth = 0
        func = ida_funcs.get_func(call_ea)
        
        if not func or called_func not in self.return_values:
            return None
            
        ret_value, ret_conf = self.return_values[called_func]
        
        while ea < func.end_ea and depth < 10:
            mnem = idc.print_insn_mnem(ea).lower()
            
            # Check for indirect call using RAX/EAX
            if mnem == "call":
                op_type = idc.get_operand_type(ea, 0)
                if op_type == idc.o_reg:
                    op_reg = idc.print_operand(ea, 0).lower()
                    ret_reg = abi.return_reg()
                    
                    if op_reg == ret_reg:
                        return (ret_value, ret_conf * 0.85)
            
            ea = idc.next_head(ea)
            depth += 1
            
        return None
    
    def _analyze_pointer_chains(self) -> List[Tuple[int, int, str, float]]:
        """Analyze multi-level pointer dereferences"""
        results = []
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
                
            pointer_chains = self._find_pointer_chains(func)
            for source, target, depth in pointer_chains:
                confidence = max(0.5, 1.0 - (depth * 0.1))
                self.add_xref(source, target, f"pointer_chain_depth_{depth}", confidence)
                results.append((source, target, f"pointer_chain_depth_{depth}", confidence))
        
        return results
    
    def _find_pointer_chains(self, func) -> List[Tuple[int, int, int]]:
        """Find multi-level pointer dereferences in a function"""
        chains = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            try:
                mnem = idc.print_insn_mnem(head).lower()
                if not mnem:
                    continue
            except:
                continue
            
            # Look for patterns like: mov rax, [rbx]; mov rcx, [rax]; call [rcx]
            if mnem == "mov":
                chain = self._trace_pointer_chain(head, func.end_ea)
                if chain and len(chain) > 1:
                    # Found a multi-level dereference
                    source = chain[0]
                    target = chain[-1]
                    depth = len(chain) - 1
                    
                    if self.is_valid_reference(target):
                        chains.append((source, target, depth))
        
        return chains
    
    def _trace_pointer_chain(self, start_ea: int, end_ea: int) -> List[int]:
        """Trace a chain of pointer dereferences"""
        chain = [start_ea]
        ea = start_ea
        tracked_reg = None
        depth = 0
        max_depth = 5
        
        while ea < end_ea and depth < max_depth:
            mnem = idc.print_insn_mnem(ea).lower()
            
            if mnem == "mov":
                dst_type = idc.get_operand_type(ea, 0)
                src_type = idc.get_operand_type(ea, 1)
                
                if dst_type == idc.o_reg:
                    dst_reg = idc.print_operand(ea, 0)
                    
                    # Check if source is a memory dereference
                    if src_type == idc.o_displ or src_type == idc.o_mem:
                        if tracked_reg is None or tracked_reg == dst_reg:
                            # This is part of our chain
                            chain.append(ea)
                            tracked_reg = dst_reg
                            depth += 1
                        
            elif mnem in ["call", "jmp"] and tracked_reg is not None:
                op_type = idc.get_operand_type(ea, 0)
                if op_type == idc.o_reg or op_type == idc.o_displ:
                    # End of chain - indirect call/jump
                    target = self._resolve_register_value(ea, tracked_reg)
                    if target:
                        chain.append(target)
                    break
            
            ea = idc.next_head(ea)
        
        return chain if len(chain) > 1 else []
    
    def _resolve_register_value(self, ea: int, reg) -> Optional[int]:
        """Try to resolve the value in a register at a given address"""
        # Look backwards for register assignment
        prev_ea = idc.prev_head(ea)
        depth = 0
        
        while prev_ea != idc.BADADDR and depth < 10:
            mnem = idc.print_insn_mnem(prev_ea).lower()
            
            if mnem == "mov":
                dst_type = idc.get_operand_type(prev_ea, 0)
                if dst_type == idc.o_reg:
                    dst_reg = idc.print_operand(prev_ea, 0)
                    if dst_reg.lower() == str(reg).lower():
                        src_type = idc.get_operand_type(prev_ea, 1)
                        if src_type == idc.o_imm:
                            return idc.get_operand_value(prev_ea, 1)
                        break
            
            prev_ea = idc.prev_head(prev_ea)
            depth += 1
            
        return None
    
    def _track_arithmetic_taint(self, ea: int, func_ea: int):
        """Track taint through arithmetic operations"""
        # Arithmetic operations typically preserve taint
        dst_type = idc.get_operand_type(ea, 0)
        
        if dst_type == idc.o_reg:
            dst_reg = idc.print_operand(ea, 0).lower()
            
            # Check if any source operand is tainted
            for i in range(1, 3):
                op_type = idc.get_operand_type(ea, i)
                if op_type == idc.o_reg:
                    src_reg = idc.print_operand(ea, i).lower()
                    if func_ea in self.tainted_regs and src_reg in self.tainted_regs[func_ea]:
                        # Propagate taint with reduced confidence
                        source, conf = self.tainted_regs[func_ea][src_reg]
                        if func_ea not in self.tainted_regs:
                            self.tainted_regs[func_ea] = {}
                        self.tainted_regs[func_ea][dst_reg] = (source, conf * 0.9)
                        break
    
    def _track_stack_taint(self, ea: int, func_ea: int):
        """Track taint through stack operations"""
        mnem = idc.print_insn_mnem(ea).lower()
        # Simple LIFO stack fallback per function when SP API isn't available
        if not hasattr(self, '_lifo_stacks'):
            self._lifo_stacks = {}
        lifo = self._lifo_stacks.setdefault(func_ea, [])
        
        if mnem == "push":
            # Check if pushed value is tainted
            op_type = idc.get_operand_type(ea, 0)
            if op_type == idc.o_reg:
                reg = idc.print_operand(ea, 0).lower()
                if func_ea in self.tainted_regs and reg in self.tainted_regs[func_ea]:
                    # Mark stack location as tainted if API available
                    if self._has_get_sp_val:
                        sp = idc.get_sp_val(ea)
                        if sp != idc.BADADDR:
                            if func_ea not in self.tainted_mem:
                                self.tainted_mem[func_ea] = {}
                            self.tainted_mem[func_ea][sp] = self.tainted_regs[func_ea][reg]
                    else:
                        lifo.append(self.tainted_regs[func_ea][reg])
        
        elif mnem == "pop":
            # Check if popping to a register from tainted stack location
            op_type = idc.get_operand_type(ea, 0)
            if op_type == idc.o_reg:
                reg_name = idc.print_operand(ea, 0).lower()
                if self._has_get_sp_val:
                    sp = idc.get_sp_val(ea)
                    if sp != idc.BADADDR and func_ea in self.tainted_mem and sp in self.tainted_mem[func_ea]:
                        # Propagate taint from stack to register
                        if func_ea not in self.tainted_regs:
                            self.tainted_regs[func_ea] = {}
                        self.tainted_regs[func_ea][reg_name] = self.tainted_mem[func_ea][sp]
                else:
                    if lifo:
                        if func_ea not in self.tainted_regs:
                            self.tainted_regs[func_ea] = {}
                        self.tainted_regs[func_ea][reg_name] = lifo.pop()
