"""
Enhanced Data Flow Analysis Module
Tracks data flow from sources to sinks, return value propagation, and pointer chains
"""

from typing import Dict, List, Tuple, Set, Optional
import idaapi
try:
    import ida_gdl
except Exception:
    ida_gdl = None
import idautils
import idc
import ida_funcs
import ida_xref
from modules.infrastructure.ida.performance.optimizer import IncrementalAnalyzer
from modules.infrastructure.ida.utils import abi
from modules.infrastructure.ida.utils.names import normalize_name
from modules.infrastructure.ida.analysis.components import ArgumentResolver, StringEvidence, HeapTracker, CFGWalker, TaintMovement, StackTaint, ArithmeticTaint, RegisterForwardTracker, RegisterResolver, ArgumentTaintChecker, StackArgScanner, ReturnValueTracker
from modules.infrastructure.ida.analysis.taint_rules import TaintRules
from modules.infrastructure.ida.analysis.sink_policy import SinkPolicy
from modules.infrastructure.ida.analysis.interprocedural import InterproceduralSummaries
from modules.infrastructure.ida.analysis.call_policies import (
    CallInfo,
    TaintSourcePolicy,
    NumericParserPolicy,
    HeapAllocPolicy,
    SanitizerPolicy,
    TaintCarryPolicy,
)
from collections import deque
import time
try:
    import ida_typeinf
except Exception:
    ida_typeinf = None
try:
    import ida_hexrays
except Exception:
    ida_hexrays = None
try:
    import ida_frame
except Exception:
    ida_frame = None
try:
    import ida_struct
except Exception:
    ida_struct = None
try:
    import ida_ida
except ImportError:
    ida_ida = None

class DataFlowAnalyzer(IncrementalAnalyzer):
    """Enhanced data flow analysis for taint tracking and value propagation"""
    
    def _safe_get_operand_value(self, ea: int, op_idx: int) -> Optional[int]:
        """Safely get operand value with error handling"""
        try:
            if idc.get_operand_type(ea, op_idx) != idc.o_void:
                return idc.get_operand_value(ea, op_idx)
        except Exception:
            return None
        return None
    
    def _safe_print_operand(self, ea: int, op_idx: int) -> str:
        """Safely get operand string with error handling"""
        try:
            if idc.get_operand_type(ea, op_idx) != idc.o_void:
                return idc.print_operand(ea, op_idx)
        except Exception:
            return ""
        return ""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self._procname = ""
        try:
            self._procname = idaapi.get_inf_structure().procname.lower()
        except Exception:
            self._procname = ""
        self.taint_sources = set(config.get('taint_sources', [
            'recv', 'read', 'fread', 'scanf', 'gets', 'getchar',
            'recvfrom', 'recvmsg', 'ReadFile', 'InternetReadFile',
            'fgets', 'getenv', 'getline', 'fscanf'
        ]))
        self.string_sources = set(config.get('string_sources', [
            'gets', 'fgets', 'getline', 'scanf', 'fscanf', 'recv', 'read'
        ]))
        self.numeric_parsers = set(config.get('numeric_parsers', [
            'atoi', 'atol', 'strtol', 'strtoul', 'strtoll', 'strtoull',
            'sscanf', 'scanf', 'fscanf'
        ]))
        self.taint_sinks = set(config.get('taint_sinks', [
            'system', 'exec', 'strcpy', 'sprintf', 'memcpy',
            'execve', 'execl', 'ShellExecute', 'CreateProcess',
            'strcat', 'vsprintf', 'WinExec', 'popen'
        ]))
        self.sink_exec_keywords = [s.lower() for s in config.get('sink_exec_keywords', [
            'exec', 'system', 'popen', 'createprocess'
        ])]
        self.sink_string_keywords = [s.lower() for s in config.get('sink_string_keywords', [
            'str', 'sprintf', 'printf'
        ])]
        self.taint_carrying_apis = set(config.get('taint_carrying_apis', [
            'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat',
            'sprintf', 'snprintf', 'vsprintf', 'vsnprintf'
        ]))
        self.heap_alloc_apis = set(config.get('heap_alloc_apis', [
            'malloc', 'calloc', 'realloc', 'new', 'operator new',
            'HeapAlloc', 'VirtualAlloc'
        ]))
        self.use_hexrays_taint = config.get('use_hexrays_taint', True)
        self._tuning_defaults = {
            "sink_min_confidence": 0.5,
            "function_timeout_ms": 0,
            "large_function_threshold": 2000,
            "large_function_taint_depth": 6,
            "cfg_complexity_threshold": 200,
            "cfg_depth_scale": 0.5,
            "cfg_fanout_threshold": 4,
            "cfg_loop_penalty": 0.85,
            "cfg_edge_density_threshold": 2.5,
            "cfg_loop_nesting_penalty": 0.8,
            "max_taint_depth": 10,
            "sanitizer_scoped": True,
            "jump_table_taint": True,
            "cf_sensitive_sinks": True,
            "stack_arg_scan_max_back": 16,
            "return_value_back_depth": 20,
            "return_value_forward_depth": 10,
            "register_resolve_back_depth": 10,
            "pointer_chain_max_depth": 5,
        }
        self.tuning_table = self._build_tuning_table(config)
        self.sanitizer_scoped = bool(self.tuning_table.get("sanitizer_scoped"))
        self.jump_table_taint = bool(self.tuning_table.get("jump_table_taint"))
        self.cf_sensitive_sinks = bool(self.tuning_table.get("cf_sensitive_sinks"))
        self.sink_min_confidence = float(self.tuning_table.get("sink_min_confidence"))
        self.function_timeout_ms = int(self.tuning_table.get("function_timeout_ms"))
        self.large_function_threshold = int(self.tuning_table.get("large_function_threshold"))
        self.large_function_taint_depth = int(self.tuning_table.get("large_function_taint_depth"))
        self.cfg_complexity_threshold = int(self.tuning_table.get("cfg_complexity_threshold"))
        self.cfg_depth_scale = float(self.tuning_table.get("cfg_depth_scale"))
        self.cfg_fanout_threshold = int(self.tuning_table.get("cfg_fanout_threshold"))
        self.cfg_loop_penalty = float(self.tuning_table.get("cfg_loop_penalty"))
        self.cfg_edge_density_threshold = float(self.tuning_table.get("cfg_edge_density_threshold"))
        self.cfg_loop_nesting_penalty = float(self.tuning_table.get("cfg_loop_nesting_penalty"))
        self.max_taint_depth = self.tuning_table.get("max_taint_depth")
        self.sanitizers = set(config.get('taint_sanitizers', self._default_sanitizers()))
        self.ip_depth = int(config.get('taint_interprocedural_depth', 1))
        self.ip_fanout = int(config.get('taint_interprocedural_fanout', 5))
        self.stack_arg_scan_max_back = int(self.tuning_table.get('stack_arg_scan_max_back'))
        self.stack_arg_win_slots = list(config.get('stack_arg_win_slots', [0, 8, 16, 24]))
        self.return_value_back_depth = int(self.tuning_table.get('return_value_back_depth'))
        self.return_value_forward_depth = int(self.tuning_table.get('return_value_forward_depth'))
        self.register_resolve_back_depth = int(self.tuning_table.get('register_resolve_back_depth'))
        self.pointer_chain_max_depth = int(self.tuning_table.get('pointer_chain_max_depth'))
        self.tainted_regs = {}  # func_ea -> {reg: (source_ea, confidence)}
        self.tainted_mem = {}   # func_ea -> {mem_addr: (source_ea, confidence)}
        self.taint_kinds_regs = {}  # func_ea -> {reg: kind}
        self.taint_kinds_mem = {}   # func_ea -> {mem_key: kind}
        self.taint_payload_regs = {}  # func_ea -> {reg: payload_kind}
        self.taint_kind_xrefs = {}  # (source,target) -> kind
        self.return_values = {}  # func_ea -> (value, confidence)
        self.taint_summaries = {}  # func_ea -> set(arg_regs that influence return)
        self.taint_summaries_arg = {}  # func_ea -> {src_arg: set(dst_args)}
        self.taint_summaries_mem = {}  # func_ea -> set(arg_regs that influence memory)
        self._heap_aliases = {}  # func_ea -> {reg: heap_id}
        self._current_func_ea = None
        self._mem_intervals = {}  # func_ea -> list of (prefix, start, size, kind, conf)
        self._block_out_states = {}  # func_ea -> {block_id: (regs, mem)}
        self._block_kind_states = {}  # func_ea -> {block_id: {reg: kind}}
        self._block_last_defs = {}  # func_ea -> {block_id: {reg: ea}}
        self._block_rd_in = {}  # func_ea -> {block_id: {reg: set(defs)}}
        self._profile = self._detect_compiler_profile()
        self.arg_resolver = ArgumentResolver(self)
        self.string_evidence = StringEvidence(self)
        self.heap_tracker = HeapTracker(self)
        self.cfg_walker = CFGWalker(self)
        self.taint_rules = TaintRules(self)
        self.sink_policy = SinkPolicy(self)
        self.interprocedural = InterproceduralSummaries(self)
        self.taint_movement = TaintMovement(self)
        self.stack_taint = StackTaint(self)
        self.arith_taint = ArithmeticTaint(self)
        self.reg_forward = RegisterForwardTracker(self)
        self.reg_resolver = RegisterResolver(self)
        self.arg_taint_checker = ArgumentTaintChecker(self)
        self.stack_arg_scanner = StackArgScanner(self)
        self.return_tracker = ReturnValueTracker(self)
        self._source_policy = TaintSourcePolicy(self)
        self._numeric_policy = NumericParserPolicy(self)
        self._heap_policy = HeapAllocPolicy(self)
        self._sanitizer_policy = SanitizerPolicy(self)
        self._carry_policy = TaintCarryPolicy(self)
        if self._profile in ("go", "rust"):
            self.sink_min_confidence = max(self.sink_min_confidence, 0.6)
        try:
            func_count = len(list(idautils.Functions()))
            if func_count > 5000:
                self.sink_min_confidence = max(self.sink_min_confidence, 0.65)
        except Exception:
            pass
        # Some IDA versions (including 9.1 Python API) do not expose idc.get_sp_val
        # Guard stack taint tracking accordingly
        self._has_get_sp_val = hasattr(idc, 'get_sp_val')
        self._ip_cache = set()

    def _iter_functions(self):
        """Yield (func_ea, func) for all valid functions."""
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func

    def _iter_functions_named(self):
        """Yield (func_ea, func, func_name) for functions with valid names."""
        for func_ea, func in self._iter_functions():
            try:
                func_name = idc.get_func_name(func_ea)
            except Exception:
                continue
            if func_name:
                yield func_ea, func, normalize_name(func_name)
        
    def get_name(self) -> str:
        return "DataFlowAnalyzer"
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        return super().analyze()

    def _build_tuning_table(self, config: Dict) -> Dict:
        table = {}
        raw = config.get("tuning_table", {})
        if isinstance(raw, dict):
            table.update(raw)
        for key, val in self._tuning_defaults.items():
            table.setdefault(key, val)
        return table

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        """Incremental per-function analysis."""
        results: List[Tuple[int, int, str, float]] = []
        func_ea = func.start_ea
        deadline = None
        if self.function_timeout_ms and self.function_timeout_ms > 0:
            deadline = time.time() + (self.function_timeout_ms / 1000.0)
        self._max_depth_override = None
        self._slow = hasattr(self, "_slow_functions") and func_ea in self._slow_functions
        try:
            if (func.end_ea - func.start_ea) > self.large_function_threshold:
                self._max_depth_override = self.large_function_taint_depth
        except Exception:
            self._max_depth_override = None
        try:
            blocks = list(self._iter_basic_blocks(func))
            if len(blocks) > self.cfg_complexity_threshold:
                scaled = max(2, int(self.max_taint_depth * self.cfg_depth_scale))
                self._max_depth_override = min(self._max_depth_override or scaled, scaled)
        except Exception:
            pass
        try:
            if blocks:
                edges = 0
                back_edges = 0
                max_fanout = 0
                for b in blocks:
                    succs = list(b.succs())
                    edges += len(succs)
                    max_fanout = max(max_fanout, len(succs))
                    if any(s.start_ea < b.start_ea for s in succs):
                        back_edges += 1
                if max_fanout >= self.cfg_fanout_threshold:
                    scaled = max(2, int(self.max_taint_depth * self.cfg_depth_scale))
                    self._max_depth_override = min(self._max_depth_override or scaled, scaled)
                density = edges / max(1, len(blocks))
                if density >= self.cfg_edge_density_threshold:
                    scaled = max(2, int(self.max_taint_depth * self.cfg_depth_scale))
                    self._max_depth_override = min(self._max_depth_override or scaled, scaled)
                if back_edges:
                    scaled = max(2, int(self.max_taint_depth * self.cfg_loop_penalty))
                    self._max_depth_override = min(self._max_depth_override or scaled, scaled)
                    if back_edges > 2:
                        scaled = max(2, int(self.max_taint_depth * self.cfg_loop_nesting_penalty))
                        self._max_depth_override = min(self._max_depth_override or scaled, scaled)
        except Exception:
            pass
        try:
            # Local taint propagation inside function
            self._analyze_function_taint(func_ea, deadline)
            # Source/sink logic for this function + its callers
            results.extend(self._analyze_taint_for_function(func_ea))
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in taint analysis: {e}")
        try:
            if not self._slow:
                results.extend(self._analyze_return_values_for_function(func_ea, func))
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in return value analysis: {e}")
        try:
            if not self._slow:
                results.extend(self._hexrays_taint_flow(func_ea))
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in Hex-Rays taint analysis: {e}")
        try:
            if not self._slow:
                pointer_chains = self._find_pointer_chains(func, deadline)
                results.extend(self._emit_pointer_chain_results(pointer_chains))
        except Exception as e:
            print(f"[DataFlowAnalyzer] Warning in pointer chain analysis: {e}")
        return results
    
    def _analyze_taint_for_function(self, func_ea: int) -> List[Tuple[int, int, str, float]]:
        results = []
        try:
            func_name = idc.get_func_name(func_ea)
        except Exception:
            return results
        if not func_name:
            return results
        func_name = normalize_name(func_name)
        for source in self.taint_sources:
            if source in func_name:
                for xref in idautils.XrefsTo(func_ea):
                    if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                        self._propagate_taint_from_call(xref.frm, func_ea)
        for sink in self.taint_sinks:
            if sink in func_name:
                for xref in idautils.XrefsTo(func_ea):
                    if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                        taint_info = self._check_tainted_arguments(xref.frm)
                        if taint_info:
                            source_ea, confidence, kind = taint_info
                            confidence *= self.taint_rules.adjust_sink_confidence(
                                sink, kind, xref.frm, source_ea
                            )
                            if not self.sink_policy.should_emit(source_ea, xref.frm, sink, kind, confidence):
                                continue
                            self.add_xref(source_ea, xref.frm, f"taint_flow_{sink}", confidence * 0.9)
                            try:
                                self.add_evidence(source_ea, xref.frm, "dataflow")
                            except Exception:
                                pass
                            self.taint_kind_xrefs[(source_ea, xref.frm)] = kind
                            results.append((source_ea, xref.frm, f"taint_flow_{sink}", confidence * 0.9))
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
    
    def _analyze_function_taint(self, func_ea: int, deadline: Optional[float] = None):
        """Analyze taint propagation within a function using basic blocks."""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return
        self._current_func_ea = func_ea
        self._heap_aliases.setdefault(func_ea, {})
        mnem_cache = {}
        op_type_cache = {}
        op_str_cache = {}

        def op_type(ea, idx):
            key = (ea, idx)
            if key in op_type_cache:
                return op_type_cache[key]
            try:
                val = idc.get_operand_type(ea, idx)
            except Exception:
                val = idc.o_void
            op_type_cache[key] = val
            return val


        def op_str(ea, idx):
            key = (ea, idx)
            if key in op_str_cache:
                return op_str_cache[key]
            try:
                val = idc.print_operand(ea, idx)
            except Exception:
                val = ""
            op_str_cache[key] = val
            return val

        blocks = list(self._iter_basic_blocks(func))
        if not blocks:
            return
        block_map = {b.id: b for b in blocks}
        entry = blocks[0]
        reachable = self._reachable_block_ids(entry)
        out_states = {}
        out_kinds = {}
        out_defs = {}
        work = deque([entry.id])

        while work:
            if deadline and time.time() > deadline:
                return
            bid = work.popleft()
            if bid not in reachable:
                continue
            block = block_map.get(bid)
            if not block:
                continue
            in_regs, in_mem = self._merge_pred_states(block, out_states)
            regs = dict(in_regs)
            mem = dict(in_mem)
            kinds = dict(self._merge_pred_kinds(block, out_kinds))
            defs = dict(self._merge_pred_defs(block, out_defs))

            for head in idautils.Heads(block.start_ea, block.end_ea):
                if deadline and time.time() > deadline:
                    break
                try:
                    mnem = self._mnem(head, mnem_cache)
                    if not mnem:
                        continue
                except Exception:
                    continue

                # Track MOV/LOAD/STORE instructions for taint propagation
                if mnem in self._mov_mnems():
                    self._track_mov_taint(head, func_ea, regs, mem, op_type, op_str)
                # Track arithmetic operations that preserve taint
                elif mnem in ["add", "sub", "xor", "or", "and", "shl", "shr"]:
                    self._track_arithmetic_taint(head, func_ea, regs, op_type, op_str)
                # Track memory operations
                elif mnem in self._stack_mnems():
                    self._track_stack_taint(head, func_ea, regs, mem, op_type, op_str)
                # Clear taint on sanitizing calls + interprocedural
                elif mnem == "call":
                    self._handle_call_taint(head, func_ea, regs, mem)
                elif mnem == "jmp" and self.jump_table_taint:
                    self._handle_jump_table_taint(head, func, regs)
                # keep kinds map updated per instruction from global kind maps
                for r in list(regs.keys()):
                    if func_ea in self.taint_kinds_regs and r in self.taint_kinds_regs[func_ea]:
                        kinds[r] = self.taint_kinds_regs[func_ea][r]
                # Track last definitions in block for reaching-defs
                if mnem in self._mov_mnems() | {"mov"}:
                    try:
                        dst_type = idc.get_operand_type(head, 0)
                    except Exception:
                        dst_type = idc.o_void
                    if dst_type == idc.o_reg:
                        reg = idc.print_operand(head, 0).lower()
                        defs.setdefault(reg, set()).add(head)

            prev_out = out_states.get(bid)
            out_states[bid] = (regs, mem)
            out_kinds[bid] = dict(kinds)
            out_defs[bid] = {k: set(v) for k, v in defs.items()}
            if prev_out is None or not self._state_equal(prev_out, out_states[bid]):
                for succ in block.succs():
                    work.append(succ.id)

        # Merge all block out states into per-function summaries
        final_regs, final_mem = self._merge_all_states(out_states)
        if final_regs:
            self.tainted_regs[func_ea] = final_regs
        if final_mem:
            self.tainted_mem[func_ea] = final_mem
        self._block_out_states[func_ea] = out_states
        self._block_kind_states[func_ea] = out_kinds
        self._block_last_defs[func_ea] = out_defs
        self._block_rd_in[func_ea] = self._compute_reaching_defs(func, out_defs)

        # Summary: if return register tainted and any arg register tainted, record
        ret_reg = abi.return_reg()
        arg_regs = abi.arg_registers()
        if func_ea in self.tainted_regs and ret_reg in self.tainted_regs[func_ea]:
            for reg in arg_regs:
                if reg in self.tainted_regs[func_ea]:
                    self.taint_summaries.setdefault(func_ea, set()).add(reg)
    
    def _track_mov_taint(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str):
        """Track taint through MOV instructions."""
        self.taint_movement.track_mov(ea, func_ea, regs, mem, op_type, op_str)
    
    def _track_register_forward(self, start_ea: int, reg: str, source: int):
        """Track a tainted register forward through the code."""
        self.reg_forward.track(start_ea, reg, source)
    
    def _check_tainted_arguments(self, call_ea: int) -> Optional[Tuple[int, float, str]]:
        """Check if any arguments to a call are tainted"""
        taint = self.arg_taint_checker.check(call_ea)
        if taint:
            return taint
        func = ida_funcs.get_func(call_ea)
        if not func:
            return None
        arg_regs = self._get_call_arg_regs(call_ea)
        stack_taint = self._scan_stack_arguments(call_ea, func, len(arg_regs))
        if stack_taint:
            source_ea, conf = stack_taint
            return source_ea, conf, "ptr"
        return None

    def _scan_stack_arguments(self, call_ea: int, func, reg_arg_count: int) -> Optional[Tuple[int, float]]:
        """Scan a window before call for stack-based argument setup.
        - Win64: detect home space stores to [rsp+0..24]
        - SysV: detect additional args via pushes or [rsp+offset] stores
        Returns (source_ea, confidence) if tainted data flows into an argument.
        """
        return self.stack_arg_scanner.scan(call_ea, func, reg_arg_count)

    def _get_call_arg_regs(self, call_ea: int) -> List[str]:
        return self.arg_resolver.get_call_arg_regs(call_ea)

    def _expected_arg_kind(self, call_ea: int, arg_index: int) -> Optional[str]:
        return self.arg_resolver.expected_arg_kind(call_ea, arg_index)

    def _arg_reg_index(self, reg: str) -> Optional[int]:
        return self.arg_resolver.arg_reg_index(reg)

    def _func_arg_is_ptr(self, func_ea: int, arg_index: int) -> bool:
        return self.arg_resolver.func_arg_is_ptr(func_ea, arg_index)

    def _arg_points_to_string(self, call_ea: int, reg: str) -> bool:
        return self.string_evidence.arg_points_to_string(call_ea, reg)

    def _is_format_string(self, call_ea: int) -> bool:
        return self.string_evidence.is_format_string(call_ea)

    
    def _analyze_return_values(self) -> List[Tuple[int, int, str, float]]:
        """Track function return values used as indirect call targets."""
        results = []
        for func_ea, func in self._iter_functions():
            self._collect_return_values(func_ea, func)
            results.extend(self._emit_return_value_xrefs(func_ea))
        return results

    def _analyze_return_values_for_function(self, func_ea: int, func) -> List[Tuple[int, int, str, float]]:
        results = []
        self._collect_return_values(func_ea, func)
        results.extend(self._emit_return_value_xrefs(func_ea))
        return results

    def _default_sanitizers(self) -> List[str]:
        plat = abi.platform()
        base = ["memset", "bzero", "strncpy", "strncat"]
        if plat == "windows":
            base += ["RtlZeroMemory", "SecureZeroMemory", "memcpy_s", "strcpy_s"]
        return base
    
    def _get_return_value(self, ret_ea: int, func_ea: int) -> Optional[Tuple[int, float]]:
        """Get the value in the return register at a return instruction"""
        return self.return_tracker.get_return_value(ret_ea, func_ea)
    
    def _check_return_value_usage(self, call_ea: int, called_func: int) -> Optional[Tuple[int, float]]:
        """Check if return value from a call is used for indirect call"""
        return self.return_tracker.check_return_usage(call_ea, called_func)
    
    def _analyze_pointer_chains(self) -> List[Tuple[int, int, str, float]]:
        """Analyze multi-level pointer dereferences."""
        results = []
        for _func_ea, func in self._iter_functions():
            pointer_chains = self._find_pointer_chains(func)
            results.extend(self._emit_pointer_chain_results(pointer_chains))
        return results
    
    def _find_pointer_chains(self, func, deadline: Optional[float] = None) -> List[Tuple[int, int, int]]:
        """Find multi-level pointer dereferences in a function"""
        chains = []
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if deadline and time.time() > deadline:
                break
            try:
                mnem = idc.print_insn_mnem(head).lower()
                if not mnem:
                    continue
            except Exception:
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

    def _collect_return_values(self, func_ea: int, func):
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in ["ret", "retn"]:
                ret_value = self._get_return_value(head, func_ea)
                if ret_value:
                    self.return_values[func_ea] = ret_value

    def _emit_return_value_xrefs(self, func_ea: int) -> List[Tuple[int, int, str, float]]:
        results = []
        for xref in idautils.XrefsTo(func_ea):
            if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                ret_usage = self._check_return_value_usage(xref.frm, func_ea)
                if ret_usage:
                    target, confidence = ret_usage
                    self.add_xref(xref.frm, target, "return_value_call", confidence)
                    results.append((xref.frm, target, "return_value_call", confidence))
        return results

    def _emit_pointer_chain_results(self, pointer_chains: List[Tuple[int, int, int]]) -> List[Tuple[int, int, str, float]]:
        results = []
        for source, target, depth in pointer_chains:
            confidence = max(0.5, 1.0 - (depth * 0.1))
            self.add_xref(source, target, f"pointer_chain_depth_{depth}", confidence)
            results.append((source, target, f"pointer_chain_depth_{depth}", confidence))
        return results
    
    def _trace_pointer_chain(self, start_ea: int, end_ea: int) -> List[int]:
        """Trace a chain of pointer dereferences"""
        chain = [start_ea]
        ea = start_ea
        tracked_reg = None
        depth = 0
        max_depth = self.pointer_chain_max_depth
        
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
        return self.reg_resolver.resolve_immediate(ea, reg)
    
    def _track_arithmetic_taint(self, ea: int, func_ea: int, regs: dict, op_type, op_str):
        """Track taint through arithmetic operations."""
        self.arith_taint.track_arithmetic(ea, func_ea, regs, op_type, op_str)
    
    def _track_stack_taint(self, ea: int, func_ea: int, regs: dict, mem: dict, op_type, op_str):
        """Track taint through stack operations."""
        self.stack_taint.track_stack(ea, func_ea, regs, mem, op_type, op_str)

    def _handle_call_taint(self, call_ea: int, func_ea: int, regs: dict, mem: dict):
        """Handle taint across calls (sanitizers + interprocedural)."""
        try:
            target = idc.get_operand_value(call_ea, 0)
            name = normalize_name(idc.get_func_name(target))
        except Exception:
            return
        if not name:
            return
        # If the call is to a known taint source, taint the return register
        arg_regs = self._get_call_arg_regs(call_ea)
        info = CallInfo(call_ea, target, name, arg_regs)
        self._source_policy.apply(info, regs)
        self._numeric_policy.apply(info, regs)
        self._heap_policy.apply(info, regs)
        if self._sanitizer_policy.apply(info, regs, mem):
            return
        self._carry_policy.apply(info, regs, mem)
        # Keep per-function state in sync for interprocedural propagation
        self.tainted_regs[func_ea] = regs
        self.tainted_mem[func_ea] = mem
        self._propagate_taint_to_callee(call_ea, target, func_ea, self.ip_depth, set())
        self._propagate_taint_from_callee(call_ea, target, func_ea)

    def _propagate_taint_to_callee(self, call_ea: int, callee_ea: int, caller_func_ea: int, depth: int, seen: set):
        """Propagate tainted argument registers into callee."""
        if depth <= 0:
            return
        if callee_ea in seen:
            return
        arg_regs = abi.arg_registers()
        tainted_args = tuple(reg for reg in arg_regs if reg in self.tainted_regs.get(caller_func_ea, {}))
        cache_key = (callee_ea, depth, tainted_args)
        if cache_key in self._ip_cache:
            return
        self._ip_cache.add(cache_key)
        seen.add(callee_ea)
        if not arg_regs:
            return
        if caller_func_ea not in self.tainted_regs:
            return
        callee = ida_funcs.get_func(callee_ea)
        if not callee:
            return
        callee_map = self.tainted_regs.setdefault(callee.start_ea, {})
        for reg in arg_regs:
            if reg in self.tainted_regs[caller_func_ea]:
                callee_map[reg] = self.tainted_regs[caller_func_ea][reg]
        # Shallow interprocedural: propagate one level further if requested
        if depth > 1:
            count = 0
            for head in idautils.Heads(callee.start_ea, callee.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                if mnem == "call":
                    try:
                        nxt = idc.get_operand_value(head, 0)
                    except Exception:
                        continue
                    count += 1
                    if count > self.ip_fanout:
                        break
                    self._propagate_taint_to_callee(head, nxt, callee.start_ea, depth - 1, seen)

    def _propagate_taint_from_callee(self, call_ea: int, callee_ea: int, caller_func_ea: int):
        """Propagate tainted return register from callee into caller."""
        callee = ida_funcs.get_func(callee_ea)
        if not callee:
            return
        ret_reg = abi.return_reg()
        if callee.start_ea in self.tainted_regs and ret_reg in self.tainted_regs[callee.start_ea]:
            self.tainted_regs.setdefault(caller_func_ea, {})[ret_reg] = self.tainted_regs[callee.start_ea][ret_reg]
        # Summary-based: if any tainted arg matches summary, taint return
        summary = self.taint_summaries.get(callee.start_ea, set())
        if summary and caller_func_ea in self.tainted_regs:
            for reg in summary:
                if reg in self.tainted_regs[caller_func_ea]:
                    self.tainted_regs.setdefault(caller_func_ea, {})[ret_reg] = self.tainted_regs[caller_func_ea][reg]
                    break
        self.interprocedural.apply(call_ea, callee.start_ea, caller_func_ea)

    def _mem_key(self, ea: int, op_idx: int, op_str=None) -> Optional[str]:
        """Create a lightweight key for memory operands with stack var canonicalization."""
        if op_str is None:
            op = self._safe_print_operand(ea, op_idx)
        else:
            op = op_str(ea, op_idx)
        if not op:
            return None
        lower = op.lower()
        heap_key = self._heap_mem_key(lower)
        if heap_key:
            return heap_key
        stack_key = self._stack_var_key(ea, op_idx)
        if stack_key:
            return stack_key
        glob_key = self._global_mem_key(ea, op_idx)
        if glob_key:
            return glob_key
        # Canonicalize stack variable tokens (var_/arg_)
        for token in ("var_", "arg_"):
            idx = lower.find(token)
            if idx != -1:
                end = idx + len(token)
                while end < len(lower) and (lower[end].isalnum() or lower[end] == "_"):
                    end += 1
                return lower[idx:end]
        return lower

    def _heap_mem_key(self, lower: str) -> Optional[str]:
        return self.heap_tracker.heap_mem_key(lower)

    def _stack_var_key(self, ea: int, op_idx: int) -> Optional[str]:
        return self.heap_tracker.stack_var_key(ea, op_idx)

    def _stack_var_size(self, ea: int, name: str) -> Optional[int]:
        return self.heap_tracker.stack_var_size(ea, name)

    def _stack_var_member_name(self, ea: int, name: str, op_idx: int) -> str:
        return self.heap_tracker.stack_var_member_name(ea, name, op_idx)

    def _global_mem_key(self, ea: int, op_idx: int) -> Optional[str]:
        try:
            addr = idc.get_operand_value(ea, op_idx)
        except Exception:
            return None
        if addr in (None, idc.BADADDR):
            return None
        seg = idaapi.getseg(addr)
        if not seg:
            return None
        if hasattr(seg, "perm") and hasattr(idaapi, "SEGPERM_EXEC"):
            if seg.perm & idaapi.SEGPERM_EXEC:
                return None
        return f"glob:{addr:#x}"

    def _parse_mem_base_offset(self, lower: str) -> Tuple[Optional[str], Optional[int]]:
        return self.heap_tracker.parse_mem_base_offset(lower)

    def _apply_scoped_sanitizer(self, regs: dict, mem: dict, call_ea: int):
        arg_regs = self._get_call_arg_regs(call_ea)
        if not arg_regs:
            return
        dst = arg_regs[0]
        if dst in regs:
            del regs[dst]
        aliases = self._heap_aliases.get(self._current_func_ea, {})
        if dst in aliases:
            prefix = f"heap:{aliases[dst]}"
            size = None
            if len(arg_regs) >= 3:
                size = self._resolve_arg_immediate(call_ea, arg_regs[2])
            for key in list(mem.keys()):
                if isinstance(key, str) and key.startswith(prefix):
                    if size is None:
                        del mem[key]
                        continue
                    offset = self._heap_key_offset(key)
                    if offset is not None and 0 <= offset < size:
                        del mem[key]
            intervals = self._mem_intervals.get(self._current_func_ea, [])
            if intervals:
                kept = []
                for pfx, start, rng, kind, conf in intervals:
                    if pfx != prefix:
                        kept.append((pfx, start, rng, kind, conf))
                        continue
                    if size is None:
                        continue
                    if start >= size or (start + rng) <= 0:
                        kept.append((pfx, start, rng, kind, conf))
                self._mem_intervals[self._current_func_ea] = kept

    def _apply_taint_carry(self, regs: dict, mem: dict, call_ea: int, name: str):
        arg_regs = self._get_call_arg_regs(call_ea)
        if len(arg_regs) < 2:
            return
        dst = arg_regs[0]
        if any(k in name for k in ("memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat")):
            src = arg_regs[1]
            if src in regs:
                conf = regs[src][1]
                size = None
                if len(arg_regs) >= 3:
                    size = self._resolve_arg_immediate(call_ea, arg_regs[2])
                    if size is not None and size < 16:
                        conf *= 0.8
                    elif size is not None and size > 256:
                        conf *= 1.05
                regs[dst] = (regs[src][0], min(1.0, conf))
                self.taint_kinds_regs.setdefault(self._current_func_ea, {})[dst] = \
                    self.taint_kinds_regs.get(self._current_func_ea, {}).get(src, "ptr")
                if size is not None:
                    aliases = self._heap_aliases.get(self._current_func_ea, {})
                    if dst in aliases:
                        prefix = f"heap:{aliases[dst]}"
                        self._record_mem_interval(prefix, 0, size, self.taint_kinds_regs[self._current_func_ea].get(dst, "ptr"), conf)
                    if dst in aliases and src in aliases:
                        src_prefix = f"heap:{aliases[src]}"
                        dst_prefix = f"heap:{aliases[dst]}"
                        kind = self.taint_kinds_regs[self._current_func_ea].get(src, "ptr")
                        self._record_mem_interval(dst_prefix, 0, size, kind, conf)
                else:
                    aliases = self._heap_aliases.get(self._current_func_ea, {})
                    if dst in aliases and src in aliases:
                        src_prefix = f"heap:{aliases[src]}"
                        dst_prefix = f"heap:{aliases[dst]}"
                        intervals = self._mem_intervals.get(self._current_func_ea, [])
                        for pfx, start, rng, kind, conf2 in intervals:
                            if pfx == src_prefix:
                                self._record_mem_interval(dst_prefix, start, rng, kind, conf2)
                return
        for reg in arg_regs[1:]:
            if reg in regs:
                regs[dst] = regs[reg]
                self.taint_kinds_regs.setdefault(self._current_func_ea, {})[dst] = \
                    self.taint_kinds_regs.get(self._current_func_ea, {}).get(reg, "ptr")
                return

    def _handle_jump_table_taint(self, jmp_ea: int, func, regs: dict):
        for _reg, (src, conf) in regs.items():
            for tgt in self._resolve_switch_targets(jmp_ea, func):
                if self.is_valid_reference(tgt):
                    self.add_xref(src, tgt, "tainted_indirect_call", max(0.5, conf * 0.85))

    def _resolve_switch_targets(self, jmp_ea: int, func) -> List[int]:
        if not hasattr(idaapi, "get_switch_info_ex"):
            return []
        try:
            si = idaapi.get_switch_info_ex(jmp_ea)
        except Exception:
            return []
        if not si:
            return []
        try:
            jtable = si.jumps
            size = si.get_jtable_size() if hasattr(si, "get_jtable_size") else 0
            esize = si.get_jtable_element_size() if hasattr(si, "get_jtable_element_size") else 4
        except Exception:
            return []
        if not jtable or size <= 0:
            return []
        results = []
        for i in range(size):
            ea = jtable + i * esize
            try:
                target = idc.get_qword(ea) if esize == 8 else idc.get_wide_dword(ea)
            except Exception:
                continue
            if target and func.start_ea <= target < func.end_ea:
                results.append(target)
        return results

    def _resolve_arg_immediate(self, call_ea: int, reg: str, max_back: int = 8) -> Optional[int]:
        return self.arg_resolver.resolve_arg_immediate(call_ea, reg, max_back=max_back)

    def _heap_key_offset(self, key: str) -> Optional[int]:
        return self.heap_tracker.heap_key_offset(key)

    def _record_mem_interval(self, prefix: str, start: int, size: int, kind: str, conf: float):
        return self.heap_tracker.record_mem_interval(prefix, start, size, kind, conf)

    def _ret_taint_confidence(self, callee_ea: int) -> float:
        if ida_typeinf is None:
            return 0.9
        try:
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.get_tinfo(tinfo, callee_ea):
                ftd = ida_typeinf.func_type_data_t()
                if tinfo.get_func_details(ftd):
                    ret = ftd.rettype
                    if ret.is_ptr() or ret.is_array():
                        return 0.95
                    return 0.85
        except Exception:
            return 0.9
        return 0.9

    def _detect_compiler_profile(self) -> str:
        try:
            for seg_ea in idautils.Segments():
                name = idc.get_segm_name(seg_ea).lower()
                if "gopclntab" in name:
                    return "go"
                if "rust" in name:
                    return "rust"
        except Exception:
            pass
        try:
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea)
                if not name:
                    continue
                if name.startswith("std::") or "vtable" in name:
                    return "cpp"
                if name.startswith("go.") or name.startswith("runtime."):
                    return "go"
                if name.startswith("_ZN") or name.startswith("core::"):
                    return "rust"
        except Exception:
            pass
        return "unknown"

    def _is_reg_tainted_near_call(self, call_ea: int, reg: str, func) -> bool:
        try:
            block = None
            for b in idaapi.FlowChart(func, flags=idaapi.FC_PREDS):
                if b.start_ea <= call_ea < b.end_ea:
                    block = b
                    break
            if not block:
                return True
            out_states = self._block_out_states.get(func.start_ea, {})
            state = out_states.get(block.id)
            if state:
                regs, _mem = state
                if reg in regs:
                    return True
            defs = self._block_last_defs.get(func.start_ea, {}).get(block.id, {})
            if reg in defs and defs[reg]:
                return True
            rd_in = self._block_rd_in.get(func.start_ea, {}).get(block.id, {})
            if reg in rd_in and rd_in[reg]:
                return True
            if self._dominates_last_def(call_ea, reg, func, block):
                return True
            ea = call_ea
            while ea > block.start_ea:
                ea = idc.prev_head(ea)
                if ea == idc.BADADDR or ea < block.start_ea:
                    break
                mnem = idc.print_insn_mnem(ea).lower()
                if mnem in self._mov_mnems() | {"mov"}:
                    try:
                        dst_type = idc.get_operand_type(ea, 0)
                        src_type = idc.get_operand_type(ea, 1)
                    except Exception:
                        continue
                    if dst_type == idc.o_reg and idc.print_operand(ea, 0).lower() == reg:
                        if src_type == idc.o_reg:
                            src_reg = idc.print_operand(ea, 1).lower()
                            return src_reg in self.tainted_regs.get(func.start_ea, {})
                        if src_type == idc.o_imm:
                            return False
                        return True
            return True
        except Exception:
            return True

    def _dominates_last_def(self, call_ea: int, reg: str, func, call_block) -> bool:
        if ida_gdl is None:
            return False
        try:
            dom = ida_gdl.FlowChart(func).calculate_dominators()
        except Exception:
            return False
        last_def = None
        ea = call_ea
        while ea > func.start_ea:
            ea = idc.prev_head(ea)
            if ea == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem in self._mov_mnems():
                try:
                    dst_type = idc.get_operand_type(ea, 0)
                except Exception:
                    continue
                if dst_type == idc.o_reg and idc.print_operand(ea, 0).lower() == reg:
                    last_def = ea
                    break
        if last_def is None:
            return False
        def_block = None
        for b in idaapi.FlowChart(func, flags=idaapi.FC_PREDS):
            if b.start_ea <= last_def < b.end_ea:
                def_block = b
                break
        if not def_block:
            return False
        try:
            return dom.is_dom(def_block.id, call_block.id)
        except Exception:
            return False

    def _hexrays_taint_flow(self, func_ea: int) -> List[Tuple[int, int, str, float]]:
        if not self.use_hexrays_taint or ida_hexrays is None:
            return []
        func = ida_funcs.get_func(func_ea)
        if not func:
            return []
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except Exception:
            return []
        results: List[Tuple[int, int, str, float]] = []
        tainted = set()
        sources = self.taint_sources
        sinks = self.taint_sinks

        def callee_name(expr) -> Optional[str]:
            try:
                if expr.op == ida_hexrays.cot_obj:
                    return idc.get_func_name(expr.obj_ea).lower()
                if hasattr(ida_hexrays, "cot_ref") and expr.op == ida_hexrays.cot_ref:
                    if hasattr(expr, "x"):
                        return callee_name(expr.x)
                if hasattr(ida_hexrays, "cot_ptr") and expr.op == ida_hexrays.cot_ptr:
                    if hasattr(expr, "x"):
                        return callee_name(expr.x)
                if hasattr(ida_hexrays, "cot_memptr") and expr.op == ida_hexrays.cot_memptr:
                    if hasattr(expr, "m") and hasattr(expr.m, "obj_ea"):
                        return idc.get_func_name(expr.m.obj_ea).lower()
            except Exception:
                return None
            return None

        def is_tainted_expr(e) -> bool:
            try:
                if e.op == ida_hexrays.cot_var:
                    return e.v.idx in tainted
                if e.op == ida_hexrays.cot_call:
                    name = callee_name(e.x)
                    return bool(name and any(s in name for s in sources))
            except Exception:
                return False
            return False

        class HxVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                try:
                    if e.op == ida_hexrays.cot_asg:
                        if e.x.op == ida_hexrays.cot_var and is_tainted_expr(e.y):
                            tainted.add(e.x.v.idx)
                    if e.op == ida_hexrays.cot_call:
                        name = callee_name(e.x)
                        if not name:
                            return 0
                        if any(s in name for s in sinks):
                            try:
                                for arg in e.a:
                                    if is_tainted_expr(arg):
                                        results.append((arg.ea, e.ea, f"taint_flow_{name}", 0.75))
                            except Exception:
                                pass
                except Exception:
                    pass
                return 0

        v = HxVisitor()
        try:
            v.apply_to(cfunc.body, None)
        except Exception:
            return results
        for src, dst, kind, conf in results:
            if src and dst:
                self.add_xref(src, dst, kind, conf)
                try:
                    self.add_evidence(src, dst, "hexrays")
                except Exception:
                    pass
        return results

    def _mnem(self, ea: int, cache: Optional[dict]) -> str:
        if cache is None:
            return idc.print_insn_mnem(ea).lower()
        if ea in cache:
            return cache[ea]
        val = idc.print_insn_mnem(ea).lower()
        cache[ea] = val
        return val

    def _iter_basic_blocks(self, func):
        return self.cfg_walker.iter_basic_blocks(func)

    def _reachable_block_ids(self, entry_block):
        return self.cfg_walker.reachable_block_ids(entry_block)

    def _merge_pred_states(self, block, out_states):
        return self.cfg_walker.merge_pred_states(block, out_states)

    def _merge_pred_kinds(self, block, out_kinds):
        return self.cfg_walker.merge_pred_kinds(block, out_kinds)

    def _merge_pred_defs(self, block, out_defs):
        return self.cfg_walker.merge_pred_defs(block, out_defs)

    def _compute_reaching_defs(self, func, out_defs):
        return self.cfg_walker.compute_reaching_defs(func, out_defs)

    def _merge_all_states(self, out_states):
        regs = {}
        mem = {}
        for _bid, state in out_states.items():
            if not state:
                continue
            pre_regs, pre_mem = state
            for reg, (src, conf) in pre_regs.items():
                if reg not in regs or conf > regs[reg][1]:
                    regs[reg] = (src, conf)
            for key, (src, conf) in pre_mem.items():
                if key not in mem or conf > mem[key][1]:
                    mem[key] = (src, conf)
        return regs, mem

    def _state_equal(self, a, b) -> bool:
        if a is None or b is None:
            return False
        return a[0] == b[0] and a[1] == b[1]

    def _mov_mnems(self) -> Set[str]:
        if "arm" in self._procname or "aarch64" in self._procname:
            return {"mov", "ldr", "str", "adr", "adrp", "add"}
        if "mips" in self._procname:
            return {"move", "lw", "sw", "la", "li"}
        if "ppc" in self._procname:
            return {"mr", "lwz", "stw", "addi", "lis"}
        return {"mov", "lea"}

    def _stack_mnems(self) -> Set[str]:
        if "arm" in self._procname or "aarch64" in self._procname:
            return {"push", "pop", "stp", "ldp"}
        return {"push", "pop"}
