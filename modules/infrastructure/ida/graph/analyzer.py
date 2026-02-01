"""
Graph-Based Analysis Module
Builds call chains, clusters functions, and analyzes complexity
"""

from typing import Dict, List, Tuple, Set, Optional
import idaapi
import idautils
import idc
import ida_funcs
try:
    import ida_hexrays
except Exception:
    ida_hexrays = None
import ida_segment
try:
    import ida_typeinf
except Exception:
    ida_typeinf = None
from collections import defaultdict, deque
from modules.infrastructure.ida.performance.optimizer import IncrementalAnalyzer
from modules.infrastructure.ida.graph.strategies import CallbackResolver, WrapperDetector, SEHResolver, VTableResolver
from modules.infrastructure.ida.graph.services import EntryPointFinder, ComplexityAnalyzer
from modules.infrastructure.ida.graph.noise import GraphNoisePolicy

class GraphAnalyzer(IncrementalAnalyzer):
    """Graph-based analysis for call chains and function clustering"""

    CALL_MNEMS = {"call", "bl", "blx", "jal", "jalr"}
    JMP_MNEMS = {"jmp"}
    COND_JMPS = {"je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns"}
    RET_MNEMS = {"call", "ret", "retn"}
    EXIT_MNEMS = {"ret", "retn", "retf", "iret"}
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        try:
            self._procname = idaapi.get_inf_structure().procname.lower()
        except Exception:
            self._procname = ""
        self._tuning_defaults = {
            "complexity_threshold": 10,
            "cluster_threshold": 0.7,
            "hub_threshold": 20,
            "cycle_max_len": 2,
            "skip_trivial_size": 16,
            "max_chain_depth": 20,
            "max_indirect_targets": 3,
            "min_indirect_confidence": 0.4,
            "vtable_min_len": 3,
        }
        self.tuning_table = self._build_tuning_table(config)
        self.cluster_threshold = self.tuning_table.get("cluster_threshold")
        self.complexity_threshold = self.tuning_table.get("complexity_threshold")
        self.hub_threshold = self.tuning_table.get("hub_threshold")
        self.cycle_max_len = self.tuning_table.get("cycle_max_len")
        self.max_chain_depth = self.tuning_table.get("max_chain_depth")
        self.max_indirect_targets = self.tuning_table.get("max_indirect_targets")
        self.min_indirect_confidence = self.tuning_table.get("min_indirect_confidence")
        self.skip_trivial_size = self.tuning_table.get("skip_trivial_size")
        self.vtable_min_len = self.tuning_table.get("vtable_min_len")
        self.compiler_profile = config.get('compiler_profile', 'auto')
        self.callback_targets = config.get('callback_targets', {
            "qsort": 3,
            "bsearch": 3,
            "createthread": 2,
            "enumwindows": 0,
            "enumchildwindows": 1,
        })
        self.indirect_backtrack_depth = int(config.get('indirect_backtrack_depth', 10))
        self.indirect_score_decay = float(config.get('indirect_score_decay', 0.1))
        self.indirect_direct_confidence = float(config.get('indirect_direct_confidence', 0.95))
        self.indirect_base_confidence = float(config.get('indirect_base_confidence', 0.9))
        self.merge_multi_source_bonus = float(config.get('merge_multi_source_bonus', 0.12))
        self.merge_heuristic_penalty = float(config.get('merge_heuristic_penalty', 0.9))
        self.call_chain_decay = float(config.get('call_chain_decay', 0.98))
        self.call_chain_min_length = int(config.get('call_chain_min_length', 2))
        self._confidence_defaults = {
            "hub_call": 0.6,
            "call_cycle": 0.55,
            "trampoline": 0.7,
            "wrapper_call": 0.6,
            "callback_arg": 0.75,
            "seh_handler": 0.7,
            "vtable_named": 0.65,
            "vtable_scan": 0.55,
        }
        self.confidence_table = self._build_confidence_table(config)
        if self.compiler_profile == 'auto':
            self.compiler_profile = self._detect_compiler_profile()
        
        # Graph structures
        self.call_graph = defaultdict(set)  # func -> {called_funcs}
        self.reverse_call_graph = defaultdict(set)  # func -> {callers}
        self.function_clusters = []
        self.call_chains = []
        self.function_complexity = {}
        self._direct_calls = set()
        self._indirect_cache = {}
        self._edges_by_func = {}
        self._wrapper_detector = WrapperDetector(self)
        self._callback_resolver = CallbackResolver(self)
        self._seh_resolver = SEHResolver(self)
        self._vtable_resolver = VTableResolver(self)
        self._entry_finder = EntryPointFinder(self)
        self._complexity = ComplexityAnalyzer(self)
        self._noise_policy = GraphNoisePolicy(self)

    def _iter_functions(self):
        """Yield (func_ea, func) for all valid functions."""
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                yield func_ea, func

    def _iter_heads(self, func):
        for head in idautils.Heads(func.start_ea, func.end_ea):
            yield head
        
    def get_name(self) -> str:
        return "GraphAnalyzer"
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform graph-based analysis"""
        results = []
        
        # Build call graph
        self._build_call_graph()
        self._set_noise_factor()
        
        # Analyze call chains from entry points
        chains = self._analyze_call_chains()
        results.extend(chains)
        
        # Generate function clusters
        clusters = self._generate_clusters()
        results.extend(clusters)
        
        # Analyze cyclomatic complexity
        complex_refs = self._complexity.analyze()
        results.extend(complex_refs)

        # Analyze hubs and cycles
        results.extend(self._analyze_hubs())
        results.extend(self._analyze_cycles())
        results.extend(self._vtable_resolver.analyze())
        results.extend(self._analyze_trampolines())
        results.extend(self._wrapper_detector.analyze())
        results.extend(self._callback_resolver.analyze())
        results.extend(self._seh_resolver.analyze())
        
        return results

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        """Incremental analysis for a single function: only emit its call edges."""
        func_ea = func.start_ea
        if self._is_trivial_function(func):
            return []
        local_results: List[Tuple[int, int, str, float]] = []
        mnem_cache = {}
        self._clear_edges_for_func(func_ea)
        # Build calls from this function only
        for head in self._iter_heads(func):
            mnem = self._mnem_cached(head, mnem_cache)
            if mnem in self.CALL_MNEMS:
                targets = self._get_call_targets(head)
                for target, conf in targets:
                    if self.is_valid_reference(target):
                        if (func_ea, target) in self._direct_calls and conf < 0.95:
                            continue
                        self._add_graph_edge(func_ea, target)
                        local_results.append(self._add_call_edge_xref(func_ea, target, conf))
        return local_results

    def _add_graph_edge(self, source: int, target: int):
        self.call_graph[source].add(target)
        self.reverse_call_graph[target].add(source)
        self._edges_by_func.setdefault(source, set()).add(target)

    def _add_call_edge_xref(self, source: int, target: int, conf: float = 0.9):
        self.add_xref(source, target, "call_edge", conf)
        try:
            self.add_evidence(source, target, "graph")
        except Exception:
            pass
        return (source, target, "call_edge", conf)

    def _analyze_hubs(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for func_ea, called in self.call_graph.items():
            degree = len(called) + len(self.reverse_call_graph.get(func_ea, set()))
            if degree >= self.hub_threshold:
                for target in called:
                    conf = self.confidence("hub_call")
                    self.add_xref(func_ea, target, "hub_call", conf)
                    results.append((func_ea, target, "hub_call", conf))
        return results

    def _analyze_cycles(self) -> List[Tuple[int, int, str, float]]:
        results = []
        if self.cycle_max_len < 2:
            return results
        for func_ea, called in self.call_graph.items():
            for target in called:
                if func_ea in self.call_graph.get(target, set()):
                    conf = self.confidence("call_cycle")
                    self.add_xref(func_ea, target, "call_cycle", conf)
                    results.append((func_ea, target, "call_cycle", conf))
        return results

    # Vtable analysis now lives in VTableResolver.
    
    def _build_call_graph(self):
        """Build complete call graph of the binary"""
        print("[XrefGen] Building call graph...")

        for func_ea, func in self._iter_functions():
            if self._is_trivial_function(func):
                continue
            mnem_cache = {}
            # Find all calls from this function
            for head in self._iter_heads(func):
                mnem = self._mnem_cached(head, mnem_cache)
                
                if mnem in self.CALL_MNEMS:
                    targets = self._get_call_targets(head)
                    for target, _conf in targets:
                        if self.is_valid_reference(target):
                            self._add_graph_edge(func_ea, target)
                            if idc.get_operand_type(head, 0) == idc.o_near:
                                self._direct_calls.add((func_ea, target))

    def _set_noise_factor(self):
        self._noise_policy.apply()
    
    def _get_call_targets(self, call_ea: int) -> List[Tuple[int, float]]:
        """Get targets of a call instruction with confidence."""
        candidates: List[Tuple[int, float, str]] = []
        op_type = idc.get_operand_type(call_ea, 0)
        
        if op_type == idc.o_near:
            # Direct call
            candidates.append((idc.get_operand_value(call_ea, 0), self.indirect_direct_confidence, "direct"))
        elif op_type in [idc.o_reg, idc.o_mem, idc.o_displ]:
            if call_ea in self._indirect_cache:
                for target, conf in self._indirect_cache[call_ea]:
                    candidates.append((target, conf, "heuristic"))
            else:
                res = self._resolve_indirect_call(call_ea)
                self._indirect_cache[call_ea] = res
                for target, conf in res:
                    candidates.append((target, conf, "heuristic"))
        for target, conf in self._resolve_hexrays_call(call_ea):
            candidates.append((target, conf, "hexrays"))
        
        return self._merge_targets(candidates)
    
    def _resolve_indirect_call(self, call_ea: int) -> List[Tuple[int, float]]:
        """Try to resolve indirect call target"""
        # Look for register/memory loads before call and score candidates
        candidates = []
        op_type = idc.get_operand_type(call_ea, 0)
        if op_type in [idc.o_mem, idc.o_displ]:
            tgt = self._resolve_from_mem_operand(call_ea, 0)
            if tgt and self.is_valid_reference(tgt):
                candidates.append((0.85, tgt))
        prev_ea = call_ea
        for depth in range(self.indirect_backtrack_depth):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem in self._load_mnems():
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_imm:
                    target = idc.get_operand_value(prev_ea, 1)
                    if self.is_valid_reference(target):
                        # closer = higher score
                        score = max(0.1, 1.0 - (depth * self.indirect_score_decay))
                        candidates.append((score, target))
                elif src_type in [idc.o_mem, idc.o_displ]:
                    target = self._resolve_from_mem_operand(prev_ea, 1)
                    if target and self.is_valid_reference(target):
                        score = max(0.1, 0.9 - (depth * self.indirect_score_decay))
                        candidates.append((score, target))
        if not candidates:
            return []
        candidates.sort(reverse=True)
        results = []
        for score, target in candidates[: self.max_indirect_targets]:
            conf = self.combine_confidence(self.indirect_base_confidence, score)
            conf *= self._compiler_conf_multiplier(target)
            conf = max(self.min_indirect_confidence, conf)
            conf *= getattr(self, "_noise_factor", 1.0)
            results.append((target, conf))
        return results

    def _resolve_hexrays_call(self, call_ea: int) -> List[Tuple[int, float]]:
        if ida_hexrays is None:
            return []
        try:
            func = ida_funcs.get_func(call_ea)
            if not func:
                return []
            cfunc = ida_hexrays.decompile(func.start_ea)
        except Exception:
            return []
        results = []

        class CallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.targets = []

            def visit_expr(self, e):
                try:
                    if e.op == ida_hexrays.cot_call and e.ea == call_ea:
                        if e.x.op == ida_hexrays.cot_obj:
                            self.targets.append(e.x.obj_ea)
                        elif hasattr(ida_hexrays, "cot_memptr") and e.x.op == ida_hexrays.cot_memptr:
                            if hasattr(e.x, "m") and hasattr(e.x.m, "obj_ea"):
                                self.targets.append(e.x.m.obj_ea)
                        elif hasattr(ida_hexrays, "cot_ptr") and e.x.op == ida_hexrays.cot_ptr:
                            if hasattr(e.x, "x") and hasattr(e.x.x, "obj_ea"):
                                self.targets.append(e.x.x.obj_ea)
                        elif hasattr(ida_hexrays, "cot_ref") and e.x.op == ida_hexrays.cot_ref:
                            if hasattr(e.x, "x") and hasattr(e.x.x, "obj_ea"):
                                self.targets.append(e.x.x.obj_ea)
                except Exception:
                    pass
                return 0

        v = CallVisitor()
        try:
            v.apply_to(cfunc.body, None)
        except Exception:
            return []
        for t in v.targets:
            results.append((t, 0.9))
        return results

    def _merge_targets(self, candidates: List[Tuple[int, float, str]]) -> List[Tuple[int, float]]:
        if not candidates:
            return []
        agg: Dict[int, float] = {}
        sources: Dict[int, set] = {}
        for target, conf, src in candidates:
            agg[target] = max(agg.get(target, 0.0), conf)
            sources.setdefault(target, set()).add(src)
        merged = []
        for target, conf in agg.items():
            if len(sources.get(target, set())) >= 2:
                conf = min(1.0, conf + self.merge_multi_source_bonus)
            if sources.get(target, set()) == {"heuristic"}:
                conf *= self.merge_heuristic_penalty
            merged.append((target, conf))
        merged.sort(key=lambda x: x[1], reverse=True)
        return merged

    def _analyze_trampolines(self) -> List[Tuple[int, int, str, float]]:
        results = []
        for func_ea, func in self._iter_functions():
            if (func.end_ea - func.start_ea) > self.skip_trivial_size:
                continue
            target = None
            for head in self._iter_heads(func):
                mnem = idc.print_insn_mnem(head).lower()
                if mnem in ["jmp", "call"]:
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_near:
                        target = idc.get_operand_value(head, 0)
                    break
            if target and self.is_valid_reference(target):
                conf = self.confidence("trampoline")
                self.add_xref(func_ea, target, "trampoline", conf)
                results.append((func_ea, target, "trampoline", conf))
        return results

    def _detect_compiler_profile(self) -> str:
        # Heuristic based on known symbols/segments
        try:
            for seg_ea in idautils.Segments():
                name = idc.get_segm_name(seg_ea).lower()
                if "gopclntab" in name:
                    return "go"
                if "rust" in name:
                    return "rust"
        except Exception:
            pass
        # Fall back to function names
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

    def _compiler_conf_multiplier(self, target_ea: int) -> float:
        if self.compiler_profile == "go":
            return 1.05
        if self.compiler_profile == "cpp":
            return 1.03
        if self.compiler_profile == "rust":
            return 1.03
        return 1.0

    def _is_trivial_function(self, func) -> bool:
        try:
            return (func.end_ea - func.start_ea) <= self.skip_trivial_size
        except Exception:
            return False

    def set_modified_functions(self, modified: Set[int]):
        """Extend modified set with known callers to keep graph consistent."""
        expanded = set(modified)
        for func_ea in list(modified):
            callers = self.reverse_call_graph.get(func_ea, set())
            expanded.update(callers)
        self.modified_functions = expanded

    def _clear_edges_for_func(self, func_ea: int):
        old = self._edges_by_func.get(func_ea, set())
        if not old:
            return
        for target in old:
            if func_ea in self.call_graph:
                self.call_graph[func_ea].discard(target)
            if target in self.reverse_call_graph:
                self.reverse_call_graph[target].discard(func_ea)
        self._edges_by_func[func_ea] = set()

    def _mnem_cached(self, ea: int, cache: dict) -> str:
        if ea in cache:
            return cache[ea]
        mnem = idc.print_insn_mnem(ea).lower()
        cache[ea] = mnem
        return mnem

    def _load_mnems(self) -> Set[str]:
        if "arm" in self._procname or "aarch64" in self._procname:
            return {"ldr", "adr", "adrp", "add", "mov"}
        if "mips" in self._procname:
            return {"lw", "la", "li", "move"}
        if "ppc" in self._procname:
            return {"lwz", "lis", "addi", "mr"}
        return {"mov", "lea", "ldr", "la"}

    def _resolve_from_mem_operand(self, ea: int, op_idx: int = 0) -> Optional[int]:
        try:
            addr = idc.get_operand_value(ea, op_idx)
        except Exception:
            addr = None
        if addr is None or addr == idc.BADADDR:
            return None
        try:
            seg = ida_segment.getseg(addr)
            if seg and idc.get_segm_name(addr).lower() in (".got", ".plt", ".idata", ".rdata"):
                try:
                    self.add_evidence(ea, addr, "global_alias")
                except Exception:
                    pass
        except Exception:
            pass
        target = self._read_ptr(addr)
        if target and self.is_valid_reference(target):
            return target
        return None

    def _read_ptr(self, ea: int) -> Optional[int]:
        try:
            is64 = idaapi.get_inf_structure().is_64bit()
        except Exception:
            is64 = False
        try:
            return idc.get_qword(ea) if is64 else idc.get_wide_dword(ea)
        except Exception:
            return None

    # Wrapper analysis now lives in WrapperDetector.

    # Callback analysis now lives in CallbackResolver.

    # SEH analysis now lives in SEHResolver.

    def _find_named_vtables(self) -> List[Tuple[int, bool]]:
        results: List[Tuple[int, bool]] = []
        try:
            for seg_ea in idautils.Segments():
                seg_end = idc.get_segm_end(seg_ea)
                ea = seg_ea
                while ea < seg_end:
                    name = idc.get_name(ea)
                    if name:
                        lname = name.lower()
                        if "vtable" in lname or "vftable" in lname or "??_7" in name:
                            is_rtti = True
                            ptr = 8 if idaapi.get_inf_structure().is_64bit() else 4
                            min_size = self.vtable_min_len * ptr
                            if ida_typeinf is not None:
                                try:
                                    tinfo = ida_typeinf.tinfo_t()
                                    if ida_typeinf.get_tinfo(tinfo, ea):
                                        try:
                                            if tinfo.get_size() and tinfo.get_size() < min_size:
                                                is_rtti = False
                                            if hasattr(tinfo, "is_udt") and tinfo.is_udt():
                                                if tinfo.get_size() % ptr != 0:
                                                    is_rtti = False
                                                # Validate member offsets are contiguous pointers
                                                udt = ida_typeinf.udt_type_data_t()
                                                if tinfo.get_udt_details(udt):
                                                    offsets = [m.offset for m in udt]
                                                    if offsets:
                                                        offsets.sort()
                                                        expected = [i * ptr for i in range(len(offsets))]
                                                        if offsets[: len(expected)] != expected:
                                                            is_rtti = False
                                                    # Validate member types are function pointers
                                                    for m in udt:
                                                        try:
                                                            mt = m.type
                                                            if mt.is_ptr():
                                                                mt = mt.get_pointed_object()
                                                            if not mt.is_func():
                                                                is_rtti = False
                                                                break
                                                        except Exception:
                                                            is_rtti = False
                                                            break
                                        except Exception:
                                            is_rtti = True
                                except Exception:
                                    is_rtti = True
                            results.append((ea, is_rtti))
                    ea = idc.next_head(ea, seg_end)
        except Exception:
            return results
        return results
    
    def _analyze_call_chains(self) -> List[Tuple[int, int, str, float]]:
        """Build and analyze call chains from entry points"""
        results = []
        entry_points = self._entry_finder.find_entry_points()
        
        print(f"[XrefGen] Analyzing call chains from {len(entry_points)} entry points...")
        
        for entry in entry_points:
            chains = self._build_chains_from_entry(entry)
            
            for chain in chains:
                # Pruning: require paths longer than 2 and cap total links per entry
                if len(chain) > self.call_chain_min_length:
                    chain_decay = pow(self.call_chain_decay, len(chain))
                    # Create xrefs for chain segments
                    for i in range(len(chain) - 1):
                        source = chain[i]
                        target = chain[i + 1]
                        depth = i + 1
                        base_conf = self.confidence("call_chain_base", 1.0)
                        min_conf = self.confidence("call_chain_min", 0.6)
                        depth_decay = self.confidence("call_chain_depth_decay", 0.1)
                        confidence = max(min_conf, (base_conf - (depth * depth_decay)) * chain_decay)
                        
                        self.add_xref(source, target, f"call_chain_depth_{depth}", confidence)
                        results.append((source, target, f"call_chain_depth_{depth}", confidence))
                    
                    self.call_chains.append(chain)
        
        return results
    
    def _find_entry_points(self) -> List[int]:
        return self._entry_finder.find_entry_points()
    
    def _build_chains_from_entry(self, entry: int, max_depth: int = None) -> List[List[int]]:
        """Build call chains starting from an entry point"""
        if max_depth is None:
            max_depth = self.max_chain_depth
        
        chains = []
        visited = set()
        current_chain = []
        
        def dfs(func_ea: int, depth: int):
            if depth > max_depth or func_ea in visited:
                if len(current_chain) > 1:
                    chains.append(current_chain[:])
                return
            
            visited.add(func_ea)
            current_chain.append(func_ea)
            
            # Explore called functions
            if func_ea in self.call_graph:
                for called_func in self.call_graph[func_ea]:
                    dfs(called_func, depth + 1)
            else:
                # Leaf node - save chain
                if len(current_chain) > 1:
                    chains.append(current_chain[:])
            
            current_chain.pop()
            visited.remove(func_ea)
        
        dfs(entry, 0)
        return chains
    
    def _generate_clusters(self) -> List[Tuple[int, int, str, float]]:
        """Generate function clusters based on xref patterns"""
        results = []
        
        print("[XrefGen] Generating function clusters...")
        
        # Use connected components algorithm
        clusters = self._find_connected_components()
        
        for cluster_id, cluster_funcs in enumerate(clusters):
            if len(cluster_funcs) < 3:
                continue  # Skip small clusters
            
            # Calculate cluster cohesion
            cohesion = self._calculate_cluster_cohesion(cluster_funcs)
            
            if cohesion >= self.cluster_threshold:
                # Create xrefs within cluster
                for func1 in cluster_funcs:
                    for func2 in cluster_funcs:
                        if func1 != func2 and func2 in self.call_graph.get(func1, set()):
                            self.add_xref(func1, func2, f"cluster_{cluster_id}", cohesion)
                            results.append((func1, func2, f"cluster_{cluster_id}", cohesion))
                
                self.function_clusters.append({
                    'id': cluster_id,
                    'functions': cluster_funcs,
                    'cohesion': cohesion
                })
        
        return results
    
    def _find_connected_components(self) -> List[Set[int]]:
        """Find connected components in call graph"""
        visited = set()
        components = []
        
        for func_ea, _func in self._iter_functions():
            if func_ea not in visited:
                component = set()
                queue = deque([func_ea])
                
                while queue:
                    current = queue.popleft()
                    if current in visited:
                        continue
                    
                    visited.add(current)
                    component.add(current)
                    
                    # Add neighbors (both directions for undirected graph)
                    neighbors = self.call_graph.get(current, set()) | \
                               self.reverse_call_graph.get(current, set())
                    
                    for neighbor in neighbors:
                        if neighbor not in visited:
                            queue.append(neighbor)
                
                if len(component) > 1:
                    components.append(component)
        
        return components
    
    def _calculate_cluster_cohesion(self, cluster_funcs: Set[int]) -> float:
        """Calculate cohesion score for a cluster"""
        if len(cluster_funcs) < 2:
            return 0.0
        
        # Count internal edges
        internal_edges = 0
        external_edges = 0
        
        for func in cluster_funcs:
            for called in self.call_graph.get(func, set()):
                if called in cluster_funcs:
                    internal_edges += 1
                else:
                    external_edges += 1
        
        # Calculate cohesion as ratio of internal to total edges
        total_edges = internal_edges + external_edges
        if total_edges == 0:
            return 0.0
        
        cohesion = internal_edges / total_edges
        
        # Adjust for cluster size (larger clusters naturally have lower cohesion)
        size_factor = 1.0 - (len(cluster_funcs) / 100.0)  # Normalize by 100 functions
        size_factor = max(0.5, size_factor)  # Don't penalize too much
        
        return cohesion * size_factor
    
    def _analyze_complexity(self) -> List[Tuple[int, int, str, float]]:
        print("[XrefGen] Analyzing function complexity...")
        return self._complexity.analyze()

    def confidence(self, key: str, default: float = None) -> float:
        if key in self.confidence_table:
            return float(self.confidence_table[key])
        if default is not None:
            return float(default)
        return float(self._confidence_defaults.get(key, 0.0))

    def _build_confidence_table(self, config: Dict) -> Dict[str, float]:
        table = {}
        raw = config.get("confidence_table", {})
        if isinstance(raw, dict):
            table.update(raw)
        for key, val in self._confidence_defaults.items():
            table.setdefault(key, val)
        return table

    def _build_tuning_table(self, config: Dict) -> Dict[str, float]:
        table = {}
        raw = config.get("tuning_table", {})
        if isinstance(raw, dict):
            table.update(raw)
        for key, val in self._tuning_defaults.items():
            table.setdefault(key, val)
        return table
    
    def get_call_graph(self) -> Dict[int, Set[int]]:
        """Get the call graph for external use"""
        return dict(self.call_graph)
    
    def get_clusters(self) -> List[Dict]:
        """Get function clusters for external use"""
        return self.function_clusters
    
    def get_complexity_map(self) -> Dict[int, int]:
        """Get complexity scores for all functions"""
        return self.function_complexity
