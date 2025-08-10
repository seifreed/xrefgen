"""
Graph-Based Analysis Module
Builds call chains, clusters functions, and analyzes complexity
"""

from typing import Dict, List, Tuple, Set, Optional
import idaapi
import idautils
import idc
import ida_funcs
import ida_gdl
from collections import defaultdict, deque
from modules.core.base import XrefAnalyzer
import math

class GraphAnalyzer(XrefAnalyzer):
    """Graph-based analysis for call chains and function clustering"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.max_chain_depth = config.get('max_chain_depth', 20)
        self.cluster_threshold = config.get('cluster_threshold', 0.7)
        self.complexity_threshold = config.get('complexity_threshold', 10)
        
        # Graph structures
        self.call_graph = defaultdict(set)  # func -> {called_funcs}
        self.reverse_call_graph = defaultdict(set)  # func -> {callers}
        self.function_clusters = []
        self.call_chains = []
        self.function_complexity = {}
        
    def get_name(self) -> str:
        return "GraphAnalyzer"
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Perform graph-based analysis"""
        results = []
        
        # Build call graph
        self._build_call_graph()
        
        # Analyze call chains from entry points
        chains = self._analyze_call_chains()
        results.extend(chains)
        
        # Generate function clusters
        clusters = self._generate_clusters()
        results.extend(clusters)
        
        # Analyze cyclomatic complexity
        complex_refs = self._analyze_complexity()
        results.extend(complex_refs)
        
        return results
    
    def _build_call_graph(self):
        """Build complete call graph of the binary"""
        print("[XrefGen] Building call graph...")
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            # Find all calls from this function
            for head in idautils.Heads(func.start_ea, func.end_ea):
                mnem = idc.print_insn_mnem(head).lower()
                
                if mnem in ["call", "bl", "blx", "jal", "jalr"]:
                    # Get call target
                    target = self._get_call_target(head)
                    if target and self.is_valid_reference(target):
                        # Add to call graph
                        self.call_graph[func_ea].add(target)
                        self.reverse_call_graph[target].add(func_ea)
    
    def _get_call_target(self, call_ea: int) -> Optional[int]:
        """Get target of a call instruction"""
        op_type = idc.get_operand_type(call_ea, 0)
        
        if op_type == idc.o_near:
            # Direct call
            return idc.get_operand_value(call_ea, 0)
        elif op_type in [idc.o_reg, idc.o_mem, idc.o_displ]:
            # Indirect call - try to resolve
            return self._resolve_indirect_call(call_ea)
        
        return None
    
    def _resolve_indirect_call(self, call_ea: int) -> Optional[int]:
        """Try to resolve indirect call target"""
        # Look for register/memory loads before call
        prev_ea = call_ea
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem in ["mov", "lea", "ldr", "la"]:
                src_type = idc.get_operand_type(prev_ea, 1)
                if src_type == idc.o_imm:
                    target = idc.get_operand_value(prev_ea, 1)
                    if self.is_valid_reference(target):
                        return target
        
        return None
    
    def _analyze_call_chains(self) -> List[Tuple[int, int, str, float]]:
        """Build and analyze call chains from entry points"""
        results = []
        entry_points = self._find_entry_points()
        
        print(f"[XrefGen] Analyzing call chains from {len(entry_points)} entry points...")
        
        for entry in entry_points:
            chains = self._build_chains_from_entry(entry)
            
            for chain in chains:
                if len(chain) > 2:  # Only interesting chains
                    # Create xrefs for chain segments
                    for i in range(len(chain) - 1):
                        source = chain[i]
                        target = chain[i + 1]
                        depth = i + 1
                        confidence = max(0.5, 1.0 - (depth * 0.05))
                        
                        self.add_xref(source, target, f"call_chain_depth_{depth}", confidence)
                        results.append((source, target, f"call_chain_depth_{depth}", confidence))
                    
                    self.call_chains.append(chain)
        
        return results
    
    def _find_entry_points(self) -> List[int]:
        """Find all entry points in the binary"""
        entry_points = []
        
        # Main entry point
        main_ea = idc.get_name_ea_simple("main")
        if main_ea != idc.BADADDR:
            entry_points.append(main_ea)
        
        # Start address
        start_ea = idc.get_inf_attr(idc.INF_START_EA)
        if start_ea != idc.BADADDR:
            entry_points.append(start_ea)
        
        # Exported functions
        for idx in range(idc.get_entry_qty()):
            ordinal = idc.get_entry_ordinal(idx)
            ea = idc.get_entry(ordinal)
            if ea != idc.BADADDR:
                entry_points.append(ea)
        
        # TLS callbacks
        tls_callbacks = self._find_tls_callbacks()
        entry_points.extend(tls_callbacks)
        
        # Ctors/Dtors
        ctors = self._find_ctors_dtors()
        entry_points.extend(ctors)
        
        # Remove duplicates
        return list(set(entry_points))
    
    def _find_tls_callbacks(self) -> List[int]:
        """Find TLS callback functions"""
        callbacks = []
        
        # Look for .tls section
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if ".tls" in seg_name.lower():
                # Parse TLS directory
                # This is simplified - real implementation would parse PE/ELF structures
                pass
        
        return callbacks
    
    def _find_ctors_dtors(self) -> List[int]:
        """Find constructor/destructor functions"""
        ctors = []
        
        # Look for .init_array, .ctors sections
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if any(name in seg_name.lower() for name in [".init", ".ctor", ".dtor", ".fini"]):
                # Read function pointers from section
                seg_end = idc.get_segm_end(seg_ea)
                ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
                
                ea = seg_ea
                while ea < seg_end:
                    if ptr_size == 8:
                        func_ptr = idc.get_qword(ea)
                    else:
                        func_ptr = idc.get_wide_dword(ea)
                    
                    if func_ptr and self.is_valid_reference(func_ptr):
                        ctors.append(func_ptr)
                    
                    ea += ptr_size
        
        return ctors
    
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
        
        for func_ea in idautils.Functions():
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
        """Analyze cyclomatic complexity and identify complex functions"""
        results = []
        
        print("[XrefGen] Analyzing function complexity...")
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            
            complexity = self._calculate_cyclomatic_complexity(func)
            self.function_complexity[func_ea] = complexity
            
            # Flag highly complex functions
            if complexity > self.complexity_threshold:
                # Complex functions likely have hidden control flow
                hidden_refs = self._analyze_complex_function(func, complexity)
                
                for source, target, confidence in hidden_refs:
                    self.add_xref(source, target, f"complex_func_cc_{complexity}", confidence)
                    results.append((source, target, f"complex_func_cc_{complexity}", confidence))
        
        return results
    
    def _calculate_cyclomatic_complexity(self, func) -> int:
        """Calculate cyclomatic complexity of a function"""
        # CC = E - N + 2P
        # E = edges, N = nodes, P = connected components (usually 1)
        
        nodes = 0
        edges = 0
        
        # Build control flow graph
        cfg_nodes = set()
        cfg_edges = set()
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            cfg_nodes.add(head)
            
            # Find edges (control flow transfers)
            mnem = idc.print_insn_mnem(head).lower()
            
            if mnem in ["jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", 
                        "jge", "jle", "jo", "jno", "js", "jns"]:
                # Conditional or unconditional jump
                target = idc.get_operand_value(head, 0)
                if func.start_ea <= target < func.end_ea:
                    cfg_edges.add((head, target))
                
                # Add fall-through edge for conditional jumps
                if mnem != "jmp":
                    next_ea = idc.next_head(head)
                    if next_ea != idc.BADADDR and next_ea < func.end_ea:
                        cfg_edges.add((head, next_ea))
            
            elif mnem in ["call", "ret", "retn"]:
                # These affect complexity
                edges += 1
            
            else:
                # Normal sequential flow
                next_ea = idc.next_head(head)
                if next_ea != idc.BADADDR and next_ea < func.end_ea:
                    cfg_edges.add((head, next_ea))
        
        nodes = len(cfg_nodes)
        edges = len(cfg_edges)
        
        # Cyclomatic complexity
        complexity = edges - nodes + 2
        
        # Adjust for multiple exit points
        exit_points = self._count_exit_points(func)
        if exit_points > 1:
            complexity += exit_points - 1
        
        return max(1, complexity)
    
    def _count_exit_points(self, func) -> int:
        """Count number of exit points in a function"""
        exits = 0
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in ["ret", "retn", "retf", "iret"]:
                exits += 1
        
        return max(1, exits)
    
    def _analyze_complex_function(self, func, complexity: int) -> List[Tuple[int, int, float]]:
        """Analyze complex function for hidden references"""
        refs = []
        
        # Complex functions often have:
        # 1. Jump tables
        # 2. Computed jumps
        # 3. Exception handlers
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            
            # Look for computed jumps
            if mnem == "jmp":
                op_type = idc.get_operand_type(head, 0)
                if op_type in [idc.o_reg, idc.o_mem, idc.o_displ]:
                    # Computed jump - try to resolve
                    targets = self._resolve_computed_targets(head, func)
                    for target in targets:
                        confidence = 0.6 - (complexity / 100.0)  # Lower confidence for very complex
                        refs.append((head, target, max(0.3, confidence)))
        
        return refs
    
    def _resolve_computed_targets(self, jmp_ea: int, func) -> List[int]:
        """Try to resolve computed jump targets"""
        targets = []
        
        # Look for jump table pattern
        # This is simplified - real implementation would be more sophisticated
        
        # Check if there's a bounds check before jump
        prev_ea = jmp_ea
        has_bounds_check = False
        max_value = 0
        
        for _ in range(10):
            prev_ea = idc.prev_head(prev_ea)
            if prev_ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(prev_ea).lower()
            if mnem == "cmp":
                # Found comparison - likely bounds check
                op_type = idc.get_operand_type(prev_ea, 1)
                if op_type == idc.o_imm:
                    max_value = idc.get_operand_value(prev_ea, 1)
                    has_bounds_check = True
                    break
        
        if has_bounds_check:
            # Try to find jump table
            # Look for array access pattern
            for i in range(max_value + 1):
                # Simplified - would need proper jump table parsing
                potential_target = func.start_ea + (i * 0x10)  # Arbitrary offset
                if self.is_valid_reference(potential_target):
                    targets.append(potential_target)
        
        return targets
    
    def get_call_graph(self) -> Dict[int, Set[int]]:
        """Get the call graph for external use"""
        return dict(self.call_graph)
    
    def get_clusters(self) -> List[Dict]:
        """Get function clusters for external use"""
        return self.function_clusters
    
    def get_complexity_map(self) -> Dict[int, int]:
        """Get complexity scores for all functions"""
        return self.function_complexity