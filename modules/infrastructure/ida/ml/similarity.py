"""
Machine Learning Integration Module (Placeholder)
Function similarity detection, anomaly detection, and auto-categorization
"""

from typing import Dict, List, Tuple, Set
from modules.infrastructure.ida.base import IDAXrefAnalyzer
import idautils
import idc

class MLSimilarityAnalyzer(IDAXrefAnalyzer):
    """ML-based similarity and pattern analysis"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.model_path = config.get('model_path')
        self.similarity_threshold = config.get('similarity_threshold', 0.85)
        # Default to False to avoid importing heavy C-extensions inside IDA unless explicitly requested
        self.use_embeddings = bool(config.get('use_embeddings', False))
        
        # Only check/import ML deps if embeddings are requested
        self.ml_available = self._check_ml_dependencies()
        
    def get_name(self) -> str:
        return "MLSimilarityAnalyzer"
    
    def _check_ml_dependencies(self) -> bool:
        """Check if required ML libraries are available (only when embeddings are used)."""
        if not self.use_embeddings:
            return False
        try:
            import numpy  # noqa: F401
            import sklearn  # noqa: F401
            return True
        except Exception:
            # Do not spam UI; embeddings are optional and we have a pure-Python fallback
            return False
    
    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Approximate function similarity via mnemonic shingles + Jaccard."""
        if not self.ml_available and not self.use_embeddings:
            return []

        try:
            results: List[Tuple[int, int, str, float]] = []
            max_funcs = int(self.config.get('max_functions', 1000))
            threshold = float(self.similarity_threshold)

            # Build shingles per function
            func_mnems: Dict[int, Set[str]] = {}
            count = 0
            for func_ea in idautils.Functions():
                if count >= max_funcs:
                    break
                mnems: Set[str] = set()
                try:
                    # Use ida_funcs for safer function end retrieval
                    import ida_funcs
                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        continue
                    end = func.end_ea
                except Exception:
                    # Fallback to original method with error handling
                    try:
                        end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                        if end == idc.BADADDR:
                            continue
                    except Exception:
                        continue
                
                for head in idautils.Heads(func_ea, end):
                    try:
                        m = idc.print_insn_mnem(head).lower()
                        if m:
                            mnems.add(m)
                    except Exception:
                        continue
                if mnems:
                    func_mnems[func_ea] = mnems
                    count += 1

            funcs = list(func_mnems.keys())
            n = len(funcs)
            # Pairwise Jaccard (pruned by size)
            for i in range(n):
                a = funcs[i]
                A = func_mnems[a]
                for j in range(i + 1, n):
                    b = funcs[j]
                    B = func_mnems[b]
                    # Quick size filter
                    max_possible = min(len(A), len(B)) / max(len(A), len(B))
                    if max_possible < threshold:
                        continue
                    inter = len(A & B)
                    union = len(A | B)
                    if union == 0:
                        continue
                    sim = inter / union
                    if sim >= threshold:
                        conf = min(0.95, 0.6 + 0.4 * sim)
                        results.append((a, b, 'ml_similarity', conf))

            return results
        except Exception as e:
            print(f"[MLSimilarityAnalyzer] Analysis error: {e}")
            return []
