"""Deterministic function similarity relationships."""

from typing import Dict, List, Tuple, Set
from modules.infrastructure.ida.base import IDAXrefAnalyzer
import idautils
import idc


class SimilarityAnalyzer(IDAXrefAnalyzer):
    """Compare instruction-shape signatures without a model dependency."""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.similarity_threshold = config.get("similarity_threshold", 0.85)
        self.max_functions = int(config.get("max_functions", 1000))

    def get_name(self) -> str:
        return "SimilarityAnalyzer"

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        """Emit relationship results from mnemonic-set Jaccard similarity."""
        try:
            results = []
            threshold = float(self.similarity_threshold)

            # Build shingles per function
            func_mnems: Dict[int, Set[str]] = {}
            count = 0
            for func_ea in idautils.Functions():
                if count >= self.max_functions:
                    break
                mnems: Set[str] = set()
                try:
                    # Use ida_funcs for safer function end retrieval
                    import ida_funcs

                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        continue
                    end = func.end_ea
                except (TypeError, ValueError, AttributeError, RuntimeError):
                    # Fallback to original method with error handling
                    try:
                        end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                        if end == idc.BADADDR:
                            continue
                    except (TypeError, ValueError, AttributeError, RuntimeError):
                        continue

                for head in idautils.Heads(func_ea, end):
                    try:
                        m = idc.print_insn_mnem(head).lower()
                        if m:
                            mnems.add(m)
                    except (TypeError, ValueError, AttributeError, RuntimeError):
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
                        results.append(self.emit_relationship(
                                a, b, "function_similarity", conf, ("mnemonic_jaccard",)
                        ))

            return results
        except (TypeError, ValueError, AttributeError, RuntimeError) as e:
            print(f"[SimilarityAnalyzer] Analysis error: {e}")
            return []
