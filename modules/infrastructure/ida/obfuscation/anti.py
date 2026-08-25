"""Anti-analysis detection helpers."""

from typing import List, Tuple
import idautils
import idc
from modules.infrastructure.ida.base import IDAXrefAnalyzer


class AntiAnalysisDetector:
    def __init__(self, analyzer: IDAXrefAnalyzer):
        self.analyzer = analyzer
        self.mnem_patterns = {"int3", "rdtsc", "rdtscp", "cpuid"}
        self.api_patterns = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"}

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        results = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in self.mnem_patterns:
                results.append(self.analyzer.emit_finding(
                    head, head, "anti_analysis", 0.7, ("anti_analysis",)
                ))
            elif mnem == "call":
                try:
                    target = idc.get_operand_value(head, 0)
                    name = idc.get_func_name(target).lower()
                except (TypeError, ValueError, AttributeError, RuntimeError):
                    name = ""
                if any(p in name for p in self.api_patterns):
                    results.append(self.analyzer.emit_finding(
                        head, target, "anti_analysis", 0.8, ("anti_analysis",)
                    ))
        return results
