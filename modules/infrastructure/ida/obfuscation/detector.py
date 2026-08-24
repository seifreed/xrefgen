"""Advanced Obfuscation Detection Module."""

from typing import Dict, List, Tuple
import idautils
import idc
from modules.infrastructure.ida.performance.optimizer import IncrementalAnalyzer
from modules.infrastructure.ida.obfuscation.cff import CFFDetector
from modules.infrastructure.ida.obfuscation.opaque import OpaquePredicateDetector
from modules.infrastructure.ida.obfuscation.strings import EncryptedStringDetector
from modules.infrastructure.ida.obfuscation.anti import AntiAnalysisDetector


class ObfuscationDetector(IncrementalAnalyzer):
    """Detects and resolves various obfuscation techniques."""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.detect_cff = config.get('detect_cff', True)
        self.detect_opaque = config.get('detect_opaque_predicates', True)
        self.detect_encryption = config.get('detect_string_encryption', True)
        self.detect_anti = config.get('detect_anti_analysis', True)
        self._cff = CFFDetector(self)
        self._opaque = OpaquePredicateDetector(self)
        self._strings = EncryptedStringDetector(self)
        self._anti = AntiAnalysisDetector(self)

    def get_name(self) -> str:
        return "ObfuscationDetector"

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        # Use IncrementalAnalyzer implementation (analyze_function per func)
        return super().analyze()

    def analyze_function(self, func) -> List[Tuple[int, int, str, float]]:
        results: List[Tuple[int, int, str, float]] = []
        if hasattr(self, "_slow_functions") and func.start_ea in self._slow_functions:
            # Skip heavy heuristics on slow functions
            if self.detect_anti:
                results.extend(self._anti.analyze_function(func))
            return results
        if self.detect_cff:
            results.extend(self._cff.analyze_function(func.start_ea, func))
        if self.detect_opaque:
            results.extend(self._opaque.analyze_function(func))
        if self.detect_encryption:
            results.extend(self._strings.analyze_function(func))
        if self.detect_anti:
            results.extend(self._anti.analyze_function(func))
        results.extend(self._detect_api_hashing(func))
        results.extend(self._detect_flattening(func))
        return results

    def _detect_api_hashing(self, func) -> List[Tuple[int, int, str, float]]:
        results: List[Tuple[int, int, str, float]] = []
        targets = {"getprocaddress", "ldrgetprocedureaddress"}
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head).lower() != "call":
                continue
            if idc.get_operand_type(head, 0) != idc.o_near:
                continue
            callee = idc.get_operand_value(head, 0)
            name = idc.get_func_name(callee).lower()
            if name not in targets:
                continue
            
            # Find the instruction loading the hash (usually a few before the call)
            hash_ea = None
            ea = head
            for _ in range(8):
                ea = idc.prev_head(ea)
                if ea == idc.BADADDR or ea < func.start_ea:
                    break
                if idc.get_operand_type(ea, 1) == idc.o_imm:
                    val = idc.get_operand_value(ea, 1)
                    if val and val > 0x1000:
                        hash_ea = ea
                        break
            
            if hash_ea:
                # Xref from the hash loading point to the call site
                self.add_xref(hash_ea, head, "api_hash_resolver", 0.7)
                try:
                    self.add_evidence(hash_ea, head, "api_hash")
                except (TypeError, ValueError, AttributeError, RuntimeError):
                    pass
                results.append((hash_ea, head, "api_hash_resolver", 0.7))
        return results

    def _detect_flattening(self, func) -> List[Tuple[int, int, str, float]]:
        results: List[Tuple[int, int, str, float]] = []
        jmp_count = 0
        ind_jmp = 0
        last_ind_jmp = None
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "jmp":
                jmp_count += 1
                if idc.get_operand_type(head, 0) in (idc.o_reg, idc.o_mem, idc.o_displ):
                    ind_jmp += 1
                    last_ind_jmp = head
                    
        if jmp_count >= 6 and ind_jmp >= 2 and last_ind_jmp:
            # Xref from function entry to the dispatcher/indirect jump
            self.add_xref(func.start_ea, last_ind_jmp, "flattening_suspect", 0.6)
            try:
                self.add_evidence(func.start_ea, last_ind_jmp, "obfuscation")
            except (TypeError, ValueError, AttributeError, RuntimeError):
                pass
            results.append((func.start_ea, last_ind_jmp, "flattening_suspect", 0.6))
        return results
