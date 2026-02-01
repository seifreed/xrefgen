import sys
import types
import unittest


def _install_ida_mocks():
    idautils = types.SimpleNamespace(Functions=lambda: [])
    ida_funcs = types.SimpleNamespace(get_func=lambda _ea: None)
    idc = types.SimpleNamespace(
        o_reg=1,
        o_displ=2,
        o_mem=3,
        o_imm=4,
        o_void=5,
        BADADDR=0xFFFFFFFF,
        get_operand_type=lambda _ea, _i: 1,
        print_operand=lambda _ea, _i: "eax",
        get_operand_value=lambda _ea, _i: 0,
    )
    ida_xref = types.SimpleNamespace()
    idaapi = types.SimpleNamespace()
    ida_ua = types.SimpleNamespace()
    ida_ida = types.SimpleNamespace(inf_is_64bit=lambda: False, inf_get_procname=lambda: "x86")
    ida_loader = types.SimpleNamespace(get_file_type_name=lambda: "ELF")
    sys.modules.setdefault("idautils", idautils)
    sys.modules.setdefault("ida_funcs", ida_funcs)
    sys.modules.setdefault("idc", idc)
    sys.modules.setdefault("ida_xref", ida_xref)
    sys.modules.setdefault("idaapi", idaapi)
    sys.modules.setdefault("ida_ua", ida_ua)
    sys.modules.setdefault("ida_ida", ida_ida)
    sys.modules.setdefault("ida_loader", ida_loader)


class TaintMemoryTests(unittest.TestCase):
    def setUp(self):
        _install_ida_mocks()

    def test_mem_key(self):
        from modules.infrastructure.ida.analysis.data_flow import DataFlowAnalyzer
        from modules.infrastructure.ida.analysis.components import HeapTracker

        analyzer = DataFlowAnalyzer.__new__(DataFlowAnalyzer)
        analyzer._safe_print_operand = lambda ea, idx: "[rbp+0x10]"
        analyzer._heap_aliases = {}
        analyzer._current_func_ea = None
        analyzer.heap_tracker = HeapTracker(analyzer)
        key = analyzer._mem_key(0, 0)
        self.assertEqual(key, "[rbp+0x10]")

    def test_heap_mem_key(self):
        from modules.infrastructure.ida.analysis.data_flow import DataFlowAnalyzer
        from modules.infrastructure.ida.analysis.components import HeapTracker

        analyzer = DataFlowAnalyzer.__new__(DataFlowAnalyzer)
        analyzer._safe_print_operand = lambda ea, idx: "[rax+0x10]"
        analyzer._heap_aliases = {0x1000: {"rax": "heap_100"}}
        analyzer._current_func_ea = 0x1000
        analyzer.heap_tracker = HeapTracker(analyzer)
        key = analyzer._mem_key(0, 0)
        self.assertEqual(key, "heap:heap_100+0x10")


if __name__ == "__main__":
    unittest.main()
