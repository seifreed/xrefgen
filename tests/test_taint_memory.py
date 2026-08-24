import sys
import types
import unittest
from unittest.mock import MagicMock


# Install IDA mocks before importing any module
def _create_mock_module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


def _install_ida_mocks():
    _create_mock_module("idaapi")

    idautils = _create_mock_module("idautils")
    idautils.Functions = lambda: []
    _create_mock_module("ida_funcs")

    idc = _create_mock_module("idc")
    idc.o_reg = 1
    idc.o_displ = 2
    idc.o_mem = 3
    idc.o_imm = 4
    idc.o_void = 5
    idc.BADADDR = 0xFFFFFFFF
    idc.get_operand_type = lambda _ea, _i: 1
    idc.print_operand = lambda _ea, _i: "eax"
    idc.get_operand_value = lambda _ea, _i: 0

    _create_mock_module("ida_xref")

    ida_ida = _create_mock_module("ida_ida")
    ida_ida.inf_is_64bit = lambda: False
    ida_ida.inf_get_procname = lambda: "x86"

    _create_mock_module("ida_loader")
    _create_mock_module("ida_gdl")
    _create_mock_module("ida_frame")
    _create_mock_module("ida_struct")
    _create_mock_module("ida_typeinf")
    _create_mock_module("ida_bytes")
    _create_mock_module("ida_segment")
    _create_mock_module("ida_ua")


_install_ida_mocks()


class TaintMemoryTests(unittest.TestCase):
    def setUp(self):
        pass

    def test_mem_key(self):
        from modules.infrastructure.ida.analysis.data_flow import DataFlowAnalyzer
        from modules.infrastructure.ida.analysis.components import HeapTracker

        analyzer = DataFlowAnalyzer.__new__(DataFlowAnalyzer)
        setattr(analyzer, "_safe_print_operand", MagicMock(return_value="[rbp+0x10]"))
        analyzer._heap_aliases = {}
        analyzer._current_func_ea = None
        analyzer.heap_tracker = HeapTracker(analyzer)
        key = analyzer._mem_key(0, 0)
        self.assertEqual(key, "[rbp+0x10]")

    def test_heap_mem_key(self):
        from modules.infrastructure.ida.analysis.data_flow import DataFlowAnalyzer
        from modules.infrastructure.ida.analysis.components import HeapTracker

        analyzer = DataFlowAnalyzer.__new__(DataFlowAnalyzer)
        setattr(analyzer, "_safe_print_operand", MagicMock(return_value="[rax+0x10]"))
        analyzer._heap_aliases = {0x1000: {"rax": "heap_100"}}
        analyzer._current_func_ea = 0x1000
        analyzer.heap_tracker = HeapTracker(analyzer)
        key = analyzer._mem_key(0, 0)
        self.assertEqual(key, "heap:heap_100+0x10")


if __name__ == "__main__":
    unittest.main()
