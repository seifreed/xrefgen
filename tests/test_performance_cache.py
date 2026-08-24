import sys
import time
import types
import tempfile
import unittest

def _create_mock_module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

def _install_ida_mocks():
    _create_mock_module("idaapi")
    idautils = _create_mock_module("idautils")
    idautils.Functions = lambda: [0x1000, 0x2000]
    idautils.Segments = lambda: []
    
    idc = _create_mock_module("idc")
    idc.get_segm_end = lambda _ea: 0
    idc.get_item_size = lambda _ea: 1
    idc.BADADDR = 0xFFFFFFFF
    
    _create_mock_module("ida_funcs")
    
    ida_bytes = _create_mock_module("ida_bytes")
    ida_bytes.get_byte = lambda _ea: 0
    ida_bytes.get_bytes = lambda _ea, _sz: b"\x90" * _sz
    
    _create_mock_module("ida_segment")
    
    ida_kernwin = _create_mock_module("ida_kernwin")
    ida_kernwin.MFF_READ = 0
    ida_kernwin.execute_sync = lambda fn, _mode: fn()
    
    ida_nalt = _create_mock_module("ida_nalt")
    ida_nalt.get_input_file_path = lambda: "test.exe"
    
    ida_pro = _create_mock_module("ida_pro")
    ida_pro.get_idb_change_count = lambda: 123


class PerformanceCacheTests(unittest.TestCase):
    def setUp(self):
        _install_ida_mocks()

    def test_cache_ttl_and_config_hash(self):
        from modules.infrastructure.ida.performance.optimizer import PerformanceOptimizer

        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "use_cache": True,
                "cache_dir": tmp,
                "incremental": True,
                "cache_ttl_seconds": 1,
            }
            opt = PerformanceOptimizer(cfg)
            opt.cache_analysis_result(0x1000, "mod", ["result"])
            self.assertEqual(opt.get_cached_result(0x1000, "mod"), ["result"])
            opt.save_cache()

            time.sleep(1.2)
            self.assertIsNone(opt.get_cached_result(0x1000, "mod"))

            cfg2 = dict(cfg)
            cfg2["cache_ttl_seconds"] = 2
            opt2 = PerformanceOptimizer(cfg2)
            # Config hash mismatch should result in empty cache load
            self.assertEqual(opt2.analysis_cache, {})


if __name__ == "__main__":
    unittest.main()
