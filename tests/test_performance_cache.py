import sys
import time
import types
import tempfile
import unittest


def _install_ida_mocks():
    idaapi = types.SimpleNamespace()
    idautils = types.SimpleNamespace(Segments=lambda: [], Functions=lambda: [])
    idc = types.SimpleNamespace(
        get_segm_end=lambda _ea: 0,
        get_item_size=lambda _ea: 1,
        BADADDR=0xFFFFFFFF,
    )
    ida_funcs = types.SimpleNamespace()
    ida_bytes = types.SimpleNamespace(get_byte=lambda _ea: 0)
    ida_segment = types.SimpleNamespace(getseg=lambda _ea: None)
    ida_kernwin = types.SimpleNamespace(MFF_READ=0, execute_sync=lambda fn, _mode: fn())
    sys.modules.setdefault("idaapi", idaapi)
    sys.modules.setdefault("idautils", idautils)
    sys.modules.setdefault("idc", idc)
    sys.modules.setdefault("ida_funcs", ida_funcs)
    sys.modules.setdefault("ida_bytes", ida_bytes)
    sys.modules.setdefault("ida_segment", ida_segment)
    sys.modules.setdefault("ida_kernwin", ida_kernwin)


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
