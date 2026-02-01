import unittest

from modules.application.registry import ModuleSpec, build_modules


class RegistryTests(unittest.TestCase):
    def test_build_modules_enabled(self):
        config = {"modules": {"mock": {"enabled": True}}}
        registry = (
            ModuleSpec("mock", "tests.fixtures.mock_module", "MockAnalyzer"),
        )
        modules = build_modules(config, registry=registry)
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0].get_name(), "MockAnalyzer")

    def test_build_modules_disabled(self):
        config = {"modules": {"mock": {"enabled": False}}}
        registry = (
            ModuleSpec("mock", "tests.fixtures.mock_module", "MockAnalyzer"),
        )
        modules = build_modules(config, registry=registry)
        self.assertEqual(modules, [])


if __name__ == "__main__":
    unittest.main()
