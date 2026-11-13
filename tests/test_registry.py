import unittest
import json
import io
from contextlib import redirect_stdout

from modules.application.registry import ModuleSpec, build_modules
from modules.presentation import logger


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

    def test_optional_module_warning_omits_exception_message(self):
        config = {"modules": {"optional": {"enabled": True}}}
        registry = (ModuleSpec("optional", "missing_secret_module", "Analyzer", True),)

        output = io.StringIO()
        with redirect_stdout(output):
            logger.configure(None, "warn")
            self.assertEqual(build_modules(config, registry=registry), [])
        event = json.loads(output.getvalue())
        self.assertEqual(event["event_name"], "module.registration_skipped")
        self.assertEqual(event["error_type"], "ModuleNotFoundError")
        self.assertNotIn("missing_secret_module", event["message"])


if __name__ == "__main__":
    unittest.main()
