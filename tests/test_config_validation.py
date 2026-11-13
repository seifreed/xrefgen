import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout

from modules.application.config import Config
from modules.presentation import logger


class ConfigValidationTests(unittest.TestCase):
    def test_distributed_config_matches_defaults(self):
        config_path = pathlib.Path(__file__).parents[1] / "xrefgen_config.json"
        user_config = json.loads(config_path.read_text(encoding="utf-8"))
        validator = Config.__new__(Config)
        loaded = validator._merge_configs(Config.DEFAULT_CONFIG, user_config)
        self.assertEqual(loaded, Config.DEFAULT_CONFIG)

    def test_unknown_key_detected(self):
        cfg = Config.DEFAULT_CONFIG.copy()
        cfg["general"] = dict(cfg["general"])
        cfg["general"]["unknown_key"] = 123
        validator = Config.__new__(Config)
        errors = Config.validate_config(validator, cfg)
        self.assertTrue(any("unknown_key" in e for e in errors))

    def test_config_logs_omit_untrusted_keys_and_config_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = pathlib.Path(directory) / "invalid.json"
            config_path.write_text(
                json.dumps({"general": {"alice@example.com": "private-value"}}),
                encoding="utf-8",
            )
            output = io.StringIO()
            with redirect_stdout(output):
                logger.configure(None, "info")
                config = Config(config_file=str(config_path))
                config.save_config()

            events = [json.loads(line) for line in output.getvalue().splitlines()]
            warning = next(event for event in events if event.get("event_name") == "configuration.validation_warning")
            saved = next(event for event in events if event.get("event_name") == "configuration.saved")
            self.assertGreater(warning["invalid_entry_count"], 0)
            self.assertNotIn("filename", saved)
            self.assertNotIn(str(config_path), output.getvalue())
            self.assertNotIn("alice@example.com", output.getvalue())
            self.assertNotIn("private-value", output.getvalue())


if __name__ == "__main__":
    unittest.main()
