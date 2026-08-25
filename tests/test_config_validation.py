import json
import pathlib
import unittest

from modules.application.config import Config


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


if __name__ == "__main__":
    unittest.main()
