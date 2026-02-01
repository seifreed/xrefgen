import unittest

from modules.application.config import Config


class ConfigValidationTests(unittest.TestCase):
    def test_unknown_key_detected(self):
        cfg = Config.DEFAULT_CONFIG.copy()
        cfg["general"] = dict(cfg["general"])
        cfg["general"]["unknown_key"] = 123
        validator = Config.__new__(Config)
        errors = Config.validate_config(validator, cfg)
        self.assertTrue(any("unknown_key" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
