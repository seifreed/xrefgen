import sys
import types
import unittest


def _install_ida_mocks():
    idautils = types.SimpleNamespace(Functions=lambda: [])
    ida_funcs = types.SimpleNamespace()
    idc = types.SimpleNamespace()
    ida_bytes = types.SimpleNamespace(get_byte=lambda _ea: 0)
    sys.modules.setdefault("idautils", idautils)
    sys.modules.setdefault("ida_funcs", ida_funcs)
    sys.modules.setdefault("idc", idc)
    sys.modules.setdefault("ida_bytes", ida_bytes)


class StringValidationTests(unittest.TestCase):
    def setUp(self):
        _install_ida_mocks()

    def test_utf16_detect(self):
        from modules.infrastructure.ida.obfuscation.strings import EncryptedStringDetector

        detector = EncryptedStringDetector.__new__(EncryptedStringDetector)
        data = b"T\x00e\x00s\x00t\x00"
        self.assertTrue(detector._looks_like_utf16le(data))

    def test_utf16_decode(self):
        from modules.infrastructure.ida.obfuscation.strings import EncryptedStringDetector

        detector = EncryptedStringDetector.__new__(EncryptedStringDetector)
        data = b"T\x00e\x00s\x00t\x00"
        self.assertEqual(detector._decode_string(data), "Test")

    def test_index_xor(self):
        from modules.infrastructure.ida.obfuscation.strings import EncryptedStringDetector

        detector = EncryptedStringDetector.__new__(EncryptedStringDetector)
        plain = b"Test"
        key = 7
        enc = bytes([b ^ (key ^ i) for i, b in enumerate(plain)])
        result = detector._try_index_xor(list(enc))
        self.assertIsNotNone(result)
        self.assertTrue(result.isprintable())


if __name__ == "__main__":
    unittest.main()
