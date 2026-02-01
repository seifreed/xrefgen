import unittest

from modules.domain.entities import Xref
from modules.domain.analyzer import XrefAnalyzer


class DummyAnalyzer(XrefAnalyzer):
    def analyze(self):
        return []

    def get_name(self):
        return "Dummy"


class DomainEntityTests(unittest.TestCase):
    def test_xref_tuple(self):
        xref = Xref(0x1000, 0x2000, "indirect_call", 0.75)
        self.assertEqual(xref.as_tuple(), (0x1000, 0x2000, "indirect_call", 0.75))

    def test_analyzer_add_xref(self):
        analyzer = DummyAnalyzer()
        analyzer.add_xref(1, 2, "test", 0.5)
        self.assertEqual(analyzer.get_results(), [(1, 2, "test", 0.55)])


if __name__ == "__main__":
    unittest.main()
