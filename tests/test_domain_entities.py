import unittest

from modules.domain.entities import Xref
from modules.domain.analyzer import XrefAnalyzer
from modules.domain.results import Finding, Relationship, XrefCandidate


class DummyAnalyzer(XrefAnalyzer):
    def analyze(self):
        return []

    def get_name(self):
        return "Dummy"


class DomainEntityTests(unittest.TestCase):
    def test_xref_tuple(self):
        xref = Xref(0x1000, 0x2000, "indirect_call", 0.75)
        self.assertEqual(xref.as_tuple(), (0x1000, 0x2000, "indirect_call", 0.75))

    def test_analyzer_returns_typed_results(self):
        analyzer = DummyAnalyzer()
        result = analyzer.emit_control_flow(1, 2, "indirect_call", 0.5)
        self.assertIsInstance(result, XrefCandidate)
        self.assertEqual(result.source, 1)
        self.assertEqual(result.target, 2)
        self.assertEqual(result.kind, "indirect_call")
        self.assertEqual(result.confidence, 0.5)

    def test_typed_emitters_preserve_result_role(self):
        analyzer = DummyAnalyzer()
        candidate = analyzer.emit_control_flow(1, 2, "indirect_call", 0.8, ("graph",))
        finding = analyzer.emit_finding(3, 4, "arm64_adrp_add", 0.7)
        relationship = analyzer.emit_relationship(5, 6, "call_chain_depth_1", 0.6)
        self.assertIsInstance(candidate, XrefCandidate)
        self.assertEqual(candidate.source, 1)
        self.assertIsInstance(finding, Finding)
        self.assertIsInstance(relationship, Relationship)
        self.assertEqual(finding.kind, "arm64_adrp_add")
        self.assertEqual(relationship.kind, "call_chain_depth_1")


if __name__ == "__main__":
    unittest.main()
