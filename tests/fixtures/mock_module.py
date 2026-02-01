from modules.domain.analyzer import XrefAnalyzer


class MockAnalyzer(XrefAnalyzer):
    def analyze(self):
        return []

    def get_name(self):
        return "MockAnalyzer"
