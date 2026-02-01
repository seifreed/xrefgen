"""Noise factor and threshold adjustments for graph analysis."""


class GraphNoisePolicy:
    def __init__(self, analyzer):
        self.a = analyzer

    def apply(self):
        try:
            funcs = len(self.a.call_graph) or 1
            edges = sum(len(v) for v in self.a.call_graph.values())
            ratio = edges / funcs
            if ratio > 20:
                self.a._noise_factor = 0.8
                self.a.min_indirect_confidence = min(0.9, self.a.min_indirect_confidence + 0.1)
                self.a.hub_threshold = max(self.a.hub_threshold, 30)
            elif ratio > 10:
                self.a._noise_factor = 0.9
                self.a.min_indirect_confidence = min(0.8, self.a.min_indirect_confidence + 0.05)
            else:
                self.a._noise_factor = 1.0
        except Exception:
            self.a._noise_factor = 1.0
