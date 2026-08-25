# Extending XrefGen

This guide shows how to add a new analyzer module.

## 1) Create a new analyzer

Create a new file in `modules/infrastructure/ida/<area>/my_analyzer.py`:

```python
from typing import List
from modules.domain.results import AnalysisResult
from modules.infrastructure.ida.base import IDAXrefAnalyzer

class MyAnalyzer(IDAXrefAnalyzer):
    def __init__(self, config=None):
        super().__init__(config)

    def get_name(self) -> str:
        return "MyAnalyzer"

    def analyze(self) -> List[AnalysisResult]:
        results = []
        # ... your analysis logic ...
        # results.append(self.emit_control_flow(source, target, "indirect_call", 0.9))
        return results
```

Analysis modules should return typed results. Use the emitters from
`XrefAnalyzer` so the result role is explicit:

```python
return [self.emit_control_flow(call_ea, target, "indirect_call", 0.9)]
return [self.emit_finding(source_ea, target_ea, "taint_flow", 0.7)]
return [self.emit_relationship(func_a, func_b, "function_similarity", 0.8)]
```

Four-tuples are not accepted. Every module result must be an explicit
`XrefCandidate`, `Finding`, or `Relationship`.

For incremental analysis, inherit from:

```python
from modules.infrastructure.ida.performance.optimizer import IncrementalAnalyzer

class MyAnalyzer(IncrementalAnalyzer):
    def get_name(self) -> str:
        return "MyAnalyzer"

    def analyze_function(self, func):
        # analyze a single function
        return []
```

## 2) Register the module

Add a registry entry in `modules/application/registry.py`:

```python
ModuleSpec("my_analyzer", "modules.infrastructure.ida.<area>.my_analyzer", "MyAnalyzer", optional=True)
```

## 3) Update config defaults

In `modules/application/config.py`, add a module entry:

```python
"my_analyzer": {
    "enabled": True,
    "some_option": 123
}
```

## 4) Run

Enable the module in `xrefgen_config.json` and run XrefGen.
