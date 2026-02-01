# Extending XrefGen

This guide shows how to add a new analyzer module.

## 1) Create a new analyzer

Create a new file in `modules/infrastructure/ida/<area>/my_analyzer.py`:

```python
from typing import List, Tuple
from modules.infrastructure.ida.base import IDAXrefAnalyzer

class MyAnalyzer(IDAXrefAnalyzer):
    def __init__(self, config=None):
        super().__init__(config)

    def get_name(self) -> str:
        return "MyAnalyzer"

    def analyze(self) -> List[Tuple[int, int, str, float]]:
        results = []
        # ... your analysis logic ...
        # self.add_xref(source, target, "my_type", 0.9)
        return results
```

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
