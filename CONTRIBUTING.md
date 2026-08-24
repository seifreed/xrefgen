# Contributing

Run the independent test suite before submitting changes:

```bash
PYTHONPATH=. python -m pytest -q
```

Changes that affect `_user_xrefs.txt` must include a focused test proving that
the output contains only valid control-flow references.
