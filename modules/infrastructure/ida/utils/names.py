"""Name normalization utilities for IDA symbols."""
from typing import Optional


def normalize_name(name: Optional[str]) -> str:
    if not name:
        return ""
    n = name.lower()
    for prefix in ("__imp_", "imp_", "j_", "sub_"):
        if n.startswith(prefix):
            n = n[len(prefix):]
    if n.startswith("_"):
        n = n[1:]
    if "@" in n and n.rfind("@") > 0:
        n = n[: n.rfind("@")]
    return n
