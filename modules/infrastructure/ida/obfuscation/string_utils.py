"""Helpers for stack/heap string byte extraction."""
from typing import Optional


def extract_mem_offset(op_str: str) -> Optional[int]:
    try:
        off_str = op_str.split("+", 1)[1].rstrip("]")
        return int(off_str, 0)
    except Exception:
        return None


def add_imm_to_map(bytes_map: dict, off: int, val: int):
    if 0 <= val <= 0xFF:
        bytes_map[off] = val
    elif 0 <= val <= 0xFFFFFFFF:
        for i in range(4):
            bytes_map[off + i] = (val >> (i * 8)) & 0xFF


def build_bytes_map() -> dict:
    return {}


def bytes_map_to_bytes(bytes_map: dict) -> Optional[bytes]:
    if not bytes_map:
        return None
    return bytes([bytes_map[k] for k in sorted(bytes_map.keys())])


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable_count = sum(1 for b in data if 32 <= b < 127)
    return printable_count / len(data)


def looks_like_utf16le(data: bytes) -> bool:
    if len(data) < 4 or len(data) % 2 != 0:
        return False
    zeros = 0
    ascii_count = 0
    pairs = len(data) // 2
    for i in range(0, len(data), 2):
        lo = data[i]
        hi = data[i + 1]
        if hi == 0:
            zeros += 1
            if 32 <= lo < 127:
                ascii_count += 1
    return zeros / pairs > 0.6 and ascii_count / pairs > 0.5


def looks_like_utf16be(data: bytes) -> bool:
    if len(data) < 4 or len(data) % 2 != 0:
        return False
    zeros = 0
    ascii_count = 0
    pairs = len(data) // 2
    for i in range(0, len(data), 2):
        hi = data[i]
        lo = data[i + 1]
        if lo == 0:
            zeros += 1
            if 32 <= hi < 127:
                ascii_count += 1
    return zeros / pairs > 0.6 and ascii_count / pairs > 0.5
