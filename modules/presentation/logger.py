"""Lightweight logging helpers for XrefGen."""

from datetime import datetime
from typing import Optional

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}
_level = _LEVELS["info"]
_log_file: Optional[str] = None


def configure(log_file: Optional[str], level: str = "info"):
    global _level, _log_file
    _log_file = log_file
    _level = _LEVELS.get(level.lower(), _LEVELS["info"])


def _emit(level: str, msg: str):
    if _LEVELS[level] < _level:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level.upper()}] {msg}"
    print(f"[XrefGen] {line}")
    if _log_file:
        try:
            with open(_log_file, "a", encoding="utf-8", errors="ignore") as f:
                f.write(f"{line}\n")
        except Exception:
            pass


def debug(msg: str):
    _emit("debug", msg)


def info(msg: str):
    _emit("info", msg)


def warn(msg: str):
    _emit("warn", msg)


def error(msg: str):
    _emit("error", msg)
