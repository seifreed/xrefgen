"""Thread-safe, structured logging helpers for the IDA plugin."""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

_LEVELS = {"trace": 5, "debug": logging.DEBUG, "info": logging.INFO,
           "warn": logging.WARNING, "error": logging.ERROR,
           "fatal": logging.CRITICAL, "critical": logging.CRITICAL}
logging.addLevelName(5, "TRACE")
_logger = logging.getLogger("xrefgen")
_logger.propagate = False
_logger.setLevel(logging.INFO)
_log_file: Optional[str] = None
_level = _LEVELS["info"]


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": {"warning": "warn", "critical": "fatal"}.get(record.levelname.lower(), record.levelname.lower()), "service": "xrefgen",
            "component": record.name.rsplit(".", 1)[-1], "message": record.getMessage(),
        }
        if record.exc_info:
            event["error_type"] = record.exc_info[0].__name__
            event["stack_trace"] = self.formatException(record.exc_info)
        return json.dumps(event, ensure_ascii=True)


def configure(log_file: Optional[str], level: str = "info"):
    """Configure stdout and optional size-bounded UTF-8 JSON file output."""
    global _log_file, _level
    selected = _LEVELS.get(str(level).lower())
    if selected is None:
        raise ValueError(f"Unsupported log level: {level}")
    for handler in _logger.handlers[:]:
        _logger.removeHandler(handler)
        handler.close()
    _logger.setLevel(selected)
    _level = selected
    _logger.addHandler(logging.StreamHandler(sys.stdout))
    if log_file:
        handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        _logger.addHandler(handler)
    for handler in _logger.handlers:
        handler.setFormatter(_JsonFormatter())
    _log_file = log_file


def _emit(level: str, msg: str):
    # Flatten control characters so untrusted text cannot forge additional records.
    safe = re.sub(r"[\x00-\x1f\x7f]", " ", str(msg))
    _logger.log(_LEVELS[level], safe)


def trace(msg: str): _emit("trace", msg)
def debug(msg: str): _emit("debug", msg)
def info(msg: str): _emit("info", msg)
def warn(msg: str): _emit("warn", msg)
def error(msg: str): _emit("error", msg)
def critical(msg: str): _emit("critical", msg)
