"""Thread-safe, structured logging helpers for the IDA plugin."""

import json
import logging
import re
import sys
from math import isfinite
from contextlib import contextmanager
from contextvars import ContextVar
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
_event_context = ContextVar("xrefgen_log_context", default=None)


def _sanitize(value):
    safe = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    safe = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", safe)
    safe = re.sub(r"(?i)(password|passwd|token|api[_-]?key|authorization|cookie)(\s*[=:]\s*)([^\s,;]+)", r"\1\2[REDACTED]", safe)
    return re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", safe, flags=re.IGNORECASE)


class _JsonFormatter(logging.Formatter):
    def event(self, record):
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": {"warning": "warn", "critical": "fatal"}.get(record.levelname.lower(), record.levelname.lower()), "service": "xrefgen",
            "component": _sanitize(record.module), "message": _sanitize(record.getMessage()),
        }
        if record.exc_info:
            event["error_type"] = record.exc_info[0].__name__
            event["stack_trace"] = _sanitize(self.formatException(record.exc_info))
        event.update(_event_context.get() or {})
        event.update(getattr(record, "xrefgen_fields", {}))
        return event

    def format(self, record):
        event = self.event(record)
        return json.dumps(event, ensure_ascii=True)


class _TextFormatter(_JsonFormatter):
    def format(self, record):
        event = self.event(record)
        common = {"timestamp", "level", "service", "component", "message"}
        fields = {key: value for key, value in event.items() if key not in common}
        suffix = " " + json.dumps(fields, sort_keys=True) if fields else ""
        return f"{event['timestamp']} {event['level'].upper()} [{event['component']}] {event['message']}{suffix}"


class _SafeRotatingFileHandler(RotatingFileHandler):
    """A broken optional file sink must not interrupt IDA analysis or leak handler errors."""

    def handleError(self, record):
        return


def configure(log_file: Optional[str], level: str = "info", log_format: str = "json"):
    """Configure stdout and optional size-bounded UTF-8 file output."""
    global _log_file, _level
    level_name = str(level).lower()
    format_name = str(log_format).lower()
    selected = _LEVELS.get(level_name, _LEVELS["info"])
    shutdown()
    _logger.setLevel(selected)
    _level = selected
    _logger.addHandler(logging.StreamHandler(sys.stdout))
    warnings = []
    if level_name not in _LEVELS:
        warnings.append(f"Unsupported log level {level_name!r}; using info")
    if format_name not in {"json", "text"}:
        warnings.append(f"Unsupported log format {format_name!r}; using json")
        format_name = "json"
    if log_file:
        try:
            handler = _SafeRotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
            _logger.addHandler(handler)
        except OSError as exc:
            warnings.append(f"File logging unavailable ({type(exc).__name__}); using console")
            log_file = None
    formatter = _JsonFormatter() if format_name == "json" else _TextFormatter()
    for handler in _logger.handlers:
        handler.setFormatter(formatter)
    _log_file = log_file
    for message in warnings:
        warn(message, event_name="logging.configuration_warning")


def _emit(level_name: str, msg: str, exc_info=False, **fields):
    if _LEVELS[level_name] < _logger.getEffectiveLevel():
        return
    normalized = {}
    for key, value in fields.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) or key in {"timestamp", "level", "service", "component", "message", "stack_trace"}:
            continue
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            continue
        if isinstance(value, float) and not isfinite(value):
            continue
        normalized[key] = value
        if re.search(r"(?i)(password|passwd|secret|token|api.?key|authorization|cookie|private.?key)", key):
            normalized[key] = "[REDACTED]"
        if isinstance(normalized[key], str):
            normalized[key] = _sanitize(normalized[key])
    _logger.log(_LEVELS[level_name], _sanitize(msg), exc_info=exc_info, stacklevel=3, extra={"xrefgen_fields": normalized})


def trace(msg: str, **fields): _emit("trace", msg, **fields)
def debug(msg: str, **fields): _emit("debug", msg, **fields)
def info(msg: str, **fields): _emit("info", msg, **fields)
def warn(msg: str, **fields): _emit("warn", msg, **fields)
def error(msg: str, **fields): _emit("error", msg, **fields)
def critical(msg: str, **fields): _emit("critical", msg, **fields)


def exception(msg: str, **fields):
    """Record the active exception with its sanitized type and stack."""
    _emit("error", msg, exc_info=True, **fields)


def shutdown():
    """Flush and close configured sinks during plugin termination."""
    for handler in _logger.handlers[:]:
        try:
            handler.flush()
        except (OSError, ValueError):
            pass
        finally:
            _logger.removeHandler(handler)
            try:
                handler.close()
            except (OSError, ValueError):
                pass


@contextmanager
def operation_context(operation: str, correlation_id: str):
    """Attach real operation context to events without mutating process-global state."""
    token = _event_context.set({"operation": _sanitize(operation), "correlation_id": _sanitize(correlation_id)})
    try:
        yield
    finally:
        _event_context.reset(token)
