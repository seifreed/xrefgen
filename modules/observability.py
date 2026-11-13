"""Thread-safe, structured logging helpers for the IDA plugin."""

import json
import logging
import os
import re
import sys
import traceback
from math import isfinite
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

_LEVELS = {"trace": 5, "debug": logging.DEBUG, "info": logging.INFO,
           "warn": logging.WARNING, "error": logging.ERROR,
           "fatal": logging.CRITICAL, "critical": logging.CRITICAL}
_MAX_TEXT_CHARS = 16_384
_MAX_FIELDS = 64
_DEFAULT_MAX_BYTES = 5_000_000
_DEFAULT_BACKUP_COUNT = 3
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_SENSITIVE_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization|cookie|set-cookie)\s*[:=\s]+[^\r\n]*")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie)[\"']?\s*[=:]\s*)"
    r'("[^\"]*"|\'[^\']*\'|[^\s,;]+)'
)
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@")
logging.addLevelName(5, "TRACE")
_logger = logging.getLogger("xrefgen")
_logger.propagate = False
_logger.setLevel(logging.INFO)
_log_file: Optional[str] = None
_level = _LEVELS["info"]
_event_context: ContextVar[Optional[dict[str, str]]] = ContextVar("xrefgen_log_context", default=None)


def _sanitize(value):
    safe = _SENSITIVE_HEADER.sub(r"\1: [REDACTED]", str(value))
    safe = _CONTROL_CHARS.sub(" ", safe)
    safe = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", safe)
    safe = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", safe)
    safe = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", safe)
    safe = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", safe, flags=re.IGNORECASE)
    return safe if len(safe) <= _MAX_TEXT_CHARS else safe[:_MAX_TEXT_CHARS] + " [TRUNCATED]"


class _JsonFormatter(logging.Formatter):
    def event(self, record):
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": {"warning": "warn", "critical": "fatal"}.get(record.levelname.lower(), record.levelname.lower()), "service": "xrefgen",
            "component": _sanitize(record.module), "message": _sanitize(record.getMessage()),
        }
        if record.exc_info:
            event["error_type"] = record.exc_info[0].__name__
            exception = record.exc_info[1]
            seen = set()
            chain = []
            frames = []
            while exception is not None and id(exception) not in seen:
                seen.add(id(exception))
                chain.append(type(exception).__name__)
                if exception.__traceback__:
                    frames.extend(traceback.extract_tb(exception.__traceback__))
                exception = exception.__cause__ or exception.__context__
            event["error_chain"] = " -> ".join(chain)
            event["stack_trace"] = _sanitize("\n".join(
                f'File "{os.path.basename(frame.filename)}", line {frame.lineno}, in {frame.name}'
                for frame in frames[-64:]
            ))
        event.update(getattr(record, "xrefgen_fields", {}))
        event.update(_event_context.get() or {})
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


class _SafeStreamHandler(logging.StreamHandler):
    def handleError(self, record):
        return


class _SafeRotatingFileHandler(RotatingFileHandler):
    """A broken optional sink must not interrupt IDA analysis or leak handler errors."""

    def _open(self):
        stream = super()._open()
        if os.name == "posix":
            os.chmod(self.baseFilename, 0o600)
        return stream

    def handleError(self, record):
        if getattr(self, "_failure_reported", False):
            return
        self._failure_reported = True
        exc_type, _, _ = sys.exc_info()
        failure = logging.LogRecord(
            _logger.name,
            logging.WARNING,
            __file__,
            0,
            "File logging sink failed; records may be unavailable",
            (),
            None,
            "handleError",
        )
        failure.xrefgen_fields = {"event_name": "logging.sink_failed", "sink": "file"}
        if exc_type:
            failure.xrefgen_fields["error_type"] = exc_type.__name__
        for handler in _logger.handlers[:]:
            if isinstance(handler, _SafeStreamHandler):
                try:
                    handler.handle(failure)
                except Exception:
                    pass
                break


def configure(
    log_file: Optional[str],
    level: str = "info",
    log_format: str = "json",
    max_bytes: int = _DEFAULT_MAX_BYTES,
    backup_count: int = _DEFAULT_BACKUP_COUNT,
):
    """Configure stdout and optional size-bounded UTF-8 file output."""
    global _log_file, _level
    level_name = str(level).lower()
    format_name = str(log_format).lower()
    selected = _LEVELS.get(level_name, _LEVELS["info"])
    shutdown()
    _logger.setLevel(selected)
    _level = selected
    _logger.addHandler(_SafeStreamHandler(sys.stdout))
    warnings = []
    if level_name not in _LEVELS:
        warnings.append(f"Unsupported log level {level_name!r}; using info")
    if format_name not in {"json", "text"}:
        warnings.append(f"Unsupported log format {format_name!r}; using json")
        format_name = "json"
    if type(max_bytes) is not int or not 2_000_000 <= max_bytes <= 50_000_000:
        warnings.append("Unsupported log file size; using default")
        max_bytes = _DEFAULT_MAX_BYTES
    if type(backup_count) is not int or not 0 <= backup_count <= 5:
        warnings.append("Unsupported log backup count; using default")
        backup_count = _DEFAULT_BACKUP_COUNT
    if log_file:
        try:
            file_handler = _SafeRotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            _logger.addHandler(file_handler)
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
    reserved = {"timestamp", "level", "service", "component", "message", "stack_trace"}
    if exc_info:
        reserved.update({"error_type", "error_chain"})
    for field_index, (key, value) in enumerate(fields.items()):
        if field_index >= _MAX_FIELDS:
            break
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) or key in reserved:
            continue
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            continue
        if isinstance(value, float) and not isfinite(value):
            continue
        normalized[key] = value
        if re.search(r"(?i)(password|passwd|secret|token|api.?key|access.?key|authorization|cookie|private.?key)", key):
            normalized[key] = "[REDACTED]"
        if isinstance(normalized[key], str):
            normalized[key] = _sanitize(normalized[key])
    _logger.log(_LEVELS[level_name], msg, exc_info=exc_info, stacklevel=3, extra={"xrefgen_fields": normalized})


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
    handlers = sorted(_logger.handlers[:], key=lambda item: isinstance(item, _SafeStreamHandler))
    for handler in handlers:
        try:
            handler.flush()
        except Exception:
            if isinstance(handler, _SafeRotatingFileHandler):
                handler.handleError(None)
        finally:
            _logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                if isinstance(handler, _SafeRotatingFileHandler):
                    handler.handleError(None)


@contextmanager
def operation_context(operation: str, correlation_id: str):
    """Attach real operation context to events without mutating process-global state."""
    token = _event_context.set({"operation": _sanitize(operation), "correlation_id": _sanitize(correlation_id)})
    try:
        yield
    finally:
        _event_context.reset(token)
