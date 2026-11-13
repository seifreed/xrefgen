"""Security and concurrency contracts for the shared logging boundary."""

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor

from modules.presentation import logger


def test_common_credentials_are_redacted(capsys):
    logger.configure(None, "info")
    logger.info("password=hunter2 token:abc123 api_key=secret Authorization=Bearer abc.def")
    event = json.loads(capsys.readouterr().out)
    assert "hunter2" not in event["message"]
    assert "abc123" not in event["message"]
    assert "secret" not in event["message"]
    assert "abc.def" not in event["message"]
    assert event["message"].count("[REDACTED]") >= 4


def test_quoted_secrets_and_multiline_values_are_redacted(capsys):
    logger.configure(None, "info")
    logger.info('config {"api_key": "quoted secret value"} https://user:pass@host/path access_key=private-key\nnext line')
    event = json.loads(capsys.readouterr().out)
    assert "quoted secret value" not in event["message"]
    assert "user:pass" not in event["message"]
    assert "private-key" not in event["message"]
    assert "next line" in event["message"]
    assert "\n" not in event["message"]


def test_authentication_and_cookie_headers_are_redacted_as_complete_values(capsys):
    logger.configure(None, "info")
    logger.info(
        "received headers:\nAuthorization: Basic dXNlcjpwYXNz\n"
        "Cookie: sessionid=opaque; preference=private\nrequest accepted"
    )
    message = json.loads(capsys.readouterr().out)["message"]
    assert "dXNlcjpwYXNz" not in message
    assert "sessionid=opaque" not in message
    assert "preference=private" not in message
    assert "request accepted" in message


def test_unicode_line_and_bidi_controls_cannot_forge_text_events(capsys):
    logger.configure(None, "info", "text")
    logger.info("operation\u2028FATAL forged\u0085\u202e")
    line = capsys.readouterr().out
    assert len(line.splitlines()) == 1
    assert "FATAL forged" in line
    assert "\u2028" not in line and "\u0085" not in line and "\u202e" not in line


def test_oversized_messages_and_fields_are_bounded(capsys):
    logger.configure(None, "info")
    logger.info("x" * 100_000, diagnostic="y" * 100_000)
    event = json.loads(capsys.readouterr().out)
    assert len(event["message"]) < logger._MAX_TEXT_CHARS + 32
    assert len(event["diagnostic"]) < logger._MAX_TEXT_CHARS + 32
    assert event["message"].endswith("[TRUNCATED]")


def test_structured_field_count_is_bounded(capsys):
    logger.configure(None, "info")
    logger.info("bounded fields", **{f"field_{index:03}": index for index in range(100)})
    event = json.loads(capsys.readouterr().out)
    assert len([key for key in event if key.startswith("field_")]) == logger._MAX_FIELDS


def test_concurrent_records_remain_independent(capsys):
    logger.configure(None, "info")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(logger.info, (f"event-{n}" for n in range(100))))
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(events) == 100
    assert {event["message"] for event in events} == {f"event-{n}" for n in range(100)}


def test_unavailable_file_destination_falls_back_to_console(capsys, tmp_path, monkeypatch):
    logger.configure(str(tmp_path / "missing" / "events.log"), "info")
    logger.info("console fallback")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[-1]["message"] == "console fallback"


def test_file_write_failure_does_not_raise(capsys, tmp_path):
    logger.configure(str(tmp_path / "events.log"), "info")
    class BrokenStream:
        def write(self, _text):
            raise OSError("disk unavailable")

        def flush(self):
            pass

    logger._logger.handlers[1].stream = BrokenStream()
    logger.info("still available")
    assert json.loads(capsys.readouterr().out)["message"] == "still available"


def test_console_write_failure_does_not_raise_or_leak(capsys):
    logger.configure(None, "info")

    class BrokenStream:
        def write(self, _text):
            raise OSError("token=private-value")

        def flush(self):
            pass

    logger._logger.handlers[0].stream = BrokenStream()
    try:
        raise RuntimeError("password=another-secret")
    except RuntimeError:
        logger.exception("operation failed", token="field-secret")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_private_key_material_is_redacted(capsys):
    logger.configure(None, "info")
    logger.info("-----BEGIN PRIVATE KEY-----secret\nkey-----END PRIVATE KEY-----")
    message = json.loads(capsys.readouterr().out)["message"]
    assert "secret" not in message
    assert "[REDACTED PRIVATE KEY]" in message


def test_exception_type_and_trace_are_recorded_without_secret(capsys):
    logger.configure(None, "error")
    try:
        raise RuntimeError("token=private-value")
    except RuntimeError:
        logger.exception("analysis operation failed")
    event = json.loads(capsys.readouterr().out)
    assert event["error_type"] == "RuntimeError"
    assert "stack_trace" in event
    assert "private-value" not in event["stack_trace"]


def test_explicit_fields_cannot_replace_exception_metadata(capsys):
    logger.configure(None, "error")
    try:
        raise ValueError("failure")
    except ValueError:
        logger.exception("operation failed", error_type="Spoofed", error_chain="forged")
    event = json.loads(capsys.readouterr().out)
    assert event["error_type"] == "ValueError"
    assert event["error_chain"] == "ValueError"


def test_exception_chain_keeps_types_and_frames_without_messages_or_paths(capsys):
    logger.configure(None, "error")
    try:
        try:
            raise ValueError("unstructured-secret")
        except ValueError as cause:
            raise RuntimeError("different-secret") from cause
    except RuntimeError:
        logger.exception("operation failed")
    event = json.loads(capsys.readouterr().out)
    assert event["error_type"] == "RuntimeError"
    assert event["error_chain"] == "RuntimeError -> ValueError"
    assert "unstructured-secret" not in json.dumps(event)
    assert "different-secret" not in json.dumps(event)
    assert "/Users/" not in event["stack_trace"]
    assert "test_exception_chain_keeps_types_and_frames_without_messages_or_paths" in event["stack_trace"]


def test_shutdown_closes_handlers_and_allows_reconfiguration(capsys):
    logger.configure(None, "info")
    logger.info("before shutdown")
    logger.shutdown()
    assert not logger._logger.handlers
    logger.configure(None, "info")
    logger.info("after shutdown")
    assert [json.loads(line)["message"] for line in capsys.readouterr().out.splitlines()] == [
        "before shutdown", "after shutdown"
    ]


def test_operation_context_is_scoped_and_correlated(capsys):
    logger.configure(None, "info")
    logger.info("outside")
    with logger.operation_context("analysis", "run-123"):
        logger.info("inside")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert "correlation_id" not in events[0]
    assert events[1]["operation"] == "analysis"
    assert events[1]["correlation_id"] == "run-123"


def test_explicit_fields_cannot_replace_scoped_correlation(capsys):
    logger.configure(None, "info")
    with logger.operation_context("analysis", "run-123"):
        logger.info("inside", operation="spoofed", correlation_id="spoofed")
    event = json.loads(capsys.readouterr().out)
    assert event["operation"] == "analysis"
    assert event["correlation_id"] == "run-123"


def test_operation_context_does_not_leak_between_threads(capsys):
    logger.configure(None, "info")
    with logger.operation_context("main", "parent"):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(logger.info, "child").result()
        logger.info("parent")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    by_message = {event["message"]: event for event in events}
    assert "correlation_id" not in by_message["child"]
    assert by_message["parent"]["correlation_id"] == "parent"


def test_structured_event_fields_are_safe_and_normalized(capsys):
    logger.configure(None, "info")
    logger.info("finished", event_name="analysis.finished", duration_ms=2.5, status="completed", token="secret")
    event = json.loads(capsys.readouterr().out)
    assert event["event_name"] == "analysis.finished"
    assert event["duration_ms"] == 2.5
    assert event["token"] == "[REDACTED]"
    assert event["component"] == "test_structured_logger_contract"


def test_nested_fields_are_omitted_to_prevent_unreviewed_payload_logging(capsys):
    logger.configure(None, "info")
    logger.info("operation complete", details={"api_key": "private-value"})
    event = json.loads(capsys.readouterr().out)
    assert "details" not in event
    assert "private-value" not in json.dumps(event)


def test_text_format_preserves_redaction_and_structured_context(capsys):
    logger.configure(None, "info", "text")
    with logger.operation_context("analysis", "correlation-1"):
        logger.info("password=hunter2", event_name="analysis.finished")
    line = capsys.readouterr().out
    assert "hunter2" not in line
    assert "INFO [test_structured_logger_contract]" in line
    assert '"correlation_id": "correlation-1"' in line
    assert '"event_name": "analysis.finished"' in line


def test_reserved_fields_are_ignored_without_affecting_logging(capsys):
    logger.configure(None, "info")
    logger.info("message remains", level="fatal")
    event = json.loads(capsys.readouterr().out)
    assert event["message"] == "message remains"
    assert event["level"] == "info"


def test_invalid_level_falls_back_with_structured_warning(capsys):
    logger.configure(None, "verbose-ish")
    event = json.loads(capsys.readouterr().out)
    assert event["level"] == "warn"
    assert event["event_name"] == "logging.configuration_warning"
    assert logger._level == logger._LEVELS["info"]


def test_trace_and_fatal_levels_are_normalized(capsys):
    logger.configure(None, "trace")
    logger.trace("trace event")
    logger.configure(None, "fatal")
    logger.critical("fatal event")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["level"] for event in events] == ["trace", "fatal"]


def test_invalid_file_destination_warns_and_keeps_console(capsys, tmp_path):
    logger.configure(str(tmp_path / "missing" / "events.log"), "info")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["event_name"] == "logging.configuration_warning"
    assert "File logging unavailable" in events[0]["message"]
    assert logger._log_file is None


def test_file_rotation_settings_are_configurable_and_bounded(capsys, tmp_path):
    path = tmp_path / "events.jsonl"
    logger.configure(str(path), "info", "json", max_bytes=2_500_000, backup_count=1)
    file_handler = logger._logger.handlers[1]
    assert file_handler.maxBytes == 2_500_000
    assert file_handler.backupCount == 1

    logger.configure(str(path), "info", "json", max_bytes=1, backup_count=99)
    warnings = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len([event for event in warnings if event.get("event_name") == "logging.configuration_warning"]) == 2
    file_handler = logger._logger.handlers[1]
    assert file_handler.maxBytes == logger._DEFAULT_MAX_BYTES
    assert file_handler.backupCount == logger._DEFAULT_BACKUP_COUNT


def test_filtered_debug_skips_sanitization(monkeypatch):
    logger.configure(None, "info")

    def should_not_run(_value):
        raise AssertionError("filtered log message was formatted")

    monkeypatch.setattr(logger, "_sanitize", should_not_run)
    logger.debug("disabled diagnostic", token="sensitive")


def test_file_sink_rotates_at_configured_size(tmp_path):
    path = tmp_path / "events.jsonl"
    logger.configure(str(path), "info")
    for _ in range(320):
        logger.info("x" * logger._MAX_TEXT_CHARS)
    assert path.exists()
    assert (tmp_path / "events.jsonl.1").exists()


def test_file_sink_is_owner_only_on_posix(tmp_path):
    if os.name != "posix":
        return
    path = tmp_path / "private.jsonl"
    logger.configure(str(path), "info")
    logger.info("private local event")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_size < 5_000_000
