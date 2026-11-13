"""Security and concurrency contracts for the shared logging boundary."""

import json
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


def test_invalid_file_destination_warns_and_keeps_console(capsys, tmp_path):
    logger.configure(str(tmp_path / "missing" / "events.log"), "info")
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["event_name"] == "logging.configuration_warning"
    assert "File logging unavailable" in events[0]["message"]
    assert logger._log_file is None


def test_filtered_debug_skips_sanitization(monkeypatch):
    logger.configure(None, "info")

    def should_not_run(_value):
        raise AssertionError("filtered log message was formatted")

    monkeypatch.setattr(logger, "_sanitize", should_not_run)
    logger.debug("disabled diagnostic", token="sensitive")


def test_file_sink_rotates_at_configured_size(tmp_path):
    path = tmp_path / "events.jsonl"
    logger.configure(str(path), "info")
    logger.info("x" * 2_500_000)
    logger.info("y" * 2_500_000)
    assert path.exists()
    assert (tmp_path / "events.jsonl.1").exists()
    assert path.stat().st_size < 5_000_000
