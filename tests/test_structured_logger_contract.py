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
    assert json.loads(capsys.readouterr().out)["message"] == "console fallback"


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
