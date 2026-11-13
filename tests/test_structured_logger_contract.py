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
