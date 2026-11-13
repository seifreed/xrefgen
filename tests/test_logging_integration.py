"""Application-level event contracts for module analysis."""

import json

from modules.application.module_manager import ModuleManager
from modules.domain.analyzer import XrefAnalyzer
from modules.presentation import logger


class _GoodAnalyzer(XrefAnalyzer):
    def analyze(self):
        return [self.emit_control_flow(0x1000, 0x2000, "call", 0.9)]

    def get_name(self):
        return "GoodAnalyzer"


class _FailingAnalyzer(XrefAnalyzer):
    def analyze(self):
        raise RuntimeError("token=secret-value")

    def get_name(self):
        return "FailingAnalyzer"


def _events(output):
    return [json.loads(line) for line in output.splitlines()]


def test_module_success_emits_duration_and_count(capsys):
    logger.configure(None, "info")
    manager = ModuleManager()
    manager.register_module(_GoodAnalyzer())
    assert len(manager.run_analysis()) == 1
    events = _events(capsys.readouterr().out)
    started, completed = [
        event for event in events
        if event.get("event_name") in {"module.started", "module.finished"}
    ]
    assert started["status"] == "started"
    assert completed["status"] == "completed"
    assert completed["module"] == "GoodAnalyzer"
    assert completed["result_count"] == 1
    assert completed["duration_ms"] >= 0


def test_module_failure_emits_sanitized_exception(capsys):
    logger.configure(None, "info")
    manager = ModuleManager()
    manager.register_module(_FailingAnalyzer())
    assert manager.run_analysis() == []
    failed = next(event for event in _events(capsys.readouterr().out) if event.get("event_name") == "module.failed")
    assert failed["status"] == "failed"
    assert failed["module"] == "FailingAnalyzer"
    assert failed["error_type"] == "RuntimeError"
    assert "secret-value" not in failed["stack_trace"]
    assert manager.failed_modules == ["FailingAnalyzer"]
