"""Regression tests for production observability hardening."""

from __future__ import annotations

import io
import json
import logging

import pytest

from agents.llm import OpenAICompatibleLLM
from agents.observability import (
    JsonFormatter,
    Metrics,
    TextFormatter,
    configure_logging,
    redact_text,
)


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self.request = None
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakePostClient:
    def __init__(self, text: str) -> None:
        self.text = text

    async def post(self, *_args, **_kwargs) -> _FakeResponse:
        return _FakeResponse(
            {
                "choices": [{"message": {"content": self.text}}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3},
                "model": "fake",
            }
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_llm_parses_json_tool_response_without_schema():
    """Tool rounds call complete() with no json_schema; data must still parse."""
    llm = OpenAICompatibleLLM("https://api.example.test/v1", "sk-test")
    llm._client = _FakePostClient('{"tool_name": "search", "args": {"q": "valve"}}')
    response = await llm.complete(system="sys", messages=[{"role": "user", "content": "go"}])
    assert response.data == {"tool_name": "search", "args": {"q": "valve"}}
    await llm.close()


def test_metrics_observe_records_buckets_and_sum():
    metrics = Metrics()
    metrics.observe("ingest", 40)
    metrics.observe("ingest", 750)
    snapshot = metrics.snapshot()
    counters = snapshot["counters"]
    assert counters["ingest.count"] == 2
    assert counters["ingest.sum_ms"] == 790
    # Buckets are cumulative: 40ms counts in le_50 and every larger bucket;
    # 750ms only starts counting from le_1000.
    assert counters["ingest.le_50"] == 1
    assert counters["ingest.le_100"] == 1
    assert counters["ingest.le_1000"] == 2


def test_json_formatter_redacts_stack_trace_pii():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        "mesh", logging.ERROR, __file__, 1, "sms failed", None, None, None
    )
    try:
        raise RuntimeError("send to jane.doe@example.com / +1 555 123 4567")
    except RuntimeError:
        import sys

        record.exc_info = sys.exc_info()
    rendered = formatter.format(record)
    assert "jane.doe@example.com" not in rendered
    assert "555 123 4567" not in rendered
    assert json.loads(rendered)["level"] == "ERROR"


def test_text_formatter_keeps_redacted_stack_trace():
    formatter = TextFormatter()
    record = logging.LogRecord(
        "mesh", logging.ERROR, __file__, 1, "sms failed", None, None, None
    )
    try:
        raise RuntimeError("bearer abc.def123 for operator@example.com")
    except RuntimeError:
        import sys

        record.exc_info = sys.exc_info()
    rendered = formatter.format(record)
    assert "error=" in rendered
    assert "operator@example.com" not in rendered


def test_configure_logging_keeps_externally_installed_handlers():
    root = logging.getLogger()
    external = logging.StreamHandler(io.StringIO())
    root.addHandler(external)
    try:
        configure_logging("INFO", json_logs=True)
        assert external in root.handlers
        ours = [h for h in root.handlers if getattr(h, "_usoc_handler", False)]
        assert len(ours) == 1
        # Reconfiguring must not duplicate our own handler.
        configure_logging("INFO", json_logs=True)
        ours = [h for h in root.handlers if getattr(h, "_usoc_handler", False)]
        assert len(ours) == 1
    finally:
        for handler in list(root.handlers):
            if getattr(handler, "_usoc_handler", False):
                root.removeHandler(handler)
        root.removeHandler(external)


def test_redact_text_masks_direct_email_and_phone():
    redacted = redact_text("notify jane.doe@example.com at +1 555 123 4567 now")
    assert "jane.doe@example.com" not in redacted
    assert "555 123 4567" not in redacted
