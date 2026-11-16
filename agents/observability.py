"""Structured logs, trace context and counters.

One trace id follows a goal through every agent, so a single grep answers
"what happened to this request" across every subsystem.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from typing import Any, Iterator

from .security import redact_fields, redact_text

trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")
agent_id: contextvars.ContextVar[str] = contextvars.ContextVar("agent_id", default="-")


def new_trace() -> str:
    tid = uuid.uuid4().hex[:16]
    trace_id.set(tid)
    return tid


@contextmanager
def trace(tid: str) -> Iterator[None]:
    token = trace_id.set(tid)
    try:
        yield
    finally:
        trace_id.reset(token)


@contextmanager
def bound(**fields: Any) -> Iterator[None]:
    """Attach agent=... to every log line emitted inside the block."""
    token = agent_id.set(str(fields.get("agent", agent_id.get())))
    try:
        yield
    finally:
        agent_id.reset(token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "trace": trace_id.get(),
            "agent": agent_id.get(),
            "event": record.getMessage(),
        }
        for key, value in getattr(record, "fields", {}).items():
            entry[key] = value
        if record.exc_info:
            entry["error"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<5} {trace_id.get():<16} {agent_id.get():<10} {record.getMessage()}"
        fields = getattr(record, "fields", None)
        if fields:
            base += " " + " ".join(f"{k}={v}" for k, v in fields.items())
        return base


def log(event: str, **fields: Any) -> None:
    """Emit one structured event. Field values are summarised, not dumped."""
    logging.getLogger("mesh").info(event, extra={"fields": _trim(fields)})


def _trim(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in redact_fields(fields).items():
        if isinstance(v, str) and len(v) > 300:
            out[k] = redact_text(v[:297] + "...")
        else:
            out[k] = v
    return out


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json_logs else TextFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("httpx").setLevel("WARNING")


class Metrics:
    """Process-local counters. Swap for Prometheus/OTel in production."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self._started = time.monotonic()

    def inc(self, name: str, n: int = 1) -> None:
        self.counters[name] += n

    def snapshot(self) -> dict[str, Any]:
        return {
            "uptime_s": round(time.monotonic() - self._started, 1),
            "counters": dict(sorted(self.counters.items())),
        }
