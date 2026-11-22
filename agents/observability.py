"""Structured logs, trace context and counters.

One trace id follows a goal through every agent, so a single grep answers
"what happened to this request" across every subsystem.
"""

from __future__ import annotations

import contextvars
import hashlib
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
        # Normalise at format time too: host shippers or future callers may
        # attach `fields` directly, bypassing log()'s emit-time redaction.
        for key, value in _trim(getattr(record, "fields", {})).items():
            entry[key] = value
        if record.exc_info:
            entry["error"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(entry, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<5} {trace_id.get():<16} {agent_id.get():<10} {record.getMessage()}"
        fields = _trim(getattr(record, "fields", {}))
        if fields:
            base += " " + " ".join(f"{k}={v}" for k, v in fields.items())
        if record.exc_info:
            base += " error=" + redact_text(self.formatException(record.exc_info))
        return base


def log(event: str, *, level: str = "INFO", fingerprint: str | None = None, **fields: Any) -> None:
    """Emit one structured event. Field values are summarised, not dumped.

    ``level`` lets operators filter real failures from routine INFO chatter;
    ``fingerprint`` groups repeats of the same fault without leaking volatile
    identifiers. Trace and agent are captured at emit time so a record remains
    self-describing even if a host formats it later outside the context.
    """
    payload = {"trace": trace_id.get(), "agent": agent_id.get(), **fields}
    if fingerprint is not None:
        payload["fingerprint"] = fingerprint
    severity = getattr(logging, str(level).upper(), logging.INFO)
    logging.getLogger("mesh").log(severity, event, extra={"fields": _trim(payload)})


def error_fingerprint(exc: BaseException) -> str:
    """Stable group key for an error: type plus a redacted first line."""
    first = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    digest = hashlib.sha256(f"{type(exc).__name__}:{redact_text(first)}".encode("utf-8")).hexdigest()
    return digest[:16]


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
    # Keep handlers installed by the host (e.g. a platform log shipper); only
    # replace one of our own so repeated configure calls do not duplicate lines.
    for existing in list(root.handlers):
        if getattr(existing, "_usoc_handler", False):
            root.removeHandler(existing)
    handler._usoc_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("httpx").setLevel("WARNING")


LATENCY_BUCKETS_MS = (50, 100, 250, 500, 1_000, 2_500, 5_000)


class Metrics:
    """Process-local counters and latency histograms.

    Snapshots are emitted as structured log lines so an external collector can
    aggregate them without changing the mesh's dependencies.
    """

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.latencies: dict[str, Counter[str]] = {}
        self._started = time.monotonic()

    def inc(self, name: str, n: int = 1) -> None:
        self.counters[name] += n

    def observe(self, name: str, duration_ms: float) -> None:
        bucket = self.latencies.setdefault(name, Counter())
        self.inc(f"{name}.count")
        self.inc(f"{name}.sum_ms", max(0, round(duration_ms)))
        for bound in LATENCY_BUCKETS_MS:
            if duration_ms <= bound:
                self.inc(f"{name}.le_{bound}")

    def snapshot(self) -> dict[str, Any]:
        summaries: dict[str, dict[str, int]] = {}
        for name in self.latencies:
            count = self.counters.get(f"{name}.count", 0)
            total = self.counters.get(f"{name}.sum_ms", 0)

            def percentile(fraction: float) -> int:
                if not count:
                    return 0
                target = max(1, int(-(-count * fraction // 1)))  # ceil
                for bound in LATENCY_BUCKETS_MS:
                    if self.counters.get(f"{name}.le_{bound}", 0) >= target:
                        return bound
                return LATENCY_BUCKETS_MS[-1]

            summaries[name] = {
                "count": count,
                "sum_ms": total,
                "avg_ms": round(total / count) if count else 0,
                "p50_bucket_ms": percentile(0.5),
                "p95_bucket_ms": percentile(0.95),
            }
        return {
            "uptime_s": round(time.monotonic() - self._started, 1),
            "counters": dict(sorted(self.counters.items())),
            "latency_buckets_ms": list(LATENCY_BUCKETS_MS),
            "latencies": summaries,
        }
