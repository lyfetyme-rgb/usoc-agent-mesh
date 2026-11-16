from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agents.contracts import (
    MAX_HOPS,
    MAX_PAYLOAD_BYTES,
    Failure,
    Message,
    Query,
    TaskResult,
    TaskSpec,
)


def test_task_roundtrip_is_lossless():
    msg = Message.task(sender="orchestrator", recipient="acie", objective="ingest tickets")
    wire = msg.model_dump_json()
    again = Message.model_validate_json(wire)
    assert again == msg
    assert again.kind == "task"
    assert again.recipient == "acie"
    assert again.correlation_id == msg.correlation_id


def test_reply_targets_sender_on_same_correlation():
    task = Message.task(sender="orchestrator", recipient="acie", objective="x")
    result = task.reply_with(TaskResult(ok=True, output="done"))
    assert result.recipient == "orchestrator"
    assert result.topic == "inbox.orchestrator"
    assert result.correlation_id == task.correlation_id
    assert result.causation_id == task.id


def test_hop_limit_is_enforced():
    msg = Message.task(sender="a", recipient="b", objective="x")
    with pytest.raises(ValidationError):
        Message(**{**msg.model_dump(), "hop": MAX_HOPS + 1})


def test_unknown_payload_fields_are_rejected():
    with pytest.raises(ValidationError):
        TaskSpec.model_validate({"objective": "x", "surprise": 1})


def test_payload_size_is_capped():
    with pytest.raises(ValidationError):
        Message.task(sender="a", recipient="b", objective="x", inputs={"blob": "y" * MAX_PAYLOAD_BYTES})


def test_deadline_expiry():
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    msg = Message.task(sender="a", recipient="b", objective="x", deadline=past)
    assert msg.expired()
    future = Message.task(
        sender="a", recipient="b", objective="x", deadline=datetime.now(timezone.utc) + timedelta(minutes=1)
    )
    assert not future.expired()


def test_query_and_failure_are_discriminated():
    q = Message(sender="a", recipient="b", topic="inbox.b", payload=Query(question="why?"))
    assert q.kind == "query"
    f = q.reply_with(Failure(code="timeout", message="too slow"))
    assert f.kind == "error"
    assert Message.model_validate_json(f.model_dump_json()).payload.message == "too slow"
