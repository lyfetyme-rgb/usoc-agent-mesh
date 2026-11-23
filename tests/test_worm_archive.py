"""S3 Object Lock archival: immutable, chained, redacted, observation-only."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from agents.task_ledger import TaskEvent
from agents.worm import S3WormArchiveSink

SECRET = "worm-archive-cluster-key-with-at-least-32-chars"


class FakeS3:
    """In-memory stand-in that records Object Lock write parameters."""

    def __init__(self, *, fail: bool = False) -> None:
        self.objects: dict[str, bytes] = {}
        self.calls: list[dict] = []
        self.fail = fail

    def put_object(self, **kwargs) -> None:
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("s3 unavailable")
        self.objects[kwargs["Key"]] = kwargs["Body"]

    def list_objects_v2(self, **kwargs) -> dict:
        prefix = kwargs["Prefix"]
        return {
            "Contents": [{"Key": key} for key in sorted(self.objects) if key.startswith(prefix)],
            "IsTruncated": False,
        }

    def get_object(self, *, Bucket, Key) -> dict:
        class Body:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": Body(self.objects[Key])}


def event(seq: int, reason: str | None = None, tenant: str = "tenant-a") -> TaskEvent:
    return TaskEvent(
        event_id=f"evt-{seq}",
        trace_id="trace-1",
        agent_id="oekp",
        tenant_id=tenant,
        state="completed",
        ts=float(seq),
        reason_fingerprint="a" * 16 if reason else None,
    )


def sink(client: FakeS3, **kwargs) -> S3WormArchiveSink:
    return S3WormArchiveSink(
        bucket="usoc-evidence",
        secret=SECRET,
        prefix="usoc/test",
        client=client,
        segment_size=2,
        **kwargs,
    )


async def test_segments_are_written_with_object_lock_and_verify():
    client = FakeS3()
    archive = sink(client, retention_days=30, lock_mode="COMPLIANCE")
    for seq in range(1, 6):
        archive.emit(event(seq))
    await archive.flush()

    assert len(client.calls) == 3
    for call in client.calls:
        assert call["Bucket"] == "usoc-evidence"
        assert call["ServerSideEncryption"] == "AES256"
        assert call["ObjectLockMode"] == "COMPLIANCE"
        assert call["ObjectLockRetainUntilDate"] > datetime.now(timezone.utc)
        # Only the opaque 16-hex fingerprint is present; no raw reason field.
        assert b'"reason"' not in call["Body"]
    assert archive.written == 5
    assert archive.snapshot()["backend"] == "s3-object-lock"
    assert archive.verify() is True


async def test_tampered_or_missing_segment_fails_verification():
    client = FakeS3()
    archive = sink(client)
    for seq in range(1, 4):
        archive.emit(event(seq))
    await archive.flush()

    first_key = sorted(client.objects)[0]
    record = json.loads(client.objects[first_key].decode("utf-8").splitlines()[0])
    record["hash"] = "0" * 64
    client.objects[first_key] = (json.dumps(record) + "\n").encode("utf-8")
    assert archive.verify() is False

    client.objects.pop(first_key)
    assert archive.verify() is False


async def test_write_failure_is_retried_and_never_raises():
    client = FakeS3(fail=True)
    archive = sink(client)
    archive.emit(event(1))
    await archive.flush()  # must not raise
    assert archive.failed_writes == 1
    assert archive.written == 0
    assert archive.pending == 1

    client.fail = False
    await archive.flush()
    assert archive.written == 1
    assert archive.pending == 0
    assert archive.verify() is True


async def test_raw_reason_text_never_reaches_object_storage():
    client = FakeS3()
    archive = sink(client)
    archive.emit(event(1, reason="super secret payload"))
    await archive.flush()
    body = b"".join(client.objects.values()).decode("utf-8")
    assert "super secret payload" not in body
    assert '"reason"' not in body


async def test_tenant_chains_are_partitioned_in_object_keys():
    client = FakeS3()
    archive = sink(client)
    archive.emit(event(1, tenant="tenant-a"))
    archive.emit(event(1, tenant="tenant-b"))
    archive.emit(event(2, tenant="tenant-a"))
    await archive.flush()

    keys = list(client.objects)
    assert len(keys) == 2  # tenant-a fills one 2-record segment, tenant-b one record
    assert any("tenant=tenant-a-" in key for key in keys)
    assert any("tenant=tenant-b-" in key for key in keys)
    # Both tenants start at seq=1 in their own chain and key namespace.
    assert sum("segment-000000000001.jsonl" in key for key in keys) == 2
    tenant_a_key = next(key for key in keys if "tenant=tenant-a-" in key)
    assert len(client.objects[tenant_a_key].decode("utf-8").splitlines()) == 2
    assert archive.verify() is True

    # Corrupting one tenant's segment must not silently pass global verification.
    first_key = next(key for key in keys if "tenant=tenant-b-" in key)
    record = json.loads(client.objects[first_key].decode("utf-8").splitlines()[0])
    record["seq"] = 99
    client.objects[first_key] = (json.dumps(record) + "\n").encode("utf-8")
    assert archive.verify() is False


async def test_new_emits_during_failed_flush_keep_chain_contiguous():
    client = FakeS3(fail=True)
    archive = sink(client)
    archive.emit(event(1))
    await archive.flush()
    archive.emit(event(2))
    client.fail = False
    await archive.flush()

    assert archive.written == 2
    assert archive.pending == 0
    assert archive.verify() is True

