"""Async S3 Object Lock (WORM) archival of the signed task-ledger chain.

``SignedArchiveSink`` appends a redacted HMAC hash chain to a local JSONL file,
which pins a control-plane pod to the shared ``/data`` PVC. This sink keeps the
exact same chain semantics (so the existing verification rules still apply) but
writes immutable, versioned segments to S3 with Object Lock retention.

Security properties preserved:

* only redacted ``TaskEvent`` objects are accepted -- no goal, output, error or
  payload text ever reaches object storage;
* each tenant has an independent chain and object-key prefix, so one tenant can
  never break another tenant's evidence;
* each segment carries ``prev``/``seq``/HMAC so a missing, reordered or edited
  record fails end-to-end verification;
* objects are written with ``ObjectLockMode`` + a future retention date, so a
  compromised credential cannot truncate or rewrite history (WORM);
* all I/O is observation-only: failures increment a counter and are swallowed,
  never propagated into a task handler or a policy decision.

``boto3`` is imported lazily; tests inject a fake client through ``client=``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .task_ledger import TaskEvent

DEFAULT_TENANT = "default"


@dataclass
class _TenantChain:
    """Per-tenant chain state; no global sequence can be forked by a tenant."""

    seq: int = 0
    prev: str = "0" * 64
    records: list[dict[str, Any]] = field(default_factory=list)
    written: int = 0
    segments: list[str] = field(default_factory=list)


class S3WormArchiveSink:
    """Hash-chained, tenant-partitioned immutable S3 archive for task events."""

    def __init__(
        self,
        *,
        bucket: str,
        secret: str,
        prefix: str = "usoc/task-ledger",
        region: str | None = None,
        endpoint_url: str | None = None,
        retention_days: int = 2_555,
        lock_mode: str = "COMPLIANCE",
        segment_size: int = 512,
        client: Any | None = None,
    ) -> None:
        if not bucket:
            raise ValueError("S3 WORM archive requires a bucket")
        if not secret:
            raise ValueError("S3 WORM archive requires a signing secret")
        if retention_days < 1:
            raise ValueError("retention_days must be positive")
        if lock_mode not in ("GOVERNANCE", "COMPLIANCE"):
            raise ValueError("lock_mode must be GOVERNANCE or COMPLIANCE")
        if segment_size < 1:
            raise ValueError("segment_size must be positive")
        self.bucket = bucket
        self.secret = secret
        self.prefix = prefix.rstrip("/")
        self.region = region
        self.endpoint_url = endpoint_url
        self.retention_days = int(retention_days)
        self.lock_mode = lock_mode
        self.segment_size = int(segment_size)
        self._client = client
        self._chains: dict[str, _TenantChain] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self.failed_writes = 0

    # -- identity -------------------------------------------------------------
    @staticmethod
    def _tenant(tenant_id: str | None) -> str:
        tenant = (tenant_id or DEFAULT_TENANT).strip()
        if not tenant or len(tenant) > 200:
            raise ValueError("invalid tenant_id for WORM archive")
        return tenant

    @staticmethod
    def _tenant_slug(tenant_id: str) -> str:
        # A readable prefix plus a stable hash: safe as an S3 key segment and
        # reversible enough for operators to map a key back to its tenant.
        readable = re.sub(r"[^A-Za-z0-9_-]", "_", tenant_id)[:48] or "default"
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]
        return f"{readable}-{digest}"

    def _object_key(self, tenant_id: str, first_seq: int) -> str:
        return (
            f"{self.prefix}/tenant={self._tenant_slug(tenant_id)}"
            f"/segment-{int(first_seq):012d}.jsonl"
        )

    # -- client ---------------------------------------------------------------
    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - install extra needed
                raise RuntimeError(
                    "S3 WORM archive requires agent-mesh[s3] (boto3)"
                ) from exc
            self._client = boto3.client(
                "s3",
                region_name=self.region,
                endpoint_url=self.endpoint_url,
            )
        return self._client

    # -- chain ----------------------------------------------------------------
    def _digest(self, record: dict[str, Any]) -> str:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    def _schedule_flush(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._tasks:
            return
        task = loop.create_task(self.flush())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def emit(self, event: TaskEvent) -> None:
        tenant = self._tenant(event.tenant_id)
        state = self._chains.setdefault(tenant, _TenantChain())
        # Sequence numbers are monotonic across failed flushes: a retry must
        # never renumber records emitted while a failed segment was buffered.
        state.seq += 1
        record: dict[str, Any] = {
            "seq": state.seq,
            "prev": state.prev,
            "event": event.model_dump(mode="json"),
        }
        digest = self._digest(record)
        state.records.append({**record, "hash": digest})
        state.prev = digest
        if len(state.records) >= self.segment_size:
            # Long-running pods must not hold an unbounded buffer. Schedule the
            # immutable upload from the running loop; without one, explicit
            # flush() still drains the buffer deterministically.
            self._schedule_flush()

    @property
    def pending(self) -> int:
        return sum(len(state.records) for state in self._chains.values())

    @property
    def written(self) -> int:
        return sum(state.written for state in self._chains.values())

    # -- write path -----------------------------------------------------------
    def _retain_until(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=self.retention_days)

    async def flush(self) -> None:
        """Upload buffered records as tenant-scoped WORM-locked segments."""
        for tenant, state in list(self._chains.items()):
            if not state.records:
                continue
            records, state.records = state.records, []
            for start in range(0, len(records), self.segment_size):
                chunk = records[start : start + self.segment_size]
                body = (
                    "\n".join(json.dumps(r, sort_keys=True) for r in chunk) + "\n"
                ).encode("utf-8")
                key = self._object_key(tenant, int(chunk[0]["seq"]))
                try:
                    self._get_client().put_object(
                        Bucket=self.bucket,
                        Key=key,
                        Body=body,
                        ContentType="application/x-ndjson",
                        ServerSideEncryption="AES256",
                        ObjectLockMode=self.lock_mode,
                        ObjectLockRetainUntilDate=self._retain_until(),
                    )
                except Exception:
                    self.failed_writes += 1
                    # Do not advance ``written``: the next flush retries this
                    # segment. ``prev`` already points at the last emitted
                    # record, so it must not rewind when new events arrive.
                    state.records = records[start:] + state.records
                    break
                state.written += len(chunk)
                state.segments.append(key)

    # -- verification ---------------------------------------------------------
    def _list_keys(self) -> list[str]:
        client = self._get_client()
        keys: list[str] = []
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self.bucket, "Prefix": f"{self.prefix}/"}
            if token:
                kwargs["ContinuationToken"] = token
            response = client.list_objects_v2(**kwargs)
            keys.extend(item["Key"] for item in response.get("Contents", []))
            if not response.get("IsTruncated"):
                break
            token = response.get("NextContinuationToken")
            if not token:
                break
        return sorted(keys)

    def verify(self) -> bool:
        """Rebuild every tenant chain from stored segments; any gap/edit fails."""
        try:
            keys = self._list_keys()
        except Exception:
            self.failed_writes += 1
            return False
        if not keys and any(
            state.written or state.records for state in self._chains.values()
        ):
            # An archive that should hold records but lists none is not valid.
            return False

        by_tenant: dict[str, list[tuple[dict[str, Any], str]]] = {}
        client = self._get_client()
        for key in keys:
            try:
                body = client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
            except Exception:
                self.failed_writes += 1
                return False
            parsed: list[tuple[dict[str, Any], str, str]] = []
            for line in body.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    digest = str(entry["hash"])
                except (ValueError, KeyError, TypeError):
                    return False
                canonical = {k: v for k, v in entry.items() if k != "hash"}
                tenant = self._tenant((canonical.get("event") or {}).get("tenant_id"))
                if parsed and tenant != parsed[0][2]:
                    return False  # one segment must never mix tenants
                parsed.append((canonical, digest, tenant))
            if not parsed:
                return False
            expected_key = self._object_key(parsed[0][2], int(parsed[0][0]["seq"]))
            if key != expected_key:
                return False
            by_tenant.setdefault(parsed[0][2], []).extend(
                (canonical, digest) for canonical, digest, _ in parsed
            )

        for tenant, entries in by_tenant.items():
            entries.sort(key=lambda item: int(item[0]["seq"]))
            prev = "0" * 64
            expected_seq = 1
            for canonical, digest in entries:
                if canonical.get("seq") != expected_seq or canonical.get("prev") != prev:
                    return False
                if not hmac.compare_digest(self._digest(canonical), digest):
                    return False
                prev = digest
                expected_seq += 1
        return True

    def snapshot(self) -> dict[str, Any]:
        return {
            "backend": "s3-object-lock",
            "bucket": self.bucket,
            "prefix": self.prefix,
            "lock_mode": self.lock_mode,
            "retention_days": self.retention_days,
            "tenants": len(self._chains),
            "records": self.written + self.pending,
            "segments": sum(len(state.segments) for state in self._chains.values()),
            "failed_writes": self.failed_writes,
        }

    async def close(self) -> None:
        await self.flush()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


__all__ = ["S3WormArchiveSink"]
