"""OEKP: append-only, hash-chained evidence.

Every governed decision, approval, execution and validation result can be
appended here. Each record hashes the previous record, so tampering with or
removing an entry breaks verification - which is exactly what BENGAL checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .security import Signer, exclusive_lock, secure_dir, secure_file


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    id: str
    kind: str
    actor: str
    subsystem: str | None = None
    correlation_id: str = ""
    mission_id: str | None = None
    classification: str = "internal"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)
    # Provenance travels with the record so BENGAL can tell a real execution
    # proof from a CSSSF rehearsal. These fields are covered by the hash/MAC.
    provenance: list[str] = Field(default_factory=list, max_length=32)
    origin: str | None = Field(default=None, max_length=128)
    tainted: bool = False
    rehearsal_only: bool = False
    prev_hash: str = "genesis"
    hash: str = ""
    # Keyed MAC over the record. Hash chains detect edits; the MAC makes them
    # impossible to recompute without the cluster secret.
    mac: str = ""

    def compute_hash(self) -> str:
        # The hash covers the record content; the MAC is a separate envelope
        # field, so neither the hash nor the MAC can be part of the hash input.
        body = self.model_dump(mode="json", exclude={"hash", "mac"})
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


# Compliance export formats. The canonical store stays append-only JSONL;
# these are read-only renderings over the verified chain, never a second source
# of truth. Adding a format here makes it available to `agents export`.
EXPORT_FORMATS = frozenset({"jsonl", "oekp", "bengal", "oekp_bengal"})


def render_export(
    records: list[EvidenceRecord],
    fmt: str,
    *,
    verified: bool = True,
    detail: str = "",
) -> str:
    """Render verified evidence for OEKP/BENGAL consumers.

    ``fmt`` is validated against ``EXPORT_FORMATS`` and fails closed. The
    operator can pass several formats from settings; each is rendered by a
    separate call so one bad format cannot taint the others.
    """
    if fmt not in EXPORT_FORMATS:
        raise ValueError(
            f"unknown evidence export format {fmt!r}; choose from {', '.join(sorted(EXPORT_FORMATS))}"
        )
    if fmt == "jsonl":
        return "".join(record.model_dump_json() + "\n" for record in records)

    dumped = [record.model_dump(mode="json") for record in records]
    head = dumped[-1] if dumped else None
    oekp = {
        "format": "oekp-compliance/v1",
        "chain": {
            "records": len(dumped),
            "head_seq": head["seq"] if head else 0,
            "head_hash": head["hash"] if head else "genesis",
            "verified": bool(verified),
            "verification_detail": detail,
        },
        "records": [
            {
                key: record[key]
                for key in (
                    "seq",
                    "id",
                    "kind",
                    "actor",
                    "subsystem",
                    "correlation_id",
                    "mission_id",
                    "classification",
                    "created_at",
                    "provenance",
                    "origin",
                    "tainted",
                    "rehearsal_only",
                    "data",
                    "prev_hash",
                    "hash",
                    "mac",
                )
            }
            for record in dumped
        ],
    }
    if fmt == "oekp":
        return json.dumps(oekp, indent=2, sort_keys=True) + "\n"

    def _counts(key: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for record in records:
            name = str(getattr(record, key) or "unknown")
            out[name] = out.get(name, 0) + 1
        return dict(sorted(out.items()))

    rehearsal = sum(1 for r in records if r.rehearsal_only or sandbox_origin(
        origin=r.origin, provenance=r.provenance, sender=r.subsystem
    ))
    bengal = {
        "format": "bengal-assurance/v1",
        "assurance": "PASS" if verified else "FAIL",
        "verification_detail": detail,
        "totals": {
            "records": len(records),
            "tainted": sum(1 for r in records if r.tainted),
            "restricted": sum(1 for r in records if r.classification == "restricted"),
            "rehearsal_or_sandbox": rehearsal,
        },
        "by_kind": _counts("kind"),
        "by_actor": _counts("actor"),
        "by_subsystem": _counts("subsystem"),
        "chain_head": {
            "seq": head["seq"] if head else 0,
            "hash": head["hash"] if head else "genesis",
        },
    }
    if fmt == "bengal":
        return json.dumps(bengal, indent=2, sort_keys=True) + "\n"
    return json.dumps({"format": "usoc-compliance/v1", "oekp": oekp, "bengal": bengal}, indent=2, sort_keys=True) + "\n"


SANDBOX_ORIGINS = frozenset({"csssf", "csssf:sandbox", "sandbox", "rehearsal"})


def sandbox_origin(
    *, origin: str | None, provenance: list[str] | None, sender: str | None = None
) -> bool:
    """True when a record's provenance originates from the CSSSF sandbox.

    ``origin`` is stamped from the authenticated message sender (not from task
    inputs), so an attacker cannot relabel a sandbox artifact as production
    evidence by editing the payload.
    """
    labels = {str(origin or "").strip().lower(), str(sender or "").strip().lower()}
    labels |= {str(p).strip().lower() for p in (provenance or [])}
    return any(
        label in SANDBOX_ORIGINS
        or label.startswith("csssf:")
        or label.startswith("sandbox/")
        or "rehearsal" in label
        for label in labels
        if label
    )


class EvidenceChain:
    def __init__(self, path: str | Path, *, signer: Signer | None = None) -> None:
        self.path = Path(path)
        secure_dir(self.path.parent)
        self.signer = signer
        self._lock = asyncio.Lock()
        self._seq = 0
        self._last_hash = "genesis"
        self._loaded = False

    def _tail(self) -> tuple[int, str]:
        """Best-effort read of the last record, without full verification."""
        if not self.path.is_file():
            return 0, "genesis"
        last: EvidenceRecord | None = None
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        last = EvidenceRecord.model_validate_json(line)
                    except ValueError:
                        # Fail closed; the full verification on read will say why.
                        return -1, "corrupt"
        except OSError:
            return -1, "corrupt"
        if last is None:
            return 0, "genesis"
        return last.seq, last.hash

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path.is_file():
            return
        seq, last_hash = self._tail()
        if seq == -1:
            raise RuntimeError("evidence chain contains an invalid record")
        self._seq = seq
        self._last_hash = last_hash
        ok, detail = self.verify()
        if not ok:
            raise RuntimeError(f"evidence chain verification failed: {detail}")


    async def append(
        self,
        *,
        kind: str,
        actor: str,
        correlation_id: str = "",
        data: dict[str, Any] | None = None,
        subsystem: str | None = None,
        mission_id: str | None = None,
        classification: str = "internal",
        provenance: list[str] | None = None,
        origin: str | None = None,
        tainted: bool = False,
        rehearsal_only: bool = False,
    ) -> EvidenceRecord:
        async with self._lock:
            self._load()
            with exclusive_lock(self.path, timeout_s=10.0):
                # Another process may have appended since we loaded; catch up
                # under the shared file lock before forking the chain.
                seq, last_hash = self._tail()
                if seq == -1:
                    raise RuntimeError("evidence chain contains an invalid record")
                self._seq, self._last_hash = seq, last_hash
                record = EvidenceRecord(
                    seq=self._seq + 1,
                    id=f"ev-{uuid.uuid4().hex[:12]}",
                    kind=kind,
                    actor=actor,
                    subsystem=subsystem,
                    correlation_id=correlation_id,
                    mission_id=mission_id,
                    classification=classification,
                    data=data or {},
                    provenance=list(provenance or []),
                    origin=origin,
                    tainted=bool(tainted),
                    rehearsal_only=bool(rehearsal_only),
                    prev_hash=self._last_hash,
                )
                record.hash = record.compute_hash()
                if self.signer is not None:
                    record.mac = self.signer.sign_record(
                        "evidence", record.model_dump(mode="json", exclude={"mac"})
                    )
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(record.model_dump_json() + "\n")
                    fh.flush()
                    import os

                    os.fsync(fh.fileno())
            secure_file(self.path)
            self._seq = record.seq
            self._last_hash = record.hash
            return record

    def records(self, limit: int | None = None) -> list[EvidenceRecord]:
        if not self.path.is_file():
            return []
        out: list[EvidenceRecord] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(EvidenceRecord.model_validate_json(line))
                except ValueError:
                    out.append(
                        EvidenceRecord(seq=-1, id="corrupt", kind="corrupt", actor="unknown", hash="corrupt")
                    )
        return out[-limit:] if limit else out

    def verify(self) -> tuple[bool, str]:
        expected_prev = "genesis"
        expected_seq = 1
        records = self.records()
        for record in records:
            if record.seq != expected_seq:
                return False, f"sequence gap at record {record.id} (expected {expected_seq}, got {record.seq})"
            if record.prev_hash != expected_prev:
                return False, f"broken chain at record {record.id}"
            if record.compute_hash() != record.hash:
                return False, f"record {record.id} was modified"
            if self.signer is not None:
                ok, _ = self.signer.verify_record(
                    "evidence", record.model_dump(mode="json", exclude={"mac"}), record.mac
                )
                if not ok:
                    return False, f"record {record.id} has an invalid MAC"
            expected_prev = record.hash
            expected_seq += 1
        return True, f"{len(records)} records verified"

    @property
    def head(self) -> tuple[int, str]:
        self._load()
        return self._seq, self._last_hash
