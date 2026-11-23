"""Tenant scoping for approvals ( prerequisite for the Postgres backend )."""

from __future__ import annotations

import pytest

from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    InMemoryApprovalStore,
    decision_payload_digest,
)
from agents.contracts import ActionClass, RiskLevel


def _request(tenant: str, approval_id: str = "apr-1") -> ApprovalRequest:
    return ApprovalRequest(
        id=approval_id,
        tenant_id=tenant,
        action_class=ActionClass.EXECUTE,
        target="sandbox/job",
        risk=RiskLevel.LOW,
        requested_by="alice",
    )


def test_tenant_is_part_of_the_signed_decision_payload():
    assert decision_payload_digest(_request("tenant-a")) != decision_payload_digest(
        _request("tenant-b")
    )


async def test_in_memory_store_does_not_cross_tenant_boundaries():
    store = InMemoryApprovalStore()
    await store.request(_request("tenant-a", "apr-a"))
    await store.request(_request("tenant-b", "apr-b"))

    a = await store.get("apr-a", tenant_id="tenant-a")
    b = await store.get("apr-b", tenant_id="tenant-b")
    assert a is not None and b is not None
    assert a.tenant_id == "tenant-a"
    assert b.tenant_id == "tenant-b"
    assert await store.get("apr-a", tenant_id="tenant-b") is None
    assert await store.get("apr-b", tenant_id="tenant-a") is None
    assert {r.tenant_id for r in await store.pending(tenant_id="tenant-b")} == {"tenant-b"}


async def test_consumption_in_one_tenant_cannot_spend_another_tenants_nonce():
    store = InMemoryApprovalStore()
    a = await store.request(_request("tenant-a", "apr-a"))
    await store.request(_request("tenant-b", "apr-b"))
    for tenant, approval_id in (("tenant-a", "apr-a"), ("tenant-b", "apr-b")):
        await store.decide(approval_id, tenant_id=tenant, approved=True, approver="bob")

    assert await store.consume("apr-a", tenant_id="tenant-b", nonce=a.nonce) is None
    spent = await store.consume("apr-a", tenant_id="tenant-a", nonce=a.nonce)
    assert spent is not None
    assert await store.consume("apr-a", tenant_id="tenant-a", nonce=a.nonce) is None
    other = await store.get("apr-b", tenant_id="tenant-b")
    assert other is not None and other.status is ApprovalStatus.APPROVED
