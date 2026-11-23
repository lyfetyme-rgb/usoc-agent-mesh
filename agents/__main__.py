"""CLI: python -m agents {demo,list,profiles,storyboard,export,doctor,integrity,keygen,sign-config,sign-approvers,approval-payload,serve,worker,scale-advice,probe,health,approvals,approve,deny,publish-decision,ingest,demo-fragmentation}

    python -m agents demo "Collect edge telemetry, analyse anomalies, record evidence"
    python -m agents shadow "Collect edge telemetry, evaluate containment"  # observe, never execute
    python -m agents list
    python -m agents profiles                       # 4 Industry Starter Packs and role counts
    python -m agents --profile finops_banking list  # narrow the capability-card role view
    python -m agents storyboard --vertical finance  # 3-minute Money Shot storyboard
    python -m agents llm-rehearsal                   # offline LLM/policy rehearsal (no egress)
    python -m agents llm-rehearsal --live            # opt into AGENT_LLM_BASE_URL model egress
    python -m agents benchmark                       # adaptive governance-readiness benchmark
    python -m agents export --format oekp_bengal --output exports/
    python -m agents doctor
    python -m agents integrity
    python -m agents keygen --private-key-file secrets/ed25519_private.pem --public-key-file trust/ed25519_public.hex
    python -m agents sign-config --key-file secrets/ed25519_private.pem
    python -m agents sign-approvers --registry-file trust/approvers.json --key-file secrets/approver_signing.pem
    python -m agents serve --host 127.0.0.1 --port 8080
    python -m agents probe --url http://127.0.0.1:8080/ready
    python -m agents health
    python -m agents approvals
    python -m agents approval-payload apr-1234 --by alice --approve
    python -m agents approve apr-1234 --by alice --signature-file /run/secrets/alice.sig
    python -m agents approve apr-1234 --by alice --id-token-file /run/secrets/alice.idtoken
    python -m agents publish-decision apr-1234 --signoff apr-5678
    python -m agents ingest --fixtures fixtures/fragmentation
    python -m agents demo-fragmentation --vertical healthcare
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from contextlib import suppress
from pathlib import Path

from .bus import ConfigurationError as BusConfigurationError
from .bus import topic_rules_from_authority
from .config import Settings, get_settings, subsystems_integrity, verify_subsystems_file
from .evidence import EvidenceChain
from .governance import ApprovalCredential, FileApprovalStore, decision_payload_digest
from .profiles import (
    PROFILES,
    apply_role_profile,
    get_profile,
    settings_for_profile,
)
from .registry import RegistryError, load_registry
from .security import (
    SecurityError,
    build_signer,
    configured_approvers,
    is_ephemeral_secret,
    read_secret,
    redact_fields,
    redact_url,
)
from .tools import build_default_tools
from .trust import (
    CoordinatorKeyring,
    approval_credential_payload,
    build_approval_verifier,
    oidc_approval_binding,
    build_message_authority,
    load_approver_registry,
    validate_strict_prod,
)

DEFAULT_GOAL = (
    "Collect edge telemetry from the cluster, analyse anomalies in the workload data, "
    "evaluate the policy for a containment action, then record the evidence."
)
DEFAULT_FIXTURES = Path("fixtures") / "fragmentation"


def _settings(args: argparse.Namespace) -> Settings:
    base = get_settings()
    overrides: dict = {}
    if getattr(args, "registry", None):
        overrides["subsystems_file"] = Path(args.registry)
    if getattr(args, "workspace", None):
        overrides["workspace"] = Path(args.workspace)
    if getattr(args, "connectors", None):
        overrides["connectors_file"] = Path(args.connectors)
    if getattr(args, "json_logs", False):
        overrides["log_json"] = True
    if getattr(args, "profile", None):
        overrides["role_profile"] = args.profile
    settings = base.model_copy(update=overrides) if overrides else base
    if getattr(args, "shadow", False):
        settings = settings.model_copy(update={"shadow_mode": True})
    if getattr(settings, "shadow_mode", False):
        shadow_ws = (
            settings.workspace
            if settings.workspace.name == "shadow"
            else settings.workspace / "shadow"
        )
        settings = settings.model_copy(
            update={
                "workspace": shadow_ws,
                "atlassian_bridge_enabled": False,
                "atlassian_jsm_enabled": False,
            }
        )
    return settings_for_profile(settings)


def _signer(settings: Settings):
    return build_signer(settings)


def _registry(settings: Settings):
    signer = _signer(settings)
    evidence = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)
    tools = build_default_tools(
        settings.workspace,
        evidence,
        allow_delete=settings.allow_workspace_delete,
    )
    return apply_role_profile(
        load_registry(settings.subsystems_file, tools, settings=settings),
        settings.role_profile,
    )


def _seed_workspace(settings: Settings) -> Path:
    path = settings.workspace / "inbox" / "telemetry.jsonl"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            '{"node": "edge-01", "cpu": 0.31, "mem": 0.44, "net_ms": 18, "ts": "2026-11-14T11:00:00Z"}',
            '{"node": "edge-01", "cpu": 0.33, "mem": 0.45, "net_ms": 19, "ts": "2026-11-14T11:01:00Z"}',
            '{"node": "edge-02", "cpu": 0.94, "mem": 0.88, "net_ms": 240, "ts": "2026-11-14T11:00:00Z"}',
            '{"node": "edge-02", "cpu": 0.97, "mem": 0.91, "net_ms": 310, "ts": "2026-11-14T11:01:00Z"}',
            '{"node": "edge-03", "cpu": 0.12, "mem": 0.30, "net_ms": 21, "ts": "2026-11-14T11:00:00Z"}',
        ]
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def cmd_list(args: argparse.Namespace) -> int:
    settings = _settings(args)
    registry = _registry(settings)
    width = max(len(s.id) for s in registry.subsystems)
    print(f"{len(registry)} subsystems, {registry.roles_total} logical roles ({settings.subsystems_file})\n")
    for spec in registry.subsystems:
        tools = ", ".join(spec.tools) or "-"
        subs = ", ".join(spec.subscribes) or "-"
        tier = (
            "deterministic / no LLM"
            if spec.model_tier == "deterministic"
            else spec.model_tier
        )
        scopes = (
            ", ".join(
                f"{name} -> {prefix.strip().rstrip('/')}/"
                for name, prefix in spec.tool_scopes.items()
            )
            or "-"
        )
        print(f"{spec.id:<{width}}  {spec.name}  [{tier}]  {len(spec.roles)} roles")
        print(f"{'':<{width}}  {spec.description}")
        print(f"{'':<{width}}  roles: {spec.role_titles()}")
        print(f"{'':<{width}}  tools: {tools}   listens: {subs}")
        print(f"{'':<{width}}  tool scope: {scopes}\n")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    """List the shipped Starter Profiles and their exact active-role counts."""
    settings = _settings(args)
    registry = _registry(settings)
    available = sorted(PROFILES)
    for profile_id in available:
        profile = get_profile(profile_id)
        marker = "*" if profile_id == settings.role_profile else " "
        view = apply_role_profile(registry, profile_id)
        print(
            f"{marker} {profile.id:<20} {profile.name:<48} "
            f"{view.roles_total:>2} roles / {len(view)} coordinators"
        )
        print(f"    {profile.description}")
        controls = ", ".join(f"{k}={v}" for k, v in profile.controls.items()) or "none"
        print(f"    controls: {controls}")
    print(f"\n* active profile (AGENT_ROLE_PROFILE={settings.role_profile})")
    print("All nine coordinators run under every profile; only role views are filtered.")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Render the verified evidence chain in OEKP/BENGAL compliance formats."""
    from .evidence import EXPORT_FORMATS, render_export

    settings = _settings(args)
    signer = _signer(settings)
    chain = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)
    ok, detail = chain.verify()
    if not ok:
        print(f"evidence chain is not verifiable: {detail}", file=sys.stderr)
        return 1
    formats = (
        [args.format]
        if getattr(args, "format", None)
        else [p.strip() for p in settings.evidence_export_formats.split(",") if p.strip()]
    )
    unknown = [fmt for fmt in formats if fmt not in EXPORT_FORMATS]
    if unknown:
        print(
            f"unknown export format(s): {', '.join(unknown)}; "
            f"choose from {', '.join(sorted(EXPORT_FORMATS))}",
            file=sys.stderr,
        )
        return 1
    records = chain.records()
    payloads = [(fmt, render_export(records, fmt, verified=ok, detail=detail)) for fmt in formats]
    if getattr(args, "output", None):
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        for fmt, payload in payloads:
            path = out_dir / f"evidence.{fmt.replace('_', '-')}.{'json' if fmt != 'jsonl' else 'jsonl'}"
            path.write_text(payload, encoding="utf-8")
            print(f"wrote {path}")
        return 0
    for fmt, payload in payloads:
        print(f"--- {fmt} ---")
        sys.stdout.write(payload)
    return 0


def cmd_storyboard(args: argparse.Namespace) -> int:
    """Print the 3-minute Money Shot storyboard for one vertical (or all)."""
    from .storyboards import STORYBOARDS, get_storyboard, render_storyboard

    vertical = getattr(args, "vertical", None)
    if vertical == "all" or not vertical:
        boards = list(STORYBOARDS.values())
    else:
        try:
            boards = [get_storyboard(vertical)]
        except RegistryError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    for index, board in enumerate(boards):
        if index:
            print("\n" + "=" * 78 + "\n")
        print(render_storyboard(board.id))
    return 0


def _load_rehearsal_cases(path: Path) -> list:
    """Load labeled JSONL cases, failing closed on a malformed line."""
    from .llm_rehearsal import RehearsalCase

    cases: list = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cases.append(RehearsalCase.model_validate_json(line))
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: invalid rehearsal case: {exc}") from exc
    if not cases:
        raise ValueError(f"no rehearsal cases in {path}")
    return cases


async def _run_llm_rehearsal(args: argparse.Namespace) -> int:
    """Run labeled prompts through the model and deterministic policy; observe only."""
    from .evidence import render_export
    from .governance import InMemoryApprovalStore, PolicyConfig, PolicyEngine
    from .llm import EchoLLM, build_llm
    from .llm_rehearsal import run_rehearsal

    # Force the shadow baseline: isolated workspace, bridges off. The harness
    # itself hard-codes rehearsal_only/shadow on every evidence record and never
    # calls a tool, handler, approval decision or external sink.
    args.shadow = True
    settings = _settings(args)
    live = bool(getattr(args, "live", False))
    if live and not settings.llm_base_url:
        print(
            "llm-rehearsal: --live requires AGENT_LLM_BASE_URL "
            "(omit --live for the offline EchoLLM baseline)",
            file=sys.stderr,
        )
        return 2

    cases_path = Path(args.cases)
    if not cases_path.is_file():
        print(f"llm-rehearsal: no such cases file: {cases_path}", file=sys.stderr)
        return 1
    try:
        cases = _load_rehearsal_cases(cases_path)
    except (OSError, ValueError) as exc:
        print(f"llm-rehearsal: {exc}", file=sys.stderr)
        return 1

    evidence = EvidenceChain(
        settings.workspace / "evidence" / "llm-rehearsal.jsonl", signer=_signer(settings)
    )
    policy = PolicyEngine(
        PolicyConfig(
            allowed_targets=[
                item.strip() for item in settings.allowed_targets.split(",") if item.strip()
            ],
            # Rehearsal never authorizes an egress destination.
            egress_target=None,
        ),
        InMemoryApprovalStore(),
    )
    llm = build_llm(settings) if live else EchoLLM()
    try:
        report = await run_rehearsal(
            settings=settings,
            llm=llm,
            evidence=evidence,
            policy=policy,
            cases=cases,
            live=live,
        )
    finally:
        await llm.close()

    print(json.dumps(json.loads(report.model_dump_json()), indent=2, sort_keys=True))
    if getattr(args, "output", None):
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        ok, detail = evidence.verify()
        dest = out / "evidence.oekp-bengal.json"
        dest.write_text(
            render_export(
                evidence.records(), "oekp_bengal", verified=ok, detail=detail
            ),
            encoding="utf-8",
        )
        print(f"evidence export: {dest}")
    return 0


async def _run_benchmark(args: argparse.Namespace) -> int:
    """Score fixed governance variants, focus on residual failures, archive lineage."""
    from .benchmark import load_cases, run_benchmark
    from .evidence import render_export
    from .governance import InMemoryApprovalStore, PolicyConfig, PolicyEngine

    args.shadow = True  # isolated workspace, no bridges, no live nonce
    settings = _settings(args)
    cases_path = Path(args.cases)
    if not cases_path.is_file():
        print(f"benchmark: no such cases file: {cases_path}", file=sys.stderr)
        return 1
    try:
        cases = load_cases(cases_path)
    except (OSError, ValueError) as exc:
        print(f"benchmark: {exc}", file=sys.stderr)
        return 1

    evidence = EvidenceChain(
        settings.workspace / "evidence" / "benchmark.jsonl", signer=_signer(settings)
    )
    # A fresh in-memory approval store: the benchmark can never consume or
    # mutate the store used by a running mesh.
    policy = PolicyEngine(
        PolicyConfig(
            allowed_targets=[
                item.strip() for item in settings.allowed_targets.split(",") if item.strip()
            ],
            egress_target=None,
        ),
        InMemoryApprovalStore(),
    )
    report = await run_benchmark(
        settings=settings,
        evidence=evidence,
        policy=policy,
        cases=cases,
        adaptive=not getattr(args, "full", False),
        max_rounds=max(1, int(getattr(args, "rounds", 3))),
    )
    print(json.dumps(json.loads(report.model_dump_json()), indent=2, sort_keys=True))
    if getattr(args, "output", None):
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        ok, detail = evidence.verify()
        dest = out / "evidence.oekp-bengal.json"
        dest.write_text(
            render_export(evidence.records(), "oekp_bengal", verified=ok, detail=detail),
            encoding="utf-8",
        )
        print(f"evidence export: {dest}")
    best_score = (
        report.variants[report.best].score if report.best in report.variants else 0.0
    )
    return 0 if report.hard_pass and best_score >= float(args.min_score) else 1


def _approval_store(settings: Settings, signer=None) -> FileApprovalStore:
    registry = load_approver_registry(settings)
    verifier = build_approval_verifier(settings, registry)
    approvers = configured_approvers(settings)
    if registry is not None:
        approvers = (approvers & registry.ids()) if approvers else registry.ids()
    return FileApprovalStore(
        settings.workspace / "approvals.json",
        signer=signer,
        approvers=approvers,
        require_allowlist=settings.require_approver_allowlist or settings.strict_prod,
        ttl_s=settings.approval_ttl_s,
        approver_verifier=verifier,
    )


def cmd_approvals(args: argparse.Namespace) -> int:
    settings = _settings(args)
    signer = _signer(settings)
    store = _approval_store(settings, signer)
    pending = asyncio.run(store.pending())
    if store.rejected:
        print(
            f"[warn] {store.rejected} approval record(s) failed signature verification; "
            "check AGENT_SHARED_SECRET or the configured Ed25519 trust keys",
            file=sys.stderr,
        )
    if not pending:
        print("no pending approvals")
        return 0
    for req in pending:
        print(f"{req.id}  {req.action_class.value:<8} {req.target or '-':<28} risk={req.risk.value} by={req.requested_by}")
        if req.quorum > 1:
            print(f"  quorum: {len(req.decisions)}/{req.quorum} distinct approvers")
        if req.amount:
            print(f"  transaction: {req.amount} {req.currency}")
        if req.justification:
            print(f"  {req.justification}")
    return 0


def _credential_from_args(args: argparse.Namespace) -> ApprovalCredential | None:
    """Read the human's detached signature or id_token from a flag or file."""
    signature = getattr(args, "signature", None)
    signature_file = getattr(args, "signature_file", None)
    id_token = getattr(args, "id_token", None)
    id_token_file = getattr(args, "id_token_file", None)
    if signature or signature_file:
        value = signature
        if value is None:
            try:
                value = Path(signature_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise SecurityError(f"cannot read --signature-file: {exc}") from exc
        return ApprovalCredential(kind="detached", signature=value.strip())
    if id_token or id_token_file:
        value = id_token
        if value is None:
            try:
                value = Path(id_token_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise SecurityError(f"cannot read --id-token-file: {exc}") from exc
        return ApprovalCredential(kind="oidc", id_token=value.strip())
    return None


def _log_verification_failure(settings: Settings, signer, args: argparse.Namespace, detail: str) -> None:
    """Record a rejected credential so OEKP shows failed verification attempts."""
    chain = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)

    async def run():
        await chain.append(
            kind="approval.verification",
            actor=args.by,
            subsystem="hitl",
            data={
                "approval_id": args.approval_id,
                "verified": False,
                "detail": detail,
            },
        )

    asyncio.run(run())


def _decide(args: argparse.Namespace, approved: bool) -> int:
    settings = _settings(args)
    if settings.shadow_mode:
        print(
            "shadow mode: approvals are disabled; use 'agents shadow' to observe decisions"
        )
        return 1
    signer = _signer(settings)
    store = _approval_store(settings, signer)

    async def run():
        req = await store.decide(
            args.approval_id,
            approved=approved,
            approver=args.by,
            note=args.note,
            credential=_credential_from_args(args),
        )
        chain = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)
        if req.verification is not None:
            await chain.append(
                kind="approval.verification",
                actor=req.decided_by or args.by,
                subsystem="hitl",
                mission_id=req.mission_id,
                data=req.verification.model_dump(mode="json"),
            )
        await chain.append(
            kind="approval.decided",
            actor=req.decided_by or args.by,
            subsystem="hitl",
            mission_id=req.mission_id,
            data={
                "approval_id": req.id,
                "approved": req.status.value == "approved",
                "action_class": req.action_class.value,
                "target": req.target,
                "risk": req.risk.value,
                "requested_by": req.requested_by,
                "decided_by": req.decided_by,
                "note": req.note,
                "provenance": req.provenance,
                "tainted": req.tainted,
                "credential_kind": req.credential.kind if req.credential else None,
                "quorum": req.quorum,
                "approvals": [d.model_dump(mode="json") for d in req.decisions],
                "amount": req.amount,
                "currency": req.currency,
                "verification": (
                    req.verification.model_dump(mode="json")
                    if req.verification
                    else None
                ),
            },
        )
        publication = None
        if settings.atlassian_bridge_enabled:
            from .atlassian_bridge import build_bridge
            from .egress import EgressGuard

            EgressGuard(
                block_tainted=settings.block_tainted_egress,
                shadow=settings.shadow_mode,
            ).assert_allowed(
                target=f"atlassian:{settings.atlassian_base_url or 'adr'}",
                tainted=req.tainted,
                classification="restricted" if req.tainted else "internal",
                signoffs=[req],
                payload_digest=decision_payload_digest(req),
                also_targets=[req.target],
            )
            bridge = build_bridge(settings, signer)
            seq, digest = chain.head
            try:
                publication = bridge.publish_decision(
                    req, {"seq": seq, "hash": digest}
                )
            except SecurityError as exc:
                # The decision is already persisted and signed. Publication is
                # idempotent, so an operator can retry with `publish-decision`.
                print(
                    f"[warn] decision recorded but Atlassian publication failed: {exc}",
                    file=sys.stderr,
                )
        return req, publication

    try:
        req, publication = asyncio.run(run())
    except KeyError as exc:
        print(str(exc))
        if store.rejected:
            print(
                f"[warn] {store.rejected} approval record(s) failed signature verification; "
                "set AGENT_SHARED_SECRET to the same value the mesh uses",
                file=sys.stderr,
            )
        return 1
    except (ValueError, SecurityError) as exc:
        print(str(exc))
        with suppress(Exception):
            _log_verification_failure(settings, signer, args, str(exc))
        return 1
    print(f"{req.id} is now {req.status.value} ({req.target}); decided by {req.decided_by}")
    if req.status.value == "pending":
        remaining = max(0, req.quorum - len(req.decisions))
        print(
            f"dual-approver HITL: {len(req.decisions)}/{req.quorum} signatures; "
            f"{remaining} more distinct approver(s) required"
        )
    if req.amount:
        print(f"transaction bound to {req.amount} {req.currency}")
    if publication is not None:
        print(
            f"published ADR: {publication.page_url} "
            f"(jsm={publication.jsm_key or 'disabled'}, idempotent={publication.idempotent})"
        )
    return 0


def cmd_scale_advice(args: argparse.Namespace) -> int:
    """Report desired worker replicas per agent from live Redis backlog."""
    from .autoscale import ScalePolicy
    from .mesh import Mesh

    settings = _settings(args)
    if settings.bus != "redis":
        print("scale-advice requires AGENT_BUS=redis (the backlog lives in Redis streams)")
        return 1
    raw = getattr(args, "agents", None)
    agent_ids = [item.strip() for item in raw.split(",") if item.strip()] if raw else None

    async def run():
        mesh = Mesh(settings, agents=agent_ids, run_orchestrator=False)
        await mesh.start()
        try:
            bus = mesh.bus
            return await bus.backlog()
        finally:
            await mesh.stop()

    try:
        backlog = asyncio.run(run())
    except Exception as exc:
        print(f"cannot read backlog: {exc}")
        return 1
    policy = ScalePolicy(
        settings.scale_min_replicas,
        settings.scale_max_replicas,
        settings.scale_messages_per_replica,
    )
    targets = policy.targets(backlog, {agent: 1 for agent in backlog})
    if getattr(args, "json", False):
        print(policy.as_json(targets))
        return 0
    for target in targets:
        print(
            f"{target.agent:<10} pending={target.pending:<4} "
            f"desired={target.desired}  ({target.reason})"
        )
    return 0


def cmd_publish_decision(args: argparse.Namespace) -> int:
    """Retry or re-verify publication of an already-decided approval."""
    from .atlassian_bridge import build_bridge
    from .egress import EgressGuard
    from .governance import ApprovalStatus

    settings = _settings(args)
    signer = _signer(settings)
    store = _approval_store(settings, signer)

    async def run():
        req = await store.get(args.approval_id)
        if req is None:
            raise KeyError(f"no such approval: {args.approval_id}")
        if req.status not in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED):
            raise ValueError("only decided approvals may be published")
        egress_target = f"atlassian:{settings.atlassian_base_url or 'adr'}"
        signoffs = [req]
        for signoff_id in getattr(args, "signoff", []) or []:
            extra = await store.get(signoff_id)
            if extra is None:
                raise KeyError(f"no such egress sign-off approval: {signoff_id}")
            signoffs.append(extra)
        EgressGuard(
            block_tainted=settings.block_tainted_egress,
            shadow=settings.shadow_mode,
        ).assert_allowed(
            target=egress_target,
            tainted=req.tainted,
            classification="restricted" if req.tainted else "internal",
            signoffs=signoffs,
            payload_digest=decision_payload_digest(req),
            also_targets=[req.target],
        )
        chain = EvidenceChain(
            settings.workspace / "evidence" / "chain.jsonl", signer=signer
        )
        seq, digest = chain.head
        bridge = build_bridge(settings, signer)
        if bridge is None:
            raise ValueError(
                "Atlassian bridge is disabled; set AGENT_ATLASSIAN_BRIDGE_ENABLED=true"
            )
        return bridge.publish_decision(req, {"seq": seq, "hash": digest})

    try:
        result = asyncio.run(run())
    except (KeyError, ValueError, SecurityError) as exc:
        print(str(exc))
        return 1
    print(
        f"published {args.approval_id}: page={result.page_id} "
        f"jsm={result.jsm_key or 'disabled'} idempotent={result.idempotent}"
    )
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    from .mesh import Mesh

    async def run() -> int:
        async with Mesh(_settings(args)) as mesh:
            assert mesh.shell is not None
            print(json.dumps(await mesh.shell.health(), indent=2, default=str))
            issues = await mesh.shell.diagnostics()
            print("\ndiagnostics: " + ("; ".join(issues) if issues else "none"))
        # Automation uses this documented command as a health check.
        return 1 if issues else 0

    return asyncio.run(run())


def cmd_doctor(args: argparse.Namespace) -> int:
    settings = _settings(args)
    failures = 0

    def check(ok: bool, label: str, detail: str = "") -> None:
        nonlocal failures
        print(f"[{'ok' if ok else 'FAIL'}] {label}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures += 1

    check(sys.version_info >= (3, 11), "python >= 3.11", sys.version.split()[0])
    try:
        import pydantic

        check(True, "pydantic", pydantic.VERSION)
    except Exception as exc:
        check(False, "pydantic", repr(exc))

    try:
        registry = _registry(settings)
        check(
            len(registry) == 9,
            "registry",
            f"{len(registry)} subsystems / {registry.roles_total} roles in {settings.subsystems_file}",
        )
    except (RegistryError, Exception) as exc:
        check(False, "registry", str(exc))

    try:
        settings.workspace.mkdir(parents=True, exist_ok=True)
        probe = settings.workspace / ".doctor-probe"
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
        check(True, "workspace writable", str(settings.workspace.resolve()))
    except Exception as exc:
        check(False, "workspace writable", repr(exc))

    try:
        authority = build_message_authority(settings)
        detail = (
            "per-coordinator Ed25519"
            if isinstance(authority, CoordinatorKeyring)
            else ("enabled" if authority else "DISABLED")
        )
        check(authority is not None, "message authentication", detail)
    except SecurityError as exc:
        check(False, "message authentication", str(exc))

    ephemeral = is_ephemeral_secret(settings)
    if settings.strict_prod:
        problems = validate_strict_prod(settings)
        if problems:
            for problem in problems:
                check(False, "strict production", problem)
        else:
            check(
                True,
                "strict production",
                "managed keys, signed approvers and per-coordinator signatures",
            )
        try:
            rules = topic_rules_from_authority(authority, require_kid=True)
            check(
                all(rule.kids for rule in rules.values()),
                "restricted topic keys",
                "policy.verdict and approval.granted are pinned to coordinator kids",
            )
        except (BusConfigurationError, UnboundLocalError) as exc:
            check(False, "restricted topic keys", str(exc))
    elif (
        ephemeral
        and (settings.workspace / "approvals.json").is_file()
    ):
        print(
            "[warn] memory bus uses an ephemeral signing key; set AGENT_SHARED_SECRET "
            "or configure managed per-coordinator Ed25519 keys so approvals written "
            "by another process verify"
        )

    try:
        approver_registry = load_approver_registry(settings)
        build_approval_verifier(settings, approver_registry)
    except SecurityError as exc:
        check(False, "approver registry", str(exc))
        approver_registry = None
    else:
        if approver_registry is not None:
            check(
                True,
                "approver registry",
                f"{len(approver_registry.ids())} signed approvers in {approver_registry.source}",
            )
            unknown = configured_approvers(settings) - approver_registry.ids()
            if unknown:
                check(
                    False,
                    "approver allowlist",
                    f"not in signed registry: {', '.join(sorted(unknown))}",
                )
        elif settings.require_approver_allowlist or settings.strict_prod:
            check(False, "approver registry", "no approver registry configured")
        elif settings.approvers:
            check(True, "approver allowlist", f"{len(configured_approvers(settings))} configured")
        else:
            print("[warn] AGENT_APPROVERS is empty; any name can approve in this configuration")

    if settings.bus == "redis":
        try:
            import redis.asyncio as aioredis

            async def ping() -> bool:
                client = aioredis.from_url(
                    settings.redis_url,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                try:
                    return bool(await client.ping())
                finally:
                    await client.aclose()

            from urllib.parse import urlparse

            safe_url = redact_url(settings.redis_url)
            check(asyncio.run(ping()), "redis reachable", safe_url)
            has_password = bool(urlparse(settings.redis_url).password)
            check(has_password, "redis credentials", "password configured" if has_password else "no password in URL")
        except Exception as exc:
            check(False, "redis reachable", f"{redact_url(settings.redis_url)} ({exc})")
    else:
        check(True, "bus", "memory (single process)")

    if settings.llm_base_url:
        check(bool(settings.llm_api_key), "model endpoint", f"{redact_url(settings.llm_base_url)} model={settings.model}")
    else:
        check(True, "model", "offline echo model (set AGENT_LLM_BASE_URL for real work)")

    print("\nready" if failures == 0 else f"\n{failures} check(s) failed")
    return 0 if failures == 0 else 1


async def _run_demo(args: argparse.Namespace) -> int:
    from .mesh import Mesh

    settings = _settings(args)
    ticket = _seed_workspace(settings)
    goal = args.goal or DEFAULT_GOAL
    async with Mesh(settings) as mesh:
        assert mesh.registry is not None
        if mesh.evidence is not None:
            chain_ok, detail = mesh.evidence.verify()
            if not chain_ok:
                print(f"evidence chain in this workspace is not verifiable: {detail}")
                print("use a fresh --workspace or set AGENT_SHARED_SECRET to the key that signed it")
                return 1
        print(
            f"agents: {len(mesh.agents)}  roles: {mesh.registry.roles_total}  "
            f"model: {getattr(mesh.llm, 'model', '?')}  bus: {type(mesh.bus).__name__}"
        )
        print(f"input: {ticket.relative_to(Path.cwd()) if ticket.is_relative_to(Path.cwd()) else ticket}\n")
        result = await mesh.run(goal)
        print(f"\nplan ({len(result.steps)} steps, {result.elapsed_ms} ms, {result.tokens_used} tokens)")
        for step in result.steps:
            status = "ok" if step["ok"] else "FAILED"
            refs = ""
            if step.get("policy_decision_ref"):
                refs += f"  {step['policy_decision_ref']}"
            if step.get("authorization_ref"):
                refs += f"  {step['authorization_ref']}"
            if step.get("evidence_ref"):
                refs += f"  ev={step['evidence_ref'][:12]}"
            print(f"  {step['id']:<3} {step['agent']:<11} {status:<6} {step['output'][:90].replace(chr(10), ' ')}{refs}")
        print(f"\nanswer\n{result.answer}\n")
        _print_flow(mesh.trace())
        print(f"\nmetrics: {mesh.metrics.snapshot()['counters']}")
        return 0 if result.ok else 1


async def _run_shadow(args: argparse.Namespace) -> int:
    """Run the mesh against real inputs but never execute or write externally."""
    args.shadow = True
    print(
        "SHADOW MODE: policy/HITL/evidence only; execution, mutating tools and "
        "external writes are disabled\n"
    )
    rc = await _run_demo(args)
    if rc == 0:
        print("\nshadow run complete: no action executed, no external write performed")
    return rc


def _print_flow(history: list, limit: int = 80) -> None:
    print("message flow")
    shown = [m for m in history if m.kind in ("task", "result", "event", "handoff", "error")][-limit:]
    start = shown[0].created_at.timestamp() if shown else time.time()
    for msg in shown:
        offset = msg.created_at.timestamp() - start
        target = msg.recipient or f"<{msg.topic}>"
        print(f"  +{offset:5.2f}s  {msg.sender:<12} -> {target:<12} {msg.kind:<7} {msg.summary(70)}")


async def _reclaim_loop(mesh, settings: Settings) -> None:
    from .bus import RedisBus
    from .observability import log

    while True:
        await asyncio.sleep(max(1.0, settings.reclaim_interval_s))
        bus = mesh.bus
        if not isinstance(bus, RedisBus):
            continue
        for agent_id in mesh.agents:
            try:
                await bus.reclaim_stale(agent_id)
            except Exception as exc:
                log("serve.reclaim_failed", agent=agent_id, error=repr(exc))


async def _run_serve(args: argparse.Namespace) -> int:
    from .mesh import Mesh
    from .service import HealthServer

    settings = _settings(args)
    if getattr(args, "host", None):
        settings = settings.model_copy(update={"health_host": args.host})
    if getattr(args, "port", None) is not None:
        settings = settings.model_copy(update={"health_port": args.port})
    agent_ids = None
    raw_agents = getattr(args, "agents", None)
    if raw_agents:
        agent_ids = [item.strip() for item in raw_agents.split(",") if item.strip()]
    no_orchestrator = bool(getattr(args, "no_orchestrator", False))
    if getattr(args, "worker", False):
        no_orchestrator = not bool(getattr(args, "with_orchestrator", False))
    token = read_secret(settings.health_token, settings.health_token_file)
    admin_token = read_secret(settings.admin_token, settings.admin_token_file)
    if token and admin_token and token == admin_token:
        raise SecurityError(
            "AGENT_ADMIN_TOKEN must differ from AGENT_HEALTH_TOKEN; "
            "the probe credential must not open the diagnostics surface"
        )

    mesh = Mesh(settings, agents=agent_ids, run_orchestrator=not no_orchestrator)
    await mesh.start()
    assert mesh.shell is not None
    server: HealthServer | None = None
    reclaim: asyncio.Task | None = None
    try:

        async def provider(path: str) -> tuple[int, dict]:
            if path == "/health":
                return 200, await mesh.shell.health(detailed=False)
            if path == "/ready":
                ok, info = await mesh.shell.ready(detailed=False)
                return (200 if ok else 503), info
            # /diagnostics has already passed admin authentication in HealthServer.
            return 200, redact_fields(
                {
                    "ready": (await mesh.shell.ready(detailed=True))[0],
                    "health": await mesh.shell.health(detailed=True),
                    "issues": await mesh.shell.diagnostics(),
                    "discovery": mesh.shell.discovery(),
                }
            )

        server = HealthServer(
            settings.health_host,
            settings.health_port,
            provider,
            token=token,
            admin_token=admin_token,
        )
        await server.start()
        print(
            f"mesh running: {len(mesh.agents)} agents"
            + (f" ({','.join(sorted(mesh.agents))})" if agent_ids else "")
            + f", orchestrator={'on' if mesh.orchestrator is not None else 'off'}, "
            f"bus={type(mesh.bus).__name__}, "
            f"auth={'on' if mesh.signer is not None else 'OFF'}, "
            f"health=http://{settings.health_host}:{server.port}/health, "
            f"diagnostics={'on' if admin_token else 'disabled'}"
        )
        if settings.bus == "memory":
            print("memory bus is process-local; use AGENT_BUS=redis to accept work from other processes.")

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError, ValueError):
                with suppress(ValueError, OSError):
                    signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))

        reclaim = asyncio.create_task(_reclaim_loop(mesh, settings), name="serve:reclaim")
        await stop.wait()
    finally:
        if reclaim is not None:
            reclaim.cancel()
            with suppress(asyncio.CancelledError):
                await reclaim
        if server is not None:
            await server.stop()
        await mesh.stop()
    return 0


def _fragmentation_service(mesh, settings: Settings, fixtures: str | None):
    """Return (service, owned). Fixture fallback keeps the demo runnable offline."""
    from .connectors import build_fixture_connectors
    from .fragmentation import FragmentationService

    if mesh.fragmentation is not None:
        return mesh.fragmentation, False
    directory = Path(fixtures) if fixtures else DEFAULT_FIXTURES
    if directory.is_dir():
        connectors = build_fixture_connectors(settings, directory)
        return FragmentationService(connectors, mesh.policy, mesh.evidence, settings), True
    return None, False


async def _run_ingest(args: argparse.Namespace) -> int:
    from .mesh import Mesh
    from .storyboards import get_storyboard

    settings = _settings(args)
    vertical = getattr(args, "vertical", None)
    if vertical:
        board = get_storyboard(vertical)
        settings = settings_for_profile(
            settings.model_copy(update={"role_profile": board.profile_id})
        )
        if not getattr(args, "fixtures", None):
            args.fixtures = str(board.fixtures_dir)
    async with Mesh(settings) as mesh:
        service, owned = _fragmentation_service(mesh, settings, args.fixtures)
        if service is None:
            print(
                f"no connectors configured: set AGENT_CONNECTORS_FILE or create {DEFAULT_FIXTURES}",
                file=sys.stderr,
            )
            return 1
        try:
            result = await service.ingest()
        finally:
            if owned:
                await service.close()
        payload = {
            "signals": len(result.signals),
            "by_source": result.counts_by_source,
            "by_source_type": result.counts_by_source_type,
            "errors": result.errors,
            "truncated": result.truncated_sources,
            "samples": [
                {
                    "id": s.id,
                    "source": s.source,
                    "source_type": s.source_type.value,
                    "entity": s.entity,
                    "severity": s.severity.value,
                    "category": s.category,
                    "title": s.title,
                    "observed_at": s.observed_at.isoformat(),
                }
                for s in result.signals[: args.limit]
            ],
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0


async def _run_fragmentation_demo(args: argparse.Namespace) -> int:
    from .mesh import Mesh
    from .storyboards import get_storyboard

    settings = _settings(args)
    board = None
    vertical = getattr(args, "vertical", None)
    if vertical:
        board = get_storyboard(vertical)
        settings = settings_for_profile(
            settings.model_copy(update={"role_profile": board.profile_id})
        )
        if not getattr(args, "fixtures", None):
            args.fixtures = str(board.fixtures_dir)
        # Restricted/PHI data may only be handled inside an explicit mission.
        if board.profile_id == "clinical_healthcare" and not getattr(args, "mission", None):
            args.mission = f"demo-{board.id}"
    async with Mesh(settings) as mesh:
        service, owned = _fragmentation_service(mesh, settings, args.fixtures)
        if service is None:
            print(
                f"no connectors configured: set AGENT_CONNECTORS_FILE or create {DEFAULT_FIXTURES}",
                file=sys.stderr,
            )
            return 1
        try:
            report = await service.run(
                mission_id=args.mission,
                approval_ref=args.approval,
                propose=not args.no_propose,
            )
        finally:
            if owned:
                await service.close()

        if board is not None:
            print(f"storyboard: {board.name} - {board.money_shot}")
            print(f"role profile: {settings.role_profile} (all nine coordinators still running)")
        ingest = report.ingest
        print(
            f"ingested {len(ingest.signals)} signals from "
            f"{len(ingest.batches)} connectors: {ingest.counts_by_source}"
        )
        if ingest.errors:
            print(f"connector errors: {len(ingest.errors)} (first: {ingest.errors[0]})")
        print(
            f"correlated {report.correlation.signals_considered} signals into "
            f"{len(report.correlation.incidents)} incident(s) "
            f"(window {report.correlation.window_s}s)"
        )
        for incident in report.correlation.incidents[: args.limit]:
            print(
                f"\n{incident.id}  {incident.entity}  risk={incident.risk.value} "
                f"score={incident.score}/100  sources={len(incident.source_types)}"
            )
            print(f"  {incident.summary}")
            for reason in incident.reasons:
                print(f"  - {reason}")
        if report.action is not None:
            print(
                f"\nproposed action: {report.action.action_class.value} "
                f"{report.action.target} (risk={report.action.risk.value})"
            )
        if report.decision is not None:
            print(
                f"policy decision: {report.decision.decision.value} "
                f"({report.decision.policy_ref})"
            )
            for reason in report.decision.reasons:
                print(f"  - {reason}")
        for note in report.notes:
            print(f"\n{note}")
        if report.approval_ref and (
            report.decision is None or report.decision.decision.value == "HOLD"
        ):
            extra = ""
            if args.fixtures:
                extra += f" --fixtures {args.fixtures}"
            if args.connectors:
                extra += f" --connectors {args.connectors}"
            if args.mission:
                extra += f" --mission {args.mission}"
            print(
                "\nre-dispatch after approval:\n"
                f"  python -m agents demo-fragmentation --approval {report.approval_ref}{extra}"
            )
        if report.evidence_refs:
            print(f"\nevidence: {len(report.evidence_refs)} record(s), latest={report.evidence_refs[-1]}")
        if report.decision is not None and report.decision.decision.value == "DENY":
            return 1
        return 0


def cmd_probe(args: argparse.Namespace) -> int:
    import urllib.error
    import urllib.request

    settings = _settings(args)
    url = args.url or f"http://{settings.health_host}:{settings.health_port}/health"
    token = args.token or read_secret(settings.health_token, settings.health_token_file)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read(4096).decode("utf-8", "replace")
            print(f"{response.status} {body}")
            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.HTTPError as exc:
        detail = exc.read(512).decode("utf-8", "replace")
        print(f"{exc.code} {detail}")
        return 1
    except Exception as exc:
        print(f"unhealthy: {exc}")
        return 1


def cmd_integrity(args: argparse.Namespace) -> int:
    settings = _settings(args)
    if getattr(args, "check", False):
        digest = verify_subsystems_file(settings.subsystems_file, settings)
        print(f"ok: {settings.subsystems_file} sha256={digest}")
        return 0
    digest, signature = subsystems_integrity(settings.subsystems_file, settings)
    print(f"file: {settings.subsystems_file}")
    print(f"AGENT_SUBSYSTEMS_MANIFEST_HASH={digest}")
    if signature:
        print(f"AGENT_SUBSYSTEMS_SIGNATURE={signature}")
    else:
        print("AGENT_SUBSYSTEMS_SIGNATURE=unavailable (set AGENT_SHARED_SECRET to sign)")

    if settings.signing_mode == "ed25519" or settings.ed25519_private_key_file:
        from .asymmetric import fingerprint, load_private_key, sign_file

        if settings.ed25519_private_key or settings.ed25519_private_key_file:
            private = load_private_key(
                settings.ed25519_private_key, settings.ed25519_private_key_file
            )
            ed25519 = sign_file(private, settings.subsystems_file)
            print(f"AGENT_SUBSYSTEMS_SIGNATURE_ED25519={ed25519}")
            print(
                f"ed25519_key_id={settings.ed25519_key_id} "
                f"fingerprint={fingerprint(private.public_key())}"
            )
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    import json

    from .asymmetric import fingerprint, generate_keypair, private_key_pem, public_key_hex
    from .security import secure_dir, secure_file

    private_key, public_key = generate_keypair()
    private_path = Path(args.private_key_file)
    public_path = Path(args.public_key_file)
    secure_dir(private_path.parent)
    secure_dir(public_path.parent)
    private_path.write_text(private_key_pem(private_key), encoding="utf-8")
    public_path.write_text(public_key_hex(public_key) + "\n", encoding="utf-8")
    secure_file(private_path)
    secure_file(public_path)
    print(f"private key: {private_path}  (offline only; never mount on a runtime node)")
    print(f"public key:  {public_path}")

    keyset_file = getattr(args, "keyset_file", None)
    if keyset_file:
        path = Path(keyset_file)
        secure_dir(path.parent)
        path.write_text(
            json.dumps({args.key_id: public_key_hex(public_key)}, indent=2) + "\n",
            encoding="utf-8",
        )
        secure_file(path)
        print(f"keyset:      {path} (kid={args.key_id})")
    print(f"fingerprint: {fingerprint(public_key)}")
    return 0


def cmd_sign_config(args: argparse.Namespace) -> int:
    from .asymmetric import load_private_key, sign_file

    settings = _settings(args)
    private = load_private_key(None, args.key_file)
    out = args.out or f"{settings.subsystems_file}.sig"
    signature = sign_file(private, settings.subsystems_file, out)
    print(f"{out}: {signature}")
    return 0


def _add_credential_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signature", help="detached Ed25519 approval signature (hex)")
    parser.add_argument("--signature-file", help="file containing the detached signature")
    parser.add_argument("--id-token", help="OIDC/SSO id_token (compact JWT)")
    parser.add_argument("--id-token-file", help="file containing the id_token")


def cmd_approval_payload(args: argparse.Namespace) -> int:
    """Print the exact bytes a human must sign for a detached approval.

    With ``--oidc-binding``, print the digest an id_token must carry in its
    binding claim (``nonce`` by default) to approve this exact decision.
    """
    settings = _settings(args)
    store = _approval_store(settings, _signer(settings))
    req = asyncio.run(store.get(args.approval_id))
    if req is None:
        print(f"no such approval: {args.approval_id}")
        return 1
    if getattr(args, "oidc_binding", False):
        print(
            oidc_approval_binding(
                req, approved=args.approve, approver=args.by
            )
        )
        return 0
    payload = approval_credential_payload(
        req, approved=args.approve, approver=args.by
    )
    print(payload.decode("utf-8"))
    return 0


def cmd_sign_approvers(args: argparse.Namespace) -> int:
    """Detach-sign an approver registry file with an offline Ed25519 key."""
    from .asymmetric import load_private_key, sign_file

    private = load_private_key(None, args.key_file)
    out = args.out or f"{args.registry_file}.sig"
    signature = sign_file(private, args.registry_file, out)
    print(f"{out}: {signature}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agents", description="USOC nine-subsystem agent mesh")
    parser.add_argument("--registry", help="path to subsystems.yaml")
    parser.add_argument("--workspace", help="workspace directory for tools")
    parser.add_argument("--json-logs", action="store_true", help="structured logs on stderr")
    parser.add_argument(
        "--profile",
        help="industry role-profile view (overrides AGENT_ROLE_PROFILE)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run one goal end to end")
    demo.add_argument("goal", nargs="?", help="goal text (defaults to the USOC edge-telemetry example)")

    shadow = sub.add_parser(
        "shadow", help="run one goal in shadow mode (observe only; never execute or write)"
    )
    shadow.add_argument("goal", nargs="?", help="goal text (defaults to the USOC edge-telemetry example)")
    shadow.set_defaults(shadow=True)

    sub.add_parser("list", help="print the nine capability cards and their roles")
    sub.add_parser("profiles", help="list Industry Starter Profiles and active role counts")
    sub.add_parser("doctor", help="check config, registry, bus, model and security")
    export = sub.add_parser("export", help="export verified evidence in compliance formats")
    export.add_argument(
        "--format",
        choices=["jsonl", "oekp", "bengal", "oekp_bengal"],
        help="format to render (default: AGENT_EVIDENCE_EXPORT_FORMATS)",
    )
    export.add_argument("--output", help="directory for exported evidence files")
    storyboard = sub.add_parser("storyboard", help="print a 3-minute vertical demo storyboard")
    storyboard.add_argument(
        "--vertical",
        choices=["cyber", "finance", "healthcare", "all"],
        default="all",
        help="audience vertical (default: all)",
    )
    rehearsal = sub.add_parser(
        "llm-rehearsal",
        help="run labeled prompts through the model and deterministic policy; observe only",
    )
    rehearsal.add_argument(
        "--cases",
        default=str(Path("fixtures") / "llm_rehearsal" / "cases.jsonl"),
        help="JSONL file of labeled rehearsal cases",
    )
    rehearsal.add_argument("--output", help="directory for an oekp_bengal evidence export")
    rehearsal.add_argument(
        "--live",
        action="store_true",
        help="allow AGENT_LLM_BASE_URL model egress (default: offline EchoLLM, no network)",
    )
    benchmark = sub.add_parser(
        "benchmark",
        help="adaptive governance-readiness benchmark (observation only, signed evidence)",
    )
    benchmark.add_argument(
        "--cases",
        default=str(Path("fixtures") / "benchmark" / "cases.jsonl"),
        help="JSONL file of labeled benchmark scenarios",
    )
    benchmark.add_argument("--output", help="directory for an oekp_bengal evidence export")
    benchmark.add_argument(
        "--full", action="store_true", help="evaluate all cases every round (no adaptive focus)"
    )
    benchmark.add_argument(
        "--rounds", type=int, default=3, help="maximum adaptive rounds (default: 3)"
    )
    benchmark.add_argument(
        "--min-score", type=float, default=95.0, help="minimum score for exit 0 (default: 95)"
    )
    integrity = sub.add_parser(
        "integrity", help="print or verify the capability-card manifest hash/signature"
    )
    integrity.add_argument("--check", action="store_true", help="verify pinned values instead of printing")
    keygen = sub.add_parser(
        "keygen", help="generate an Ed25519 keypair (private key for CI/KMS custody)"
    )
    keygen.add_argument(
        "--private-key-file", default="secrets/ed25519_private.pem", help="offline private key path"
    )
    keygen.add_argument(
        "--public-key-file", default="trust/ed25519_public.hex", help="runtime public key path"
    )
    keygen.add_argument(
        "--key-id", default="default", help="kid used in the trust bundle and for signing"
    )
    keygen.add_argument(
        "--keyset-file", help="also write a JSON {kid: public_key} trust bundle for runtime"
    )
    sign_config = sub.add_parser(
        "sign-config", help="sign subsystems.yaml with an offline Ed25519 private key"
    )
    sign_config.add_argument("--key-file", required=True, help="Ed25519 private key (PEM/hex)")
    sign_config.add_argument("--out", help="detached signature path (default: <registry>.sig)")
    sign_approvers = sub.add_parser(
        "sign-approvers", help="detach-sign the approver registry with an offline Ed25519 key"
    )
    sign_approvers.add_argument("--registry-file", required=True, help="approver registry JSON")
    sign_approvers.add_argument("--key-file", required=True, help="offline Ed25519 private key")
    sign_approvers.add_argument("--out", help="signature path (default: <registry>.sig)")
    approval_payload = sub.add_parser(
        "approval-payload", help="print the canonical payload a human signs for an approval"
    )
    approval_payload.add_argument("approval_id")
    approval_payload.add_argument("--by", required=True, help="approver identity")
    decision = approval_payload.add_mutually_exclusive_group(required=True)
    decision.add_argument("--approve", action="store_true", help="payload for an approval")
    decision.add_argument("--deny", action="store_true", help="payload for a denial")
    approval_payload.add_argument(
        "--oidc-binding",
        action="store_true",
        help="print the id_token binding digest instead of the detached-signature payload",
    )
    serve = sub.add_parser("serve", help="start the mesh, health endpoint and recovery loop")
    serve.add_argument("--host", help="health bind address (default AGENT_HEALTH_HOST)")
    serve.add_argument("--port", type=int, help="health port (default AGENT_HEALTH_PORT)")
    serve.add_argument("--agents", help="comma-separated subsystem ids to run (default: all nine)")
    serve.add_argument(
        "--no-orchestrator", action="store_true",
        help="run subsystem agents only; the control plane keeps the orchestrator",
    )
    worker = sub.add_parser(
        "worker", help="run selected subsystems as a stateless worker (no orchestrator)"
    )
    worker.add_argument("--agents", help="comma-separated subsystem ids (e.g. 'oekp,bengal')")
    worker.add_argument("--with-orchestrator", action="store_true", help="also run the orchestrator (not recommended on workers)")
    worker.add_argument("--host", help="health bind address (default AGENT_HEALTH_HOST)")
    worker.add_argument("--port", type=int, help="health port (default AGENT_HEALTH_PORT)")
    scale = sub.add_parser(
        "scale-advice", help="read live Redis backlog and print desired worker replicas per agent"
    )
    scale.add_argument("--agents", help="comma-separated subsystem ids (default: all nine)")
    scale.add_argument("--json", action="store_true", help="emit the recommendation as JSON")
    probe = sub.add_parser("probe", help="check a running mesh health endpoint")
    probe.add_argument("--url", help="health URL (default from settings)")
    probe.add_argument("--token", help="bearer token (default AGENT_HEALTH_TOKEN)")
    sub.add_parser("health", help="SHELL runtime health and integration diagnostics")
    sub.add_parser("approvals", help="list pending human approvals")

    approve = sub.add_parser("approve", help="approve a pending action as a human")
    approve.add_argument("approval_id")
    approve.add_argument("--by", default="operator", help="approver identity")
    approve.add_argument("--note")
    _add_credential_args(approve)

    deny = sub.add_parser("deny", help="deny a pending action as a human")
    deny.add_argument("approval_id")
    deny.add_argument("--by", default="operator")
    deny.add_argument("--note")
    _add_credential_args(deny)

    publish = sub.add_parser(
        "publish-decision", help="publish/retry a decided approval to Atlassian"
    )
    publish.add_argument("approval_id")
    publish.add_argument(
        "--signoff",
        action="append",
        default=[],
        metavar="APPROVAL_ID",
        help="approved, signed approval whose target covers this external egress",
    )

    ingest = sub.add_parser("ingest", help="poll read-only connectors and print normalized signals")
    ingest.add_argument("--fixtures", help="directory of <source_type>.jsonl fixtures")
    ingest.add_argument("--connectors", help="path to connectors.yaml")
    ingest.add_argument(
        "--vertical",
        choices=["cyber", "finance", "healthcare"],
        help="demo storyboard vertical (swaps connector/target nouns and fixtures)",
    )
    ingest.add_argument("--limit", type=int, default=10, help="sample signals to print")

    frag = sub.add_parser(
        "demo-fragmentation",
        help="ingest, correlate across incumbent tools and request governed containment",
    )
    frag.add_argument("--fixtures", help="directory of <source_type>.jsonl fixtures")
    frag.add_argument("--connectors", help="path to connectors.yaml")
    frag.add_argument("--mission", help="mission id to scope the approval and evidence")
    frag.add_argument("--approval", help="approval ref from a previous HOLD to re-dispatch")
    frag.add_argument("--no-propose", action="store_true", help="correlate without requesting action")
    frag.add_argument("--limit", type=int, default=5, help="incidents to print")
    frag.add_argument(
        "--vertical",
        choices=["cyber", "finance", "healthcare"],
        help="demo storyboard vertical (swaps connector/target nouns and fixtures)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "profiles":
        return cmd_profiles(args)
    if args.command == "export":
        return cmd_export(args)
    if args.command == "storyboard":
        return cmd_storyboard(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "integrity":
        return cmd_integrity(args)
    if args.command == "keygen":
        return cmd_keygen(args)
    if args.command == "sign-config":
        return cmd_sign_config(args)
    if args.command == "sign-approvers":
        return cmd_sign_approvers(args)
    if args.command == "approval-payload":
        return cmd_approval_payload(
            argparse.Namespace(**{**vars(args), "approve": not args.deny})
        )
    if args.command == "approvals":
        return cmd_approvals(args)
    if args.command == "probe":
        return cmd_probe(args)
    if args.command == "approve":
        return _decide(args, True)
    if args.command == "deny":
        return _decide(args, False)
    if args.command == "publish-decision":
        return cmd_publish_decision(args)
    if args.command == "scale-advice":
        return cmd_scale_advice(args)
    try:
        if args.command == "demo":
            return asyncio.run(_run_demo(args))
        if args.command == "shadow":
            return asyncio.run(_run_shadow(args))
        if args.command == "serve":
            return asyncio.run(_run_serve(args))
        if args.command == "worker":
            args.worker = True
            return asyncio.run(_run_serve(args))
        if args.command == "health":
            return cmd_health(args)
        if args.command == "ingest":
            return asyncio.run(_run_ingest(args))
        if args.command == "demo-fragmentation":
            return asyncio.run(_run_fragmentation_demo(args))
        if args.command == "llm-rehearsal":
            return asyncio.run(_run_llm_rehearsal(args))
        if args.command == "benchmark":
            return asyncio.run(_run_benchmark(args))
    except KeyboardInterrupt:
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
