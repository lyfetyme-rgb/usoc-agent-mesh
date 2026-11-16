"""CLI: python -m agents {demo,list,doctor,serve,probe,health,approvals,approve,deny,ingest,demo-fragmentation}

    python -m agents demo "Collect edge telemetry, analyse anomalies, record evidence"
    python -m agents list
    python -m agents doctor
    python -m agents serve --host 127.0.0.1 --port 8080
    python -m agents probe --url http://127.0.0.1:8080/ready
    python -m agents health
    python -m agents approvals
    python -m agents approve apr-1234 --by alice
    python -m agents ingest --fixtures fixtures/fragmentation
    python -m agents demo-fragmentation --fixtures fixtures/fragmentation
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

from .config import Settings, get_settings
from .evidence import EvidenceChain
from .governance import FileApprovalStore
from .registry import RegistryError, load_registry
from .security import SecurityError, build_signer, configured_approvers, read_secret, redact_url
from .tools import build_default_tools

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
    return base.model_copy(update=overrides) if overrides else base


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
    return load_registry(settings.subsystems_file, tools)


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
        print(f"{spec.id:<{width}}  {spec.name}  [{spec.model_tier}]  {len(spec.roles)} roles")
        print(f"{'':<{width}}  {spec.description}")
        print(f"{'':<{width}}  roles: {spec.role_titles()}")
        print(f"{'':<{width}}  tools: {tools}   listens: {subs}\n")
    return 0


def _approval_store(settings: Settings, signer=None) -> FileApprovalStore:
    return FileApprovalStore(
        settings.workspace / "approvals.json",
        signer=signer,
        approvers=configured_approvers(settings),
        require_allowlist=settings.require_approver_allowlist,
        ttl_s=settings.approval_ttl_s,
    )


def cmd_approvals(args: argparse.Namespace) -> int:
    settings = _settings(args)
    signer = _signer(settings)
    store = _approval_store(settings, signer)
    pending = asyncio.run(store.pending())
    if store.rejected:
        print(
            f"[warn] {store.rejected} approval record(s) failed signature verification; "
            "set AGENT_SHARED_SECRET to the same value the mesh uses",
            file=sys.stderr,
        )
    if not pending:
        print("no pending approvals")
        return 0
    for req in pending:
        print(f"{req.id}  {req.action_class.value:<8} {req.target or '-':<28} risk={req.risk.value} by={req.requested_by}")
        if req.justification:
            print(f"  {req.justification}")
    return 0


def _decide(args: argparse.Namespace, approved: bool) -> int:
    settings = _settings(args)
    signer = _signer(settings)
    store = _approval_store(settings, signer)

    async def run():
        req = await store.decide(
            args.approval_id, approved=approved, approver=args.by, note=args.note
        )
        chain = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)
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
            },
        )
        return req

    try:
        req = asyncio.run(run())
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
        return 1
    print(f"{req.id} is now {req.status.value} ({req.target}); decided by {req.decided_by}")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    from .mesh import Mesh

    async def run() -> int:
        async with Mesh(_settings(args)) as mesh:
            assert mesh.shell is not None
            print(json.dumps(await mesh.shell.health(), indent=2, default=str))
            issues = await mesh.shell.diagnostics()
            print("\ndiagnostics: " + ("; ".join(issues) if issues else "none"))
        return 0

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
        signer = build_signer(settings)
        check(signer is not None, "message authentication", "enabled" if signer else "DISABLED")
    except SecurityError as exc:
        check(False, "message authentication", str(exc))

    if (
        settings.bus == "memory"
        and not settings.shared_secret
        and not settings.shared_secret_file
        and (settings.workspace / "approvals.json").is_file()
    ):
        print(
            "[warn] memory bus uses an ephemeral secret; set AGENT_SHARED_SECRET "
            "so approvals written by another process verify"
        )

    if settings.require_approver_allowlist and not settings.approvers:
        check(False, "approver allowlist", "AGENT_APPROVERS is required but empty")
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
    token = read_secret(settings.health_token, settings.health_token_file)

    mesh = Mesh(settings)
    await mesh.start()
    assert mesh.shell is not None
    server: HealthServer | None = None
    reclaim: asyncio.Task | None = None
    try:

        async def provider(path: str) -> tuple[int, dict]:
            if path == "/health":
                return 200, {
                    "status": "ok",
                    "agents": len(mesh.agents),
                    "bus": type(mesh.bus).__name__,
                    "message_auth": mesh.signer is not None,
                    "fragmentation": mesh.fragmentation is not None,
                    "fragmentation_error": mesh.fragmentation_error,
                }
            ok, info = await mesh.shell.ready()
            return (200 if ok else 503), info

        server = HealthServer(
            settings.health_host, settings.health_port, provider, token=token
        )
        await server.start()
        print(
            f"mesh running: {len(mesh.agents)} agents, bus={type(mesh.bus).__name__}, "
            f"auth={'on' if mesh.signer is not None else 'OFF'}, "
            f"health=http://{settings.health_host}:{server.port}/health"
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

    settings = _settings(args)
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

    settings = _settings(args)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agents", description="USOC nine-subsystem agent mesh")
    parser.add_argument("--registry", help="path to subsystems.yaml")
    parser.add_argument("--workspace", help="workspace directory for tools")
    parser.add_argument("--json-logs", action="store_true", help="structured logs on stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run one goal end to end")
    demo.add_argument("goal", nargs="?", help="goal text (defaults to the USOC edge-telemetry example)")

    sub.add_parser("list", help="print the nine capability cards and their roles")
    sub.add_parser("doctor", help="check config, registry, bus, model and security")
    serve = sub.add_parser("serve", help="start the mesh, health endpoint and recovery loop")
    serve.add_argument("--host", help="health bind address (default AGENT_HEALTH_HOST)")
    serve.add_argument("--port", type=int, help="health port (default AGENT_HEALTH_PORT)")
    probe = sub.add_parser("probe", help="check a running mesh health endpoint")
    probe.add_argument("--url", help="health URL (default from settings)")
    probe.add_argument("--token", help="bearer token (default AGENT_HEALTH_TOKEN)")
    sub.add_parser("health", help="SHELL runtime health and integration diagnostics")
    sub.add_parser("approvals", help="list pending human approvals")

    approve = sub.add_parser("approve", help="approve a pending action as a human")
    approve.add_argument("approval_id")
    approve.add_argument("--by", default="operator", help="approver identity")
    approve.add_argument("--note")

    deny = sub.add_parser("deny", help="deny a pending action as a human")
    deny.add_argument("approval_id")
    deny.add_argument("--by", default="operator")
    deny.add_argument("--note")

    ingest = sub.add_parser("ingest", help="poll read-only connectors and print normalized signals")
    ingest.add_argument("--fixtures", help="directory of <source_type>.jsonl fixtures")
    ingest.add_argument("--connectors", help="path to connectors.yaml")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "approvals":
        return cmd_approvals(args)
    if args.command == "probe":
        return cmd_probe(args)
    if args.command == "approve":
        return _decide(args, True)
    if args.command == "deny":
        return _decide(args, False)
    try:
        if args.command == "demo":
            return asyncio.run(_run_demo(args))
        if args.command == "serve":
            return asyncio.run(_run_serve(args))
        if args.command == "health":
            return cmd_health(args)
        if args.command == "ingest":
            return asyncio.run(_run_ingest(args))
        if args.command == "demo-fragmentation":
            return asyncio.run(_run_fragmentation_demo(args))
    except KeyboardInterrupt:
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
