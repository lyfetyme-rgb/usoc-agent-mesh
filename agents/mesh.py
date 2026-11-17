"""Wires the nine USOC subsystems, a planner and a bus into one runnable mesh.

    async with Mesh() as mesh:
        result = await mesh.run("Ingest these tickets, validate them, analyse trends, report.")

The mesh is a thin composition root. Everything it builds is injectable, which
is what makes the tests fast and the demo runnable without Redis or an API key.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .bus import Bus, acls_from_specs, build_bus, topic_rules_from_authority
from .config import Settings, get_settings
from .connectors import IngestResult, load_connectors
from .contracts import GoalResult
from .correlation import CorrelationResult
from .evidence import EvidenceChain
from .fragmentation import FragmentationReport, FragmentationService
from .governance import ApprovalStore, FileApprovalStore, PolicyConfig, PolicyEngine
from .llm import EchoLLM, LLM, build_llm
from .observability import Metrics, configure_logging, log
from .orchestrator import LLMPlanner, Orchestrator, Planner, RouterPlanner
from .profiles import apply_role_profile, get_profile, settings_for_profile
from .registry import Registry, SubsystemSpec, load_registry
from .runtime import SubsystemAgent
from .security import SecurityError, Signer, build_signer, configured_approvers
from .shell import Shell
from .store import InMemoryStore, RedisStore, StateStore
from .trust import (
    CoordinatorKeyring,
    build_approval_verifier,
    build_message_authority,
    load_approver_registry,
)
from .tools import ToolRegistry, build_default_tools, scoped_tool_registry
from .usoc_agents import AiceeAgent, BengalAgent, HitlAgent, OekpAgent, SeraphimAgent

AGENT_CLASSES: dict[str, type[SubsystemAgent]] = {
    "aicee": AiceeAgent,
    "seraphim": SeraphimAgent,
    "hitl": HitlAgent,
    "oekp": OekpAgent,
    "bengal": BengalAgent,
}


def validate_agent_tiers(
    specs: list[SubsystemSpec],
    classes: dict[str, type[SubsystemAgent]] | None = None,
) -> None:
    """Fail startup if a deterministic card maps to an LLM-capable class.

    A label without an implementation check is just marketing. The capability
    card and the Python class must agree in both directions: a deterministic
    class cannot be downgraded to an LLM tier by accident either.
    """
    implementations = AGENT_CLASSES if classes is None else classes
    for spec in specs:
        cls = implementations.get(spec.id, SubsystemAgent)
        impl_deterministic = bool(getattr(cls, "deterministic", False))
        card_deterministic = spec.model_tier == "deterministic"
        if impl_deterministic != card_deterministic:
            raise SecurityError(
                f"{spec.id}: model_tier={spec.model_tier!r} does not match "
                f"{cls.__name__}.deterministic={impl_deterministic}"
            )


class Mesh:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        registry_path: str | Path | None = None,
        bus: Bus | None = None,
        llm: LLM | None = None,
        store: StateStore | None = None,
        planner: Planner | None = None,
        approvals: ApprovalStore | None = None,
        fragmentation: FragmentationService | None = None,
        workspace_subdir: str = "",
        agents: list[str] | None = None,
        run_orchestrator: bool = True,
    ) -> None:
        self.settings = settings_for_profile(settings or get_settings())
        self._registry_path = Path(registry_path or self.settings.subsystems_file)
        self._bus_override = bus
        self._llm_override = llm
        self._store_override = store
        self._planner_override = planner
        self._approvals_override = approvals
        self._fragmentation_override = fragmentation
        self._workspace = self.settings.workspace / workspace_subdir if workspace_subdir else self.settings.workspace
        self._agents_filter = [a.strip() for a in agents] if agents else None
        self._run_orchestrator = run_orchestrator

        self.bus: Bus | None = None
        self.llm: LLM | None = None
        self.store: StateStore | None = None
        self.registry: Registry | None = None
        self.approvals: ApprovalStore | None = None
        self.policy: PolicyEngine | None = None
        self.evidence: EvidenceChain | None = None
        self.signer: Signer | None = None
        self.message_authority: Signer | CoordinatorKeyring | None = None
        self.approver_registry: Any | None = None
        self.approver_verifier: Any | None = None
        self.topic_rules: dict[str, Any] = {}
        self.agents: dict[str, SubsystemAgent] = {}
        # Per-agent registries. CSSSF gets a scoped registry; other agents keep
        # the base one so their workspace tools are not silently narrowed.
        self.agent_tools: dict[str, ToolRegistry] = {}
        self.orchestrator: Orchestrator | None = None
        self.shell: Shell | None = None
        self.fragmentation: FragmentationService | None = None
        self.fragmentation_error: str | None = None
        self.metrics = Metrics()
        self._started = False

    # -- lifecycle ----------------------------------------------------------
    async def start(self) -> "Mesh":
        configure_logging(self.settings.log_level, self.settings.log_json)
        self.message_authority = build_message_authority(self.settings)
        if isinstance(self.message_authority, CoordinatorKeyring):
            # Bus keys are per-coordinator; evidence, approvals and ADRs keep
            # the cluster-level signer so cross-process records still verify.
            self.signer = build_signer(self.settings)
        else:
            # Dev/demo share one HMAC or global Ed25519 identity everywhere.
            self.signer = self.message_authority
        self.approver_registry = load_approver_registry(self.settings)
        self.approver_verifier = build_approval_verifier(
            self.settings, self.approver_registry
        )
        self.evidence = EvidenceChain(self._workspace / "evidence" / "chain.jsonl", signer=self.signer)
        tools = build_default_tools(
            self._workspace,
            self.evidence,
            allow_delete=self.settings.allow_workspace_delete,
        )
        self.registry = load_registry(self._registry_path, tools, settings=self.settings)
        # The profile narrows role views only. Every coordinator stays running
        # with the same signed card, ACLs and tool scopes as the full mesh.
        self.registry = apply_role_profile(self.registry, self.settings.role_profile)
        validate_agent_tiers(self.registry.subsystems)
        # Only the owning coordinator's key may emit control-plane verdicts and
        # approval grants. In strict prod a missing kid fails startup closed.
        self.topic_rules = topic_rules_from_authority(
            self.message_authority, require_kid=self.settings.strict_prod
        )
        if self._bus_override is not None:
            self.bus = self._bus_override
            # An injected bus (tests, custom transports) still gets message auth.
            if hasattr(self.bus, "signer"):
                self.bus.signer = self.message_authority
            if hasattr(self.bus, "topic_rules"):
                self.bus.topic_rules = self.topic_rules
        else:
            publish_acl, subscribe_acl = acls_from_specs(self.registry.subsystems)
            self.bus = build_bus(
                self.settings,
                signer=self.message_authority,
                publish_acl=publish_acl,
                subscribe_acl=subscribe_acl,
                topic_rules=self.topic_rules,
            )
            log(
                "bus.acl",
                mode="least-privilege",
                publish=len(publish_acl),
                subscribe=len(subscribe_acl),
                topic_rules=len(self.topic_rules),
            )
        self.llm = self._llm_override or build_llm(self.settings)
        if self._store_override:
            self.store = self._store_override
        elif self.settings.bus == "redis":
            self.store = RedisStore(
                self.settings.redis_url,
                socket_timeout_s=self.settings.redis_socket_timeout_s,
            )
        else:
            self.store = InMemoryStore()

        approvers = configured_approvers(self.settings)
        if self.approver_registry is not None:
            # The signed registry is authoritative; a configured plain name
            # that is absent from it must never be able to approve.
            approvers = (approvers & self.approver_registry.ids()) if approvers else self.approver_registry.ids()
        self.approvals = self._approvals_override or FileApprovalStore(
            self._workspace / "approvals.json",
            signer=self.signer,
            approvers=approvers,
            require_allowlist=self.settings.require_approver_allowlist
            or self.settings.strict_prod,
            ttl_s=self.settings.approval_ttl_s,
            approver_verifier=self.approver_verifier,
        )
        targets = [t.strip() for t in self.settings.allowed_targets.split(",") if t.strip()]

        async def record_consumed_approval(request: Any, **context: Any) -> None:
            # OEKP owns the evidence chain: a spent nonce is immutable proof
            # that this approval can never authorise a second execution.
            await self.evidence.append(
                kind="approval.consumed",
                actor="oekp",
                subsystem="oekp",
                correlation_id=str(context.get("correlation_id") or ""),
                mission_id=context.get("mission_id"),
                data={
                    "approval_id": request.id,
                    "nonce": request.nonce or request.id,
                    "action_class": request.action_class.value,
                    "target": request.target,
                    "risk": request.risk.value,
                    "taint_hash": request.taint_hash,
                    "tainted": request.tainted,
                    "provenance": list(context.get("provenance") or []),
                    "amount": request.amount,
                    "currency": request.currency,
                    "quorum": request.quorum,
                    "approvers": [d.approver for d in request.decisions],
                },
                tainted=request.tainted,
            )

        from .profiles import parse_amount

        self.policy = PolicyEngine(
            PolicyConfig(
                allowed_targets=targets,
                approval_ttl_s=self.settings.approval_ttl_s,
                max_transaction_amount=parse_amount(self.settings.max_transaction_amount),
                transaction_currency=self.settings.transaction_currency,
                approval_quorum=self.settings.approval_quorum,
            ),
            self.approvals,
            self.approver_registry,
            consumption_audit=record_consumed_approval,
        )

        # Connectors are optional. A broken integration is reported by SHELL and
        # must not stop the nine agents from starting.
        self.fragmentation = self._fragmentation_override
        if self.fragmentation is None:
            connectors_path = Path(self.settings.connectors_file)
            if connectors_path.is_file():
                try:
                    connectors = load_connectors(connectors_path, settings=self.settings)
                    if connectors:
                        self.fragmentation = FragmentationService(
                            connectors, self.policy, self.evidence, self.settings
                        )
                        log("fragmentation.configured", connectors=len(connectors))
                except Exception as exc:
                    self.fragmentation_error = f"{type(exc).__name__}: {exc}"
                    log("fragmentation.disabled", error=self.fragmentation_error)

        if self._run_orchestrator:
            self.orchestrator = Orchestrator(
                self.bus,
                self.registry,
                self._planner_override or self._default_planner(),
                self.settings,
                self.metrics,
                mission_id=self.settings.mission_id,
            )
        known = set(self.registry.by_id)
        specs = list(self.registry.subsystems)
        if self._agents_filter is not None:
            unknown = sorted(set(self._agents_filter) - known)
            if unknown:
                raise SecurityError(
                    f"AGENT worker agents not in registry: {', '.join(unknown)}"
                )
            specs = [spec for spec in specs if spec.id in self._agents_filter]
        self.agent_tools = {
            spec.id: (
                scoped_tool_registry(
                    tools, workspace=self._workspace, scopes=spec.tool_scopes
                )
                if spec.tool_scopes
                else tools
            )
            for spec in specs
        }
        self.agents = {
            spec.id: AGENT_CLASSES.get(spec.id, SubsystemAgent)(
                spec,
                self.bus,
                llm=self.llm,
                tools=self.agent_tools[spec.id],
                settings=self.settings,
                store=self.store,
                metrics=self.metrics,
                known_agents=known,
                policy=self.policy,
                evidence=self.evidence,
                approvals=self.approvals,
            )
            for spec in specs
        }
        self.shell = Shell(
            self.registry,
            self.agents,
            self.bus,
            self.metrics,
            self.approvals,
            fragmentation=self.fragmentation,
            fragmentation_error=self.fragmentation_error,
        )

        if self.orchestrator is not None:
            await self.orchestrator.start()
        await asyncio.gather(*(agent.start() for agent in self.agents.values()))
        self._started = True
        log(
            "mesh.started",
            agents=len(self.agents),
            roles=self.registry.roles_total,
            profile=self.settings.role_profile,
            bus=type(self.bus).__name__,
            model=getattr(self.llm, "model", "?"),
            planner=type(self.orchestrator.planner).__name__ if self.orchestrator is not None else "disabled",
            message_auth=self.signer is not None,
            approvers=len(configured_approvers(self.settings)),
        )
        return self

    def _default_planner(self) -> Planner:
        assert self.registry and self.llm
        if isinstance(self.llm, EchoLLM):
            return RouterPlanner(self.registry)
        return LLMPlanner(self.llm, self.registry, self.settings)

    async def stop(self) -> None:
        if not self._started:
            return
        if self.orchestrator:
            await self.orchestrator.stop()
        await asyncio.gather(*(agent.stop() for agent in self.agents.values()), return_exceptions=True)
        if self.fragmentation is not None:
            try:
                await self.fragmentation.close()
            except Exception:
                pass
        for closable in (self.llm, self.store, self.bus, self.approvals):
            if closable is not None:
                try:
                    await closable.close()
                except Exception:
                    pass
        self._started = False
        log("mesh.stopped")

    async def __aenter__(self) -> "Mesh":
        return await self.start()

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()

    # -- work ---------------------------------------------------------------
    async def run(self, goal: str, mission_id: str | None = None) -> GoalResult:
        if not self._started:
            await self.start()
        if self.orchestrator is None:
            raise RuntimeError(
                "this mesh is running in worker mode (no orchestrator); "
                "run `agents serve` on the control plane"
            )
        if mission_id:
            self.orchestrator.mission_id = mission_id
        return await self.orchestrator.run(goal)

    # -- fragmentation ------------------------------------------------------
    async def ingest(self) -> IngestResult:
        """Poll every configured read-only connector and normalize the result."""
        if not self._started:
            await self.start()
        if self.fragmentation is None:
            raise RuntimeError(
                self.fragmentation_error or "no fragmentation connectors are configured"
            )
        return await self.fragmentation.ingest()

    async def correlate(
        self,
        signals: list | None = None,
        *,
        mission_id: str | None = None,
    ) -> CorrelationResult:
        """Correlate the current ingestion (or supplied signals) across sources."""
        if not self._started:
            await self.start()
        if self.fragmentation is None:
            raise RuntimeError(
                self.fragmentation_error or "no fragmentation connectors are configured"
            )
        if signals is None:
            signals = (await self.fragmentation.ingest()).signals
        return await self.fragmentation.correlate(signals, mission_id=mission_id)

    async def fragmentation_report(
        self,
        *,
        mission_id: str | None = None,
        approval_ref: str | None = None,
        propose: bool = True,
    ) -> FragmentationReport:
        """Run ingest -> correlate -> governed proposal in one call."""
        if not self._started:
            await self.start()
        if self.fragmentation is None:
            raise RuntimeError(
                self.fragmentation_error or "no fragmentation connectors are configured"
            )
        return await self.fragmentation.run(
            mission_id=mission_id, approval_ref=approval_ref, propose=propose
        )

    def trace(self) -> list:
        return list(self.bus.history) if self.bus else []

    def describe(self) -> dict[str, Any]:
        assert self.registry is not None
        return {
            "agents": [spec.model_dump() for spec in self.registry.subsystems],
            "roles_total": self.registry.roles_total,
            "role_profile": self.settings.role_profile,
            "profile_name": get_profile(self.settings.role_profile).name,
            "metrics": self.metrics.snapshot(),
            "bus": type(self.bus).__name__ if self.bus else None,
            "model": getattr(self.llm, "model", None),
            "message_auth": self.signer is not None,
            "fragmentation": (
                self.fragmentation.describe() if self.fragmentation is not None else None
            ),
            "fragmentation_error": self.fragmentation_error,
            "running_agents": sorted(self.agents),
            "orchestrator": self.orchestrator is not None,
        }
