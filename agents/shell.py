"""USOC SHELL.

The seven SHELL roles are platform functions, not another domain agent:

  1 Service Discovery        -> Registry.by_id / menu()
  2 Communication Routing    -> Bus (inbox.* direct, topic.* broadcast)
  3 Workflow Lifecycle       -> Orchestrator (waves, retries, timeouts)
  4 Contract Validation      -> pydantic contracts + Message validators
  5 Runtime Health           -> health() below
  6 Configuration Coordination-> Settings, subsystems.yaml, signed policy refs
  7 Integration Diagnostics  -> diagnostics() below

Keeping SHELL as infrastructure follows the in-repo delivery constitution
(``toolbox/CONSTITUTION.md``), which requires deterministic, fail-closed policy
and routing controls rather than probabilistic agents. The SHELL boundary is
recorded in ``subsystems.yaml``.
"""

from __future__ import annotations

from typing import Any

from .contracts import SCHEMA_VERSION
from .observability import Metrics
from .registry import Registry
from .security import redact_fields, redact_text


class Shell:
    def __init__(
        self,
        registry: Registry,
        agents: dict[str, Any],
        bus: Any,
        metrics: Metrics,
        approvals: Any = None,
        *,
        fragmentation: Any = None,
        fragmentation_error: str | None = None,
        ledger: Any = None,
        bengal_status: dict[str, Any] | None = None,
    ) -> None:
        self.registry = registry
        self.agents = agents
        self.bus = bus
        self.metrics = metrics
        self.approvals = approvals
        self.fragmentation = fragmentation
        self.fragmentation_error = fragmentation_error
        self.ledger = ledger
        # Static BENGAL capability metadata only: no case data or fingerprints.
        self.bengal_status: dict[str, Any] = bengal_status or {"enabled": False}

    def _fragmentation_status(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "configured": self.fragmentation is not None,
            "connectors": 0,
            "error": self.fragmentation_error,
        }
        if self.fragmentation is not None:
            try:
                described = self.fragmentation.describe()
                status["connectors"] = len(described.get("connectors", []))
                status["window_s"] = described.get("window_s")
                status["min_sources"] = described.get("min_sources")
                status["min_score"] = described.get("min_score")
            except Exception as exc:  # diagnostics must never fail the health call
                status["error"] = f"{type(exc).__name__}: {exc}"
        return status

    async def _pending_count(self) -> tuple[int, bool]:
        """Read approval count without letting a store fault fail a probe."""
        if self.approvals is None:
            return 0, True
        try:
            return len(await self.approvals.pending()), True
        except Exception:
            return 0, False

    def _degraded(self, *, bus_ok: bool, approvals_ok: bool) -> tuple[bool, int]:
        """Count-only degradation signal for public probes (no ids or error text)."""
        issues = 0
        if len(self.agents) != len(self.registry.subsystems):
            issues += 1
        if getattr(self.bus, "dlq", None):
            issues += 1
        if (getattr(self.bus, "stats", {}) or {}).get("unrouted"):
            issues += 1
        if not bus_ok:
            issues += 1
        if self.fragmentation_error:
            issues += 1
        if not approvals_ok:
            issues += 1
        return issues > 0, issues

    def discovery(self) -> list[dict[str, Any]]:
        return [
            {
                "id": spec.id,
                "name": spec.name,
                "roles": len(spec.roles),
                "tools": spec.tools,
                "subscribes": spec.subscribes,
                "healthy": spec.id in self.agents,
            }
            for spec in self.registry.subsystems
        ]

    async def health(self, *, detailed: bool = True) -> dict[str, Any]:
        stats = getattr(self.bus, "stats", {}) or {}
        dlq = getattr(self.bus, "dlq", []) or []
        pending, approvals_ok = await self._pending_count()
        degraded, issue_count = self._degraded(bus_ok=True, approvals_ok=approvals_ok)
        if not detailed:
            # Public liveness only: counts and flags, never topology, agent ids,
            # internal endpoints, or configuration error text.
            return {
                "status": "degraded" if degraded else "ok",
                "schema_version": SCHEMA_VERSION,
                "agents_running": len(self.agents),
                "agents_expected": len(self.registry.subsystems),
                "degraded": degraded,
                "issues": issue_count,
                "message_auth": getattr(self.bus, "signer", None) is not None,
                "pending_approvals": pending,
                "tasks": self.ledger.counts() if self.ledger is not None else {},
                "bengal": self.bengal_status,
            }
        return redact_fields(
            {
                "degraded": degraded,
                "issues": issue_count,
                "schema_version": SCHEMA_VERSION,
                "bus": type(self.bus).__name__,
                "agents": [
                    {"id": a.id, "uptime_s": a.uptime_s, "inflight": len(a._tasks)}
                    for a in self.agents.values()
                ],
                "roles": self.registry.roles_total,
                "metrics": self.metrics.snapshot(),
                "task_ledger": self.ledger.snapshot() if self.ledger is not None else {},
                "transport": {
                    "published": stats.get("published", 0),
                    "delivered": stats.get("delivered", 0),
                    "dead_letters": len(dlq),
                    "unrouted": stats.get("unrouted", 0),
                },
                "pending_approvals": pending,
                "message_auth": getattr(self.bus, "signer", None) is not None,
                "fragmentation": self._fragmentation_status(),
                "bengal": self.bengal_status,
            }
        )

    async def ready(self, *, detailed: bool = True) -> tuple[bool, dict[str, Any]]:
        """Readiness for container probes: agents present and transport live."""
        missing = [spec.id for spec in self.registry.subsystems if spec.id not in self.agents]
        bus_ok = True
        ping = getattr(self.bus, "ping", None)
        if ping is not None:
            try:
                bus_ok = bool(await ping())
            except Exception:
                bus_ok = False
        pending, approvals_ok = await self._pending_count()
        ok = not missing and bus_ok
        degraded, issue_count = self._degraded(bus_ok=bus_ok, approvals_ok=approvals_ok)
        if not detailed:
            return ok, {
                "ready": ok,
                "agents_running": len(self.agents),
                "agents_expected": len(self.registry.subsystems),
                "bus_ok": bus_ok,
                "degraded": degraded,
                "issues": issue_count,
                "pending_approvals": pending,
            }
        return ok, redact_fields(
            {
                "ready": ok,
                "degraded": degraded,
                "issues": issue_count,
                "missing_agents": missing,
                "bus_ok": bus_ok,
                "pending_approvals": pending,
                "roles": self.registry.roles_total,
                "fragmentation": self._fragmentation_status(),
            }
        )

    async def diagnostics(self) -> list[str]:
        issues: list[str] = []
        missing = [spec.id for spec in self.registry.subsystems if spec.id not in self.agents]
        if missing:
            issues.append(f"agents not running: {', '.join(missing)}")
        if getattr(self.bus, "dlq", None):
            issues.append(f"{len(self.bus.dlq)} dead-lettered messages")
        stats = getattr(self.bus, "stats", {}) or {}
        if stats.get("unrouted"):
            issues.append(f"{stats['unrouted']} unrouted broadcasts")
        pending, approvals_ok = await self._pending_count()
        if not approvals_ok:
            issues.append("approval store unavailable")
        elif pending:
            issues.append(f"{pending} approvals waiting on a human")
        if self.fragmentation_error:
            issues.append(f"fragmentation disabled: {self.fragmentation_error}")
        if self.ledger is not None:
            counts = self.ledger.counts()
            if counts.get("tasks_unresolved"):
                issues.append(f"{counts['tasks_unresolved']} unresolved tasks")
        return [redact_text(issue) for issue in issues]
