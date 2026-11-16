"""Demand-based scaling advice for USOC workers.

The mesh does not manage containers itself. What it can do — and what the
operator needs — is observe the backlog per agent and translate it into a
desired worker count. Horizontal scaling then becomes a closed loop:

    Redis pending entries  ->  ScalePolicy  ->  desired replicas
    docker compose up -d --scale oekp-worker=<n>   (or k8s HPA)

`agents scale-advice` prints the recommendation as JSON (machine-consumable)
or text (for humans). ScalePolicy is intentionally dumb and explicit: it never
scales below ``min_replicas`` or above ``max_replicas``, every decision is
logged with its inputs, and the whole path fails closed when Redis is missing
or unreachable.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass

from .security import SecurityError


@dataclass(frozen=True)
class ReplicaTarget:
    agent: str
    pending: int
    desired: int
    current: int
    reason: str


@dataclass(frozen=True)
class ScalePolicy:
    min_replicas: int = 1
    max_replicas: int = 4
    messages_per_replica: int = 8

    def __post_init__(self) -> None:
        if self.min_replicas < 1:
            raise SecurityError("scale_min_replicas must be >= 1")
        if self.max_replicas < self.min_replicas:
            raise SecurityError("scale_max_replicas must be >= scale_min_replicas")
        if self.messages_per_replica < 1:
            raise SecurityError("messages_per_replica must be >= 1")

    def desired(self, pending: int) -> int:
        # Zero backlog never drains workers to death: keep one.
        base = math.ceil(max(0, pending) / self.messages_per_replica)
        return max(self.min_replicas, min(self.max_replicas, base))

    def targets(
        self,
        backlog: dict[str, int],
        current: dict[str, int] | None = None,
    ) -> list[ReplicaTarget]:
        current = current or {}
        out = []
        for agent in sorted(backlog):
            pending = max(0, int(backlog[agent]))
            desired = self.desired(pending)
            cur = max(0, int(current.get(agent, 1)))
            if desired > cur:
                reason = f"backlog {pending} >= {self.messages_per_replica} per replica"
            elif desired < cur:
                reason = f"backlog {pending} below {self.messages_per_replica} per replica"
            else:
                reason = "steady state"
            out.append(
                ReplicaTarget(
                    agent=agent,
                    pending=pending,
                    desired=desired,
                    current=cur,
                    reason=reason,
                )
            )
        return out

    def as_json(self, targets: list[ReplicaTarget]) -> str:
        return json.dumps(
            {"policy": asdict(self), "targets": [asdict(t) for t in targets]},
            indent=2,
        )
