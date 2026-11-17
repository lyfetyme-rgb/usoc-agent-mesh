"""Cross-vertical 3-minute demo storyboards.

The *shape* of the demo never changes: messy signals -> entity resolution ->
ranked risk -> proposed high-impact action -> deterministic HOLD. Only the
connector noun, the target noun and the human approver change. That makes one
demo reusable for cyber, finance and healthcare audiences without weakening the
governance story (the last beat is always a machine-enforced HOLD).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .registry import RegistryError

Vertical = Literal["cyber", "finance", "healthcare"]


class Beat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    time: str
    title: str
    narration: str
    on_screen: str


class Storyboard(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Vertical
    name: str
    audience: str
    connector_noun: str
    signal_noun: str
    action_verb: str
    target_noun: str
    approver_role: str
    fixtures_dir: Path
    profile_id: str
    beats: list[Beat] = Field(default_factory=list, min_length=5, max_length=5)

    @property
    def money_shot(self) -> str:
        return (
            f"{self.signal_noun} -> {self.action_verb} {self.target_noun} "
            f"-> HOLD for {self.approver_role}"
        )


def _beats(board: Storyboard) -> list[Beat]:
    signal = board.signal_noun
    target = board.target_noun
    verb = board.action_verb
    return [
        Beat(
            time="0:00-0:30",
            title="Messy signals",
            narration=(
                f"We ingest {signal.lower()} from incumbent tools as read-only connectors. "
                "Nothing is trusted, nothing is changed."
            ),
            on_screen=f"connectors -> normalized signals ({signal})",
        ),
        Beat(
            time="0:30-1:00",
            title="Entity resolution",
            narration=(
                "Aliases from different systems collapse onto one entity with provenance "
                "and a hash for every source record."
            ),
            on_screen="entity resolution -> one entity, many sources",
        ),
        Beat(
            time="1:00-1:40",
            title="Ranked risk",
            narration=(
                "Deterministic correlation ranks the incident. No LLM decides the score "
                "and no vendor payload can widen the scope."
            ),
            on_screen="ranked incident: risk tier + score + reasons",
        ),
        Beat(
            time="1:40-2:20",
            title="Proposed high-impact action",
            narration=(
                f"The mesh proposes exactly one governed action: {verb} {target}. "
                "It is a recommendation, not authority."
            ),
            on_screen=f"proposed: {verb} {target}",
        ),
        Beat(
            time="2:20-3:00",
            title="Deterministic HOLD",
            narration=(
                f"The policy gate returns HOLD and opens a signed approval for the "
                f"{board.approver_role}. An AI recommendation cannot become execution."
            ),
            on_screen=f"HOLD -> signed approval ({board.approver_role})",
        ),
    ]


def _board(**kwargs: object) -> Storyboard:
    board = Storyboard(**kwargs)  # type: ignore[arg-type]
    return board.model_copy(update={"beats": _beats(board)})


STORYBOARDS: dict[Vertical, Storyboard] = {
    "cyber": _board(
        id="cyber",
        name="Cyber / Critical Infrastructure",
        audience="SOC, infrastructure and defense buyers",
        connector_noun="threat-intel and network telemetry",
        signal_noun="Malicious IP signals",
        action_verb="CONTAIN",
        target_noun="prod-db-01",
        approver_role="SecOps lead",
        fixtures_dir=Path("fixtures") / "fragmentation",
        profile_id="full_usoc",
    ),
    "finance": _board(
        id="finance",
        name="FinOps & Banking",
        audience="Risk, payments and finance operations buyers",
        connector_noun="wire, ledger and merchant monitoring feeds",
        signal_noun="Anomalous wire pattern",
        action_verb="FREEZE",
        target_noun="merchant-account-884",
        approver_role="Risk Officer",
        fixtures_dir=Path("fixtures") / "finance",
        profile_id="finops_banking",
    ),
    "healthcare": _board(
        id="healthcare",
        name="Clinical & Healthcare",
        audience="Clinical safety, pharmacy and compliance buyers",
        connector_noun="medication, lab and dispense feeds",
        signal_noun="Conflicting medication/lab feed",
        action_verb="PAUSE",
        target_noun="automated-dispense-queue",
        approver_role="Attending Clinician",
        fixtures_dir=Path("fixtures") / "healthcare",
        profile_id="clinical_healthcare",
    ),
}

DEFAULT_VERTICAL: Vertical = "cyber"


def get_storyboard(vertical: str | None) -> Storyboard:
    key = str(vertical or DEFAULT_VERTICAL).strip().lower()
    board = STORYBOARDS.get(key)  # type: ignore[arg-type]
    if board is None:
        raise RegistryError(
            f"unknown storyboard {key!r}; choose one of: {', '.join(sorted(STORYBOARDS))}"
        )
    return board


def render_storyboard(vertical: str | None = None) -> str:
    """Printable buyer-facing storyboard with the exact vertical swap sheet."""
    board = get_storyboard(vertical)
    lines = [
        f"# 3-minute demo storyboard - {board.name}",
        "",
        f"Audience: {board.audience}",
        f"Money shot: {board.money_shot}",
        f"Connectors: {board.connector_noun}",
        f"Role profile: {board.profile_id}",
        f"Fixtures: {board.fixtures_dir}",
        "",
        "| Time | Beat | Narration | On screen |",
        "| --- | --- | --- | --- |",
    ]
    for beat in board.beats:
        lines.append(
            f"| {beat.time} | {beat.title} | {beat.narration} | {beat.on_screen} |"
        )
    lines += [
        "",
        "Vertical swap sheet (same flow, different nouns):",
    ]
    for other in STORYBOARDS.values():
        lines.append(
            f"  {other.id:<10} {other.signal_noun} -> {other.action_verb} "
            f"{other.target_noun} -> HOLD for {other.approver_role}"
        )
    lines += [
        "",
        "Run it:",
        f"  python -m agents storyboard --vertical {board.id}",
        f"  python -m agents demo-fragmentation --vertical {board.id}",
        "",
        "Note: the governed target is namespaced (for example "
        f"sandbox/{board.target_noun}) so a vendor field cannot widen the blast radius.",
    ]
    return "\n".join(lines)
