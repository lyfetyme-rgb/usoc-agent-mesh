"""USOC subsystems: capability cards + deterministic routing.

An agent's capability card is its public contract: what it can do, which tools
it may use, which topics it listens to. The planner only ever sees cards, so
adding or renaming a subsystem never requires touching orchestration code.

``Registry.route`` is a keyword/tag scorer, not a model. It is the fallback
when no LLM is configured, and it is what makes routing testable and
explainable. With a real model, the planner reads the same cards and picks
owners itself; the scorer is still used to validate its choices.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .contracts import ActionClass
from .tools import ToolRegistry

EXPECTED_SUBSYSTEMS = 9

STOPWORDS = frozenset(
    """
    a an the and or of to in on for with from by as at is are be been being this that these those
    it its into your you we our their them they i me my then than so if but not no do does did done
    can could should would will shall may might must use using make made get got give given
    all any each every some such other more most few many much very just also only own same
    """.split()
)


class SubsystemSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,30}$")
    name: str = Field(min_length=1, max_length=60)
    description: str = Field(min_length=10, max_length=600)
    capabilities: list[str] = Field(min_length=1, max_length=12)
    # Distinctive routing terms. Capabilities are shared vocabulary; keywords are
    # what tells two similar subsystems apart without a model.
    keywords: list[str] = Field(default_factory=list, max_length=24)
    roles: list[str] = Field(default_factory=list, max_length=20)
    tools: list[str] = Field(default_factory=list)
    subscribes: list[str] = Field(default_factory=list)
    # Least-privilege authorization matrix. None means "unrestricted" (backward
    # compatible with existing capability cards). A non-None list restricts the
    # agent to only those recipients/action classes/targets.
    allowed_recipients: list[str] | None = None
    allowed_senders: list[str] | None = None
    allowed_action_classes: list[ActionClass] | None = None
    allowed_targets: list[str] | None = None
    system_prompt: str = Field(default="", max_length=8_000)
    model_tier: Literal["fast", "strong"] = "fast"

    def card(self) -> str:
        caps = "; ".join(self.capabilities)
        return f"- {self.id} ({self.name}): {self.description} Capabilities: {caps}"

    def role_titles(self) -> str:
        return ", ".join(self.roles) if self.roles else "none declared"


class RegistryError(ValueError):
    pass


def _stem(word: str) -> str:
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 4 and word.endswith("ing"):
        return word[:-3]
    if len(word) > 4 and word.endswith("ed"):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {_stem(w) for w in words if w not in STOPWORDS}


@dataclass
class Registry:
    subsystems: list[SubsystemSpec]
    tools: ToolRegistry

    def __post_init__(self) -> None:
        ids = [s.id for s in self.subsystems]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise RegistryError(f"duplicate subsystem ids: {sorted(dupes)}")
        for spec in self.subsystems:
            missing = [t for t in spec.tools if t not in self.tools.tools]
            if missing:
                raise RegistryError(f"{spec.id} declares unknown tools: {missing}")

    def __len__(self) -> int:
        return len(self.subsystems)

    @property
    def roles_total(self) -> int:
        return sum(len(s.roles) for s in self.subsystems)

    @property
    def by_id(self) -> dict[str, SubsystemSpec]:
        return {s.id: s for s in self.subsystems}

    def get(self, agent_id: str) -> SubsystemSpec:
        try:
            return self.by_id[agent_id]
        except KeyError as exc:
            raise RegistryError(f"unknown subsystem: {agent_id}") from exc

    def menu(self) -> str:
        return "\n".join(s.card() for s in self.subsystems)

    def score(self, agent: SubsystemSpec, text: str) -> float:
        text_tokens = tokens(text)
        if not text_tokens:
            return 0.0
        lowered = text.lower()
        score = 0.0
        if agent.id in lowered:
            score += 6.0
        if agent.name.lower() in lowered:
            score += 5.0
        for capability in agent.capabilities:
            cap_tokens = tokens(capability)
            if not cap_tokens:
                continue
            overlap = len(cap_tokens & text_tokens) / math.sqrt(len(cap_tokens))
            score += overlap
            if len(cap_tokens) > 1 and capability.lower() in lowered:
                score += 3.0
        for keyword in agent.keywords:
            key_tokens = tokens(keyword)
            if not key_tokens:
                continue
            score += 1.5 * len(key_tokens & text_tokens) / math.sqrt(len(key_tokens))
            if keyword.lower() in lowered:
                score += 2.0
        score += 0.4 * len(tokens(agent.description) & text_tokens) / math.sqrt(
            max(1, len(tokens(agent.description)))
        )
        return round(score, 3)

    def route(self, text: str, k: int = 3) -> list[tuple[float, SubsystemSpec]]:
        scored = [(self.score(s, text), s) for s in self.subsystems]
        scored = [pair for pair in scored if pair[0] > 0]
        scored.sort(key=lambda pair: (-pair[0], pair[1].id))
        return scored[:k]

    def best(self, text: str) -> SubsystemSpec | None:
        ranked = self.route(text, k=1)
        return ranked[0][1] if ranked else None


def load_registry(
    path: str | Path,
    tools: ToolRegistry,
    expected_count: int | None = EXPECTED_SUBSYSTEMS,
) -> Registry:
    file = Path(path)
    if not file.is_file():
        raise RegistryError(f"subsystems file not found: {file}")
    try:
        raw: dict[str, Any] = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RegistryError(f"invalid YAML in {file}: {exc}") from exc

    entries = raw.get("subsystems")
    if not isinstance(entries, list) or not entries:
        raise RegistryError(f"{file} must contain a non-empty 'subsystems' list")
    try:
        specs = [SubsystemSpec.model_validate(entry) for entry in entries]
    except ValidationError as exc:
        raise RegistryError(f"invalid subsystem definition: {exc}") from exc

    if expected_count is not None and len(specs) != expected_count:
        raise RegistryError(f"expected {expected_count} subsystems, found {len(specs)}")
    return Registry(subsystems=specs, tools=tools)
