"""Tools an agent may call.

Tools are declared with a JSON schema, invoked by name, and always return a
string or JSON-serialisable value. They are the only way an agent touches the
outside world, which keeps side effects auditable and testable.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from .security import secure_dir

Handler = Callable[..., Awaitable[Any] | Any]


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler
    timeout_s: float = 15.0

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class ToolRegistry:
    tools: dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec, *, replace: bool = False) -> None:
        if spec.name in self.tools and not replace:
            raise ToolError(f"tool already registered: {spec.name}")
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self.tools[name]
        except KeyError as exc:
            raise ToolError(f"unknown tool: {name}") from exc

    def describe(self, names: list[str] | None = None) -> list[dict[str, Any]]:
        keys = names if names is not None else list(self.tools)
        return [self.tools[k].describe() for k in keys if k in self.tools]

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        spec = self.get(name)
        try:
            result = spec.handler(**(arguments or {}))
            if asyncio.iscoroutine(result):
                result = await asyncio.wait_for(result, timeout=spec.timeout_s)
            return result
        except asyncio.TimeoutError as exc:
            raise ToolError(f"tool {name} timed out after {spec.timeout_s}s") from exc
        except TypeError as exc:
            raise ToolError(f"bad arguments for {name}: {exc}") from exc


def _workspace(root: Path) -> Path:
    secure_dir(root)
    return root.resolve()


def _safe(root: Path, relative: str) -> Path:
    target = (_workspace(root) / relative).resolve()
    if root.resolve() not in target.parents and target != root.resolve():
        raise ToolError(f"path escapes workspace: {relative}")
    return target


def build_default_tools(
    workspace: Path,
    evidence: Any | None = None,
    *,
    allow_delete: bool = False,
) -> ToolRegistry:
    registry = ToolRegistry()

    async def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    async def write(path: str, content: str, append: bool = False) -> str:
        target = _safe(workspace, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a" if append else "w", encoding="utf-8") as fh:
            fh.write(content)
        return f"wrote {len(content)} chars to {target.name}"

    async def read(path: str, max_chars: int = 20_000) -> str:
        target = _safe(workspace, path)
        if not target.is_file():
            raise ToolError(f"no such file: {path}")
        return target.read_text(encoding="utf-8")[:max_chars]

    async def list_files(subdir: str = ".", limit: int = 200) -> list[str]:
        root = _workspace(workspace)
        base = _safe(workspace, subdir)
        if not base.is_dir():
            return []
        found: list[str] = []
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if root not in resolved.parents and resolved != root:
                # Never follow a symlink that escapes the sandbox.
                continue
            found.append(str(path.relative_to(root)))
        return sorted(found)[:limit]

    async def delete(path: str) -> str:
        target = _safe(workspace, path)
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        return f"deleted {path}"

    registry.register(
        ToolSpec(
            name="clock.now",
            description="Current UTC time in ISO-8601.",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            handler=now,
        )
    )
    registry.register(
        ToolSpec(
            name="workspace.write",
            description="Write UTF-8 text inside the workspace directory.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "path relative to the workspace"},
                    "content": {"type": "string"},
                    "append": {"type": "boolean", "default": False},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
            handler=write,
        )
    )
    registry.register(
        ToolSpec(
            name="workspace.read",
            description="Read a UTF-8 text file inside the workspace directory.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}, "max_chars": {"type": "integer"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            handler=read,
        )
    )
    registry.register(
        ToolSpec(
            name="workspace.list",
            description="List files inside the workspace directory.",
            input_schema={
                "type": "object",
                "properties": {"subdir": {"type": "string", "default": "."}, "limit": {"type": "integer"}},
                "additionalProperties": False,
            },
            handler=list_files,
        )
    )
    if evidence is not None:

        async def evidence_append(
            kind: str, actor: str, data: dict[str, Any] | None = None, correlation_id: str = "", classification: str = "internal"
        ) -> dict[str, Any]:
            record = await evidence.append(
                kind=kind,
                actor=actor,
                data=data or {},
                correlation_id=correlation_id,
                classification=classification,
            )
            return {"id": record.id, "seq": record.seq, "hash": record.hash}

        async def evidence_verify() -> dict[str, Any]:
            ok, detail = evidence.verify()
            return {"ok": ok, "detail": detail}

        async def evidence_read(limit: int = 20) -> list[dict[str, Any]]:
            return [r.model_dump(mode="json") for r in evidence.records(limit=limit)]

        registry.register(
            ToolSpec(
                name="evidence.append",
                description="Append a hash-chained record to the OEKP evidence log.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "actor": {"type": "string"},
                        "data": {"type": "object"},
                        "correlation_id": {"type": "string"},
                        "classification": {"type": "string"},
                    },
                    "required": ["kind", "actor"],
                    "additionalProperties": False,
                },
                handler=evidence_append,
            )
        )
        registry.register(
            ToolSpec(
                name="evidence.verify",
                description="Verify the hash chain and sequence of the OEKP evidence log.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                handler=evidence_verify,
            )
        )
        registry.register(
            ToolSpec(
                name="evidence.read",
                description="Read the most recent OEKP evidence records.",
                input_schema={
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                    "additionalProperties": False,
                },
                handler=evidence_read,
            )
        )

    if allow_delete:
        registry.register(
            ToolSpec(
                name="workspace.delete",
                description="Delete a file or directory inside the workspace. Destructive; off by default.",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
                handler=delete,
            )
        )
    return registry
