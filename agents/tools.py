"""Tools an agent may call.

Tools are declared with a JSON schema, invoked by name, and always return a
string or JSON-serialisable value. They are the only way an agent touches the
outside world, which keeps side effects auditable and testable.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from .security import secure_dir

Handler = Callable[..., Awaitable[Any] | Any]

# Path-taking tools and the argument that carries the path. A scope is refused
# for any other tool so a typo can never silently leave a side effect unconfined.
PATH_ARGUMENTS = {
    "workspace.read": "path",
    "workspace.write": "path",
    "workspace.list": "subdir",
    "workspace.delete": "path",
}
_ABSOLUTE_PATH = re.compile(r"^(?:/|[A-Za-z]:)")


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


def _normalize_scope(prefix: str) -> str:
    """Return a canonical relative directory prefix such as ``sandbox``."""
    scope = str(prefix).strip().replace("\\", "/").strip("/")
    parts = scope.split("/") if scope else []
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ToolError(f"invalid tool scope: {prefix!r}")
    if _ABSOLUTE_PATH.match(str(prefix).strip().replace("\\", "/")):
        raise ToolError(f"tool scope must be relative: {prefix!r}")
    return "/".join(parts)


def _scoped_relative(
    value: Any, *, scope: str, argument: str, allow_root: bool = False
) -> str:
    """Normalize a model-supplied path into a path inside ``scope``.

    Both ``foo`` and ``sandbox/foo`` mean the same thing: the caller's view is
    rooted at the sandbox. Anything that tries to climb out, use an absolute
    path, or address the real workspace layout directly is rejected before the
    base tool sees it.
    """
    raw = str(value).strip().replace("\\", "/")
    if not raw or _ABSOLUTE_PATH.match(raw):
        raise ToolError(f"{argument} must be a relative path inside {scope}/")
    if raw in {".", scope, f"{scope}/"}:
        if allow_root:
            return "."
        raise ToolError(f"{argument} must name a file inside {scope}/: {value!r}")

    parts = raw.split("/")
    if parts[0] == scope:
        parts = parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ToolError(f"{argument} escapes {scope}/: {value!r}")
    return "/".join(parts)


def _scoped_target(
    workspace_root: Path,
    scope_root: Path,
    scope: str,
    value: Any,
    *,
    argument: str,
    allow_root: bool = False,
) -> str:
    """Resolve a scoped path and hand the base tool a workspace-relative path."""
    relative = _scoped_relative(
        value, scope=scope, argument=argument, allow_root=allow_root
    )
    candidate = (scope_root / relative).resolve()
    if candidate != scope_root and scope_root not in candidate.parents:
        # Resolve after joining, so a symlink under sandbox/ that points into
        # evidence/ or the live workspace is rejected here, not after the write.
        raise ToolError(f"{argument} escapes {scope}/: {value!r}")
    return str(candidate.relative_to(workspace_root))


def scoped_tool_registry(
    tools: ToolRegistry,
    *,
    workspace: Path,
    scopes: Mapping[str, str],
) -> ToolRegistry:
    """Return a per-agent registry whose path arguments are chrooted.

    This is enforcement at the tool-runtime boundary, not a prompt convention:
    the agent receives a different ``ToolRegistry`` instance and its path
    arguments are rewritten and re-validated before the base handler runs.
    """
    if not scopes:
        return tools

    normalized = {name: _normalize_scope(prefix) for name, prefix in scopes.items()}
    for name in normalized:
        if name not in tools.tools:
            raise ToolError(f"cannot scope unknown tool: {name}")
        if name not in PATH_ARGUMENTS:
            raise ToolError(f"tool has no path argument to scope: {name}")

    workspace_root = _workspace(workspace)
    scoped = ToolRegistry()
    for name, spec in tools.tools.items():
        scope = normalized.get(name)
        if scope is None:
            scoped.register(spec)
            continue

        scope_root = (workspace_root / scope).resolve()
        if scope_root != workspace_root and workspace_root not in scope_root.parents:
            raise ToolError(f"tool scope escapes workspace: {scope}")

        argument = PATH_ARGUMENTS[name]
        base_handler = spec.handler
        # workspace.list defaults to the workspace root in the base tool. A
        # scoped agent must instead inherit its own scope root, or an omitted
        # argument would silently widen the search.
        list_default = scope if name == "workspace.list" else None

        def make_handler(
            handler: Handler,
            *,
            scope_label: str,
            root: Path,
            arg: str,
            default: str | None,
        ) -> Handler:
            async def handler_with_scope(**kwargs: Any) -> Any:
                if arg not in kwargs and default is None:
                    raise ToolError(f"missing {arg} for scoped tool {scope_label}")
                value_arg = kwargs.get(arg, default)
                kwargs[arg] = _scoped_target(
                    workspace_root,
                    root,
                    scope_label,
                    value_arg,
                    argument=arg,
                    allow_root=default is not None,
                )
                value = handler(**kwargs)
                if asyncio.iscoroutine(value):
                    return await value
                return value

            return handler_with_scope

        scoped.register(
            ToolSpec(
                name=spec.name,
                description=f"{spec.description} Confined to {scope}/.",
                input_schema=spec.input_schema,
                handler=make_handler(
                    base_handler,
                    scope_label=scope,
                    root=scope_root,
                    arg=argument,
                    default=list_default,
                ),
                timeout_s=spec.timeout_s,
            )
        )
    return scoped


def build_default_tools(
    workspace: Path,
    evidence: Any | None = None,
    *,
    allow_delete: bool = False,
    allow_write: bool = True,
) -> ToolRegistry:
    registry = ToolRegistry()

    async def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    async def write(path: str, content: str, append: bool = False) -> str:
        if not allow_write:
            raise ToolError("shadow mode: mutating tools are disabled")
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
        if not allow_write:
            raise ToolError("shadow mode: mutating tools are disabled")
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
            if not allow_write:
                raise ToolError("shadow mode: mutating tools are disabled")
            record = await evidence.append(
                kind=kind,
                actor=actor,
                data=data or {},
                correlation_id=correlation_id,
                classification=classification,
            )
            return {"id": record.id, "seq": record.seq, "hash": record.hash}

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

        async def evidence_verify() -> dict[str, Any]:
            ok, detail = evidence.verify()
            return {"ok": ok, "detail": detail}

        async def evidence_read(limit: int = 20) -> list[dict[str, Any]]:
            return [r.model_dump(mode="json") for r in evidence.records(limit=limit)]

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
