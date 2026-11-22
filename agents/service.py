"""Minimal read-only health endpoint for container orchestration.

There is deliberately no work submission over HTTP. The mesh accepts work over
the authenticated bus, so this server can be small, read-only, and easy to
reason about:

    GET /health       liveness  -> public counts and flags only
    GET /ready        readiness -> public 200/503, counts only
    GET /diagnostics  admin     -> topology and issues, admin token required

``AGENT_HEALTH_TOKEN`` optionally protects /health and /ready. Diagnostics is a
separate administrative surface: it returns topology and issue detail, so it is
only served when ``AGENT_ADMIN_TOKEN`` (or its file) is configured, and it is
hidden entirely otherwise. Public responses never include agent ids, internal
endpoints, configuration errors, or secret values.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from typing import Awaitable, Callable

from .observability import error_fingerprint, log

Provider = Callable[[str], Awaitable[tuple[int, dict]]]

REASONS = {
    200: "OK",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
MAX_REQUEST_BYTES = 8 * 1024


def _request_path(raw: bytes) -> str:
    """Best-effort route label for logs; never include query strings or bodies."""
    try:
        return raw.decode("latin-1").split("\r\n", 1)[0].split(" ", 2)[1]
    except (IndexError, UnicodeError, ValueError):
        return "-"


class HealthServer:
    def __init__(
        self,
        host: str,
        port: int,
        provider: Provider,
        *,
        token: str | None = None,
        admin_token: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.provider = provider
        self.token = token
        self.admin_token = admin_token
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        status = 400
        payload: dict = {"error": "bad request"}
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
            if len(raw) > MAX_REQUEST_BYTES:
                status, payload = 400, {"error": "request too large"}
            else:
                status, payload = await self._dispatch(raw)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            status, payload = 408, {"error": "incomplete request"}
        except Exception as exc:
            log(
                "health.server_error",
                level="ERROR",
                fingerprint=error_fingerprint(exc),
                path=_request_path(raw),
                error_type=type(exc).__name__,
                error=repr(exc),
            )
            status, payload = 500, {"error": "internal error"}
        finally:
            body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
            reason = REASONS.get(status, "Error")
            head = (
                f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Cache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Connection: close\r\n\r\n"
            ).encode("latin-1")
            try:
                writer.write(head + body)
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

    async def _dispatch(self, raw: bytes) -> tuple[int, dict]:
        lines = raw.decode("latin-1").split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            return 400, {"error": "malformed request line"}
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        if method not in ("GET", "HEAD"):
            return 405, {"error": "method not allowed"}
        path = target.split("?", 1)[0]

        # Diagnostics exposes topology, so it is a separate admin surface. If
        # no admin token is configured the route does not exist (fail closed).
        if path == "/diagnostics":
            if self.admin_token is None:
                return 404, {"error": "not found"}
            if not self._authorized(headers, self.admin_token):
                return 401, {"error": "unauthorized"}
        elif self.token is not None:
            if not self._authorized(headers, self.token):
                return 401, {"error": "unauthorized"}

        if path not in ("/health", "/ready", "/diagnostics"):
            return 404, {"error": "not found"}
        return await self.provider(path)

    @staticmethod
    def _authorized(headers: dict[str, str], token: str) -> bool:
        supplied = headers.get("authorization", "")
        expected = f"Bearer {token}"
        return hmac.compare_digest(
            supplied.encode("latin-1", "ignore"), expected.encode("latin-1")
        )
