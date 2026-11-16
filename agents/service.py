"""Minimal read-only health endpoint for container orchestration.

There is deliberately no work submission over HTTP. The mesh accepts work over
the authenticated bus, so this server can be small, read-only, and easy to
reason about:

    GET /health   liveness  -> 200 while the process is running
    GET /ready    readiness -> 200 only when agents and transport are healthy

Optional bearer auth (``AGENT_HEALTH_TOKEN``) protects both routes. Responses
never include secrets; only counts and status flags.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from typing import Awaitable, Callable

Provider = Callable[[str], Awaitable[tuple[int, dict]]]

REASONS = {
    200: "OK",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    503: "Service Unavailable",
}
MAX_REQUEST_BYTES = 8 * 1024


class HealthServer:
    def __init__(
        self,
        host: str,
        port: int,
        provider: Provider,
        *,
        token: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.provider = provider
        self.token = token
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
        except Exception:
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

        if self.token is not None:
            supplied = headers.get("authorization", "")
            expected = f"Bearer {self.token}"
            if not hmac.compare_digest(
                supplied.encode("latin-1", "ignore"), expected.encode("latin-1")
            ):
                return 401, {"error": "unauthorized"}

        if method not in ("GET", "HEAD"):
            return 405, {"error": "method not allowed"}
        path = target.split("?", 1)[0]
        if path not in ("/health", "/ready"):
            return 404, {"error": "not found"}
        return await self.provider(path)
