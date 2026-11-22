"""Model clients.

Agents depend on the small ``LLM`` protocol, not on a vendor SDK:

* ``OpenAICompatibleLLM`` works with OpenAI, OpenRouter, vLLM, Ollama, LiteLLM
  and anything else exposing ``/chat/completions``.
* ``EchoLLM`` is deterministic and offline. It lets the mesh, the demo and the
  tests run with no key, and it is obviously *not* an intelligence layer - its
  output says so. Real work needs a real endpoint.

Structured output is requested with a JSON schema; providers that reject
``response_format`` fall back to a "reply with JSON only" instruction. Parsing
is defensive either way.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from .observability import error_fingerprint, log
from .security import SecurityError


class LLMResponse(BaseModel):
    text: str
    data: dict[str, Any] | None = None
    tokens: int = 0
    model: str = ""


@runtime_checkable
class LLM(Protocol):
    async def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, str]],
        json_schema: dict[str, Any] | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse: ...

    async def close(self) -> None: ...


_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model reply, fences or not."""
    candidates = [text]
    candidates += _JSON_BLOCK.findall(text)
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            start, end = candidate.find("{"), candidate.rfind("}")
            if start == -1 or end <= start:
                continue
            try:
                value = json.loads(candidate[start : end + 1])
            except json.JSONDecodeError:
                continue
        if isinstance(value, dict):
            return value
    return None


class OpenAICompatibleLLM:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        model: str = "gpt-4.1-mini",
        timeout_s: float = 60.0,
        temperature: float = 0.0,
        max_retries: int = 2,
        allow_insecure: bool = False,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise SecurityError("AGENT_LLM_BASE_URL must be an http(s) URL")
        if (
            parsed.scheme == "http"
            and not allow_insecure
            and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        ):
            raise SecurityError(
                "AGENT_LLM_BASE_URL must use https:// so the API key is not sent "
                "in clear text; set AGENT_ALLOW_INSECURE_LLM=true only for a "
                "trusted local network"
            )
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=httpx.Timeout(timeout_s, connect=10.0),
        )

    async def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, str]],
        json_schema: dict[str, Any] | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        chosen = model or self.model
        body: dict[str, Any] = {
            "model": chosen,
            "temperature": self.temperature,
            "messages": [{"role": "system", "content": system}, *messages],
        }
        if max_tokens:
            body["max_tokens"] = max_tokens
        if json_schema:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": json_schema.get("title", "output"),
                    "strict": True,
                    "schema": json_schema,
                },
            }

        last_error: Exception | None = None
        last_status: int | None = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._client.post("/chat/completions", json=body)
                last_status = resp.status_code
                if resp.status_code in (400, 422) and json_schema:
                    # Provider does not support json_schema; ask in prose instead.
                    log("llm.schema_fallback", status=resp.status_code, model=chosen)
                    body.pop("response_format", None)
                    body["messages"] = [
                        {"role": "system", "content": f"{system}\n\nReply with one JSON object that conforms to this schema:\n{json.dumps(json_schema)}"},
                        *messages,
                    ]
                    json_schema = None
                    continue
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise httpx.HTTPStatusError("retryable", request=resp.request, response=resp)
                resp.raise_for_status()
                payload = resp.json()
                # Providers occasionally return 200 with an empty or partial
                # body. Treat that as a retryable fault instead of letting an
                # IndexError/TypeError escape past the retry budget.
                choices = payload.get("choices") if isinstance(payload, dict) else None
                if not isinstance(choices, list) or not choices:
                    raise ValueError("LLM response contained no choices")
                choice = choices[0].get("message") if isinstance(choices[0], dict) else None
                if not isinstance(choice, dict):
                    raise ValueError("LLM response contained a malformed choice")
                text = choice.get("content") or ""
                usage = payload.get("usage") or {}
                tokens = int(usage.get("prompt_tokens", 0) or 0) + int(
                    usage.get("completion_tokens", 0) or 0
                )
                return LLMResponse(
                    text=text,
                    # Tool rounds call complete() without a schema, so parsing
                    # only here would drop every structured tool response.
                    data=extract_json(text),
                    tokens=tokens,
                    model=payload.get("model", chosen),
                )
            except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                log(
                    "llm.retry",
                    level="WARNING",
                    model=chosen,
                    attempt=attempt + 1,
                    attempts=self.max_retries + 1,
                    error_type=type(exc).__name__,
                    status=last_status,
                )
                await asyncio.sleep(0.5 * 2**attempt)
                continue
        log(
            "llm.failed",
            level="ERROR",
            fingerprint=error_fingerprint(last_error) if last_error else None,
            model=chosen,
            attempts=self.max_retries + 1,
            error_type=type(last_error).__name__ if last_error else "Unknown",
            status=last_status,
            error=repr(last_error),
        )
        raise RuntimeError(f"LLM call failed after {self.max_retries + 1} attempts: {last_error}")

    async def close(self) -> None:
        await self._client.aclose()


class EchoLLM:
    """Offline stand-in. Deterministic, cheap, and honest about being a stand-in."""

    def __init__(self, model: str = "offline-echo") -> None:
        self.model = model
        self.calls = 0

    async def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, str]],
        json_schema: dict[str, Any] | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls += 1
        raw = messages[-1]["content"] if messages else ""
        objective, inputs = raw, {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                objective = str(parsed.get("objective") or parsed.get("goal") or raw)
                inputs = parsed.get("inputs") or {}
        except json.JSONDecodeError:
            parsed = None

        summary = f"[offline model] Processed: {objective}"
        data: dict[str, Any] = {
            "offline": True,
            "note": "No AGENT_LLM_BASE_URL configured; output is a deterministic echo, not model work.",
            "received": sorted(inputs) if isinstance(inputs, dict) else [],
        }
        text = json.dumps({"summary": summary, "data": data, "confidence": 0.2}, default=str)
        return LLMResponse(text=text, data=json.loads(text), tokens=0, model=self.model)

    async def close(self) -> None:
        return None


def build_llm(settings: Any) -> LLM:
    if settings.llm_base_url:
        return OpenAICompatibleLLM(
            settings.llm_base_url,
            settings.llm_api_key,
            model=settings.model,
            timeout_s=settings.llm_timeout_s,
            temperature=settings.temperature,
            allow_insecure=settings.allow_insecure_llm,
        )
    return EchoLLM()
