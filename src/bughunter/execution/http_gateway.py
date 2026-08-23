from __future__ import annotations

import asyncio
from typing import Any

import httpx

from bughunter.contracts.enums import HttpMethod
from bughunter.contracts.policy import CompiledPolicy, ScopeDecision, CanonicalUrl, ScopeAction
from .rate_limits import RateLimiter


class HttpResponse:
    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        text: str,
        elapsed_ms: float,
        url: str,
        redirect_chain: list[str] | None = None,
    ) -> None:
        self.status = status
        self.headers = headers
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.url = url
        self.redirect_chain = redirect_chain or []


class HttpGateway:
    def __init__(
        self,
        policy: CompiledPolicy,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 10.0,
        max_response_bytes: int = 1_048_576,
        user_agents: list[str] | None = None,
    ) -> None:
        self._policy = policy
        self._rate_limiter = rate_limiter or RateLimiter()
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ]
        self._client: httpx.AsyncClient | None = None
        self._scope_decisions: list[ScopeDecision] = []

    async def __aenter__(self) -> HttpGateway:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            http2=True,
            headers={"User-Agent": self._user_agents[0]},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    def check_scope(self, url: str, method: str = "GET") -> ScopeDecision:
        canonical = CanonicalUrl.from_raw(url)
        decision = self._policy.source.evaluate(canonical, HttpMethod(method))
        self._scope_decisions.append(decision)
        return decision

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        decision = self.check_scope(url, method)
        if not decision.allowed:
            raise ScopeViolationError(f"Scope denied: {decision.reasons}")

        await self._rate_limiter.wait()

        assert self._client is not None, "HttpGateway must be used as async context manager"
        try:
            resp = await self._client.request(
                method=method,
                url=url,
                headers=headers or {},
                content=body,
            )
            text = resp.text[: self._max_response_bytes]
            return HttpResponse(
                status=resp.status_code,
                headers=dict(resp.headers),
                text=text,
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                url=str(resp.url),
            )
        except httpx.TimeoutException:
            return HttpResponse(
                status=0, headers={}, text="TIMEOUT",
                elapsed_ms=self._timeout * 1000, url=url,
            )
        except Exception as e:
            return HttpResponse(
                status=0, headers={}, text=f"ERROR: {e}",
                elapsed_ms=0, url=url,
            )

    @property
    def scope_decisions(self) -> list[ScopeDecision]:
        return list(self._scope_decisions)


class ScopeViolationError(Exception):
    pass
