from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.exception
import dns.resolver

from bughunter.contracts.policy import CanonicalUrl, CompiledPolicy


@dataclass
class DnsAnswer:
    host: str
    records: dict[str, list[str]]
    ttl: int = 0
    resolver: str = ""
    lookup_ms: float = 0.0
    is_nxdomain: bool = False
    is_wildcard: bool = False


class DnsGateway:
    def __init__(self, policy: CompiledPolicy) -> None:
        self._policy = policy
        self._resolver = dns.resolver.Resolver()
        self._cache: dict[str, DnsAnswer] = {}

    async def resolve(self, host: str) -> DnsAnswer:
        if host in self._cache:
            return self._cache[host]

        _canonical = CanonicalUrl.from_raw(f"https://{host}")
        if not self._policy.source.is_host_allowed(host):
            return DnsAnswer(
                host=host,
                records={},
                is_nxdomain=True,
            )

        try:
            result = await asyncio.to_thread(self._resolve_sync, host)
            self._cache[host] = result
            return result
        except dns.resolver.NXDOMAIN:
            answer = DnsAnswer(host=host, records={}, is_nxdomain=True)
            self._cache[host] = answer
            return answer
        except Exception:
            answer = DnsAnswer(host=host, records={})
            self._cache[host] = answer
            return answer

    def _resolve_sync(self, host: str) -> DnsAnswer:
        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
            try:
                answers = self._resolver.resolve(host, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        return DnsAnswer(host=host, records=records)

    async def is_wildcard(self, domain: str) -> bool:
        import secrets
        fake = f"{secrets.token_hex(8)}.{domain}"
        answer = await self.resolve(fake)
        return not answer.is_nxdomain and bool(answer.records)
