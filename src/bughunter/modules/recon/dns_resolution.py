from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.exception
import dns.resolver


@dataclass
class DnsResult:
    host: str
    a_records: list[str]
    aaaa_records: list[str]
    cname_records: list[str]
    mx_records: list[str]
    txt_records: list[str]
    is_nxdomain: bool = False
    is_wildcard: bool = False
    wildcard_ips: set[str] | None = None
    error: str = ""


async def resolve_host(host: str) -> DnsResult:
    """Resolve a host via dnspython in a thread executor."""
    return await asyncio.to_thread(_resolve_sync, host)


def _resolve_sync(host: str) -> DnsResult:
    result = DnsResult(host=host, a_records=[], aaaa_records=[], cname_records=[], mx_records=[], txt_records=[])
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for rtype, attr in [
        ("A", "a_records"),
        ("AAAA", "aaaa_records"),
        ("CNAME", "cname_records"),
        ("MX", "mx_records"),
        ("TXT", "txt_records"),
    ]:
        try:
            answers = resolver.resolve(host, rtype)
            setattr(result, attr, [str(r) for r in answers])
        except dns.resolver.NXDOMAIN:
            result.is_nxdomain = True
            break
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout:
            result.error = f"timeout resolving {rtype}"
        except Exception as e:
            result.error = f"{rtype}: {e}"

    return result


async def detect_wildcard(domain: str) -> tuple[bool, set[str]]:
    """Check if domain has wildcard DNS by querying a random label."""
    import secrets
    fake_host = f"{secrets.token_hex(8)}.{domain}"
    result = await resolve_host(fake_host)
    if not result.is_nxdomain and (result.a_records or result.aaaa_records):
        ips = set(result.a_records + result.aaaa_records)
        return True, ips
    return False, set()
