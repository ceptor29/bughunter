from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx


@dataclass
class PassiveSource:
    name: str
    hostnames: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


async def crtsh_source(domain: str, client: httpx.AsyncClient) -> PassiveSource:
    src = PassiveSource(name="crt.sh")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await client.get(url, timeout=15.0)
        if resp.status_code == 200:
            import json
            data = json.loads(resp.text)
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{domain}") or line == domain:
                        src.hostnames.add(line)
    except Exception as e:
        src.errors.append(f"crt.sh: {e}")
    return src


async def hackertarget_source(domain: str, client: httpx.AsyncClient) -> PassiveSource:
    src = PassiveSource(name="hackertarget")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                host = line.split(",")[0].strip().lower()
                if host.endswith(f".{domain}") or host == domain:
                    src.hostnames.add(host)
    except Exception as e:
        src.errors.append(f"hackertarget: {e}")
    return src


async def rapiddns_source(domain: str, client: httpx.AsyncClient) -> PassiveSource:
    src = PassiveSource(name="rapiddns")
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            for row in soup.select("table tbody tr"):
                cols = row.find_all("td")
                if cols:
                    host = cols[0].text.strip().lower()
                    if host.endswith(f".{domain}") or host == domain:
                        src.hostnames.add(host)
    except Exception as e:
        src.errors.append(f"rapiddns: {e}")
    return src


ALL_SOURCES = [crtsh_source, hackertarget_source, rapiddns_source]


async def enumerate_subdomains(domain: str) -> tuple[set[str], list[str]]:
    """Run all passive sources, return merged hostnames + errors."""
    all_hosts: set[str] = set()
    all_errors: list[str] = []
    async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
        tasks = [src(domain, client) for src in ALL_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                all_errors.append(str(r))
            elif isinstance(r, PassiveSource):
                all_hosts.update(r.hostnames)
                all_errors.extend(r.errors)
    all_hosts.add(domain)
    return all_hosts, all_errors
