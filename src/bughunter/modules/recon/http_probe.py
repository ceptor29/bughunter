from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


@dataclass
class ProbeResult:
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    tech_markers: list[str] = field(default_factory=list)
    body_snippet: str = ""
    error: str = ""


TECH_SIGNATURES = {
    "X-Powered-By: PHP": "PHP",
    "X-Powered-By: ASP.NET": "ASP.NET",
    "X-Powered-By: Express": "Node.js/Express",
    "X-Powered-By: Next.js": "Next.js",
    "Server: Apache": "Apache",
    "Server: nginx": "Nginx",
    "Server: cloudflare": "Cloudflare",
    "Server: Microsoft-IIS": "IIS",
    "__NEXT_DATA__": "Next.js",
    "wp-content": "WordPress",
    "Drupal": "Drupal",
    "Joomla": "Joomla",
    "React": "React",
    "Vue": "Vue.js",
    "Angular": "Angular",
    "Django": "Django",
    "Flask": "Flask",
    "Rails": "Ruby on Rails",
    "Laravel": "Laravel",
    "Spring": "Spring",
}


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    techs = []
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    for sig, name in TECH_SIGNATURES.items():
        if sig in header_str or sig in body[:5000]:
            techs.append(name)
    return techs


async def probe_host(
    host: str,
    client: httpx.AsyncClient,
    timeout: float = 10.0,
) -> list[ProbeResult]:
    """Probe https then http, return results for each that responds."""
    results = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = await client.get(url, timeout=timeout)
            body = resp.text[:10000]
            soup = BeautifulSoup(body, "html.parser") if resp.status_code < 500 else None
            title = soup.title.string.strip() if soup and soup.title and soup.title.string else ""

            headers = dict(resp.headers)
            techs = _detect_tech(headers, body)

            results.append(ProbeResult(
                url=str(resp.url),
                status=resp.status_code,
                title=title,
                server=headers.get("server", ""),
                powered_by=headers.get("x-powered-by", ""),
                content_type=headers.get("content-type", ""),
                content_length=int(headers.get("content-length", 0)),
                redirect_url=str(resp.url) if str(resp.url) != url else "",
                headers=headers,
                tech_markers=techs,
                body_snippet=body[:500],
            ))
            if resp.status_code < 400:
                break
        except Exception as e:
            results.append(ProbeResult(url=url, error=str(e)))
    return results
