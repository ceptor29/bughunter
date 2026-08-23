from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class Endpoint:
    url: str
    method: str
    params: list[str]
    path_params: list[str]
    source: str


PARAM_PATTERNS = [
    re.compile(r"[?&](\w+)=", re.I),
    re.compile(r":(\w+)(?:/|$)"),
]


async def scan_endpoint_inventory(
    base_url: str,
    client: httpx.AsyncClient,
    pages: dict[str, str] | None = None,
) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    seen: set[str] = set()

    sources: list[tuple[str, str]] = []
    if pages:
        for url, body in pages.items():
            sources.append((url, body))
    else:
        try:
            resp = await client.get(base_url, timeout=10.0)
            sources.append((base_url, resp.text[:50000]))
        except httpx.HTTPError:
            return endpoints

    for source_url, body in sources:
        for m in re.finditer(r"href=\"(/[^\"?#]+)", body):
            path = m.group(1)
            if path not in seen:
                seen.add(path)
                endpoints.append(Endpoint(
                    url=f"{base_url.rstrip('/')}{path}",
                    method="GET",
                    params=[],
                    path_params=[],
                    source="href",
                ))

        for m in re.finditer(r"action=\"([^\"]+)\"", body):
            action = m.group(1)
            if action.startswith("http"):
                url = action
            else:
                url = f"{base_url.rstrip('/')}{action}"
            if url not in seen:
                seen.add(url)
                endpoints.append(Endpoint(
                    url=url,
                    method="POST",
                    params=[],
                    path_params=[],
                    source="form-action",
                ))

        for m in re.finditer(r"/api/[a-zA-Z0-9/_-]+", body):
            path = m.group(0)
            if path not in seen:
                seen.add(path)
                endpoints.append(Endpoint(
                    url=f"{base_url.rstrip('/')}{path}",
                    method="GET",
                    params=[],
                    path_params=[],
                    source="api-pattern",
                ))

    return endpoints
