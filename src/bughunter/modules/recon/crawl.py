from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[dict[str, str]]
    enctype: str = ""


@dataclass
class CrawlResult:
    url: str
    forms: list[FormInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    params_found: list[dict[str, str]] = field(default_factory=list)
    error: str = ""


def _extract_forms(soup: BeautifulSoup, base_url: str) -> list[FormInfo]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        method = (form.get("method") or "GET").upper()
        enctype = form.get("enctype", "")
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append(FormInfo(action=action, method=method, inputs=inputs, enctype=enctype))
    return forms


def _extract_params(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    params = []
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.append({"url": url, "param": k, "value": v})
    return params


async def crawl_page(
    url: str,
    client: httpx.AsyncClient,
    max_depth: int = 1,
    visited: set[str] | None = None,
) -> CrawlResult:
    visited = visited or set()
    if url in visited:
        return CrawlResult(url=url)
    visited.add(url)

    try:
        resp = await client.get(url, timeout=10.0)
        body = resp.text[:50000]
        soup = BeautifulSoup(body, "html.parser")
    except Exception as e:
        return CrawlResult(url=url, error=str(e))

    forms = _extract_forms(soup, url)
    links = []
    script_srcs = []
    params = _extract_params(url)

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith(("http://", "https://")):
            links.append(href)
        elif href.startswith("/"):
            parsed = urlparse(url)
            links.append(f"{parsed.scheme}://{parsed.netloc}{href}")

    for script in soup.find_all("script", src=True):
        src = script["src"]
        if src.startswith(("http://", "https://")):
            script_srcs.append(src)
        elif src.startswith("/"):
            parsed = urlparse(url)
            script_srcs.append(f"{parsed.scheme}://{parsed.netloc}{src}")

    return CrawlResult(
        url=url,
        forms=forms,
        links=links,
        script_srcs=script_srcs,
        params_found=params,
    )
