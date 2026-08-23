from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx


@dataclass
class CrawlScope:
    allowed_schemes: set[str] = field(default_factory=lambda: {"http", "https"})
    allowed_hosts: set[str] = field(default_factory=set)
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_paths: list[str] = field(default_factory=list)
    third_party_domains: set[str] = field(default_factory=set)
    follow_external: bool = False
    same_origin_only: bool = True
    max_depth: int = 2
    max_pages: int = 50

    def is_in_scope(self, url: str, origin_host: str) -> tuple[bool, str]:
        parsed = urlparse(url)

        if parsed.scheme not in self.allowed_schemes:
            return False, "scheme_out_of_scope"

        host = parsed.hostname or ""
        if not host:
            return False, "no_host"

        if host in self.excluded_hosts:
            return False, "host_excluded"

        for pattern in self.excluded_paths:
            if parsed.path.startswith(pattern):
                return False, "path_excluded"

        if host == origin_host:
            return True, "same_origin"

        if host in self.allowed_hosts:
            return True, "allowed_host"

        if self.follow_external and host in self.third_party_domains:
            return True, "third_party_allowed"

        if self.same_origin_only:
            return False, "cross_origin_blocked"

        return False, "not_in_scope"

    def add_third_party(self, domain: str) -> None:
        self.third_party_domains.add(domain)

    def remove_third_party(self, domain: str) -> None:
        self.third_party_domains.discard(domain)


async def fetch_robots_txt(base_url: str, client: httpx.AsyncClient) -> dict[str, list[str]]:
    robots_url = f"{base_url.rstrip('/')}/robots.txt"
    try:
        resp = await client.get(robots_url, timeout=8.0)
        if resp.status_code != 200:
            return {}
        rules: dict[str, list[str]] = {}
        current_agent = "*"
        for line in resp.text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("user-agent:"):
                current_agent = line.split(":", 1)[1].strip()
            elif line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    if current_agent not in rules:
                        rules[current_agent] = []
                    rules[current_agent].append(path)
        return rules
    except httpx.HTTPError:
        return {}


def is_path_allowed_by_robots(path: str, robots_rules: dict[str, list[str]], user_agent: str = "*") -> bool:
    rules = robots_rules.get(user_agent, robots_rules.get("*", []))
    for disallowed in rules:
        if path.startswith(disallowed):
            return False
    return True


def extract_same_origin_urls(html: str, origin_url: str, scope: CrawlScope) -> list[str]:
    parsed_origin = urlparse(origin_url)
    origin_host = parsed_origin.hostname or ""
    urls: list[str] = []

    for m in re.finditer(r'(?:href|src|action)="([^"]+)"', html, re.IGNORECASE):
        raw = m.group(1)
        if raw.startswith("#") or raw.startswith("javascript:") or raw.startswith("mailto:"):
            continue

        if raw.startswith("//"):
            full_url = f"{parsed_origin.scheme}:{raw}"
        elif raw.startswith("/"):
            full_url = f"{parsed_origin.scheme}://{origin_host}{raw}"
        elif raw.startswith("http://") or raw.startswith("https://"):
            full_url = raw
        else:
            full_url = f"{parsed_origin.scheme}://{origin_host}{parsed_origin.path.rsplit('/', 1)[0]}/{raw}"

        in_scope, _ = scope.is_in_scope(full_url, origin_host)
        if in_scope:
            urls.append(full_url)

    return list(set(urls))


def should_follow_link(url: str, origin_host: str, scope: CrawlScope, depth: int) -> bool:
    if depth > scope.max_depth:
        return False
    in_scope, reason = scope.is_in_scope(url, origin_host)
    if not in_scope:
        return False
    if scope.same_origin_only:
        parsed = urlparse(url)
        if parsed.hostname != origin_host:
            return False
    return True
