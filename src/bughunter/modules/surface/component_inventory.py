from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


@dataclass
class Component:
    name: str
    version: str | None
    source: str
    confidence: str


HEADER_PATTERNS = [
    re.compile(r"Server:\s*(\S+)", re.I),
    re.compile(r"X-Powered-By:\s*(.+?)(?:;|$)", re.I),
]

HTML_PATTERNS = [
    re.compile(r"wp-content/themes/([a-zA-Z0-9_-]+)", re.I),
    re.compile(r"wp-includes/js/([a-zA-Z0-9_-]+)/", re.I),
    re.compile(r"/(?:jquery|angular|react|vue|bootstrap|tailwind|backbone|ember|svelte)[/.-]v?(\d+\.\d+[\d.]*)(?:/|\.js)", re.I),
    re.compile(r"generator\"\s+content=\"([^\"]+)\"", re.I),
    re.compile(r"<script[^>]+src=\"([^\"]+/lib/([a-zA-Z0-9_-]+)/[^\"]+)\"", re.I),
]

JS_PATTERNS = [
    re.compile(r"webpackJsonp|__webpack_require__"),
    re.compile(r"React\.createElement|ReactDOM\.render"),
    re.compile(r"angular\.module|ng-app"),
    re.compile(r"Vue\.component|createApp|Vue\.use"),
    re.compile(r"Backbone\.Router|Backbone\.Model"),
    re.compile(r"__NEXT_DATA__"),
    re.compile(r"__NUXT__"),
    re.compile(r"gatsby"),
]

VERSION_PATTERNS = [
    re.compile(r"v(\d+\.\d+\.\d+[\w.-]*)", re.I),
    re.compile(r"version[\"':\s]+(\d+\.\d+[\d.]*[a-zA-Z0-9.-]*)", re.I),
    re.compile(r"(\d+\.\d+\.\d{1,4}[\w.-]*)", re.I),
]

CDN_PATTERNS = [
    re.compile(r"cdn\.([a-zA-Z0-9_-]+)\.com", re.I),
    re.compile(r"(?:unpkg|jsdelivr|cdnjs|cloudflare)\.com/([a-zA-Z0-9_-]+)", re.I),
]


async def scan_component_inventory(
    base_url: str,
    client: httpx.AsyncClient,
    pages: dict[str, str] | None = None,
) -> list[Component]:
    components: list[Component] = []
    seen: set[str] = set()

    try:
        resp = await client.get(base_url, timeout=10.0)
        body = resp.text[:50000]
        headers = resp.headers
    except httpx.HTTPError:
        return components

    for pat in HEADER_PATTERNS:
        for m in pat.finditer(str(headers)):
            name = m.group(1).strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                components.append(Component(name=name, version=None, source="http-header", confidence="high"))

    for pat in HTML_PATTERNS:
        for m in pat.finditer(body):
            groups = m.groups()
            name = groups[0] if groups else m.group(0)
            version = groups[1] if len(groups) > 1 else None
            if name and name.lower() not in seen:
                seen.add(name.lower())
                components.append(Component(name=name, version=version, source="html-pattern", confidence="medium"))

    for pat in CDN_PATTERNS:
        for m in pat.finditer(body):
            name = m.group(1)
            if name and name.lower() not in seen:
                seen.add(name.lower())
                components.append(Component(name=name, version=None, source="cdn-pattern", confidence="medium"))

    js_frameworks = []
    for pat in JS_PATTERNS:
        if pat.search(body):
            js_frameworks.append(pat.pattern[:30])

    if js_frameworks and "javascript-framework" not in seen:
        seen.add("javascript-framework")
        components.append(Component(
            name="javascript-framework-detected",
            version=None,
            source="js-pattern",
            confidence="low",
        ))

    for script_url in re.findall(r"src=\"(https?://[^\"]+/[a-zA-Z0-9._-]+\.js)\"", body):
        for pat in VERSION_PATTERNS:
            m = pat.search(script_url)
            if m:
                lib_name = script_url.split("/")[-1].split(".")[0]
                if lib_name.lower() not in seen:
                    seen.add(lib_name.lower())
                    components.append(Component(
                        name=lib_name,
                        version=m.group(1),
                        source="script-url",
                        confidence="medium",
                    ))
                break

    return components


@dataclass
class AdvisoryFinding:
    module: str
    title: str
    affected: str
    severity: str
    confidence: str
    url: str = ""
    evidence: str = ""
    invariant: str = ""
    remediation: str = ""


OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


async def query_osv(package_name: str, version: str | None = None) -> list[dict]:
    payload: dict = {"package": {"name": package_name, "ecosystem": "npm"}}
    if version:
        payload["version"] = version

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(OSV_QUERY, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
    except httpx.HTTPError:
        pass
    return []


async def check_dependency_advisories(
    components: list[Component],
) -> list[AdvisoryFinding]:
    findings: list[AdvisoryFinding] = []

    for comp in components:
        if comp.name in ("javascript-framework-detected",) or not comp.name:
            continue

        vulns = await query_osv(comp.name, comp.version)

        for vuln in vulns:
            severity = "high"
            for sev in vuln.get("severity", []):
                if "CVSS" in sev.get("type", ""):
                    score_str = sev.get("score", "")
                    try:
                        score = float(score_str.split("/")[-1])
                        if score >= 9.0:
                            severity = "critical"
                        elif score >= 7.0:
                            severity = "high"
                        elif score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    except (ValueError, IndexError):
                        pass

            aliases = vuln.get("aliases", [])
            summary = vuln.get("summary", "No summary")

            findings.append(AdvisoryFinding(
                module="dependency_advisories",
                title=f"Vulnerable dependency: {comp.name} ({summary})",
                affected=f"{comp.name}@{comp.version or 'unknown'}",
                severity=severity,
                confidence="high" if comp.version else "medium",
                evidence=f"OSV ID: {vuln.get('id', 'unknown')}. Aliases: {', '.join(aliases[:3])}",
                invariant="Dependencies must not contain known vulnerabilities",
                remediation=f"Update {comp.name} to a patched version. Advisory: {vuln.get('id', '')}",
            ))

    return findings
