from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class RepoFinding:
    module: str
    title: str
    url: str
    evidence: str
    severity: str
    confidence: str
    invariant: str = ""
    remediation: str = ""


GIT_OBJECT_RE = re.compile(r"ref:\s*refs/heads/(\S+)")


async def scan_repository_metadata(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[RepoFinding]:
    findings: list[RepoFinding] = []
    paths_to_check = [
        ("/.git/HEAD", "Git HEAD reference"),
        ("/.git/config", "Git configuration"),
        ("/.gitignore", "Git ignore rules"),
    ]

    for path, description in paths_to_check:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = await client.get(url, timeout=8.0)
        except httpx.HTTPError:
            continue

        if resp.status_code != 200:
            continue

        body = resp.text[:5000]
        severity = "medium"
        evidence = ""
        title = ""
        invariant = ""
        remediation = ""

        if path == "/.git/HEAD":
            match = GIT_OBJECT_RE.search(body)
            if match:
                branch = match.group(1)
                title = f"Git repository exposed (HEAD -> {branch})"
                invariant = "Version control metadata should not be publicly accessible"
                remediation = "Add server-level deny rules for .git/ directory"
                evidence = body.strip()
                severity = "high"
            else:
                continue

        elif path == "/.git/config":
            has_remote = "remote" in body.lower() or "url" in body.lower()
            if has_remote:
                title = "Git configuration exposed (remote URLs visible)"
                invariant = "Git configuration should not be publicly accessible"
                remediation = "Add server-level deny rules for .git/ directory"
                evidence = body[:500]
                severity = "high"
            else:
                title = "Git configuration file exposed"
                invariant = "Git configuration should not be publicly accessible"
                remediation = "Add server-level deny rules for .git/ directory"
                evidence = body[:200]
                severity = "medium"

        elif path == "/.gitignore":
            sensitive_patterns = [
                r"\.env", r"secret", r"key", r"credential", r"password",
                r"\.pem", r"\.key", r"\.p12", r"\.jks",
            ]
            body_lower = body.lower()
            if any(re.search(p, body_lower) for p in sensitive_patterns):
                title = "Git ignore file reveals sensitive file patterns"
                invariant = "Git ignore rules should not hint at sensitive files"
                remediation = "Review .gitignore to ensure sensitive files are not tracked"
                evidence = body[:300]
                severity = "medium"
            else:
                continue

        else:
            continue

        findings.append(RepoFinding(
            module="repository_metadata",
            title=title,
            url=url,
            evidence=evidence,
            severity=severity,
            confidence="high",
            invariant=invariant,
            remediation=remediation,
        ))

    return findings
