from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class ArtifactFinding:
    module: str
    title: str
    url: str
    evidence: str
    severity: str
    confidence: str
    invariant: str = ""
    remediation: str = ""


PROBE_PATHS = [
    "/.env", "/.env.local", "/.env.bak", "/.env.old",
    "/phpinfo.php", "/info.php", "/test.php",
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
    "/actuator", "/actuator/env", "/actuator/health",
    "/server-status", "/server-info",
    "/debug/vars", "/debug/pprof",
    "/.DS_Store", "/.htaccess", "/web.config",
    "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/config.json", "/config.yml", "/config.php",
    "/wp-config.php.bak", "/wp-config.php",
    "/.svn/entries", "/.bzr/README",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd",
    "/.well-known/security.txt",
]

ENV_KEY_PATTERNS = re.compile(
    r"(DB_|AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE|MYSQL|POSTGRES|REDIS|MONGO|MAIL|SMTP|SENDGRID|STRIPE|PAYPAL)",
    re.IGNORECASE,
)

DIR_LISTING_MARKERS = ["Index of /", "Parent Directory", "<title>Index of"]


def _is_env_content(body: str) -> bool:
    lines = body.strip().split("\n")
    key_value_count = 0
    for line in lines[:30]:
        if "=" in line and not line.strip().startswith("#"):
            key, _, val = line.partition("=")
            if key.strip() and val.strip():
                key_value_count += 1
    return key_value_count >= 3


def _has_credential_keys(body: str) -> bool:
    return bool(ENV_KEY_PATTERNS.search(body))


def _classify_env(body: str) -> tuple[str, str]:
    if _has_credential_keys(body):
        return "critical", "credential_exposure"
    if _is_env_content(body):
        return "high", "config_exposure"
    return "medium", "config_file"


PHPINFO_MARKERS = ["phpinfo()", "PHP Version", "php.ini"]


def _classify_phpinfo(body: str) -> tuple[str, str]:
    has_sensitive = any(m in body for m in ["SERVER_NAME", "DOCUMENT_ROOT", "SCRIPT_FILENAME"])
    if has_sensitive:
        return "high", "phpinfo_sensitive"
    return "medium", "phpinfo_info_only"


def _classify_swagger(body: str) -> tuple[str, str]:
    if "\"securityDefinitions\"" in body or "\"bearerAuth\"" in body:
        return "high", "swagger_with_auth"
    return "medium", "api_documentation_exposed"


def _classify_debug(body: str) -> tuple[str, str]:
    if any(k in body for k in ["password", "secret", "token", "key", "credential"]):
        return "critical", "debug_credential_leak"
    return "high", "debug_endpoint_exposed"


DIR_LISTING_EXTENSIONS = {".zip", ".tar.gz", ".sql", ".bak", ".old", ".dump"}


def _classify_dir_listing(body: str, url: str) -> tuple[str, str]:
    for ext in DIR_LISTING_EXTENSIONS:
        if ext in body:
            return "critical", f"backup_in_listing{ext}"
    return "high", "directory_listing"


def _redact_env(body: str) -> str:
    lines = body.strip().split("\n")
    redacted = []
    for line in lines[:20]:
        if "=" in line and not line.strip().startswith("#"):
            key, _, val = line.partition("=")
            if val.strip() and len(val.strip()) > 4:
                redacted.append(f"{key.strip()}={val.strip()[:4]}{'*' * min(len(val.strip()) - 4, 8)}")
            else:
                redacted.append(line.strip())
        else:
            redacted.append(line.strip())
    return "\n".join(redacted)


async def scan_exposed_artifacts(
    base_url: str,
    client: httpx.AsyncClient,
    already_probed: set[str] | None = None,
) -> list[ArtifactFinding]:
    findings: list[ArtifactFinding] = []
    probed = already_probed or set()

    async def _check(path: str) -> None:
        if path in probed:
            return
        probed.add(path)
        try:
            resp = await client.get(f"{base_url.rstrip('/')}{path}", timeout=8.0)
        except httpx.HTTPError:
            return

        if resp.status_code != 200:
            return

        body = resp.text[:15000]
        content_type = resp.headers.get("content-type", "")
        content_length = resp.headers.get("content-length", "0")

        if int(content_length or "0") > 500000:
            return

        url = f"{base_url.rstrip('/')}{path}"
        severity = "medium"
        confidence = "medium"
        evidence = ""
        invariant = ""
        remediation = ""
        title = ""

        if path.startswith("/.env") or "env" in path.lower():
            severity, kind = _classify_env(body)
            if kind == "credential_exposure":
                title = "Environment file with credentials exposed"
                invariant = "No credential-bearing files should be publicly accessible"
                remediation = "Move .env files outside web root, add server-level deny rules"
                evidence = _redact_env(body)
            else:
                title = "Environment file exposed"
                invariant = "Configuration files should not be publicly accessible"
                remediation = "Add server-level deny rules for dotfiles"
                evidence = _redact_env(body)
            confidence = "high"

        elif "phpinfo" in path.lower() or any(m in body for m in PHPINFO_MARKERS):
            severity, kind = _classify_phpinfo(body)
            title = "phpinfo() page exposed" if kind == "phpinfo_sensitive" else "phpinfo() info page exposed"
            invariant = "Server configuration details should not be publicly accessible"
            remediation = "Remove phpinfo() pages from production"
            evidence = body[:500]
            confidence = "high"

        elif any(m in path.lower() for m in ["swagger", "openapi", "api-docs"]):
            severity, kind = _classify_swagger(body)
            title = "API documentation exposed"
            invariant = "API documentation should not be publicly accessible"
            remediation = "Restrict API docs to internal networks or authenticated users"
            evidence = body[:300]
            confidence = "medium"

        elif any(m in path.lower() for m in ["actuator", "server-status", "server-info"]):
            severity = "high"
            title = "Application actuator/monitoring endpoint exposed"
            invariant = "Monitoring endpoints should not be publicly accessible"
            remediation = "Restrict actuator endpoints to internal management port"
            evidence = body[:300]
            confidence = "high"

        elif any(m in path.lower() for m in ["debug", "elmah", "trace"]):
            severity, kind = _classify_debug(body)
            title = "Debug endpoint exposed"
            invariant = "Debug endpoints should not be accessible in production"
            remediation = "Disable debug endpoints in production, restrict to VPN"
            evidence = body[:300]
            confidence = "high"

        elif any(m in body for m in DIR_LISTING_MARKERS):
            severity, kind = _classify_dir_listing(body, url)
            title = "Directory listing enabled" if kind == "directory_listing" else "Backup file in directory listing"
            invariant = "Directory listings should not expose backup files"
            remediation = "Disable directory listing, move backups outside web root"
            evidence = body[:300]
            confidence = "high"

        elif any(m in body for m in ["DS_Store", "htaccess", "web.config"]):
            severity = "low"
            title = "Server configuration file exposed"
            invariant = "Server configuration files should not be publicly accessible"
            remediation = "Add server-level deny rules for configuration files"
            evidence = body[:100]
            confidence = "medium"

        elif path.endswith(("/wp-config.php", "/wp-config.php.bak")):
            severity = "critical"
            title = "WordPress configuration file exposed"
            invariant = "WordPress config files should not be publicly accessible"
            remediation = "Move wp-config.php outside web root"
            evidence = body[:200]
            confidence = "high"

        elif path.startswith("/.svn") or path.startswith("/.bzr"):
            severity = "high"
            title = "Version control metadata exposed"
            invariant = "Version control metadata should not be publicly accessible"
            remediation = "Add server-level deny rules for VCS directories"
            evidence = body[:200]
            confidence = "high"

        else:
            return

        findings.append(ArtifactFinding(
            module="exposed_artifacts",
            title=title,
            url=url,
            evidence=evidence,
            severity=severity,
            confidence=confidence,
            invariant=invariant,
            remediation=remediation,
        ))

    import asyncio
    await asyncio.gather(*[_check(p) for p in PROBE_PATHS])
    return findings
