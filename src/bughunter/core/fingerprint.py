from __future__ import annotations

import hashlib
from typing import Any


def generate_fingerprint(
    weakness_type: str,
    canonical_asset: str,
    route_template: str,
    parameter: str = "",
    invariant: str = "",
) -> str:
    """Generate a stable fingerprint from canonical components.
    Excludes mutable text (titles, timestamps) per V2 §11.3."""
    parts = [
        weakness_type.lower().strip(),
        canonical_asset.lower().strip(),
        route_template.lower().strip(),
        parameter.lower().strip(),
        invariant.lower().strip(),
    ]
    content = ":".join(parts)
    return hashlib.sha256(content.encode()).hexdigest()[:24]


def fingerprint_from_url(
    weakness_type: str,
    url: str,
    param: str = "",
    invariant: str = "",
) -> str:
    """Extract route template from URL and generate fingerprint."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    route = f"{parsed.scheme}://{parsed.netloc}{path}"
    host = parsed.netloc
    return generate_fingerprint(weakness_type, host, route, param, invariant)


FINGERPRINT_SEEDS: dict[str, str] = {
    "exposed_artifact": "v1:exposed-artifact",
    "repository_metadata": "v1:repository-metadata",
    "takeover": "v1:subdomain-takeover",
    "security_controls": "v1:security-controls",
    "graphql_surface": "v1:graphql-surface",
    "component_exposure": "v1:component-exposure",
    "open_redirect": "v1:open-redirect",
    "path_traversal": "v1:path-traversal",
    "ssti": "v1:ssti",
    "sqli_error": "v1:sqli-error",
    "sqli_blind": "v1:sqli-blind",
    "xss_reflected": "v1:xss-reflected",
    "xss_dom": "v1:xss-dom",
    "crlf": "v1:crlf",
    "ssrf": "v1:ssrf",
    "idor": "v1:idor",
    "auth_bypass": "v1:auth-bypass",
    "priv_escalation": "v1:priv-escalation",
    "jwt_flaw": "v1:jwt-flaw",
    "oauth_misconfig": "v1:oauth-misconfig",
    "race_condition": "v1:race-condition",
    "upload_bypass": "v1:upload-bypass",
    "xxe": "v1:xxe",
    "cache_poison": "v1:cache-poison",
    "websocket_hijack": "v1:websocket-hijack",
}
