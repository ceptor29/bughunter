from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class SecurityFinding:
    module: str
    title: str
    url: str
    evidence: str
    severity: str
    confidence: str
    invariant: str = ""
    remediation: str = ""


MISSING_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "title": "Missing HSTS header",
        "severity": "high",
        "invariant": "HTTPS-only sites must include HSTS with appropriate max-age",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header": "X-Frame-Options",
        "title": "Missing X-Frame-Options header (clickjacking)",
        "severity": "medium",
        "invariant": "Framable pages must declare X-Frame-Options or CSP frame-ancestors",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
        "header": "X-Content-Type-Options",
        "title": "Missing X-Content-Type-Options header",
        "severity": "low",
        "invariant": "Pages should prevent MIME type sniffing",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    {
        "header": "Content-Security-Policy",
        "title": "Missing Content-Security-Policy header",
        "severity": "medium",
        "invariant": "Pages should define a CSP to limit resource loading origins",
        "remediation": "Add Content-Security-Policy header with appropriate directives",
    },
    {
        "header": "Referrer-Policy",
        "title": "Missing Referrer-Policy header",
        "severity": "low",
        "invariant": "Pages should control referrer information leakage",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
]

COOKIE_SECURE_ATTRIBUTES = ["Secure", "HttpOnly", "SameSite"]
CSRF_TOKEN_PATTERNS = ["csrf", "xsrf", "_token", "authenticity_token"]


def _check_csp(csp: str) -> list[str]:
    issues: list[str] = []
    csp_lower = csp.lower()

    if "unsafe-inline" in csp_lower:
        issues.append("CSP allows unsafe-inline")
    if "unsafe-eval" in csp_lower:
        issues.append("CSP allows unsafe-eval")
    if "*" in csp_lower and "default-src *" in csp_lower:
        issues.append("CSP default-src allows all origins")
    if "data:" in csp_lower and "default-src" not in csp_lower:
        issues.append("CSP allows data: URIs")
    if "connect-src *" in csp_lower:
        issues.append("CSP connect-src allows all origins")
    return issues


def _check_cookies(headers: httpx.Headers) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    cookies_raw = headers.get_list("set-cookie")

    for cookie in cookies_raw:
        cookie_lower = cookie.lower()
        missing: list[str] = []

        if "secure" not in cookie_lower:
            missing.append("Secure")
        if "httponly" not in cookie_lower:
            missing.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing.append("SameSite")

        if missing:
            name = cookie.split("=")[0].strip()
            findings.append(SecurityFinding(
                module="security_controls",
                title=f"Cookie '{name}' missing attributes: {', '.join(missing)}",
                url="",
                evidence=f"Set-Cookie: {cookie[:200]}",
                severity="medium" if "HttpOnly" in missing or "Secure" in missing else "low",
                confidence="high",
                invariant="Cookies must use Secure, HttpOnly, and SameSite attributes",
                remediation=f"Add {', '.join(missing)} to cookie '{name}'",
            ))

    return findings


def _check_cors(headers: httpx.Headers) -> SecurityFinding | None:
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        return SecurityFinding(
            module="security_controls",
            title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
            url="",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            severity="high",
            confidence="high",
            invariant="CORS must not allow all origins for authenticated endpoints",
            remediation="Replace wildcard with explicit origin whitelist",
        )
    return None


async def scan_security_controls(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    try:
        resp = await client.get(base_url, timeout=10.0)
    except httpx.HTTPError:
        return findings

    headers = resp.headers
    url = base_url
    body = resp.text[:5000]

    # Check missing headers
    for check in MISSING_HEADERS:
        if check["header"].lower() not in {h.lower() for h in headers.keys()}:
            findings.append(SecurityFinding(
                module="security_controls",
                title=check["title"],
                url=url,
                evidence=f"Missing header: {check['header']}",
                severity=check["severity"],
                confidence="high",
                invariant=check["invariant"],
                remediation=check["remediation"],
            ))

    # Check CSP quality
    csp = headers.get("content-security-policy", "")
    if csp:
        csp_issues = _check_csp(csp)
        for issue in csp_issues:
            findings.append(SecurityFinding(
                module="security_controls",
                title=f"CSP policy issue: {issue}",
                url=url,
                evidence=f"CSP: {csp[:300]}",
                severity="medium",
                confidence="medium",
                invariant="CSP should not use unsafe directives",
                remediation=f"Review and harden CSP: {issue}",
            ))

    # Check cookies
    cookie_findings = _check_cookies(headers)
    for f in cookie_findings:
        f.url = url
        findings.append(f)

    # Check CORS
    cors_finding = _check_cors(headers)
    if cors_finding:
        cors_finding.url = url
        findings.append(cors_finding)

    # Check for clickjacking (X-Frame-Options or CSP frame-ancestors)
    has_xfo = "x-frame-options" in {h.lower() for h in headers.keys()}
    has_csp_frame = "frame-ancestors" in csp.lower() if csp else False
    if not has_xfo and not has_csp_frame:
        content_type = headers.get("content-type", "")
        if "text/html" in content_type:
            findings.append(SecurityFinding(
                module="security_controls",
                title="HTML page frameable (clickjacking risk)",
                url=url,
                evidence="No X-Frame-Options or CSP frame-ancestors on HTML page",
                severity="medium",
                confidence="medium",
                invariant="HTML pages must declare framing restrictions",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors directive",
            ))

    # Check for password in URL
    body_lower = body.lower()
    for token in CSRF_TOKEN_PATTERNS:
        if token in body_lower:
            break
    else:
        has_form = "<form" in body_lower
        if has_form:
            findings.append(SecurityFinding(
                module="security_controls",
                title="Form page without CSRF token",
                url=url,
                evidence="Form element found without CSRF token patterns",
                severity="medium",
                confidence="low",
                invariant="State-changing forms must include CSRF tokens",
                remediation="Add CSRF token to all state-changing forms",
            ))

    return findings
