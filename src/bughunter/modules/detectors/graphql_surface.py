from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class GraphqlFinding:
    module: str
    title: str
    url: str
    evidence: str
    severity: str
    confidence: str
    invariant: str = ""
    remediation: str = ""


GRAPHQL_ENDPOINTS = ["/graphql", "/graphiql", "/v1/graphql", "/v2/graphql", "/api/graphql", "/query"]
INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}'

SENSITIVE_TYPE_PATTERNS = [
    re.compile(r"password", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"token", re.I),
    re.compile(r"session", re.I),
    re.compile(r"email", re.I),
    re.compile(r"phone", re.I),
    re.compile(r"address", re.I),
    re.compile(r"credit.?card", re.I),
    re.compile(r"payment", re.I),
    re.compile(r"admin", re.I),
    re.compile(r"role", re.I),
    re.compile(r"permission", re.I),
    re.compile(r"auth", re.I),
]

SENSITIVE_FIELD_PATTERNS = [
    re.compile(r"\bpassword\b", re.I),
    re.compile(r"\bsecret\b", re.I),
    re.compile(r"\btoken\b", re.I),
    re.compile(r"\bapi.?key\b", re.I),
    re.compile(r"\bprivate.?key\b", re.I),
    re.compile(r"\bsocial.?security\b", re.I),
    re.compile(r"\bssn\b", re.I),
    re.compile(r"\bcredit.?card\b", re.I),
    re.compile(r"\bcvv\b", re.I),
]


async def scan_graphql_surface(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[GraphqlFinding]:
    findings: list[GraphqlFinding] = []

    async def _check_endpoint(endpoint: str) -> None:
        url = f"{base_url.rstrip('/')}{endpoint}"

        # Check 1: Introspection query
        try:
            resp = await client.post(
                url,
                content=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                body = resp.text[:5000]
                if "__schema" in body or "types" in body:
                    sensitive_types = []
                    body_lower = body.lower()
                    for pat in SENSITIVE_TYPE_PATTERNS:
                        if pat.search(body_lower):
                            sensitive_types.append(pat.pattern)

                    findings.append(GraphqlFinding(
                        module="graphql_surface",
                        title="GraphQL introspection enabled",
                        url=url,
                        evidence=f"Introspection query returned schema ({len(body)} chars). Sensitive types: {len(sensitive_types)}",
                        severity="high" if sensitive_types else "medium",
                        confidence="high",
                        invariant="GraphQL introspection must be disabled in production",
                        remediation="Disable introspection in production configuration",
                    ))

                    # Check for sensitive fields in schema
                    if sensitive_types:
                        findings.append(GraphqlFinding(
                            module="graphql_surface",
                            title="GraphQL schema contains sensitive types",
                            url=url,
                            evidence=f"Sensitive type patterns found: {', '.join(sensitive_types[:5])}",
                            severity="high",
                            confidence="medium",
                            invariant="GraphQL schemas should not expose sensitive data types",
                            remediation="Review schema for sensitive data exposure, add field-level authorization",
                        ))
        except httpx.HTTPError:
            pass

        # Check 2: GraphiQL interface
        try:
            resp = await client.get(url, timeout=8.0)
            if resp.status_code == 200:
                body = resp.text[:10000]
                if "graphiql" in body.lower() or "graphql-playground" in body.lower() or "GraphiQL" in body:
                    findings.append(GraphqlFinding(
                        module="graphql_surface",
                        title="GraphQL IDE (GraphiQL/Playground) exposed",
                        url=url,
                        evidence="GraphQL IDE interface detected in response",
                        severity="high",
                        confidence="high",
                        invariant="GraphQL IDEs must not be publicly accessible",
                        remediation="Disable GraphQL IDE in production or restrict to internal networks",
                    ))
        except httpx.HTTPError:
            pass

        # Check 3: Error response with GraphQL hints
        try:
            resp = await client.post(
                url,
                content='{"query":"{ invalid }"}',
                headers={"Content-Type": "application/json"},
                timeout=8.0,
            )
            if resp.status_code in (400, 500):
                body = resp.text[:2000]
                if "graph" in body.lower() or "query" in body.lower() or "mutation" in body.lower():
                    findings.append(GraphqlFinding(
                        module="graphql_surface",
                        title="GraphQL endpoint responds to malformed queries",
                        url=url,
                        evidence=f"Error response: {body[:200]}",
                        severity="low",
                        confidence="medium",
                        invariant="GraphQL endpoints should not expose detailed error messages",
                        remediation="Disable detailed error messages in production",
                    ))
        except httpx.HTTPError:
            pass

    import asyncio
    await asyncio.gather(*[_check_endpoint(ep) for ep in GRAPHQL_ENDPOINTS])
    return findings
