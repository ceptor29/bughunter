from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from .enums import HttpMethod, RiskLevel, ScopeAction

# ---------------------------------------------------------------------------
# Canonical URL
# ---------------------------------------------------------------------------

class CanonicalUrl(BaseModel):
    scheme: str
    host: str
    port: int
    path: str

    @classmethod
    def from_raw(cls, url: str) -> CanonicalUrl:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = (parsed.scheme or "https").lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        path = PurePosixPath(parsed.path or "/")
        return cls(scheme=scheme, host=host, port=port, path=str(path))

    def matches_host(self, pattern: str) -> bool:
        p = pattern.lower().strip(".")
        if p.startswith("*."):
            suffix = p[1:]
            return self.host.endswith(suffix) or self.host == p[2:]
        return self.host == p

    def matches_path(self, pattern: str) -> bool:
        return fnmatch.fnmatch(self.path, pattern)

    def is_private(self) -> bool:
        try:
            addr = ipaddress.ip_address(self.host)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False

    def as_key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


# ---------------------------------------------------------------------------
# Scope rule
# ---------------------------------------------------------------------------

class ScopeRule(BaseModel):
    action: ScopeAction
    hosts: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    schemes: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    methods: list[HttpMethod] = Field(default_factory=list)
    reason: str = ""

    def matches(self, url: CanonicalUrl, method: HttpMethod = HttpMethod.GET) -> bool:
        if self.methods and method not in self.methods:
            return False
        if self.schemes and url.scheme not in self.schemes:
            return False
        if self.ports and url.port not in self.ports:
            return False
        if self.paths and not any(url.matches_path(p) for p in self.paths):
            return False
        if self.hosts:
            return any(url.matches_host(h) for h in self.hosts)
        return bool(self.paths or self.schemes or self.ports)


# ---------------------------------------------------------------------------
# Scope policy
# ---------------------------------------------------------------------------

class ScopePolicy(BaseModel):
    version: int = 1
    allowed_schemes: list[str] = Field(default_factory=lambda: ["https"])
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/**"])
    excluded_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    allow_private_ips: bool = False
    pin_dns_per_task: bool = True
    max_redirects: int = 3
    rules: list[ScopeRule] = Field(default_factory=list)

    def is_host_allowed(self, host: str) -> bool:
        h = host.lower().strip(".")
        for ex in self.excluded_hosts:
            if fnmatch.fnmatch(h, ex.lower()):
                return False
        for al in self.allowed_hosts:
            if fnmatch.fnmatch(h, al.lower()):
                return True
        return False

    def is_path_allowed(self, path: str) -> bool:
        for ex in self.excluded_paths:
            if fnmatch.fnmatch(path, ex):
                return False
        return any(fnmatch.fnmatch(path, p) for p in self.allowed_paths)

    def is_scheme_allowed(self, scheme: str) -> bool:
        return scheme.lower() in self.allowed_schemes

    def is_port_allowed(self, port: int) -> bool:
        return not self.allowed_ports or port in self.allowed_ports

    def is_ip_allowed(self, host: str) -> bool:
        if self.allow_private_ips:
            return True
        try:
            addr = ipaddress.ip_address(host)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
        except ValueError:
            return True

    def evaluate(self, url: CanonicalUrl, method: HttpMethod = HttpMethod.GET) -> ScopeDecision:
        reasons: list[str] = []

        if not self.is_scheme_allowed(url.scheme):
            reasons.append(f"scheme {url.scheme} not in {self.allowed_schemes}")
        if not self.is_host_allowed(url.host):
            reasons.append(f"host {url.host} not in allowed_hosts / in excluded_hosts")
        if not self.is_port_allowed(url.port):
            reasons.append(f"port {url.port} not in allowed_ports")
        if not self.is_path_allowed(url.path):
            reasons.append(f"path {url.path} not in allowed_paths / in excluded_paths")
        if not self.is_ip_allowed(url.host):
            reasons.append(f"IP {url.host} is private/link-local and allow_private_ips is false")
        for rule in self.rules:
            if rule.matches(url, method):
                if rule.action == ScopeAction.DENY:
                    reasons.append(f"deny rule matched: {rule.reason or rule.model_dump()}")
                else:
                    return ScopeDecision(action=ScopeAction.ALLOW, matched_rule=rule, reasons=[])

        if reasons:
            return ScopeDecision(action=ScopeAction.DENY, matched_rule=None, reasons=reasons)
        return ScopeDecision(action=ScopeAction.ALLOW, matched_rule=None, reasons=[])

    def policy_hash(self) -> str:
        import json as _json
        data = self.model_dump(mode="json")
        raw = _json.dumps(data, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Compiled policy (after canonicalization + validation)
# ---------------------------------------------------------------------------

class CompiledPolicy(BaseModel):
    source: ScopePolicy
    hash: str
    max_redirects: int = 3
    pin_dns_per_task: bool = True
    active_risk_authorized: bool = False
    stateful_risk_authorized: bool = False
    high_risk_authorized: bool = False
    manifest_ref: str | None = None
    manifest_valid_until: datetime | None = None

    @classmethod
    def from_scope(cls, scope: ScopePolicy, manifest: AuthorizationManifest | None = None) -> CompiledPolicy:
        active = False
        stateful = False
        high_risk = False
        ref = None
        valid_until = None
        if manifest:
            ref = manifest.reference
            valid_until = manifest.valid_until
            rl = manifest.approved_risk_level
            if rl in (RiskLevel.ACTIVE, RiskLevel.STATEFUL, RiskLevel.HIGH_RISK):
                active = True
            if rl in (RiskLevel.STATEFUL, RiskLevel.HIGH_RISK):
                stateful = True
            if rl == RiskLevel.HIGH_RISK:
                high_risk = True
        return cls(
            source=scope,
            hash=scope.policy_hash(),
            max_redirects=scope.max_redirects,
            pin_dns_per_task=scope.pin_dns_per_task,
            active_risk_authorized=active,
            stateful_risk_authorized=stateful,
            high_risk_authorized=high_risk,
            manifest_ref=ref,
            manifest_valid_until=valid_until,
        )


# ---------------------------------------------------------------------------
# Authorization manifest
# ---------------------------------------------------------------------------

class AuthorizationManifest(BaseModel):
    version: int = 1
    reference: str = ""
    issued_to: str = "local-operator"
    valid_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_risk_level: RiskLevel = RiskLevel.SAFE
    allowed_assets: list[str] = Field(default_factory=list)
    excluded_assets: list[str] = Field(default_factory=list)
    constraints: dict[str, str | bool | int] = Field(default_factory=dict)
    acknowledgement: str = ""

    @field_validator("valid_until")
    @classmethod
    def must_be_future(cls, v: datetime) -> datetime:
        return v

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now > self.valid_until

    def is_asset_allowed(self, host: str) -> bool:
        h = host.lower().strip(".")
        for ex in self.excluded_assets:
            if fnmatch.fnmatch(h, ex.lower()):
                return False
        return any(fnmatch.fnmatch(h, a.lower()) for a in self.allowed_assets)

    def manifest_hash(self) -> str:
        import json as _json
        data = self.model_dump(mode="json")
        raw = _json.dumps(data, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Scope decision (returned per-request)
# ---------------------------------------------------------------------------

class ScopeDecision(BaseModel):
    action: ScopeAction
    matched_rule: ScopeRule | None = None
    reasons: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == ScopeAction.ALLOW
