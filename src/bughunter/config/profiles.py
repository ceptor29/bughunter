from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ScopeConfig:
    allowed_schemes: list[str] = field(default_factory=lambda: ["https"])
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=lambda: [443, 80])
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    allow_private_ips: bool = False
    max_redirects: int = 3


@dataclass
class ExecutionConfig:
    profile: str = "safe"
    max_total_requests: int = 5000
    max_scan_minutes: int = 60
    global_concurrency: int = 20
    per_origin_concurrency: int = 4
    per_origin_rps: float = 2.0
    max_response_bytes: int = 1048576
    retries: int = 1
    respect_retry_after: bool = True


@dataclass
class ModuleConfig:
    include: list[str] = field(default_factory=lambda: ["passive.*", "recon.*"])
    exclude: list[str] = field(default_factory=lambda: ["expert.*"])


@dataclass
class EvidenceConfig:
    store_bodies: str = "on_candidate"
    retention_days: int = 30


@dataclass
class ReportingConfig:
    formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    minimum_state: str = "validated"


@dataclass
class CrawlConfig:
    max_depth: int = 2
    max_pages: int = 50
    follow_external: bool = False
    external_domains: list[str] = field(default_factory=list)
    respect_robots: bool = True
    same_origin_only: bool = True
    path_patterns_allow: list[str] = field(default_factory=list)
    path_patterns_deny: list[str] = field(default_factory=list)


@dataclass
class IntegrationConfig:
    mode: str = "auto"
    subfinder: bool = True
    amass: bool = True
    httpx: bool = True
    nuclei: bool = True
    naabu: bool = True
    ffuf: bool = True
    arjun: bool = True


@dataclass
class AuthConfig:
    auth_file: str = "auth.yaml"
    auto_refresh: bool = False
    expiry_warn_seconds: float = 300.0


@dataclass
class SafetyConfig:
    require_manifest: bool = True
    require_operator_approval: bool = False
    blocked_paths: list[str] = field(default_factory=lambda: [
        "/admin", "/wp-admin", "/phpmyadmin", "/.env",
    ])
    blocked_methods: list[str] = field(default_factory=lambda: ["DELETE"])
    risk_ack_required_above: str = "safe"


@dataclass
class Profile:
    name: str
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    modules: ModuleConfig = field(default_factory=ModuleConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    integrations: IntegrationConfig = field(default_factory=IntegrationConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Profile:
        p = Path(path)
        if not p.exists():
            return cls(name="default")
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> Profile:
        scope_data = data.get("scope", {})
        execution_data = data.get("execution", {})
        modules_data = data.get("modules", {})
        evidence_data = data.get("evidence", {})
        reporting_data = data.get("reporting", {})
        crawl_data = data.get("crawl", {})
        integration_data = data.get("integrations", {})
        auth_data = data.get("auth", {})
        safety_data = data.get("safety", {})

        return cls(
            name=data.get("project", {}).get("name", "default"),
            scope=ScopeConfig(**{k: v for k, v in scope_data.items() if k in ScopeConfig.__dataclass_fields__}),
            execution=ExecutionConfig(**{k: v for k, v in execution_data.items() if k in ExecutionConfig.__dataclass_fields__}),
            modules=ModuleConfig(**{k: v for k, v in modules_data.items() if k in ModuleConfig.__dataclass_fields__}),
            evidence=EvidenceConfig(**{k: v for k, v in evidence_data.items() if k in EvidenceConfig.__dataclass_fields__}),
            reporting=ReportingConfig(**{k: v for k, v in reporting_data.items() if k in ReportingConfig.__dataclass_fields__}),
            crawl=CrawlConfig(**{k: v for k, v in crawl_data.items() if k in CrawlConfig.__dataclass_fields__}),
            integrations=IntegrationConfig(**{k: v for k, v in integration_data.items() if k in IntegrationConfig.__dataclass_fields__}),
            auth=AuthConfig(**{k: v for k, v in auth_data.items() if k in AuthConfig.__dataclass_fields__}),
            safety=SafetyConfig(**{k: v for k, v in safety_data.items() if k in SafetyConfig.__dataclass_fields__}),
        )

    def to_dict(self) -> dict:
        return {
            "project": {"name": self.name},
            "scope": {
                "allowed_schemes": self.scope.allowed_schemes,
                "allowed_hosts": self.scope.allowed_hosts,
                "allowed_ports": self.scope.allowed_ports,
                "excluded_hosts": self.scope.excluded_hosts,
                "excluded_paths": self.scope.excluded_paths,
                "allow_private_ips": self.scope.allow_private_ips,
                "max_redirects": self.scope.max_redirects,
            },
            "execution": {
                "profile": self.execution.profile,
                "max_total_requests": self.execution.max_total_requests,
                "max_scan_minutes": self.execution.max_scan_minutes,
                "global_concurrency": self.execution.global_concurrency,
                "per_origin_concurrency": self.execution.per_origin_concurrency,
                "per_origin_rps": self.execution.per_origin_rps,
                "max_response_bytes": self.execution.max_response_bytes,
                "retries": self.execution.retries,
                "respect_retry_after": self.execution.respect_retry_after,
            },
            "modules": {
                "include": self.modules.include,
                "exclude": self.modules.exclude,
            },
            "evidence": {
                "store_bodies": self.evidence.store_bodies,
                "retention_days": self.evidence.retention_days,
            },
            "reporting": {
                "formats": self.reporting.formats,
                "minimum_state": self.reporting.minimum_state,
            },
            "crawl": {
                "max_depth": self.crawl.max_depth,
                "max_pages": self.crawl.max_pages,
                "follow_external": self.crawl.follow_external,
                "external_domains": self.crawl.external_domains,
                "respect_robots": self.crawl.respect_robots,
                "same_origin_only": self.crawl.same_origin_only,
                "path_patterns_allow": self.crawl.path_patterns_allow,
                "path_patterns_deny": self.crawl.path_patterns_deny,
            },
            "integrations": {
                "mode": self.integrations.mode,
                "subfinder": self.integrations.subfinder,
                "amass": self.integrations.amass,
                "httpx": self.integrations.httpx,
                "nuclei": self.integrations.nuclei,
                "naabu": self.integrations.naabu,
                "ffuf": self.integrations.ffuf,
                "arjun": self.integrations.arjun,
            },
            "auth": {
                "auth_file": self.auth.auth_file,
                "auto_refresh": self.auth.auto_refresh,
                "expiry_warn_seconds": self.auth.expiry_warn_seconds,
            },
            "safety": {
                "require_manifest": self.safety.require_manifest,
                "require_operator_approval": self.safety.require_operator_approval,
                "blocked_paths": self.safety.blocked_paths,
                "blocked_methods": self.safety.blocked_methods,
                "risk_ack_required_above": self.safety.risk_ack_required_above,
            },
        }

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)

    def is_module_enabled(self, module_id: str) -> bool:
        import fnmatch
        for pattern in self.modules.exclude:
            if fnmatch.fnmatch(module_id, pattern):
                return False
        for pattern in self.modules.include:
            if fnmatch.fnmatch(module_id, pattern):
                return True
        return False

    def is_path_blocked(self, url: str) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        for path in self.safety.blocked_paths:
            if parsed.path.startswith(path):
                return True
        for pattern in self.crawl.path_patterns_deny:
            import re
            if re.search(pattern, parsed.path):
                return True
        return False

    def validate(self) -> list[str]:
        errors = []
        if not self.scope.allowed_hosts:
            errors.append("scope.allowed_hosts must not be empty")
        if self.execution.max_total_requests <= 0:
            errors.append("execution.max_total_requests must be > 0")
        if self.execution.max_scan_minutes <= 0:
            errors.append("execution.max_scan_minutes must be > 0")
        if self.crawl.max_depth < 0:
            errors.append("crawl.max_depth must be >= 0")
        if self.crawl.max_pages <= 0:
            errors.append("crawl.max_pages must be > 0")
        return errors


# Built-in profiles
BUILTIN_PROFILES: dict[str, dict] = {
    "safe": {
        "execution": {"profile": "safe", "max_total_requests": 500},
        "modules": {"include": ["passive.*", "recon.*", "surface.*", "detect.*"], "exclude": ["active.*", "expert.*", "authn.*", "authz.*"]},
        "safety": {"require_manifest": False, "blocked_paths": ["/admin", "/wp-admin"]},
    },
    "unrestricted": {
        "execution": {"profile": "unrestricted", "max_total_requests": 5000},
        "modules": {"include": ["*"], "exclude": ["expert.smuggling"]},
        "safety": {"require_manifest": True, "blocked_paths": []},
    },
    "active": {
        "execution": {"profile": "active", "max_total_requests": 2000},
        "modules": {"include": ["passive.*", "recon.*", "surface.*", "detect.*", "active.*"], "exclude": ["expert.*", "authn.*", "authz.*"]},
        "safety": {"require_manifest": True, "blocked_paths": ["/admin"]},
    },
}


def load_profile(name: str = "safe", config_path: str | Path | None = None) -> Profile:
    if config_path:
        return Profile.from_yaml(config_path)
    if name in BUILTIN_PROFILES:
        base = Profile(name=name)
        for section, values in BUILTIN_PROFILES[name].items():
            section_obj = getattr(base, section)
            for k, v in values.items():
                if hasattr(section_obj, k):
                    setattr(section_obj, k, v)
        return base
    return Profile(name=name)
