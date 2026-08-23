from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from bughunter.auth.policy import AuthPolicyManager
from bughunter.auth.tokens import TokenManager
from bughunter.contracts.policy import AuthorizationManifest, CompiledPolicy, ScopePolicy
from bughunter.control.authorization import AuthorizationManager
from bughunter.control.cancellation import CancellationManager
from bughunter.control.lifecycle import ScanLifecycle
from bughunter.execution.budgets import BudgetManager
from bughunter.execution.rate_limits import RateLimiter
from bughunter.execution.redaction import Redactor
from bughunter.storage.database import Database

# Profile-based request restrictions
SAFE_MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_EXCLUDED_PATHS = {
    "/.env", "/.env.local", "/.env.bak", "/.env.old",
    "/phpinfo.php", "/info.php", "/test.php",
    "/wp-config.php", "/wp-config.php.bak",
    "/config.json", "/config.yml", "/config.php",
    "/dump.sql", "/backup.zip", "/backup.tar.gz",
}

# Max requests per profile tier
PROFILE_QUOTAS = {
    "passive": 0,
    "safe": 500,
    "unrestricted": 5000,
    "active": 2000,
}


@dataclass
class ScanConfig:
    target: str
    profile: str = "safe"
    config_path: str = "bughunter.yaml"
    manifest_path: str | None = None
    passive_only: bool = False
    out_dir: str | None = None
    max_concurrency: int = 20
    rate_limit_rps: float = 10.0
    resume_scan_id: str | None = None


@dataclass
class ScanContext:
    target_domain: str = ""
    base_urls: list[str] = field(default_factory=list)
    subdomains: set[str] = field(default_factory=set)
    alive_hosts: list[dict[str, Any]] = field(default_factory=list)
    pages: dict[str, Any] = field(default_factory=dict)
    forms: list[dict[str, Any]] = field(default_factory=list)
    params: list[dict[str, str]] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skip_reasons: list[dict[str, str]] = field(default_factory=list)


class ScanEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.ctx = ScanContext(target_domain=config.target)
        self._auth_mgr = AuthorizationManager()
        self._cancel = CancellationManager()
        self._lifecycle = ScanLifecycle()
        self._redactor = Redactor()
        self._rate_limiter = RateLimiter(rps=config.rate_limit_rps)
        self._db: Database | None = None
        self._policy: CompiledPolicy | None = None
        self._start_time: float = 0.0
        self._request_count: int = 0
        self._request_quota: int = PROFILE_QUOTAS.get(config.profile, 500)
        self._budget_mgr = BudgetManager()
        self._budget_mgr.register_phase("recon", max_requests=200, max_runtime=120.0)
        self._budget_mgr.register_phase("detection", max_requests=400, max_runtime=240.0)
        self._budget_mgr.register_phase("passive", max_requests=0, max_runtime=60.0)
        self._token_mgr = TokenManager()
        self._auth_policy_mgr = AuthPolicyManager(self._token_mgr)

    def _check_quota(self, method: str = "GET", path: str = "") -> bool:
        if self._request_count >= self._request_quota:
            self.ctx.warnings.append(f"Request quota exhausted ({self._request_quota}). Remaining requests skipped.")
            return False
        if self.config.profile == "safe":
            if method.upper() in SAFE_MUTATION_METHODS:
                return False
            if any(path.startswith(p) for p in SAFE_EXCLUDED_PATHS):
                return False
        return True

    def _record_request(self, method: str = "GET", response_bytes: int = 0) -> None:
        self._request_count += 1
        self._budget_mgr.record(requests=1, response_bytes=response_bytes)

    async def run(self) -> ScanContext:
        self._start_time = time.time()
        self.ctx.target_domain = self.config.target

        # Install signal handlers for graceful stop
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._cancel.cancel)
            except NotImplementedError:
                pass  # Windows doesn't support add_signal_handler

        from pathlib import Path

        import yaml
        config_path = Path(self.config.config_path)
        if config_path.exists():
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
        else:
            cfg = {}

        scope_data = cfg.get("scope", {})
        scope_data.setdefault("allowed_hosts", [self.config.target])
        scope = ScopePolicy(**scope_data)

        manifest = None
        if self.config.manifest_path:
            mp = Path(self.config.manifest_path)
            if mp.exists():
                with open(mp) as f:
                    manifest_data = yaml.safe_load(f) or {}
                manifest = AuthorizationManifest(**manifest_data)
                self._auth_mgr.load_manifest(manifest)

        self._policy = CompiledPolicy.from_scope(scope, manifest)

        # Load auth tokens and policies
        auth_path = config_path.parent / "auth.yaml"
        if auth_path.exists():
            self._token_mgr.load_from_yaml(auth_path)
            self._auth_policy_mgr.load_from_yaml(auth_path)
            token_health = self._auth_policy_mgr.check_token_health()
            for issue in token_health:
                self.ctx.warnings.append(f"Auth: {issue['message']}")

        workspace = Path(cfg.get("project", {}).get("workspace", ".bughunter")) / self.config.target
        workspace.mkdir(parents=True, exist_ok=True)
        self._db = Database(workspace / "project.db")
        self._db.save_project(self.config.target, self.config.target, str(workspace))

        # Resume support
        if self.config.resume_scan_id:
            self._lifecycle._scan_id = __import__("uuid").UUID(self.config.resume_scan_id)
            self.ctx.warnings.append(f"Resuming scan {self.config.resume_scan_id}")
            completed = self._db.get_completed_task_ids(self.config.resume_scan_id)
            self.ctx.warnings.append(f"Previously completed tasks: {len(completed)}")
        else:
            completed = set()

        self._db.save_scan(
            scan_id=str(self._lifecycle.scan_id),
            project_id=self.config.target,
            target=self.config.target,
            profile=self.config.profile,
            policy_hash=self._policy.hash,
            manifest_hash=manifest.manifest_hash() if manifest else "",
        )
        self._db.save_audit_event("scan_started", str(self._lifecycle.scan_id), details={"target": self.config.target})

        try:
            if not self.config.passive_only:
                await self._run_recon(completed)
                if not self._cancel.is_cancelled:
                    await self._run_detection(completed)
            else:
                await self._run_passive()
        except asyncio.CancelledError:
            self.ctx.warnings.append("Scan cancelled by operator (Ctrl+C)")
            self._db.save_audit_event("scan_cancelled", str(self._lifecycle.scan_id))
        except Exception as e:
            self.ctx.errors.append(f"Scan error: {e}")
            self._db.save_audit_event("scan_failed", str(self._lifecycle.scan_id), details={"error": str(e)})
        finally:
            elapsed = time.time() - self._start_time
            scan_status = "cancelled" if self._cancel.is_cancelled else "completed"
            self._db.complete_scan(str(self._lifecycle.scan_id), status=scan_status)
            self._db.save_audit_event(f"scan_{scan_status}", str(self._lifecycle.scan_id), details={"elapsed": f"{elapsed:.1f}s", "findings": str(len(self.ctx.findings))})

        return self.ctx

    async def _run_passive(self) -> None:
        from bughunter.modules.passive.provider_sources import enumerate_subdomains
        self.ctx.warnings.append("Passive-only mode: no HTTP traffic to target")
        hosts, errors = await enumerate_subdomains(self.config.target)
        self.ctx.subdomains = hosts
        self.ctx.errors.extend(errors)
        self.ctx.warnings.append(f"Passive found {len(hosts)} subdomains")

    async def _run_recon(self, completed: set[str] | None = None) -> None:
        from bughunter.modules.passive.provider_sources import enumerate_subdomains
        from bughunter.modules.recon.dns_resolution import detect_wildcard, resolve_host
        from bughunter.modules.recon.http_probe import probe_host

        self.ctx.warnings.append("Phase: subdomain enumeration...")
        hosts, errors = await enumerate_subdomains(self.config.target)
        self.ctx.subdomains = hosts
        self.ctx.errors.extend(errors)

        self.ctx.warnings.append("Phase: wildcard detection...")
        is_wildcard, wildcard_ips = await detect_wildcard(self.config.target)
        if is_wildcard:
            self.ctx.warnings.append(f"Wildcard DNS detected: *.{'.'.join(self.config.target.split('.')[-2:])} → {wildcard_ips}")
            non_wildcard = set()
            for h in hosts:
                if self._cancel.is_cancelled or not self._budget_mgr.check(phase="recon"):
                    break
                resolved = await resolve_host(h)
                host_ips = set(resolved.a_records + resolved.aaaa_records)
                if not host_ips.intersection(wildcard_ips):
                    non_wildcard.add(h)
            if non_wildcard:
                self.ctx.subdomains = non_wildcard | {self.config.target}
                self.ctx.warnings.append(f"After wildcard suppression: {len(self.ctx.subdomains)} hosts")

        self.ctx.warnings.append(f"Phase: DNS resolution ({len(self.ctx.subdomains)} hosts)...")
        for host in list(self.ctx.subdomains):
            if self._cancel.is_cancelled or not self._budget_mgr.check(phase="recon"):
                self.ctx.warnings.append("Recon budget/cancellation — skipping remaining DNS")
                break
            resolved = await resolve_host(host)
            if resolved.is_nxdomain:
                self.ctx.subdomains.discard(host)

        self.ctx.warnings.append("Phase: HTTP probing...")
        async with httpx.AsyncClient(follow_redirects=False, http2=True, timeout=10.0,
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}) as client:
            probe_tasks = []
            for h in self.ctx.subdomains:
                if self._cancel.is_cancelled or not self._budget_mgr.check(phase="recon"):
                    self.ctx.warnings.append("Recon budget exhausted — skipping remaining probes")
                    break
                probe_tasks.append(probe_host(h, client))
            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
            for r in probe_results:
                if isinstance(r, Exception):
                    self.ctx.errors.append(f"Probe error: {r}")
                elif isinstance(r, list):
                    for pr in r:
                        if pr.status > 0 and not pr.error:
                            self.ctx.alive_hosts.append({
                                "url": pr.url,
                                "status": pr.status,
                                "title": pr.title,
                                "server": pr.server,
                                "powered_by": pr.powered_by,
                                "tech": pr.tech_markers,
                            })
                            if pr.body_snippet:
                                self.ctx.pages[pr.url] = pr.body_snippet

            self._budget_mgr.record(requests=len(probe_results), phase="recon")

        self.ctx.warnings.append(f"Recon complete: {len(self.ctx.alive_hosts)} alive hosts from {len(self.ctx.subdomains)} subdomains")

    async def _run_detection(self, completed: set[str] | None = None) -> None:
        from bughunter.modules.detectors.exposed_artifacts import scan_exposed_artifacts
        from bughunter.modules.detectors.graphql_surface import scan_graphql_surface
        from bughunter.modules.detectors.repository_metadata import scan_repository_metadata
        from bughunter.modules.detectors.security_controls import scan_security_controls
        from bughunter.modules.detectors.takeover import scan_takeover
        from bughunter.modules.recon.crawl import crawl_page
        from bughunter.modules.surface.component_inventory import (
            check_dependency_advisories,
            scan_component_inventory,
        )
        from bughunter.modules.surface.endpoint_inventory import scan_endpoint_inventory

        self.ctx.warnings.append("Phase: crawling alive hosts...")
        _all_pages: dict[str, str] = {}
        base_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        async with httpx.AsyncClient(follow_redirects=False, http2=True, timeout=10.0, headers=base_headers) as client:
            # Inject auth into probing
            for host_info in self.ctx.alive_hosts[:20]:
                url = host_info["url"]
                if self._auth_policy_mgr.should_authenticate(url):
                    auth = self._auth_policy_mgr.get_auth_for_url(url)
                    for k, v in auth.items():
                        if k.startswith("cookie:"):
                            cookie_name = k.split(":", 1)[1]
                            client.cookies.set(cookie_name, v)
                        elif k.startswith("param:"):
                            pass  # params handled at request time
                        else:
                            client.headers[k] = v

            for host_info in self.ctx.alive_hosts[:20]:
                url = host_info["url"]
                try:
                    result = await crawl_page(url, client)
                    if result.forms:
                        for form in result.forms:
                            self.ctx.forms.append({
                                "url": url,
                                "action": form.action,
                                "method": form.method,
                                "inputs": form.inputs,
                                "enctype": form.enctype,
                            })
                    for p in result.params_found:
                        self.ctx.params.append(p)
                    self.ctx.js_files.extend(result.script_srcs[:10])
                except Exception as e:
                    self.ctx.errors.append(f"Crawl error on {url}: {e}")

            self.ctx.js_files = list(set(self.ctx.js_files))[:30]
            self.ctx.warnings.append(f"Crawl complete: {len(self.ctx.forms)} forms, {len(self.ctx.params)} params, {len(self.ctx.js_files)} JS files")

            self.ctx.warnings.append("Phase: running detectors...")
            for host_info in self.ctx.alive_hosts[:20]:
                if not self._check_quota():
                    self.ctx.warnings.append("Quota exhausted — skipping remaining detection")
                    break
                base_url = host_info["url"]
                try:
                    from bughunter.guidance.hunting_guide import get_verification_steps

                    exposed = await scan_exposed_artifacts(base_url, client)
                    for f in exposed:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    repo = await scan_repository_metadata(base_url, client)
                    for f in repo:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    takeover = await scan_takeover(base_url, client)
                    for f in takeover:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    security = await scan_security_controls(base_url, client)
                    for f in security:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    graphql = await scan_graphql_surface(base_url, client)
                    for f in graphql:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    components = await scan_component_inventory(base_url, client)
                    advisories = await check_dependency_advisories(components)
                    for f in advisories:
                        self.ctx.findings.append({
                            "module": f.module, "title": f.title, "url": f.url or base_url,
                            "evidence": f.evidence, "severity": f.severity,
                            "confidence": f.confidence, "invariant": f.invariant,
                            "remediation": f.remediation,
                            "verification_steps": get_verification_steps(f.module, f.title),
                        })

                    endpoints = await scan_endpoint_inventory(base_url, client)
                    for ep in endpoints:
                        self.ctx.params.extend(ep.params)

                except Exception as e:
                    self.ctx.errors.append(f"Detection error on {base_url}: {e}")

            self.ctx.warnings.append(f"Detection complete: {len(self.ctx.findings)} findings from {len(self.ctx.alive_hosts)} hosts")
            self.ctx.warnings.append(f"Requests: {self._request_count}/{self._request_quota} ({self.config.profile} profile)")
            phase_sum = self._budget_mgr.phase_summary()
            for phase_name, stats in phase_sum.items():
                self.ctx.warnings.append(f"Budget [{phase_name}]: {stats['consumed']}/{stats['max']} requests")
            if self._token_mgr.all_tokens:
                self.ctx.warnings.append(f"Auth tokens: {len(self._token_mgr.all_tokens)} loaded, {len(self._token_mgr.get_expired_tokens())} expired")
