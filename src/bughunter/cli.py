from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from bughunter.contracts.enums import RiskLevel, ScopeAction
from bughunter.contracts.policy import (
    AuthorizationManifest,
    CompiledPolicy,
    ScopePolicy,
    CanonicalUrl,
)
from bughunter.control.authorization import AuthorizationManager
from bughunter.control.policy_compiler import PolicyCompiler
from bughunter.control.planner import Planner
from bughunter.storage.database import Database
from bughunter.auth.tokens import TokenManager, AuthToken, AuthType
from bughunter.auth.policy import AuthPolicyManager

app = typer.Typer(
    name="bughunter",
    help="Authorization-first, evidence-driven web security assessment framework",
    no_args_is_help=True,
)
scope_app = typer.Typer(help="Scope policy management.")
auth_app = typer.Typer(help="Authorization manifest management.")
app.add_typer(scope_app, name="scope")
app.add_typer(auth_app, name="auth")
console = Console()

CONFIG_NAME = "bughunter.yaml"
MANIFEST_NAME = "manifest.yaml"
PROJECTS_DIR = ".bughunter"


def _find_project_root() -> Path | None:
    current = Path.cwd()
    for parent in [current, *current.parents]:
        if (parent / CONFIG_NAME).exists():
            return parent
    return None


def _load_config(path: Path | None = None) -> dict:
    config_path = path or Path(CONFIG_NAME)
    if not config_path.exists():
        console.print(f"[red]Config not found: {config_path}[/red]")
        raise typer.Exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f)


# ────────────────────────────────────────────────────────────────
# init
# ────────────────────────────────────────────────────────────────
@app.command()
def init(
    project: str = typer.Argument(help="Project name"),
    workspace: str = typer.Option(".bughunter", help="Workspace directory"),
) -> None:
    """Initialize a new bughunter project."""
    ws = Path(workspace) / project
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "artifacts").mkdir(exist_ok=True)
    (ws / "exports").mkdir(exist_ok=True)
    (ws / "logs").mkdir(exist_ok=True)

    config = {
        "version": 2,
        "project": {"name": project, "workspace": str(ws)},
        "execution": {
            "profile": "safe",
            "max_total_requests": 5000,
            "max_scan_minutes": 60,
            "global_concurrency": 20,
            "per_origin_concurrency": 4,
            "per_origin_rps": 2,
            "max_response_bytes": 1048576,
            "retries": 1,
            "respect_retry_after": True,
        },
        "scope": {
            "allowed_schemes": ["https"],
            "allowed_hosts": [],
            "allowed_ports": [443],
            "excluded_hosts": [],
            "excluded_paths": [],
            "allow_private_ips": False,
            "max_redirects": 3,
        },
        "modules": {"include": ["passive.*", "recon.*"], "exclude": ["expert.*"]},
        "integrations": {"mode": "auto"},
        "evidence": {"store_bodies": "on_candidate", "retention_days": 30},
        "reporting": {"formats": ["json", "markdown", "html"], "minimum_state": "validated"},
    }
    config_path = ws / CONFIG_NAME
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    console.print(f"[green]Project initialized: {ws}[/green]")
    console.print(f"  Config: {config_path}")
    console.print(f"  Edit scope.allowed_hosts to begin.")


# ────────────────────────────────────────────────────────────────
# scope
# ────────────────────────────────────────────────────────────────
@scope_app.command("validate")
def scope_validate(
    config: str = typer.Option(CONFIG_NAME, help="Config file path"),
) -> None:
    """Validate the scope policy from config."""
    cfg = _load_config(Path(config))
    scope_data = cfg.get("scope", {})
    try:
        policy = ScopePolicy(**scope_data)
    except Exception as e:
        console.print(f"[red]Scope validation failed: {e}[/red]")
        raise typer.Exit(1)

    table = Table(title="Scope Policy")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Allowed hosts", ", ".join(policy.allowed_hosts) or "(none)")
    table.add_row("Excluded hosts", ", ".join(policy.excluded_hosts) or "(none)")
    table.add_row("Allowed schemes", ", ".join(policy.allowed_schemes))
    table.add_row("Allowed ports", ", ".join(str(p) for p in policy.allowed_ports))
    table.add_row("Allow private IPs", str(policy.allow_private_ips))
    table.add_row("Max redirects", str(policy.max_redirects))
    table.add_row("Policy hash", policy.policy_hash())
    console.print(table)
    console.print("[green]Scope policy is valid.[/green]")


@scope_app.command("explain")
def scope_explain(
    url: str = typer.Argument(help="URL to check"),
    config: str = typer.Option(CONFIG_NAME, help="Config file path"),
) -> None:
    """Explain whether a URL would be allowed by the scope policy."""
    cfg = _load_config(Path(config))
    scope_data = cfg.get("scope", {})
    policy = ScopePolicy(**scope_data)
    canonical = CanonicalUrl.from_raw(url)
    decision = policy.evaluate(canonical)

    table = Table(title=f"Scope Decision: {url}")
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green" if decision.allowed else "red")
    table.add_row("Canonical host", canonical.host)
    table.add_row("Canonical port", str(canonical.port))
    table.add_row("Canonical path", canonical.path)
    table.add_row("Canonical scheme", canonical.scheme)
    table.add_row("Host allowed", str(policy.is_host_allowed(canonical.host)))
    table.add_row("Port allowed", str(policy.is_port_allowed(canonical.port)))
    table.add_row("Path allowed", str(policy.is_path_allowed(canonical.path)))
    table.add_row("Scheme allowed", str(policy.is_scheme_allowed(canonical.scheme)))
    table.add_row("Private IP", str(canonical.is_private()))
    table.add_row("Final decision", "ALLOW" if decision.allowed else "DENY")
    if decision.reasons:
        for r in decision.reasons:
            table.add_row("Denial reason", r)
    console.print(table)


# ────────────────────────────────────────────────────────────────
# auth
# ────────────────────────────────────────────────────────────────
@auth_app.command("validate")
def auth_validate(
    manifest_path: str = typer.Argument(MANIFEST_NAME, help="Manifest file path"),
    config: str = typer.Option(CONFIG_NAME, help="Config file path"),
) -> None:
    """Validate an authorization manifest."""
    mp = Path(manifest_path)
    if not mp.exists():
        console.print(f"[red]Manifest not found: {mp}[/red]")
        raise typer.Exit(1)

    with open(mp) as f:
        manifest_data = yaml.safe_load(f)

    try:
        manifest = AuthorizationManifest(**manifest_data)
    except Exception as e:
        console.print(f"[red]Manifest validation failed: {e}[/red]")
        raise typer.Exit(1)

    mgr = AuthorizationManager()
    errors = mgr.load_manifest(manifest)

    if errors:
        console.print("[red]Manifest errors:[/red]")
        for e in errors:
            console.print(f"  - {e}")
        raise typer.Exit(1)

    table = Table(title="Authorization Manifest")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Reference", manifest.reference)
    table.add_row("Issued to", manifest.issued_to)
    table.add_row("Valid from", str(manifest.valid_from))
    table.add_row("Valid until", str(manifest.valid_until))
    table.add_row("Approved risk", manifest.approved_risk_level.value)
    table.add_row("Allowed assets", ", ".join(manifest.allowed_assets))
    table.add_row("Excluded assets", ", ".join(manifest.excluded_assets) or "(none)")
    table.add_row("Expired", str(manifest.is_expired()))
    table.add_row("Hash", manifest.manifest_hash())
    console.print(table)
    console.print("[green]Manifest is valid.[/green]")


@auth_app.command("tokens")
def auth_tokens(
    auth_file: str = typer.Option("auth.yaml", help="Auth config file path"),
    check: bool = typer.Option(False, "--check", help="Check token health"),
) -> None:
    """List auth tokens and check health."""
    from bughunter.auth.tokens import TokenManager
    from bughunter.auth.policy import AuthPolicyManager

    ap = Path(auth_file)
    tm = TokenManager()
    pm = AuthPolicyManager(tm)

    if ap.exists():
        tm.load_from_yaml(ap)
        pm.load_from_yaml(ap)

    if check:
        issues = pm.check_token_health()
        if issues:
            console.print("[yellow]Token health issues:[/yellow]")
            for issue in issues:
                console.print(f"  - {issue['message']}")
        else:
            console.print("[green]All tokens healthy.[/green]")

    table = Table(title="Auth Tokens")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Expires")
    table.add_column("Status")

    for t in tm.all_tokens:
        if t.is_expired:
            status = "[red]EXPIRED[/red]"
        elif t.seconds_until_expiry < 300:
            status = f"[yellow]expiring in {t.seconds_until_expiry:.0f}s[/yellow]"
        else:
            status = "[green]valid[/green]"
        exp = f"{t.expires_at:.0f}" if t.expires_at > 0 else "(none)"
        table.add_row(t.name, t.auth_type.value, t.scope or "(default)", exp, status)

    console.print(table)
    console.print(f"Active policy: {pm.get_active_policy().name if pm.get_active_policy() else '(none)'}")


@auth_app.command("add-token")
def auth_add_token(
    name: str = typer.Argument(help="Token name"),
    token_type: str = typer.Option("bearer", help="Token type (bearer, header, cookie, query_param, basic)"),
    value: str = typer.Option(..., help="Token value"),
    header_name: str = typer.Option("Authorization", help="Header name (for header type)"),
    scope: str = typer.Option("", help="URL pattern scope"),
    auth_file: str = typer.Option("auth.yaml", help="Auth config file path"),
) -> None:
    """Add an auth token to the auth config."""
    from bughunter.auth.tokens import TokenManager, AuthToken, AuthType

    ap = Path(auth_file)
    tm = TokenManager()
    if ap.exists():
        tm.load_from_yaml(ap)

    token = AuthToken(
        name=name,
        auth_type=AuthType(token_type),
        value=value,
        header_name=header_name,
        scope=scope,
    )
    tm.register_token(token)
    console.print(f"[green]Token '{name}' added ({token_type}).[/green]")
    console.print(f"  Scope: {scope or '(default)'}")
    console.print(f"  Auth file: {ap}")


@auth_app.command("validate-token")
def auth_validate_token(
    token_value: str = typer.Argument(help="Token value to validate (JWT or bearer)"),
) -> None:
    """Validate a JWT token and show claims."""
    from bughunter.auth.tokens import parse_jwt_expiry
    import base64
    import json

    parts = token_value.split(".")
    if len(parts) == 3:
        try:
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp", 0)
            console.print("[cyan]JWT Token:[/cyan]")
            console.print(f"  Issuer: {payload.get('iss', '(none)')}")
            console.print(f"  Subject: {payload.get('sub', '(none)')}")
            console.print(f"  Audience: {payload.get('aud', '(none)')}")
            console.print(f"  Expiry: {exp}")
            if exp:
                import time
                remaining = exp - time.time()
                if remaining <= 0:
                    console.print(f"  Status: [red]EXPIRED[/red]")
                else:
                    console.print(f"  Status: [green]valid for {remaining:.0f}s[/green]")
        except Exception as e:
            console.print(f"[red]Failed to parse JWT: {e}[/red]")
    else:
        console.print(f"[cyan]Token type: non-JWT bearer/header token[/cyan]")
        console.print(f"  Length: {len(token_value)} chars")
        console.print(f"  Prefix: {token_value[:20]}...")
@app.command()
def modules(
    list_all: bool = typer.Option(False, "--list", "-l", help="List all modules"),
    module_id: Optional[str] = typer.Argument(None, help="Show details for a specific module"),
) -> None:
    """List available modules or show details for a specific module."""
    BUILTIN_MODULES = [
        ("passive.certificate_names", "passive", "0.1.0", "Certificate transparency name enumeration"),
        ("passive.provider_sources", "passive", "0.1.0", "Passive subdomain sources (crt.sh, hackertarget, rapiddns)"),
        ("recon.dns_resolution", "safe", "0.1.0", "DNS resolution (A/AAAA/CNAME/MX/TXT)"),
        ("recon.http_probe", "safe", "0.1.0", "HTTP alive check, titles, tech fingerprinting"),
        ("recon.crawl", "safe", "0.1.0", "Bounded same-origin page crawl"),
        ("recon.port_adapter", "active", "0.1.0", "Port scan adapter (naabu/nmap)"),
        ("surface.endpoint_inventory", "safe", "0.1.0", "Endpoint and parameter extraction"),
        ("surface.component_inventory", "safe", "0.1.0", "Component and version detection"),
        ("surface.dependency_advisories", "safe", "0.1.0", "OSV dependency advisory lookup"),
        ("detect.exposed_artifacts", "safe", "0.1.0", "Exposed sensitive files (.env, .git, phpinfo, etc.)"),
        ("detect.repository_metadata", "safe", "0.1.0", "Exposed repository metadata (.git/HEAD)"),
        ("detect.takeover", "safe", "0.1.0", "Subdomain takeover candidates"),
        ("detect.security_controls", "safe", "0.1.0", "Security header and control checks"),
        ("detect.graphql_surface", "safe", "0.1.0", "GraphQL introspection and surface"),
        ("detect.component_exposure", "safe", "0.1.0", "Vulnerable component detection via OSV"),
        ("detect.redirect", "active", "0.1.0", "Open redirect detection"),
        ("detect.traversal", "active", "0.1.0", "Path traversal detection"),
        ("detect.ssti", "active", "0.1.0", "Server-side template injection"),
        ("detect.sqli", "active", "0.1.0", "SQL injection (error and time-blind)"),
        ("detect.xss", "active", "0.1.0", "Cross-site scripting (reflected/DOM)"),
        ("detect.crlf", "active", "0.1.0", "CRLF header injection"),
        ("detect.ssrf", "active", "0.1.0", "Server-side request forgery"),
        ("authn.oauth_review", "stateful", "0.1.0", "OAuth flow review"),
        ("authn.jwt_review", "local", "0.1.0", "JWT token review and forgery test"),
        ("authz.session_differential", "stateful", "0.1.0", "Cross-account session differential"),
        ("expert.race", "high_risk", "0.1.0", "Race condition detection"),
        ("expert.upload", "stateful", "0.1.0", "File upload filter testing"),
        ("expert.xxe", "high_risk", "0.1.0", "XML external entity detection"),
        ("expert.cache_poison", "high_risk", "0.1.0", "Cache poisoning detection"),
        ("expert.websocket", "stateful", "0.1.0", "WebSocket origin checks"),
        ("expert.smuggling", "lab", "0.1.0", "Request smuggling (lab only)"),
    ]

    if module_id:
        for mid, risk, ver, desc in BUILTIN_MODULES:
            if mid == module_id:
                console.print(f"[cyan]{mid}[/cyan] v{ver} ({risk})")
                console.print(f"  {desc}")
                return
        console.print(f"[red]Module not found: {module_id}[/red]")
        raise typer.Exit(1)

    table = Table(title="Available Modules")
    table.add_column("ID", style="cyan")
    table.add_column("Risk", style="yellow")
    table.add_column("Version")
    table.add_column("Description")
    for mid, risk, ver, desc in BUILTIN_MODULES:
        table.add_row(mid, risk, ver, desc)
    console.print(table)


# ────────────────────────────────────────────────────────────────
# doctor
# ────────────────────────────────────────────────────────────────
@app.command()
def doctor(json_output: bool = typer.Option(False, "--json")) -> None:
    """Check optional external tool availability."""
    import shutil
    tools = {
        "subfinder": "Passive subdomain enumeration (boosts passive.provider_sources)",
        "amass": "Deep subdomain enumeration (boosts passive.provider_sources)",
        "httpx": "Mass HTTP probing (boosts recon.http_probe)",
        "nuclei": "Template-based scanning (8000+ community templates)",
        "naabu": "Port scanning (enables recon.port_adapter)",
        "nmap": "Port scanning (enables recon.port_adapter)",
        "ffuf": "Content discovery (boosts detect.exposed_artifacts)",
        "arjun": "Parameter discovery (boosts surface.endpoint_inventory)",
    }
    results = {}
    for tool, desc in tools.items():
        path = shutil.which(tool)
        results[tool] = {"installed": path is not None, "path": path, "description": desc}

    if json_output:
        console.print_json(json.dumps(results, indent=2))
    else:
        table = Table(title="External Tool Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Path")
        table.add_column("Description")
        for tool, info in results.items():
            status = "[green]installed[/green]" if info["installed"] else "[dim]not found[/dim]"
            table.add_row(tool, status, info["path"] or "", info["description"])
        console.print(table)
        installed = sum(1 for r in results.values() if r["installed"])
        console.print(f"\n{installed}/{len(results)} tools installed.")


# ────────────────────────────────────────────────────────────────
# scan
# ────────────────────────────────────────────────────────────────
@app.command()
def scan(
    target: str = typer.Argument(help="Target domain to scan"),
    config: str = typer.Option(CONFIG_NAME, help="Config file path"),
    manifest: Optional[str] = typer.Option(None, help="Authorization manifest path"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Passive recon only (no HTTP to target)"),
    out: Optional[str] = typer.Option(None, "--out", help="Output directory"),
    concurrency: int = typer.Option(20, help="Max concurrent requests"),
    rate_limit: float = typer.Option(10.0, help="Requests per second limit"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume a previous scan by ID"),
) -> None:
    """Run a security scan against a target domain."""
    import asyncio
    import time as _time
    from bughunter.core.engine import ScanEngine, ScanConfig
    from bughunter.reporting.native_json import generate_json_report
    from bughunter.reporting.markdown import generate_markdown_report

    config_path = Path(config)
    if not config_path.exists():
        console.print(f"[red]Config not found: {config_path}[/red]")
        console.print("[dim]Run 'bughunter init' first.[/dim]")
        raise typer.Exit(1)

    cfg = ScanConfig(
        target=target,
        config_path=str(config_path),
        manifest_path=manifest,
        passive_only=passive_only,
        out_dir=out,
        max_concurrency=concurrency,
        rate_limit_rps=rate_limit,
        resume_scan_id=resume,
    )

    console.print(f"[bold cyan]BUGHUNTER v0.1.0 — Scan Starting[/bold cyan]")
    console.print(f"  Target:      {target}")
    console.print(f"  Profile:     {'passive' if passive_only else 'safe'}")
    console.print(f"  Manifest:    {manifest or '(none)'}")
    console.print()

    engine = ScanEngine(cfg)
    start = _time.time()
    ctx = asyncio.run(engine.run())
    elapsed = _time.time() - start

    console.print()
    for w in ctx.warnings:
        console.print(f"  [dim]{w}[/dim]")
    console.print()

    scan_id = str(engine._lifecycle.scan_id)
    out_dir = Path(out) if out else Path(".") / f"reports_{target.replace('.', '_')}"
    out_dir.mkdir(parents=True, exist_ok=True)

    json_report = generate_json_report(ctx, scan_id, target, elapsed)
    md_report = generate_markdown_report(ctx, scan_id, target, elapsed)

    (out_dir / "findings.json").write_text(json_report)
    (out_dir / "findings.md").write_text(md_report)

    console.print(f"[bold green]Scan complete in {elapsed:.1f}s[/bold green]")
    console.print(f"  Subdomains:  {len(ctx.subdomains)}")
    console.print(f"  Alive hosts: {len(ctx.alive_hosts)}")
    console.print(f"  Forms:       {len(ctx.forms)}")
    console.print(f"  Params:      {len(ctx.params)}")
    console.print(f"  JS files:    {len(ctx.js_files)}")
    console.print(f"  Findings:    {len(ctx.findings)}")
    console.print(f"  Errors:      {len(ctx.errors)}")
    console.print()
    console.print(f"  Reports: {out_dir / 'findings.json'}")
    console.print(f"           {out_dir / 'findings.md'}")


# ────────────────────────────────────────────────────────────────
# web
# ────────────────────────────────────────────────────────────────
@app.command()
def web(
    findings_dir: str = typer.Option(".", help="Directory containing findings.json"),
    bind: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8484, help="Port"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser automatically"),
) -> None:
    """Start the local web dashboard."""
    from bughunter.web.dashboard import create_app
    import json
    import webbrowser

    fd = Path(findings_dir)
    findings_file = fd / "findings.json"
    if not findings_file.exists():
        findings_file = fd
        if findings_file.is_dir():
            findings_file = findings_file / "findings.json"

    findings = []
    target = ""
    if findings_file.exists():
        with open(findings_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings", [])
            target = data.get("target", "")

    app_instance = create_app(findings, target)
    console.print(f"[bold cyan]Bughunter Dashboard[/bold cyan]")
    console.print(f"  Findings: {len(findings)}")
    console.print(f"  Target: {target or '(unknown)'}")
    console.print(f"  URL: http://{bind}:{port}")
    console.print()

    if open_browser:
        import threading
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{bind}:{port}")).start()

    app_instance.run(host=bind, port=port, debug=False)


if __name__ == "__main__":
    app()
