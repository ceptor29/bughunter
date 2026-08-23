# Bughunter

Authorization-first, evidence-driven web security assessment framework. Automates ~30 bug classes with context-aware manual hunting guidance for non-automatable bugs.

## Features

- **35+ built-in modules** — passive recon, active detection, subdomain takeover, security controls, GraphQL, dependency advisories
- **Authorization-first** — scope manifests required, no `--yes` bypass, per-endpoint auth policies
- **Evidence lifecycle** — observation → candidate → validated → confirmed, with disposition tracking
- **Auth management** — JWT expiry detection, per-endpoint token injection, scope-based selection
- **Safe-mode enforcement** — read-only by default, no mutations, per-profile request quotas
- **Hierarchical budgets** — scan/phase/task level with graceful cancellation (Ctrl+C)
- **Web dashboard** — findings browser, severity filter, disposition workflow, JSON/CSV export
- **Manual hunting guide** — step-by-step instructions for non-automatable bugs (IDOR, business logic, race conditions, etc.)
- **Verification steps** — every finding includes steps to confirm it's a true positive
- **Copy for Report** — one-click copy formatted for HackerOne/Bugcrowd submission
- **Interop** — import Burp XML/JSON, Nmap XML, Nuclei JSON results
- **Custom profiles** — YAML config for scope, risk, budgets, module selection
- **Config rollback** — snapshots, versioned rollback, diff against current

## Quick start

### Install

```bash
git clone https://github.com/ceptor29/bughunter.git
cd bughunter
python -m pip install -e ".[dev]"
```

### Start the dashboard

```bash
python -m bughunter.cli web
# Opens → http://127.0.0.1:8484
```

### Or use the CLI

```bash
# Init a project
python -m bughunter.cli init my-target

# Run a scan
python -m bughunter.cli scan scanme.nmap.org --config .bughunter/my-target/bughunter.yaml

# View results
cat findings.md
```

## Web dashboard

The dashboard provides a full UI for all operations:

| Page | What you can do |
|------|----------------|
| **Dashboard** | Stats, recent findings, live scan log |
| **New Scan** | Enter target, pick profile, start/stop scan, live output |
| **Findings** | Filter by severity/module/search, click for detail, disposition buttons, export JSON/CSV |
| **Auth Tokens** | Add/remove tokens, check health, validate JWTs |
| **Scope** | Check URL against scope, edit allowed/excluded hosts, save |
| **Modules** | Doctor (external tools status), all 30 built-in modules |
| **Projects** | Create new project, list existing, select for scan |
| **Manual Hunt** | Step-by-step guides for non-automatable bugs |

## Findings workflow

### 1. Verify a finding

Every finding includes **"How to Verify"** — step-by-step instructions:

```
1. Open the URL in your browser
2. Press F12 → Network tab → reload the page
3. Click the first request → Response Headers
4. Look for 'Strict-Transport-Security'
5. If missing, the finding is confirmed
```

### 2. Copy for Report

Click **Copy for Report** → pastes formatted text for HackerOne/Bugcrowd:

```markdown
## [high] Missing HSTS header

**URL:** http://example.com
**Module:** security_controls
**Evidence:** Missing header: Strict-Transport-Security
**Remediation:** Add Strict-Transport-Security: max-age=31536000
```

### 3. Disposition

Mark findings as:
- **False Positive** — not a real bug
- **Accepted Risk** — real but won't fix
- **Fixed** — already patched

## Manual hunting guide

The **Manual Hunt** page covers bugs that can't be detected automatically:

| Category | What to test | Time |
|----------|-------------|------|
| **IDOR** | Change user IDs in API calls | 2-4h |
| **Business Logic** | Price manipulation, race conditions | 1-2h |
| **Privilege Escalation** | Access admin features as regular user | 2-3h |
| **Authentication** | Brute force, password reset flow | 30min-2h |
| **Authorization** | Horizontal/vertical privilege escalation | 2-4h |
| **API Security** | Mass assignment, rate limiting | 2-4h |
| **File Upload** | Filter bypass (.php as .jpg) | 1-2h |
| **Session Management** | Session fixation, timeout | 30min |
| **CORS** | Origin reflection, credentials | 30min |
| **Cache Poisoning** | Unkeyed headers | 2-4h |
| **WebSocket** | Channel authorization | 1-2h |

Each task includes: step-by-step instructions, estimated time, tools needed, severity if found.

## Scan profiles

| Profile | Description | Max requests |
|---------|-------------|-------------|
| `passive` | Passive recon only, no HTTP traffic | 0 |
| `safe` | Read-only, no mutations (default) | 500 |
| `active` | Active testing with safe payloads | 2000 |
| `unrestricted` | Full testing, auth-managed | 5000 |

## Auth tokens

Create `auth.yaml` for authenticated scanning:

```yaml
auth_tokens:
  - name: session-cookie
    type: cookie
    value: "session=abc123..."
    cookie_name: session
    scope: ".*example\\.com.*"

  - name: api-key
    type: bearer
    value: "Bearer eyJ..."

  - name: jwt-token
    type: jwt
    value: "eyJhbGciOiJIUzI1NiIs..."
    # Expiry auto-detected from JWT claims
```

Manage via dashboard (Auth Tokens page) or CLI:

```bash
python -m bughunter.cli auth tokens --check
python -m bughunter.cli auth add-token my-token --token-type bearer --value "eyJ..."
python -m bughunter.cli auth validate-token "eyJ..."
```

## Scope configuration

Edit `bughunter.yaml` or use the dashboard Scope page:

```yaml
scope:
  allowed_schemes: [https]
  allowed_hosts: [example.com, *.example.com]
  allowed_ports: [443, 80]
  excluded_hosts: [staging.example.com]
  excluded_paths: [/admin, /wp-admin]
  allow_private_ips: false
  max_redirects: 3
```

## Import external results

```python
from bughunter.interop import load_burp_state, burp_to_scan_context
from bughunter.interop.nmap_adapter import parse_nmap_xml
from bughunter.interop.nuclei_adapter import import_nuclei_results

# Burp Suite
requests = load_burp_state("burp_export.xml")
ctx = burp_to_scan_context(requests)

# Nmap
hosts = parse_nmap_xml("nmap_scan.xml")

# Nuclei
findings = import_nuclei_results("nuclei_results.json")
```

## CLI commands

```
bughunter init <project>           Initialize project
bughunter scan <target>            Run scan
bughunter web                      Start dashboard (port 8484)
bughunter auth tokens --check      Check token health
bughunter auth add-token           Add auth token
bughunter auth validate-token      Validate JWT
bughunter scope validate           Validate scope
bughunter scope explain <url>      Check URL against scope
bughunter modules --list           List all modules
bughunter doctor                   Check external tools
```

## Module list

| Module | Risk | Description |
|--------|------|-------------|
| passive.provider_sources | passive | crt.sh, hackertarget, rapiddns |
| recon.dns_resolution | safe | A/AAAA/CNAME/MX/TXT + wildcard detection |
| recon.http_probe | safe | HTTP alive check, titles, tech fingerprinting |
| recon.crawl | safe | Bounded same-origin page crawl |
| surface.endpoint_inventory | safe | Endpoint and parameter extraction |
| surface.component_inventory | safe | Component and version detection |
| surface.dependency_advisories | safe | OSV dependency advisory lookup |
| detect.exposed_artifacts | safe | .env, .git, phpinfo, swagger, debug, dir listing |
| detect.repository_metadata | safe | .git/HEAD, .git/config exposure |
| detect.takeover | safe | 40+ subdomain takeover fingerprints |
| detect.security_controls | safe | Missing headers, CORS, cookie flags, clickjacking |
| detect.graphql_surface | safe | Introspection, GraphiQL, schema sensitive types |
| detect.component_exposure | safe | Vulnerable components via OSV |
| detect.xss | active | Cross-site scripting (reflected/DOM) |
| detect.sqli | active | SQL injection (error and time-blind) |
| detect.ssrf | active | Server-side request forgery |
| detect.ssti | active | Server-side template injection |
| detect.crlf | active | CRLF header injection |
| detect.traversal | active | Path traversal detection |
| detect.redirect | active | Open redirect detection |
| authn.oauth_review | stateful | OAuth flow review |
| authn.jwt_review | local | JWT token review and forgery test |
| authz.session_differential | stateful | Cross-account session differential |
| expert.race | high_risk | Race condition detection |
| expert.upload | stateful | File upload filter testing |
| expert.xxe | high_risk | XML external entity detection |
| expert.cache_poison | high_risk | Cache poisoning detection |
| expert.websocket | stateful | WebSocket origin checks |
| expert.smuggling | lab | Request smuggling (lab only) |

## Optional external tools

```bash
python -m bughunter.cli doctor
```

| Tool | Purpose |
|------|---------|
| subfinder | Passive subdomain enumeration |
| amass | Deep subdomain enumeration |
| httpx | Mass HTTP probing |
| nuclei | Template-based scanning |
| naabu/nmap | Port scanning |
| ffuf | Content discovery |
| arjun | Parameter discovery |

## Project structure

```
bughunter/
├── src/bughunter/
│   ├── auth/          Token management, per-endpoint auth policies
│   ├── config/        Profiles, rollback, YAML config system
│   ├── contracts/     Enums, policy, tasks, artifacts, evidence, findings
│   ├── control/       Authorization, lifecycle, cancellation, prompts, closure
│   ├── core/          Engine, evidence lifecycle, fingerprint, dispositions
│   ├── execution/     HTTP gateway, DNS, rate limits, budgets, redaction
│   ├── guidance/      Manual hunting guide, verification steps
│   ├── interop/       Burp, Nmap, Nuclei adapters
│   ├── modules/
│   │   ├── passive/   Certificate names, provider sources
│   │   ├── recon/     DNS, HTTP probe, crawl, crawl scope
│   │   ├── surface/   Endpoint inventory, component inventory, advisories
│   │   └── detectors/ exposed artifacts, takeover, security controls, GraphQL
│   ├── storage/       SQLite database, artifact store
│   ├── web/           Flask dashboard
│   └── cli.py         Typer CLI
├── pyproject.toml     Package config
└── .github/           CI, issue templates, dependabot
```

## License

MIT
