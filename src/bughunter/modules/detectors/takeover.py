from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class TakeoverFinding:
    module: str
    title: str
    url: str
    evidence: str
    severity: str
    confidence: str
    service: str
    invariant: str = ""
    remediation: str = ""


SERVICE_FINGERPRINTS: dict[str, list[re.Pattern]] = {
    "herokuapp": [re.compile(r"No such app|Heroku|herokucdn", re.IGNORECASE)],
    "github-pages": [re.compile(r"There isn't a GitHub Pages site here|pages\.github\.com", re.IGNORECASE)],
    "shopify": [re.compile(r"Sorry, this shop is currently unavailable|Only one step left", re.IGNORECASE)],
    "fastly": [re.compile(r"Fastly error: unknown domain|fastly\.net", re.IGNORECASE)],
    "pantheon": [re.compile(r"404 error unknown site|Pantheon\.io", re.IGNORECASE)],
    "ghost": [re.compile(r"The thing you were looking for is no longer here|Ghost\.io", re.IGNORECASE)],
    "tumblr": [re.compile(r"Whatever you were looking for|tumblr\.com", re.IGNORECASE)],
    "amazonaws-s3": [re.compile(r"NoSuchBucket|The specified bucket does not exist|Code: NoSuchBucket", re.IGNORECASE)],
    "google-cloud-storage": [re.compile(r"NoSuchBucket|The specified bucket does not exist", re.IGNORECASE)],
    "microsoft-azure": [re.compile(r"Azure Web App|azurewebsites\.net|does not exist", re.IGNORECASE)],
    "unbounce": [re.compile(r"The requested URL was not found on this server|If you need assistance, contact", re.IGNORECASE)],
    "landingi": [re.compile(r"It looks like you're lost|Landingi", re.IGNORECASE)],
    "netlify": [re.compile(r"Not Found - Request ID|netlify\.com", re.IGNORECASE)],
    "vercel": [re.compile(r"The deployment could not be found|vercel\.app", re.IGNORECASE)],
    "surge": [re.compile(r"project not found|surge\.sh", re.IGNORECASE)],
    "bitbucket": [re.compile(r"Repository not found|bitbucket\.org", re.IGNORECASE)],
    "gitlab": [re.compile(r"The page you're looking for could not be found|gitlab\.io", re.IGNORECASE)],
    "teamwork": [re.compile(r"Oops - We didn't find your site\.|teamwork\.com", re.IGNORECASE)],
    "helpjuice": [re.compile(r"We could not find what you're looking for|helpjuice\.com", re.IGNORECASE)],
    "helpscout": [re.compile(r"No settings were found for this company|helpscoutdocs\.com", re.IGNORECASE)],
    "cargocollective": [re.compile(r"If this is your website and you've just created it|cargocollective\.com", re.IGNORECASE)],
    "statuspage": [re.compile(r"You are being redirected|statuspage\.io", re.IGNORECASE)],
    "userVoice": [re.compile(r"This UserVoice site is currently available|uservoice\.com", re.IGNORECASE)],
    "Zendesk": [re.compile(r"Help Center Closed|zendesk\.com", re.IGNORECASE)],
    "Anima": [re.compile(r"If this is your website|animaapp\.io", re.IGNORECASE)],
    "Intercom": [re.compile(r"This page is reserved for|intercom-termin", re.IGNORECASE)],
    "Webflow": [re.compile(r"The page you are looking for|webflow\.com", re.IGNORECASE)],
    "Kajabi": [re.compile(r"The page you were looking for|kajabi\.com", re.IGNORECASE)],
    "Thinkific": [re.compile(r"You may have typed the address incorrectly|thinkific\.com", re.IGNORECASE)],
    "Teachable": [re.compile(r"Teachable|teachable\.com", re.IGNORECASE)],
    "Wix": [re.compile(r"Moved Permanently|wix\.com", re.IGNORECASE)],
    "Squarespace": [re.compile(r"This site can.t be reached|squarespace\.com", re.IGNORECASE)],
    "Campaignmonitor": [re.compile(r"Double check the URL|campaignmonitor\.com", re.IGNORECASE)],
    "Acquia": [re.compile(r"Web Site Not Found|acquia\.com", re.IGNORECASE)],
    "Proposify": [re.compile(r"proposify\.biz", re.IGNORECASE)],
    "Simplebooklet": [re.compile(r"We can.t find this Simplebooklet|simplebooklet\.com", re.IGNORECASE)],
    "GetResponse": [re.compile(r"With GetResponse Landing Pages|getresponse\.com", re.IGNORECASE)],
    "Vend": [re.compile(r"Looks like you've followed a broken link|vend\.com", re.IGNORECASE)],
    "Aftership": [re.compile(r"aftership\.com", re.IGNORECASE)],
    "Aha!": [re.compile(r"Log in to your account|aha\.io", re.IGNORECASE)],
    "Tave": [re.compile(r"Client. Hidden for Privacy|tave\.com", re.IGNORECASE)],
    "Wishpond": [re.compile(r"https?://wishpond\.com", re.IGNORECASE)],
    "Apester": [re.compile(r"apester\.com", re.IGNORECASE)],
    "Lightspeed": [re.compile(r"lightspeed", re.IGNORECASE)],
    "BigCartel": [re.compile(r"bigcartel\.com", re.IGNORECASE)],
    "JETBRAINS": [re.compile(r"You've got 99 problems but a domain ain't one", re.IGNORECASE)],
    "Ngrok": [re.compile(r"ngrok\.io|ngrok-free\.app", re.IGNORECASE)],
    "Fly.io": [re.compile(r"fly\.dev", re.IGNORECASE)],
    "Render": [re.compile(r"render\.app|onrender\.com", re.IGNORECASE)],
    "Railway": [re.compile(r"railway\.app|up\.railway\.app", re.IGNORECASE)],
    "Replit": [re.compile(r"replit\.com|repl\.co", re.IGNORECASE)],
}

SENSITIVE_PATHS = [
    "/", "/api", "/admin", "/login", "/dashboard", "/graphql",
]


async def scan_takeover(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[TakeoverFinding]:
    findings: list[TakeoverFinding] = []

    async def _check(path: str) -> None:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = await client.get(url, timeout=8.0, follow_redirects=True)
        except httpx.HTTPError:
            return

        if resp.status_code >= 500:
            return

        body = resp.text[:10000]
        matched_service = None
        matched_evidence = ""

        for service, patterns in SERVICE_FINGERPRINTS.items():
            for pat in patterns:
                m = pat.search(body)
                if m:
                    matched_service = service
                    matched_evidence = m.group(0)
                    break
            if matched_service:
                break

        if not matched_service:
            return

        findings.append(TakeoverFinding(
            module="takeover",
            title=f"Possible subdomain takeover via {matched_service}",
            url=url,
            evidence=f"Service fingerprint: {matched_evidence}",
            severity="critical",
            confidence="medium",
            service=matched_service,
            invariant="Unclaimed subdomains pointing to third-party services must be deprovisioned",
            remediation=f"Claim the {matched_service} resource or remove the dangling DNS record",
        ))

    import asyncio
    await asyncio.gather(*[_check(p) for p in SENSITIVE_PATHS])
    return findings
