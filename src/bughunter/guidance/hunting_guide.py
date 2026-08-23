from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HuntingTask:
    category: str
    title: str
    description: str
    steps: list[str]
    severity_if_found: str
    estimated_time: str
    tools_needed: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


MANUAL_HUNTING_GUIDE: dict[str, list[HuntingTask]] = {
    "idor": [
        HuntingTask(
            category="IDOR",
            title="Test IDOR on user endpoints",
            description="Change user IDs in API calls to access other users' data",
            steps=[
                "Find endpoints with numeric IDs: /api/users/123, /api/orders/456",
                "Log in as User A, note the ID in URLs and API calls",
                "Log in as User B, try User A's IDs",
                "Try incrementing/decrementing IDs",
                "Check if IDs appear in responses (profile pages, order confirmations)",
                "Test both GET (read) and PUT/POST (modify) endpoints",
            ],
            severity_if_found="critical",
            estimated_time="2-4 hours",
            tools_needed=["browser devtools", "Burp Suite"],
        ),
    ],
    "business_logic": [
        HuntingTask(
            category="Business Logic",
            title="Test price manipulation",
            description="Try to buy items for less than intended price",
            steps=[
                "Add item to cart, note the price",
                "Intercept the checkout request",
                "Change price, quantity, or discount fields",
                "Try applying multiple coupons",
                "Try negative quantities",
                "Try changing currency parameters",
                "Check if server validates price or trusts client",
            ],
            severity_if_found="critical",
            estimated_time="1-2 hours",
            tools_needed=["Burp Suite", "browser devtools"],
        ),
        HuntingTask(
            category="Business Logic",
            title="Test race conditions",
            description="Send simultaneous requests to exploit timing",
            steps=[
                "Find a state-changing action (coupon apply, balance transfer, vote)",
                "Send 10+ simultaneous requests using Burp Turbo Intruder or curl",
                "Check if any requests succeeded multiple times",
                "Try: apply coupon 10 times, transfer money 10 times simultaneously",
                "Check if balance/votes/credits increased more than once",
            ],
            severity_if_found="high",
            estimated_time="1-2 hours",
            tools_needed=["Burp Suite", "Turbo Intruder"],
        ),
        HuntingTask(
            category="Business Logic",
            title="Test privilege escalation",
            description="Try to access admin features as regular user",
            steps=[
                "Find admin endpoints (try /admin, /dashboard, /manage)",
                "Intercept admin requests, replay as regular user",
                "Change role parameters in API calls",
                "Check if admin endpoints check authorization server-side",
                "Try accessing other users' private data",
            ],
            severity_if_found="critical",
            estimated_time="2-3 hours",
            tools_needed=["Burp Suite"],
        ),
    ],
    "authentication": [
        HuntingTask(
            category="Authentication",
            title="Test brute force protection",
            description="Try multiple login attempts to test rate limiting",
            steps=[
                "Try logging in with wrong password 10+ times",
                "Check if account gets locked",
                "Check if there's rate limiting on login",
                "Try different usernames to enumerate valid accounts",
                "Check error messages: 'invalid password' vs 'user not found'",
            ],
            severity_if_found="medium",
            estimated_time="30 minutes",
            tools_needed=["Burp Suite", "Hydra"],
        ),
        HuntingTask(
            category="Authentication",
            title="Test password reset flow",
            description="Try to exploit password reset mechanism",
            steps=[
                "Request password reset for your account",
                "Intercept the reset link",
                "Try changing the email in the request",
                "Try using an expired reset link",
                "Try reusing a reset link after password change",
                "Check if reset token is predictable (sequential, timestamp-based)",
            ],
            severity_if_found="high",
            estimated_time="1-2 hours",
            tools_needed=["Burp Suite"],
        ),
    ],
    "authorization": [
        HuntingTask(
            category="Authorization",
            title="Test horizontal privilege escalation",
            description="Access other users' resources",
            steps=[
                "Create two accounts (User A and User B)",
                "As User A, create a private resource (document, post, profile)",
                "Note the resource ID/URL",
                "As User B, try to access User A's resource",
                "Try different HTTP methods (GET, PUT, DELETE)",
                "Check API endpoints for user-scoped resources",
            ],
            severity_if_found="critical",
            estimated_time="2-4 hours",
            tools_needed=["two accounts", "Burp Suite"],
        ),
        HuntingTask(
            category="Authorization",
            title="Test vertical privilege escalation",
            description="Access admin features as regular user",
            steps=[
                "Find admin-only functionality",
                "Intercept admin requests",
                "Replay them as a regular user",
                "Try changing role/user_type parameters",
                "Check if authorization is enforced server-side",
            ],
            severity_if_found="critical",
            estimated_time="2-3 hours",
            tools_needed=["Burp Suite"],
        ),
    ],
    "api": [
        HuntingTask(
            category="API Security",
            title="Test mass assignment",
            description="Try adding unexpected fields to API requests",
            steps=[
                "Find API endpoints that create/update resources",
                "Add extra fields to the request: is_admin, role, credit, balance",
                "Check if the extra fields are stored/used",
                "Try adding fields you saw in other API responses",
                "Check GraphQL introspection for hidden fields",
            ],
            severity_if_found="high",
            estimated_time="2-4 hours",
            tools_needed=["Burp Suite"],
        ),
        HuntingTask(
            category="API Security",
            title="Test API rate limiting",
            description="Try to abuse API endpoints without rate limits",
            steps=[
                "Find sensitive API endpoints (login, password reset, OTP)",
                "Send 100+ requests quickly",
                "Check if you get rate-limited (429 status)",
                "Try different IP addresses or headers",
                "Check if rate limit applies per-user or per-IP",
            ],
            severity_if_found="medium",
            estimated_time="1 hour",
            tools_needed=["Burp Suite", "curl"],
        ),
    ],
    "file_upload": [
        HuntingTask(
            category="File Upload",
            title="Test upload filter bypass",
            description="Try uploading malicious files through upload forms",
            steps=[
                "Find file upload endpoints",
                "Try uploading a .php file renamed to .jpg",
                "Try double extensions: shell.php.jpg",
                "Try null bytes: shell.php%00.jpg",
                "Try uploading SVG with embedded JavaScript",
                "Try uploading HTML files",
                "Check if uploaded files are served back directly",
            ],
            severity_if_found="critical",
            estimated_time="1-2 hours",
            tools_needed=["Burp Suite", "text editor"],
        ),
    ],
    "session": [
        HuntingTask(
            category="Session Management",
            title="Test session fixation",
            description="Try to fixate a session ID before login",
            steps=[
                "Note your session cookie before login",
                "Log in",
                "Check if the session cookie changed after login",
                "If not, the session is fixated — an attacker can set it before victim logs in",
                "Try setting a session cookie manually before login",
            ],
            severity_if_found="high",
            estimated_time="30 minutes",
            tools_needed=["browser devtools"],
        ),
        HuntingTask(
            category="Session Management",
            title="Test session timeout",
            description="Check if sessions expire properly",
            steps=[
                "Log in and note the session cookie",
                "Wait for the idle timeout (usually 15-30 minutes)",
                "Try using the old session cookie",
                "Check if it's still accepted",
                "Test absolute timeout (24 hours)",
            ],
            severity_if_found="low",
            estimated_time="30 minutes",
            tools_needed=["browser"],
        ),
    ],
    "cors": [
        HuntingTask(
            category="CORS",
            title="Test CORS misconfiguration",
            description="Try to exploit CORS to steal data cross-origin",
            steps=[
                "Send request with Origin: https://evil.com",
                "Check if Access-Control-Allow-Origin: https://evil.com",
                "Check if Access-Control-Allow-Credentials: true",
                "If both, you can steal data cross-origin",
                "Try null origin (sandboxed iframe)",
                "Try subdomain: https://evil.target.com",
            ],
            severity_if_found="high",
            estimated_time="30 minutes",
            tools_needed=["Burp Suite", "curl"],
        ),
    ],
    "cache": [
        HuntingTask(
            category="Cache Poisoning",
            title="Test web cache poisoning",
            description="Try to poison CDN cache with malicious responses",
            steps=[
                "Find unkeyed headers (X-Forwarded-Host, X-Original-URL)",
                "Send request with poisoned header",
                "Check if response is cached",
                "If cached, other users will get poisoned response",
                "Try: X-Forwarded-Host: evil.com, X-Original-URL: /admin",
            ],
            severity_if_found="high",
            estimated_time="2-4 hours",
            tools_needed=["Burp Suite"],
        ),
    ],
    "websocket": [
        HuntingTask(
            category="WebSocket",
            title="Test WebSocket authorization",
            description="Try to access other users' WebSocket channels",
            steps=[
                "Find WebSocket endpoints (wss://)",
                "Note the channel/user ID in the connection",
                "Try connecting with a different user's channel ID",
                "Try sending messages to other users' channels",
                "Check if origin is validated",
            ],
            severity_if_found="high",
            estimated_time="1-2 hours",
            tools_needed=["Burp Suite", "wscat"],
        ),
    ],
}


def get_hunting_guide(target_info: dict | None = None) -> dict[str, list[dict]]:
    guide: dict[str, list[dict]] = {}
    for category, tasks in MANUAL_HUNTING_GUIDE.items():
        guide[category] = []
        for task in tasks:
            guide[category].append({
                "title": task.title,
                "description": task.description,
                "steps": task.steps,
                "severity_if_found": task.severity_if_found,
                "estimated_time": task.estimated_time,
                "tools_needed": task.tools_needed,
            })
    return guide


def get_verification_steps(finding_module: str, finding_title: str) -> list[str]:
    title_lower = finding_title.lower()

    if "hsts" in title_lower:
        return [
            "Open the URL in your browser",
            "Press F12 → Network tab → reload the page",
            "Click the first request → Response Headers",
            "Look for 'Strict-Transport-Security'",
            "If missing, the finding is confirmed",
        ]
    if "x-frame" in title_lower or "clickjack" in title_lower:
        return [
            "Open the URL in your browser",
            "Press F12 → Console",
            "Type: document.querySelector('iframe') — check if page can be framed",
            "Try: create an iframe with src=target URL on your own page",
            "If the page loads inside an iframe, finding is confirmed",
        ]
    if "content-security-policy" in title_lower:
        return [
            "Open the URL in your browser",
            "Press F12 → Network tab → click the request → Response Headers",
            "Look for 'Content-Security-Policy'",
            "If missing, the finding is confirmed",
        ]
    if "csrf" in title_lower:
        return [
            "Find a form on the page",
            "Right-click → View Page Source",
            "Search for 'csrf' or '_token' or 'authenticity_token'",
            "If no token found in the form, finding is confirmed",
            "Also check: does the form use GET method for state changes?",
        ]
    if "exposed" in title_lower or ".env" in title_lower or "git" in title_lower:
        return [
            "Open the URL directly in your browser",
            "If you see file contents (not 403/404), finding is confirmed",
            "For .env: look for DB_, AWS_, SECRET, TOKEN keys",
            "For .git/HEAD: look for 'ref: refs/heads/'",
            "Screenshot the evidence for your report",
        ]
    if "takeover" in title_lower:
        return [
            "Open the URL in your browser",
            "Check if it shows a third-party page (Heroku, GitHub Pages, etc.)",
            "The page should say something like 'No such app' or 'Not found'",
            "If you can claim the resource, finding is confirmed",
            "Try to register/claim the dangling resource",
        ]
    if "graphql" in title_lower or "introspection" in title_lower:
        return [
            "Open the URL in your browser (e.g. /graphql)",
            "Try an introspection query: { __schema { types { name } } }",
            "If it returns the schema, finding is confirmed",
            "Check for sensitive types: User, Token, Admin, Password",
        ]
    if "cors" in title_lower:
        return [
            "curl -H 'Origin: https://evil.com' -I https://target.com",
            "Check if 'Access-Control-Allow-Origin: https://evil.com'",
            "If yes and credentials are allowed, finding is confirmed",
        ]

    return [
        "Open the URL mentioned in the finding",
        "Check the evidence provided",
        "Verify the issue exists as described",
        "Take a screenshot for your report",
        "Test with different browsers/tools if needed",
    ]
