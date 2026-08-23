from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .tokens import AuthToken, AuthType, TokenManager


@dataclass
class EndpointAuthRule:
    pattern: str
    auth_required: bool = True
    auth_token_name: str = ""
    auth_type: AuthType = AuthType.BEARER
    skip_auth: bool = False
    scope_override: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def matches(self, url: str) -> bool:
        return bool(re.search(self.pattern, url))


@dataclass
class AuthPolicy:
    name: str
    rules: list[EndpointAuthRule] = field(default_factory=list)
    default_auth_type: AuthType = AuthType.BEARER
    default_token_name: str = ""
    expiry_warn_seconds: float = 300.0
    auto_refresh: bool = False
    refresh_endpoint: str = ""
    refresh_body: str = ""
    scope: str = ""

    def match_rule(self, url: str) -> EndpointAuthRule | None:
        for rule in self.rules:
            if rule.matches(url):
                return rule
        return None


class AuthPolicyManager:
    def __init__(self, token_manager: TokenManager | None = None) -> None:
        self._token_mgr = token_manager or TokenManager()
        self._policies: dict[str, AuthPolicy] = {}
        self._active_policy: str = ""
        self._global_skip: set[str] = set()

    def load_from_yaml(self, path: str | Path) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p) as f:
            data = yaml.safe_load(f) or {}

        for pol_data in data.get("auth_policies", []):
            rules = []
            for rule_data in pol_data.get("rules", []):
                rules.append(EndpointAuthRule(
                    pattern=rule_data["pattern"],
                    auth_required=rule_data.get("auth_required", True),
                    auth_token_name=rule_data.get("auth_token_name", ""),
                    auth_type=AuthType(rule_data.get("auth_type", "bearer")),
                    skip_auth=rule_data.get("skip_auth", False),
                    scope_override=rule_data.get("scope_override", ""),
                    headers=rule_data.get("headers", {}),
                    cookies=rule_data.get("cookies", {}),
                ))
            policy = AuthPolicy(
                name=pol_data["name"],
                rules=rules,
                default_auth_type=AuthType(pol_data.get("default_auth_type", "bearer")),
                default_token_name=pol_data.get("default_token_name", ""),
                expiry_warn_seconds=pol_data.get("expiry_warn_seconds", 300.0),
                auto_refresh=pol_data.get("auto_refresh", False),
                refresh_endpoint=pol_data.get("refresh_endpoint", ""),
                refresh_body=pol_data.get("refresh_body", ""),
                scope=pol_data.get("scope", ""),
            )
            self._policies[policy.name] = policy

        self._active_policy = data.get("active_auth_policy", "")
        for skip in data.get("skip_auth_paths", []):
            self._global_skip.add(skip)

    def register_policy(self, policy: AuthPolicy) -> None:
        self._policies[policy.name] = policy

    def set_active(self, name: str) -> bool:
        if name in self._policies:
            self._active_policy = name
            return True
        return False

    def get_active_policy(self) -> AuthPolicy | None:
        return self._policies.get(self._active_policy)

    def should_authenticate(self, url: str) -> bool:
        for skip in self._global_skip:
            if re.search(skip, url):
                return False

        policy = self.get_active_policy()
        if not policy:
            return True

        rule = policy.match_rule(url)
        if rule:
            if rule.skip_auth:
                return False
            return rule.auth_required

        return True

    def get_auth_for_url(self, url: str) -> dict[str, str]:
        policy = self.get_active_policy()
        if not policy:
            return {}

        rule = policy.match_rule(url)
        token_name = ""
        auth_type = policy.default_auth_type
        extra_headers: dict[str, str] = {}
        extra_cookies: dict[str, str] = {}

        if rule:
            token_name = rule.auth_token_name or policy.default_token_name
            auth_type = rule.auth_type if rule.auth_token_name else policy.default_auth_type
            extra_headers = dict(rule.headers)
            extra_cookies = dict(rule.cookies)
        else:
            token_name = policy.default_token_name

        token = None
        if token_name:
            for t in self._token_mgr.all_tokens:
                if t.name == token_name and not t.is_expired:
                    token = t
                    break

        if not token:
            token = self._token_mgr.get_token(url=url, scope=policy.scope)

        if not token:
            return {}

        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        params: dict[str, str] = {}

        if auth_type == AuthType.BEARER or auth_type == AuthType.JWT:
            headers["Authorization"] = f"Bearer {token.value}"
        elif auth_type == AuthType.BASIC:
            headers["Authorization"] = f"Basic {token.value}"
        elif auth_type == AuthType.HEADER:
            header_name = rule.header_name if rule and rule.headers else "Authorization"
            headers[header_name] = token.value
        elif auth_type == AuthType.COOKIE:
            cookie_name = rule.cookie_name if rule else token.cookie_name or "session"
            cookies[cookie_name] = token.value
        elif auth_type == AuthType.QUERY:
            param_name = rule.query_param if rule else token.query_param or "token"
            params[param_name] = token.value

        headers.update(extra_headers)
        cookies.update(extra_cookies)

        result = dict(headers)
        for k, v in cookies.items():
            result[f"cookie:{k}"] = v
        for k, v in params.items():
            result[f"param:{k}"] = v

        return result

    def check_token_health(self) -> list[dict]:
        issues = []
        expired = self._token_mgr.get_expired_tokens()
        for t in expired:
            issues.append({
                "type": "expired",
                "token": t.name,
                "expired_at": t.expires_at,
                "message": f"Token '{t.name}' has expired",
            })
        expiring = self._token_mgr.get_expiring_soon()
        for t in expiring:
            issues.append({
                "type": "expiring_soon",
                "token": t.name,
                "expires_in": t.seconds_until_expiry,
                "message": f"Token '{t.name}' expires in {t.seconds_until_expiry:.0f}s",
            })
        return issues

    @property
    def all_policies(self) -> list[str]:
        return list(self._policies.keys())

    def summary(self) -> dict:
        return {
            "active_policy": self._active_policy,
            "policies": len(self._policies),
            "tokens": self._token_mgr.summary(),
            "health_issues": len(self.check_token_health()),
            "global_skip_patterns": len(self._global_skip),
        }
