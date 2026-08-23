from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import yaml


class AuthType(StrEnum):
    HEADER = "header"
    COOKIE = "cookie"
    QUERY = "query_param"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM = "custom"


@dataclass
class AuthToken:
    name: str
    auth_type: AuthType
    value: str
    header_name: str = ""
    cookie_name: str = ""
    query_param: str = ""
    expires_at: float = 0.0
    scope: str = ""
    is_refresh_token: bool = False
    meta: dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at <= 0:
            return False
        return time.time() >= self.expires_at

    @property
    def seconds_until_expiry(self) -> float:
        if self.expires_at <= 0:
            return float("inf")
        return max(0.0, self.expires_at - time.time())

    def apply_to_headers(self, headers: dict[str, str]) -> dict[str, str]:
        if self.is_expired:
            return headers
        h = dict(headers)
        if self.auth_type == AuthType.BEARER:
            h["Authorization"] = f"Bearer {self.value}"
        elif self.auth_type == AuthType.BASIC:
            h["Authorization"] = f"Basic {self.value}"
        elif self.auth_type == AuthType.HEADER:
            name = self.header_name or "Authorization"
            h[name] = self.value
        return h

    def apply_to_cookies(self, cookies: dict[str, str]) -> dict[str, str]:
        if self.is_expired:
            return cookies
        c = dict(cookies)
        if self.auth_type == AuthType.COOKIE:
            name = self.cookie_name or self.name
            c[name] = self.value
        return c

    def apply_to_params(self, params: dict[str, str]) -> dict[str, str]:
        if self.is_expired:
            return params
        p = dict(params)
        if self.auth_type == AuthType.QUERY:
            name = self.query_param or self.name
            p[name] = self.value
        return p


JWT_EXPIRY_RE = re.compile(r'"exp"\s*:\s*(\d+)')


def parse_jwt_expiry(token_value: str) -> float:
    match = JWT_EXPIRY_RE.search(token_value)
    if match:
        return float(match.group(1))
    return 0.0


class TokenManager:
    def __init__(self) -> None:
        self._tokens: dict[str, AuthToken] = {}
        self._scope_map: dict[str, list[str]] = {}
        self._default_token: str = ""

    def load_from_yaml(self, path: str | Path) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        for token_data in data.get("auth_tokens", []):
            token = AuthToken(
                name=token_data["name"],
                auth_type=AuthType(token_data["type"]),
                value=token_data["value"],
                header_name=token_data.get("header_name", ""),
                cookie_name=token_data.get("cookie_name", ""),
                query_param=token_data.get("query_param", ""),
                expires_at=token_data.get("expires_at", 0.0),
                scope=token_data.get("scope", ""),
                meta=token_data.get("meta", {}),
            )
            if token.auth_type == AuthType.JWT and token.expires_at <= 0:
                token.expires_at = parse_jwt_expiry(token.value)
            self.register_token(token)

        default = data.get("default_auth_token", "")
        if default:
            self._default_token = default

    def register_token(self, token: AuthToken) -> None:
        self._tokens[token.name] = token
        if token.scope:
            for pattern in token.scope.split(","):
                pattern = pattern.strip()
                if pattern not in self._scope_map:
                    self._scope_map[pattern] = []
                self._scope_map[pattern].append(token.name)

    def get_token(self, url: str = "", scope: str = "") -> AuthToken | None:
        if scope:
            candidates = self._scope_map.get(scope, [])
            for name in candidates:
                t = self._tokens.get(name)
                if t and not t.is_expired:
                    return t

        for pattern, names in self._scope_map.items():
            if re.search(pattern, url):
                for name in names:
                    t = self._tokens.get(name)
                    if t and not t.is_expired:
                        return t

        if self._default_token:
            t = self._tokens.get(self._default_token)
            if t and not t.is_expired:
                return t

        for t in self._tokens.values():
            if not t.is_expired:
                return t

        return None

    def get_expired_tokens(self) -> list[AuthToken]:
        return [t for t in self._tokens.values() if t.is_expired]

    def get_expiring_soon(self, within_seconds: float = 300) -> list[AuthToken]:
        now = time.time()
        return [
            t for t in self._tokens.values()
            if 0 < t.expires_at - now < within_seconds
        ]

    @property
    def all_tokens(self) -> list[AuthToken]:
        return list(self._tokens.values())

    @property
    def has_valid_tokens(self) -> bool:
        return any(not t.is_expired for t in self._tokens.values())

    def remove_token(self, name: str) -> bool:
        if name in self._tokens:
            del self._tokens[name]
            return True
        return False

    def summary(self) -> dict:
        expired = self.get_expired_tokens()
        expiring = self.get_expiring_soon()
        return {
            "total": len(self._tokens),
            "valid": len(self._tokens) - len(expired),
            "expired": len(expired),
            "expiring_soon": len(expiring),
            "default": self._default_token,
        }
