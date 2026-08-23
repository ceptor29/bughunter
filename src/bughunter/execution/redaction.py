from __future__ import annotations

import re
from typing import Any


class Redactor:
    DEFAULT_PATTERNS: list[tuple[str, str]] = [
        (r"(?i)(authorization['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(cookie['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(set-cookie['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(secret['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(password['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"(?i)(token['\"]?\s*[:=]\s*['\"])([^'\"]+)", r"\1[REDACTED]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*", "[REDACTED_JWT]"),
    ]

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        self._patterns: list[tuple[re.Pattern, str]] = []
        for pat, repl in self.DEFAULT_PATTERNS + (extra_patterns or []):
            self._patterns.append((re.compile(pat), repl))

    def redact_text(self, text: str) -> str:
        result = text
        for pattern, repl in self._patterns:
            result = pattern.sub(repl, result)
        return result

    def redact_headers(self, headers: dict[str, str], sensitive: list[str] | None = None) -> dict[str, str]:
        sensitive = sensitive or ["authorization", "cookie", "set-cookie", "proxy-authorization"]
        redacted = {}
        for k, v in headers.items():
            if any(s in k.lower() for s in sensitive):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = v
        return redacted
