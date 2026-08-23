from __future__ import annotations

from enum import StrEnum, auto


class RiskLevel(StrEnum):
    PASSIVE = "passive"
    SAFE = "safe"
    ACTIVE = "active"
    STATEFUL = "stateful"
    HIGH_RISK = "high_risk"
    LAB = "lab"


class ResultState(StrEnum):
    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    ACCEPTED_RISK = "accepted_risk"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ScopeAction(StrEnum):
    ALLOW = auto()
    DENY = auto()


class SkipReason(StrEnum):
    MISSING_CAPABILITY = "missing_capability"
    POLICY_DENIED = "policy_denied"
    RISK_NOT_AUTHORIZED = "risk_not_authorized"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOOL_MISSING = "tool_missing"
    TOOL_INCOMPATIBLE = "tool_incompatible"
    PRECONDITION_ABSENT = "precondition_absent"
    USER_CANCELLED = "user_cancelled"
    EXPIRED_MANIFEST = "expired_manifest"
    DRY_RUN = "dry_run"
