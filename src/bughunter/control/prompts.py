from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import StrEnum


class PromptKind(StrEnum):
    RISK_ACK = "risk_ack"
    SCOPE_CHANGE = "scope_change"
    CREDENTIAL_USE = "credential_use"
    DANGEROUS_ACTION = "dangerous_action"
    BUDGET_OVERRIDE = "budget_override"
    AUTH_EXPIRY = "auth_expiry"


@dataclass
class PromptResult:
    accepted: bool
    reason: str = ""
    operator: str = ""


@dataclass
class OperatorPrompt:
    kind: PromptKind
    title: str
    description: str
    risk_level: str = "safe"
    requires_input: bool = True
    default_accept: bool = False
    meta: dict = field(default_factory=dict)


class PromptManager:
    def __init__(self, interactive: bool = True) -> None:
        self._interactive = interactive
        self._history: list[dict] = []
        self._auto_accept: set[PromptKind] = set()

    def set_auto_accept(self, kinds: list[PromptKind]) -> None:
        self._auto_accept = set(kinds)

    def prompt(self, request: OperatorPrompt) -> PromptResult:
        if request.kind in self._auto_accept:
            result = PromptResult(accepted=True, reason="auto-accepted")
            self._history.append({"kind": request.kind.value, "title": request.title, "result": "auto-accepted"})
            return result

        if not self._interactive:
            result = PromptResult(accepted=request.default_accept, reason="non-interactive mode")
            self._history.append({"kind": request.kind.value, "title": request.title, "result": "non-interactive"})
            return result

        risk_indicator = {
            "safe": "\033[92m",    # green
            "active": "\033[93m",  # yellow
            "high_risk": "\033[91m",  # red
            "lab": "\033[95m",     # magenta
        }.get(request.risk_level, "\033[0m")

        reset = "\033[0m"

        print(f"\n{risk_indicator}╔══════════════════════════════════════════╗{reset}")
        print(f"{risk_indicator}║  {request.kind.value.upper():^38} ║{reset}")
        print(f"{risk_indicator}╚══════════════════════════════════════════╝{reset}")
        print(f"  {request.title}")
        print(f"  {request.description}")
        if request.meta:
            for k, v in request.meta.items():
                print(f"  {k}: {v}")
        print()

        while True:
            try:
                if request.requires_input:
                    choice = input("  Accept? [y/N/r(eason)]: ").strip().lower()
                else:
                    choice = "y"

                if choice in ("y", "yes"):
                    result = PromptResult(accepted=True, reason="operator approved")
                    self._history.append({"kind": request.kind.value, "title": request.title, "result": "approved"})
                    return result
                elif choice in ("n", "no", ""):
                    reason = input("  Reason for rejection (optional): ").strip() if choice != "" else "operator declined"
                    result = PromptResult(accepted=False, reason=reason)
                    self._history.append({"kind": request.kind.value, "title": request.title, "result": "rejected", "reason": reason})
                    return result
                elif choice in ("r", "reason"):
                    print(f"  Risk: {request.risk_level}")
                    print(f"  Kind: {request.kind.value}")
                    for k, v in request.meta.items():
                        print(f"  {k}: {v}")
            except (EOFError, KeyboardInterrupt):
                result = PromptResult(accepted=False, reason="interrupted")
                self._history.append({"kind": request.kind.value, "title": request.title, "result": "interrupted"})
                return result

    def prompt_risk_ack(self, title: str, description: str, risk_level: str, meta: dict | None = None) -> PromptResult:
        return self.prompt(OperatorPrompt(
            kind=PromptKind.RISK_ACK,
            title=title,
            description=description,
            risk_level=risk_level,
            requires_input=True,
            meta=meta or {},
        ))

    def prompt_scope_change(self, title: str, description: str, meta: dict | None = None) -> PromptResult:
        return self.prompt(OperatorPrompt(
            kind=PromptKind.SCOPE_CHANGE,
            title=title,
            description=description,
            risk_level="active",
            requires_input=True,
            meta=meta or {},
        ))

    def prompt_credential_use(self, title: str, description: str, meta: dict | None = None) -> PromptResult:
        return self.prompt(OperatorPrompt(
            kind=PromptKind.CREDENTIAL_USE,
            title=title,
            description=description,
            risk_level="active",
            requires_input=True,
            meta=meta or {},
        ))

    def prompt_budget_override(self, title: str, description: str, meta: dict | None = None) -> PromptResult:
        return self.prompt(OperatorPrompt(
            kind=PromptKind.BUDGET_OVERRIDE,
            title=title,
            description=description,
            risk_level="safe",
            requires_input=True,
            meta=meta or {},
        ))

    @property
    def history(self) -> list[dict]:
        return list(self._history)

    def summary(self) -> dict:
        approved = sum(1 for h in self._history if h["result"] == "approved")
        rejected = sum(1 for h in self._history if h["result"] == "rejected")
        return {
            "total": len(self._history),
            "approved": approved,
            "rejected": rejected,
            "auto_accepted": sum(1 for h in self._history if h["result"] == "auto-accepted"),
        }
