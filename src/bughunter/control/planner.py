from __future__ import annotations

from bughunter.contracts.enums import SkipReason
from bughunter.contracts.policy import CompiledPolicy
from bughunter.contracts.tasks import TaskSpec


class Planner:
    def __init__(self, policy: CompiledPolicy) -> None:
        self.policy = policy

    def plan_tasks(
        self,
        module_specs: list[dict],
        available_capabilities: set[str],
    ) -> tuple[list[TaskSpec], list[tuple[str, SkipReason]]]:
        tasks: list[TaskSpec] = []
        skips: list[tuple[str, SkipReason]] = []

        for spec in module_specs:
            module_id = spec["id"]
            risk = spec.get("risk_level", "safe")
            requires = set(spec.get("requires", []))

            missing = requires - available_capabilities
            if missing:
                skips.append((module_id, SkipReason.MISSING_CAPABILITY))
                continue

            risk_allowed = self._check_risk(risk)
            if not risk_allowed:
                skips.append((module_id, SkipReason.RISK_NOT_AUTHORIZED))
                continue

            tasks.append(TaskSpec(
                module_id=module_id,
                module_version=spec.get("version", "0.1.0"),
                policy_hash=self.policy.hash,
                risk_level=risk,
                budget=spec.get("budget", {}),
            ))

        return tasks, skips

    def _check_risk(self, risk_level: str) -> bool:
        from bughunter.contracts.enums import RiskLevel
        risk = RiskLevel(risk_level)
        if risk in (RiskLevel.PASSIVE, RiskLevel.SAFE):
            return True
        if risk == RiskLevel.ACTIVE:
            return self.policy.active_risk_authorized
        if risk == RiskLevel.STATEFUL:
            return self.policy.stateful_risk_authorized
        if risk == RiskLevel.HIGH_RISK:
            return self.policy.high_risk_authorized
        return False
