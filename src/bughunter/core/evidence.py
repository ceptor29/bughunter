from __future__ import annotations

from bughunter.contracts.evidence import ValidationAttemptDraft
from bughunter.contracts.findings import Finding, FindingState

# Valid state transitions per V2 evidence lifecycle
VALID_TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.OBSERVATION: {FindingState.CANDIDATE, FindingState.DISMISSED},
    FindingState.CANDIDATE: {FindingState.VALIDATED, FindingState.DISMISSED},
    FindingState.VALIDATED: {FindingState.CONFIRMED, FindingState.DISMISSED, FindingState.ACCEPTED_RISK},
    FindingState.CONFIRMED: {FindingState.DISMISSED, FindingState.ACCEPTED_RISK},
    FindingState.DISMISSED: {FindingState.CANDIDATE},  # reopen
    FindingState.ACCEPTED_RISK: {FindingState.CANDIDATE},  # reopen
}


class EvidenceLifecycle:
    """Manages finding state transitions with validation controls."""

    def __init__(self) -> None:
        self._transition_log: list[dict] = []

    def can_transition(self, current: FindingState, target: FindingState) -> bool:
        return target in VALID_TRANSITIONS.get(current, set())

    def transition(
        self,
        finding: Finding,
        target: FindingState,
        reason: str = "",
        operator: str = "system",
    ) -> Finding:
        if not self.can_transition(finding.state, target):
            raise InvalidTransitionError(
                f"Cannot transition {finding.state.value} → {target.value}"
            )
        old_state = finding.state
        finding.state = target
        self._transition_log.append({
            "finding_id": str(finding.id),
            "from": old_state.value,
            "to": target.value,
            "reason": reason,
            "operator": operator,
        })
        return finding

    def promote_observation_to_candidate(
        self, finding: Finding, evidence: str = ""
    ) -> Finding:
        return self.transition(finding, FindingState.CANDIDATE, reason=evidence)

    def validate_candidate(
        self,
        finding: Finding,
        validation: ValidationAttemptDraft,
    ) -> Finding:
        if not validation.positive_result:
            raise ValidationError("Validation must have positive_result=True to promote")
        if not validation.negative_controls_passed:
            raise ValidationError("Negative controls must pass for validation")
        finding.confidence = min(finding.confidence + 0.3, 1.0)
        return self.transition(finding, FindingState.VALIDATED, reason=f"Validation {validation.id}")

    def confirm_validated(self, finding: Finding, reason: str = "") -> Finding:
        return self.transition(finding, FindingState.CONFIRMED, reason=reason)

    def dismiss(self, finding: Finding, reason: str = "") -> Finding:
        return self.transition(finding, FindingState.DISMISSED, reason=reason)

    def accept_risk(self, finding: Finding, reason: str = "") -> Finding:
        return self.transition(finding, FindingState.ACCEPTED_RISK, reason=reason)

    @property
    def transition_log(self) -> list[dict]:
        return list(self._transition_log)


class InvalidTransitionError(Exception):
    pass


class ValidationError(Exception):
    pass
