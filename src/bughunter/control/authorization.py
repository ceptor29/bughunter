from __future__ import annotations

from bughunter.contracts.enums import RiskLevel, SkipReason
from bughunter.contracts.policy import AuthorizationManifest, CompiledPolicy


class AuthorizationManager:
    def __init__(self) -> None:
        self._manifest: AuthorizationManifest | None = None

    def load_manifest(self, manifest: AuthorizationManifest) -> list[str]:
        errors: list[str] = []
        if not manifest.allowed_assets:
            errors.append("manifest has no allowed_assets")
        if not manifest.reference:
            errors.append("manifest has no reference")
        if manifest.is_expired():
            errors.append("manifest is expired")
        if not manifest.acknowledgement:
            errors.append("manifest has no acknowledgement")
        self._manifest = manifest
        return errors

    @property
    def manifest(self) -> AuthorizationManifest | None:
        return self._manifest

    def is_asset_allowed(self, host: str) -> bool:
        if not self._manifest:
            return False
        return self._manifest.is_asset_allowed(host)

    def check_risk_level(self, risk: RiskLevel) -> tuple[bool, SkipReason | None]:
        if risk == RiskLevel.PASSIVE:
            return True, None
        if risk == RiskLevel.SAFE:
            return True, None
        if self._manifest is None:
            return False, SkipReason.MISSING_CAPABILITY
        if self._manifest.is_expired():
            return False, SkipReason.EXPIRED_MANIFEST
        rl = self._manifest.approved_risk_level
        if risk == RiskLevel.ACTIVE and rl in (RiskLevel.ACTIVE, RiskLevel.STATEFUL, RiskLevel.HIGH_RISK):
            return True, None
        if risk == RiskLevel.STATEFUL and rl in (RiskLevel.STATEFUL, RiskLevel.HIGH_RISK):
            return True, None
        if risk == RiskLevel.HIGH_RISK and rl == RiskLevel.HIGH_RISK:
            return True, None
        return False, SkipReason.RISK_NOT_AUTHORIZED

    def compile(self, policy: CompiledPolicy) -> CompiledPolicy:
        if self._manifest:
            return CompiledPolicy.from_scope(policy.source, self._manifest)
        return policy
