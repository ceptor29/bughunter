from __future__ import annotations

import fnmatch

from bughunter.contracts.policy import AuthorizationManifest, CompiledPolicy, ScopePolicy


class PolicyCompiler:
    def __init__(self) -> None:
        self._errors: list[str] = []

    def compile(
        self,
        scope: ScopePolicy,
        manifest: AuthorizationManifest | None = None,
    ) -> CompiledPolicy:
        self._errors = []

        if not scope.allowed_hosts:
            self._errors.append("scope has no allowed_hosts")

        if manifest:
            mgr_errors = self._validate_manifest_for_scope(scope, manifest)
            self._errors.extend(mgr_errors)

        compiled = CompiledPolicy.from_scope(scope, manifest)
        return compiled

    def _validate_manifest_for_scope(
        self, scope: ScopePolicy, manifest: AuthorizationManifest
    ) -> list[str]:
        errors: list[str] = []
        if manifest.is_expired():
            errors.append("manifest is expired")
        for asset in manifest.allowed_assets:
            asset_clean = asset.lower().strip(".")
            found = any(
                asset_clean == h.lower().strip(".") or fnmatch.fnmatch(asset_clean, h.lower())
                for h in scope.allowed_hosts
            )
            if not found:
                errors.append(f"asset '{asset}' not in scope")
        return errors

    @property
    def errors(self) -> list[str]:
        return list(self._errors)
