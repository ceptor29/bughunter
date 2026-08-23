from __future__ import annotations

import hashlib
from pathlib import Path

from bughunter.contracts.artifacts import ArtifactDraft, ArtifactRef


class ArtifactStore:
    def __init__(self, base_path: str | Path) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def store(self, artifact: ArtifactDraft) -> ArtifactRef:
        sha = hashlib.sha256(artifact.content).hexdigest()
        prefix = sha[:2]
        dir_path = self._base / "sha256" / prefix
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / sha
        if not file_path.exists():
            file_path.write_bytes(artifact.content)
        return ArtifactRef(
            id=artifact.id,
            sha256=sha,
            kind=artifact.kind,
            size_bytes=len(artifact.content),
            sensitivity=artifact.sensitivity,
            retention_days=artifact.retention_days,
        )

    def get(self, ref: ArtifactRef) -> bytes:
        prefix = ref.sha256[:2]
        file_path = self._base / "sha256" / prefix / ref.sha256
        if file_path.exists():
            return file_path.read_bytes()
        return b""

    def exists(self, sha256: str) -> bool:
        prefix = sha256[:2]
        return (self._base / "sha256" / prefix / sha256).exists()
