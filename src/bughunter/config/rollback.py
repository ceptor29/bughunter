from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class ConfigSnapshot:
    version: int
    timestamp: float
    config: dict
    description: str = ""


class ConfigRollback:
    def __init__(self, workspace: str | Path) -> None:
        self._workspace = Path(workspace)
        self._snapshots_dir = self._workspace / "config_snapshots"
        self._snapshots_dir.mkdir(parents=True, exist_ok=True)
        self._max_snapshots = 10

    def save_snapshot(self, config_path: str | Path, description: str = "") -> Path:
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")

        with open(config_path) as f:
            config = yaml.safe_load(f) or {}

        snapshots = self._list_snapshots()
        version = len(snapshots) + 1

        snapshot = ConfigSnapshot(
            version=version,
            timestamp=time.time(),
            config=config,
            description=description,
        )

        snapshot_path = self._snapshots_dir / f"snapshot_v{version}_{int(time.time())}.json"
        with open(snapshot_path, "w") as f:
            json.dump(snapshot.__dict__, f, indent=2)

        if len(snapshots) >= self._max_snapshots:
            oldest = sorted(snapshots, key=lambda s: s.timestamp)[0]
            oldest_path = self._snapshots_dir / f"snapshot_v{oldest.version}_{int(oldest.timestamp)}.json"
            if oldest_path.exists():
                oldest_path.unlink()

        return snapshot_path

    def rollback(self, config_path: str | Path, snapshot_version: int | None = None) -> bool:
        config_path = Path(config_path)
        snapshots = self._list_snapshots()
        if not snapshots:
            return False

        if snapshot_version is not None:
            target = next((s for s in snapshots if s.version == snapshot_version), None)
            if not target:
                return False
        else:
            target = max(snapshots, key=lambda s: s.version)

        backup_path = config_path.with_suffix(f".backup_{int(time.time())}.yaml")
        if config_path.exists():
            shutil.copy2(config_path, backup_path)

        with open(config_path, "w") as f:
            yaml.dump(target.config, f, default_flow_style=False, sort_keys=False)

        return True

    def list_snapshots(self) -> list[dict]:
        snapshots = self._list_snapshots()
        return [
            {"version": s.version, "timestamp": s.timestamp, "description": s.description}
            for s in sorted(snapshots, key=lambda s: s.version, reverse=True)
        ]

    def _list_snapshots(self) -> list[ConfigSnapshot]:
        snapshots = []
        for p in self._snapshots_dir.glob("snapshot_v*.json"):
            try:
                with open(p) as f:
                    data = json.load(f)
                snapshots.append(ConfigSnapshot(
                    version=data["version"],
                    timestamp=data["timestamp"],
                    config=data["config"],
                    description=data.get("description", ""),
                ))
            except Exception:
                continue
        return snapshots

    def diff_with_current(self, config_path: str | Path) -> dict | None:
        config_path = Path(config_path)
        if not config_path.exists():
            return None

        with open(config_path) as f:
            current = yaml.safe_load(f) or {}

        snapshots = self._list_snapshots()
        if not snapshots:
            return None

        latest = max(snapshots, key=lambda s: s.version)

        changes = {}
        all_keys = set(list(current.keys()) + list(latest.config.keys()))
        for key in all_keys:
            if current.get(key) != latest.config.get(key):
                changes[key] = {"current": current.get(key), "snapshot": latest.config.get(key)}

        return {
            "snapshot_version": latest.version,
            "snapshot_timestamp": latest.timestamp,
            "changes": changes,
        }
