from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from bughunter.contracts.tasks import TaskSpec

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    workspace TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    target TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'safe',
    status TEXT NOT NULL DEFAULT 'pending',
    started_at REAL,
    finished_at REAL,
    policy_hash TEXT,
    manifest_hash TEXT,
    config_hash TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE IF NOT EXISTS scope_policies (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    source_json TEXT NOT NULL,
    compiled_hash TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS authorization_manifests (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    reference TEXT,
    issued_to TEXT,
    valid_from REAL,
    valid_until REAL,
    approved_risk TEXT,
    hash TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    module_id TEXT NOT NULL,
    module_version TEXT,
    state TEXT NOT NULL DEFAULT 'pending',
    risk_level TEXT,
    policy_hash TEXT,
    budget_json TEXT,
    depends_on_json TEXT,
    params_json TEXT,
    attempts INTEGER DEFAULT 0,
    checkpoint_json TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    sensitivity TEXT DEFAULT 'normal',
    retention_days INTEGER DEFAULT 30,
    metadata_json TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS http_transactions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    request_intent_id TEXT,
    status INTEGER,
    request_headers_json TEXT,
    request_body_artifact_id TEXT,
    response_headers_json TEXT,
    response_body_artifact_id TEXT,
    elapsed_ms REAL,
    url TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    task_id TEXT,
    module_id TEXT,
    state TEXT NOT NULL DEFAULT 'raw',
    title TEXT,
    description TEXT,
    evidence_refs_json TEXT,
    metadata_json TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    stable_fingerprint TEXT,
    state TEXT NOT NULL DEFAULT 'observation',
    title TEXT,
    affected_asset_ids_json TEXT,
    security_invariant TEXT,
    technical_impact TEXT,
    business_impact TEXT,
    confidence REAL DEFAULT 0.0,
    severity_label TEXT,
    cvss_v4_vector TEXT,
    cvss_v4_score REAL,
    evidence_refs_json TEXT,
    validation_attempt_ids_json TEXT,
    remediation TEXT,
    review_status TEXT DEFAULT 'pending',
    module_id TEXT,
    metadata_json TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS finding_relations (
    id TEXT PRIMARY KEY,
    from_finding TEXT NOT NULL,
    to_finding TEXT NOT NULL,
    relation TEXT NOT NULL,
    FOREIGN KEY (from_finding) REFERENCES findings(id),
    FOREIGN KEY (to_finding) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS manual_tasks (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT,
    rule_version TEXT,
    title TEXT,
    category TEXT,
    priority TEXT,
    why TEXT,
    steps_json TEXT,
    tools_json TEXT,
    completed INTEGER DEFAULT 0,
    notes TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    task_id TEXT,
    module_id TEXT,
    details_json TEXT,
    timestamp_ns INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at REAL NOT NULL
            )
        """)
        current = self._conn.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0] or 0
        if current < SCHEMA_VERSION:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, time.time()),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_project(self, project_id: str, name: str, workspace: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO projects (id, name, workspace, created_at) VALUES (?, ?, ?, ?)",
            (project_id, name, workspace, time.time()),
        )
        self._conn.commit()

    def save_scan(self, scan_id: str, project_id: str, target: str, profile: str, policy_hash: str, manifest_hash: str = "") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (id, project_id, target, profile, status, started_at, policy_hash, manifest_hash) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)",
            (scan_id, project_id, target, profile, time.time(), policy_hash, manifest_hash),
        )
        self._conn.commit()

    def complete_scan(self, scan_id: str, status: str = "completed") -> None:
        self._conn.execute(
            "UPDATE scans SET status=?, finished_at=? WHERE id=?",
            (status, time.time(), scan_id),
        )
        self._conn.commit()

    def save_task(self, task: TaskSpec, scan_id: str, state: str = "pending") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO tasks (id, scan_id, module_id, module_version, state, risk_level, policy_hash, params_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (task.id, scan_id, task.module_id, task.module_version, state, task.risk_level.value, task.policy_hash, json.dumps(task.params)),
        )
        self._conn.commit()

    def update_task_state(self, task_id: str, state: str) -> None:
        self._conn.execute("UPDATE tasks SET state=? WHERE id=?", (state, task_id))
        self._conn.commit()

    def save_audit_event(self, event_kind: str, scan_id: str, task_id: str = "", module_id: str = "", details: dict | None = None) -> None:
        import uuid
        self._conn.execute(
            "INSERT INTO audit_events (id, scan_id, kind, task_id, module_id, details_json, timestamp_ns) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), scan_id, event_kind, task_id, module_id, json.dumps(details or {}), int(time.time_ns())),
        )
        self._conn.commit()

    def get_scan_tasks(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, module_id, state, risk_level FROM tasks WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return [{"id": r[0], "module_id": r[1], "state": r[2], "risk_level": r[3]} for r in rows]

    def get_audit_events(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT kind, task_id, module_id, details_json, timestamp_ns FROM audit_events WHERE scan_id=? ORDER BY timestamp_ns",
            (scan_id,),
        ).fetchall()
        return [{"kind": r[0], "task_id": r[1], "module_id": r[2], "details": json.loads(r[3]), "timestamp_ns": r[4]} for r in rows]

    def save_finding(self, finding: dict, scan_id: str) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO findings
            (id, scan_id, stable_fingerprint, state, title, affected_asset_ids_json,
             security_invariant, technical_impact, business_impact, confidence,
             severity_label, cvss_v4_vector, cvss_v4_score, evidence_refs_json,
             validation_attempt_ids_json, remediation, review_status, module_id, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.get("id", ""),
                scan_id,
                finding.get("fingerprint", ""),
                finding.get("state", "observation"),
                finding.get("title", ""),
                json.dumps(finding.get("affected_assets", [])),
                finding.get("invariant", ""),
                finding.get("technical_impact", ""),
                finding.get("business_impact"),
                finding.get("confidence", 0.0),
                finding.get("severity"),
                finding.get("cvss_vector"),
                finding.get("cvss_score"),
                json.dumps(finding.get("evidence_refs", [])),
                json.dumps(finding.get("validation_ids", [])),
                finding.get("remediation", ""),
                finding.get("review_status", "pending"),
                finding.get("module", ""),
                json.dumps(finding.get("metadata", {})),
            ),
        )
        self._conn.commit()

    def get_findings(self, scan_id: str, state: str | None = None) -> list[dict]:
        if state:
            rows = self._conn.execute(
                "SELECT id, stable_fingerprint, state, title, confidence, severity_label, module_id FROM findings WHERE scan_id=? AND state=?",
                (scan_id, state),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, stable_fingerprint, state, title, confidence, severity_label, module_id FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        return [{"id": r[0], "fingerprint": r[1], "state": r[2], "title": r[3], "confidence": r[4], "severity": r[5], "module": r[6]} for r in rows]

    def save_disposition(self, finding_id: str, kind: str, reason: str = "", operator: str = "system", related_finding_id: str = "") -> None:
        import uuid
        self._conn.execute(
            """INSERT INTO audit_events (id, scan_id, kind, task_id, module_id, details_json, timestamp_ns)
            VALUES (?, ?, 'disposition', ?, ?, ?, ?)""",
            (str(uuid.uuid4()), "", finding_id, kind, json.dumps({"reason": reason, "operator": operator, "related": related_finding_id}), int(time.time_ns())),
        )
        self._conn.commit()

    def get_completed_task_ids(self, scan_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT id FROM tasks WHERE scan_id=? AND state='completed'", (scan_id,)
        ).fetchall()
        return {r[0] for r in rows}
