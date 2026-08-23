from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from bughunter.core.dispositions import DispositionTracker, DispositionKind


@dataclass
class RetestResult:
    finding_id: str
    retested: bool
    still_present: bool
    evidence: str = ""
    retested_at: float = 0.0


@dataclass
class ClosureReport:
    scan_id: str
    target: str
    created_at: float = 0.0
    total_findings: int = 0
    fixed: int = 0
    accepted_risk: int = 0
    false_positive: int = 0
    open: int = 0
    retest_results: list[RetestResult] = field(default_factory=list)
    changelog: list[dict] = field(default_factory=list)
    operator_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "created_at": self.created_at,
            "total_findings": self.total_findings,
            "fixed": self.fixed,
            "accepted_risk": self.accepted_risk,
            "false_positive": self.false_positive,
            "open": self.open,
            "retest_results": [
                {"finding_id": r.finding_id, "retested": r.retested, "still_present": r.still_present, "evidence": r.evidence}
                for r in self.retest_results
            ],
            "changelog": self.changelog,
            "operator_notes": self.operator_notes,
        }


class ClosureManager:
    def __init__(self, workspace: str | Path) -> None:
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._closure_dir = self._workspace / "closure"
        self._closure_dir.mkdir(exist_ok=True)

    def generate_report(
        self,
        scan_id: str,
        target: str,
        findings: list[dict],
        disposition_tracker: DispositionTracker | None = None,
    ) -> ClosureReport:
        report = ClosureReport(
            scan_id=scan_id,
            target=target,
            created_at=time.time(),
            total_findings=len(findings),
        )

        for f in findings:
            fid = f.get("id", f.get("fingerprint", ""))
            state = f.get("state", "observation")

            if disposition_tracker:
                disp = disposition_tracker.get_disposition(fid)
                if disp:
                    kind = disp.get("kind", "")
                    if kind == "fixed":
                        report.fixed += 1
                    elif kind == "accepted_risk":
                        report.accepted_risk += 1
                    elif kind == "false_positive":
                        report.false_positive += 1
                    else:
                        report.open += 1
                else:
                    report.open += 1
            else:
                if state == "observation":
                    report.open += 1
                elif state == "confirmed":
                    report.open += 1

        return report

    def save_report(self, report: ClosureReport) -> Path:
        path = self._closure_dir / f"closure_{report.scan_id}.json"
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        return path

    def add_changelog_entry(self, report: ClosureReport, entry: str, operator: str = "system") -> None:
        report.changelog.append({
            "entry": entry,
            "operator": operator,
            "timestamp": time.time(),
        })

    def archive_pat(self, scan_id: str, pat_data: dict) -> Path:
        archive_path = self._closure_dir / f"pat_archive_{scan_id}.json"
        with open(archive_path, "w") as f:
            json.dump(pat_data, f, indent=2)
        return archive_path
