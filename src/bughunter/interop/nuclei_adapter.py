from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    ip: str = ""
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    curl_command: str = ""
    extracted_results: list[str] = field(default_factory=list)
    matcher_name: str = ""
    type: str = ""


def parse_nuclei_json(json_path: str | Path) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    with open(json_path) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("results", [])

    for item in items:
        try:
            findings.append(NucleiFinding(
                template_id=item.get("template-id", item.get("templateID", "")),
                name=item.get("info", {}).get("name", item.get("name", "")),
                severity=item.get("info", {}).get("severity", item.get("severity", "info")),
                host=item.get("host", ""),
                matched_at=item.get("matched-at", item.get("matched", "")),
                ip=item.get("ip", ""),
                description=item.get("info", {}).get("description", item.get("description", "")),
                reference=item.get("info", {}).get("reference", []),
                tags=item.get("info", {}).get("tags", []) if isinstance(item.get("info", {}).get("tags", []), list) else item.get("info", {}).get("tags", "").split(","),
                curl_command=item.get("curl-command", ""),
                extracted_results=item.get("extracted-results", []),
                matcher_name=item.get("matcher-name", ""),
                type=item.get("type", ""),
            ))
        except Exception:
            continue

    return findings


def nuclei_to_bughunter_finding(nf: NucleiFinding) -> dict[str, Any]:
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "informational",
        "unknown": "informational",
    }
    severity = severity_map.get(nf.severity.lower(), "informational")

    return {
        "module": "nuclei_import",
        "title": f"[Nuclei] {nf.name} ({nf.template_id})",
        "url": nf.matched_at,
        "evidence": nf.description or f"Template: {nf.template_id}, Host: {nf.host}",
        "severity": severity,
        "confidence": "high",
        "invariant": f"Nuclei template {nf.template_id} matched",
        "remediation": "",
        "metadata": {
            "nuclei_template_id": nf.template_id,
            "nuclei_severity": nf.severity,
            "nuclei_host": nf.host,
            "nuclei_ip": nf.ip,
            "nuclei_tags": nf.tags,
            "nuclei_reference": nf.reference,
            "nuclei_curl": nf.curl_command,
        },
    }


def import_nuclei_results(json_path: str | Path) -> list[dict[str, Any]]:
    nuclei_findings = parse_nuclei_json(json_path)
    return [nuclei_to_bughunter_finding(nf) for nf in nuclei_findings]
