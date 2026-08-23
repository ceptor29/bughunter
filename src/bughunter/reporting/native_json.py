from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def generate_json_report(ctx: Any, scan_id: str, target: str, elapsed: float) -> str:
    report = {
        "bughunter_version": "0.1.0",
        "scan_id": scan_id,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "summary": {
            "subdomains_found": len(ctx.subdomains),
            "alive_hosts": len(ctx.alive_hosts),
            "forms_found": len(ctx.forms),
            "params_found": len(ctx.params),
            "js_files_found": len(ctx.js_files),
            "findings": len(ctx.findings),
            "errors": len(ctx.errors),
        },
        "subdomains": sorted(ctx.subdomains),
        "alive_hosts": ctx.alive_hosts,
        "forms": ctx.forms[:50],
        "params": ctx.params[:100],
        "js_files": ctx.js_files,
        "findings": ctx.findings,
        "errors": ctx.errors,
        "warnings": ctx.warnings,
        "skip_reasons": ctx.skip_reasons,
    }
    return json.dumps(report, indent=2, default=str)
