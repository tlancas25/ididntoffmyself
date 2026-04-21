"""findings.json schema linter.

Why this exists
---------------
Specialist agents write findings.json in parallel. A malformed object silently
drops from the synthesizer's aggregation (json.loads succeeds on missing keys
— it just produces weak report output). This linter fails LOUD so agents
correct their output before synthesis runs.

Severity-calibration fields added post-trial-#1 review (2026-04-20) are
RECOMMENDED (warn-if-missing) rather than required, so old findings don't
retroactively fail validation. New-style findings from the updated specialist
prompts include them.

Differences from the dev-workspace ancestor (`redforge-dev/tools/validate_finding.py`)
-------------------------------------------------------------------------------------
1. Logic exposed as `validate_file(path)` and `validate_findings(data)` callables.
2. No `if __name__ == "__main__"` block — CLI entry point is `rfatk validate`.
"""

from __future__ import annotations

import json
import pathlib

REQUIRED: set[str] = {
    "id", "title", "surface", "severity", "exploitable",
    "confidence", "target_refs", "description",
}
RECOMMENDED: set[str] = {
    "exploitable_now",
    "requires_future_change",
    "reproduction_status",
    "root_cause_confidence",
}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCES = {"high", "medium", "low"}
REPRODUCTION_STATUSES = {"verified", "code-path-traced", "theoretical"}
ROOT_CAUSE_CONFS = {"high", "medium", "low"}
SURFACES = {
    "auth", "injection", "idor", "ssrf", "xss", "file-handling",
    "business-logic", "api", "prompt-injection", "mcp-tool-abuse",
    "agent-autonomy", "secrets", "ci-cd", "container", "dependency",
}


def validate_finding(obj: object, idx: int) -> tuple[list[str], list[str]]:
    """Validate a single finding object. Returns (errors, warnings)."""
    errs: list[str] = []
    warns: list[str] = []
    if not isinstance(obj, dict):
        return [f"[{idx}] not an object"], []

    missing = REQUIRED - set(obj.keys())
    if missing:
        errs.append(f"[{idx}] missing required keys: {sorted(missing)}")
    if obj.get("severity") not in SEVERITIES:
        errs.append(
            f"[{idx}] severity: got {obj.get('severity')!r}, "
            f"want one of {sorted(SEVERITIES)}"
        )
    if not isinstance(obj.get("exploitable"), bool):
        errs.append(f"[{idx}] exploitable must be bool")
    if obj.get("confidence") not in CONFIDENCES:
        errs.append(
            f"[{idx}] confidence: got {obj.get('confidence')!r}, "
            f"want one of {sorted(CONFIDENCES)}"
        )
    if obj.get("surface") not in SURFACES:
        errs.append(
            f"[{idx}] surface: got {obj.get('surface')!r}, "
            f"want one of {sorted(SURFACES)}"
        )
    if not isinstance(obj.get("target_refs"), list) or not obj.get("target_refs"):
        errs.append(f"[{idx}] target_refs must be non-empty list")
    if not isinstance(obj.get("description"), str) or len(obj.get("description", "")) < 20:
        errs.append(f"[{idx}] description must be string >= 20 chars")

    miss_rec = RECOMMENDED - set(obj.keys())
    if miss_rec:
        warns.append(
            f"[{idx}] missing recommended fields (severity-calibration): "
            f"{sorted(miss_rec)}"
        )

    if "exploitable_now" in obj and not isinstance(obj["exploitable_now"], bool):
        errs.append(f"[{idx}] exploitable_now must be bool")
    if "requires_future_change" in obj:
        v = obj["requires_future_change"]
        if v is not None and not isinstance(v, str):
            errs.append(f"[{idx}] requires_future_change must be string or null")
    if "reproduction_status" in obj and obj["reproduction_status"] not in REPRODUCTION_STATUSES:
        errs.append(
            f"[{idx}] reproduction_status: got {obj['reproduction_status']!r}, "
            f"want one of {sorted(REPRODUCTION_STATUSES)}"
        )
    if "root_cause_confidence" in obj and obj["root_cause_confidence"] not in ROOT_CAUSE_CONFS:
        errs.append(
            f"[{idx}] root_cause_confidence: got {obj['root_cause_confidence']!r}, "
            f"want one of {sorted(ROOT_CAUSE_CONFS)}"
        )

    # Optional hardening_plan (M7+, host findings). If present, must be a dict
    # with specific subfields all of string or effort-enum type.
    if "hardening_plan" in obj:
        hp = obj["hardening_plan"]
        if not isinstance(hp, dict):
            errs.append(f"[{idx}] hardening_plan must be an object")
        else:
            for k in ("immediate", "configuration", "monitoring", "compensating_controls"):
                if k in hp and not isinstance(hp[k], str):
                    errs.append(f"[{idx}] hardening_plan.{k} must be a string")
            if "estimated_effort" in hp and hp["estimated_effort"] not in {"minutes", "hours", "days", "weeks"}:
                errs.append(
                    f"[{idx}] hardening_plan.estimated_effort must be one of "
                    "minutes|hours|days|weeks"
                )

    # Cross-field sanity: §1 CRITICAL reserve
    if obj.get("severity") == "CRITICAL" and obj.get("exploitable_now") is False:
        errs.append(
            f"[{idx}] CRITICAL with exploitable_now=false — per §1 rule, "
            "CRITICAL requires exploitable_now=true (downgrade to HIGH or "
            "revise exploitable_now)"
        )

    return errs, warns


def validate_findings(data: object) -> tuple[list[str], list[str]]:
    """Validate a whole findings array. Returns (errors, warnings)."""
    if not isinstance(data, list):
        return ["findings.json must be a JSON array"], []
    all_errs: list[str] = []
    all_warns: list[str] = []
    for i, obj in enumerate(data):
        errs, warns = validate_finding(obj, i)
        all_errs.extend(errs)
        all_warns.extend(warns)
    return all_errs, all_warns


def validate_file(path: pathlib.Path) -> tuple[list[str], list[str], int]:
    """Load a findings.json file and validate. Returns (errors, warnings, count).

    Raises:
        FileNotFoundError: if path does not exist.
        json.JSONDecodeError: if contents are not valid JSON.
    """
    text = pathlib.Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    errs, warns = validate_findings(data)
    count = len(data) if isinstance(data, list) else 0
    return errs, warns, count
