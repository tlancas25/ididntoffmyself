"""OpenAI-format tool schemas for the host-scan sandbox.

Why this exists
---------------
Paired with `host_sandbox.py`. Agents in a host-scan trial see a different
tool suite than code-scan agents — no `read_file` / `glob` / `grep` into an
intake folder; instead `run_system_query` (allowlisted shell), plus the
reused output tools (`submit_finding`, `write_notes`).

Scopes of tools exposed to a host-scan agent:

- `run_system_query(cmd)` — execute one allowlisted read-only system query.
  The agent treats this as "ask the running machine a question."
- `capture_baseline()` — snapshot alerting surfaces before invasive
  enumeration. Only the `alert-triage` specialist calls this pre-scan; it
  runs once and is a no-op for later agents.
- `submit_finding(finding)` — reused from code sandbox.
- `write_notes(content)` — reused from code sandbox.
"""

from __future__ import annotations

from redforge_attack.tools.schemas import SUBMIT_FINDING, WRITE_NOTES


RUN_SYSTEM_QUERY: dict = {
    "type": "function",
    "function": {
        "name": "run_system_query",
        "description": (
            "Execute ONE read-only system query on the target machine via "
            "PowerShell. The command must match the REDFORGE host-scan "
            "allowlist (Get-Service, netstat, reg query HKLM\\..., "
            "Get-WinEvent, etc.). Commands referencing the user's "
            "Documents / Downloads / Pictures / Videos folders are REJECTED "
            "regardless of allowlist match. No pipelines, no redirections, "
            "no subshells — one command per call. Output is the raw stdout "
            "(+ stderr if non-empty) with an exit-code header."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cmd": {
                    "type": "string",
                    "description": (
                        "The exact command to run (e.g. 'Get-Service -Name *defender*', "
                        "'netstat -ano', 'reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\"')."
                    ),
                },
            },
            "required": ["cmd"],
            "additionalProperties": False,
        },
    },
}


CAPTURE_BASELINE: dict = {
    "type": "function",
    "function": {
        "name": "capture_baseline",
        "description": (
            "Capture the pre-scan state of the machine's alerting surfaces "
            "(Windows Defender detections, Security / System / Application "
            "event log high-water marks, Defender operational log, etc.) to "
            "evidence/alert-triage-baseline/. Call this EXACTLY ONCE, as the "
            "very first action of the alert-triage specialist, BEFORE any "
            "other specialist runs invasive enumeration. Takes no arguments. "
            "Returns a summary string naming each baseline snapshot captured."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
}


def default_host_tools() -> list[dict]:
    """The full host-scan tool suite a specialist sees."""
    return [RUN_SYSTEM_QUERY, CAPTURE_BASELINE, SUBMIT_FINDING, WRITE_NOTES]
