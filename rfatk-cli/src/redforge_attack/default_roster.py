"""Default specialist rosters.

Why this exists
---------------
`roster.yaml` (bundled prompts/roster.yaml) is the human-readable source of
truth and ships with metadata per specialist. For runtime, though, all we
need is the FLAT LIST OF IDs in canonical run order. Hardcoding this here
keeps the runtime stdlib-only (no PyYAML dep) and makes the default roster
explicit-and-grep-able.

Rosters:
- `DEFAULT_CODE_ROSTER` — the 16 web/AI/infra specialists that run against
  a code-on-disk target (everything we've shipped to date).
- `HOST_SCAN_ROSTER` — the 10 host-scan specialists (M7). Populated with
  `[]` at M3 since the host-scan prompts don't exist yet; filled when M7
  lands.

When the CLI is asked for `--agents auto`, it picks the roster appropriate
to the `target_type` in `target.yaml`. Default target_type = `code`.
"""

from __future__ import annotations


# M1-M3 scope: code-on-disk trials.
DEFAULT_CODE_ROSTER: list[str] = [
    # Web application (8)
    "auth-session",
    "authz-idor",
    "injection",
    "ssrf-network",
    "xss-client",
    "file-handling",
    "business-logic",
    "api-surface",
    # AI / agentic (4)
    "prompt-injection",
    "mcp-tool-abuse",
    "agent-autonomy",
    "llm-output-trust",
    # Infra / supply chain (4)
    "secrets-hunt",
    "ci-cd",
    "container-infra",
    "dependency-supply",
]


# M7a + M7b: full 9-specialist roster for host-scan trials.
# recon runs as a separate orchestrator phase (not in the specialist list).
HOST_SCAN_ROSTER: list[str] = [
    # M7a (core posture)
    "services-startup",
    "network-listening",
    "network-posture",
    "alert-triage",
    # M7b (expanded coverage per user: "leave no stone unturned")
    "windows-config-audit",
    "firewall-audit",
    "local-subnet-sweep",
    "credentials-exposure",
    "persistence-hunt",
]


# Auxiliary specialists — never in the default roster; opt-in via --agents.
AUXILIARY_ROSTER: list[str] = [
    "baseline-compare",
]


def get_roster(name: str) -> list[str]:
    """Return a roster list by name. Unknown name -> empty list."""
    return {
        "code": list(DEFAULT_CODE_ROSTER),
        "host": list(HOST_SCAN_ROSTER),
        "auxiliary": list(AUXILIARY_ROSTER),
    }.get(name, [])
