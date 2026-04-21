"""Load bundled prompt files at runtime via importlib.resources.

Why this exists
---------------
Prompts (recon.md, synthesizer.md, specialists.md, targets_schema.md,
roster.yaml) ship inside the package as data files. importlib.resources is
the standard, zip-safe way to read them at runtime — works identically with
`pipx install -e .`, `pip install redforge-attack`, and PyInstaller bundles.
"""

from __future__ import annotations

from importlib import resources


def _read_prompt(name: str) -> str:
    with resources.files("redforge_attack.prompts").joinpath(name).open(
        "r", encoding="utf-8"
    ) as fh:
        return fh.read()


def load_system_prompt(agent_id: str, target_type: str = "code") -> str:
    """Load the system prompt for a given agent id.

    For `target_type="code"` (default, M1-M3 behavior):
      - recon            -> recon.md
      - synthesizer      -> synthesizer.md
      - everything else  -> specialists.md (full brief)

    For `target_type="host"` (M7+):
      - recon            -> host_recon.md
      - synthesizer      -> synthesizer.md (role is the same — aggregate findings)
      - everything else  -> host_specialists.md

    The full targets_schema.md is always appended so agents know the findings
    shape without a separate tool call.
    """
    if target_type == "host":
        if agent_id == "recon":
            base = _read_prompt("host_recon.md")
        elif agent_id == "synthesizer":
            base = _read_prompt("synthesizer.md")
        else:
            base = _read_prompt("host_specialists.md")
    else:
        if agent_id == "recon":
            base = _read_prompt("recon.md")
        elif agent_id == "synthesizer":
            base = _read_prompt("synthesizer.md")
        else:
            base = _read_prompt("specialists.md")
    schema = _read_prompt("targets_schema.md")
    return f"{base}\n\n---\n\n# Bundled reference: findings schema\n\n{schema}"


def load_roster_yaml() -> str:
    return _read_prompt("roster.yaml")
