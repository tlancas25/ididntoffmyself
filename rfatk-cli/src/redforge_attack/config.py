"""Layered configuration resolution.

Why this exists
---------------
The CLI has many knobs (provider, model, concurrency cap, sandbox mode, etc.).
At M1 we need just enough config to locate `targets_dir`. As providers land
(M2+) the Config grows — but the resolution precedence is fixed here so we
never end up with inconsistent config paths:

  CLI flags  >  environment  >  ./redforge.toml  >  ~/.redforge/config.toml  >  defaults

API-key resolution is deliberately confined to providers/anthropic.py etc.
(the §TOS rule: never read ~/.claude/). This module is agnostic to API keys.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover — Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class RunConfig:
    max_parallel_specialists: int = 6
    max_turns_per_agent: int = 40
    max_tokens_per_agent: int = 200_000
    per_call_timeout_seconds: int = 120
    agent_roster: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SandboxConfig:
    mode: str = "strict"  # strict | loose
    allow_shell: bool = False
    shell_timeout_seconds: int = 30
    shell_max_output_bytes: int = 65_536


@dataclass(frozen=True)
class ReportConfig:
    emit_hardening_section: bool = True
    emit_duplicate_clusters: bool = True


@dataclass(frozen=True)
class Config:
    targets_dir: pathlib.Path
    provider: str = "anthropic"
    model: str | None = None
    run: RunConfig = field(default_factory=RunConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    # Opaque provider-specific sub-sections loaded from TOML, normalized later
    # by each provider's factory (e.g. providers/anthropic.py reads provider.anthropic.*).
    provider_overrides: dict = field(default_factory=dict)


def _load_toml(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_config(
    *,
    cli_targets_dir: str | None = None,
    cli_provider: str | None = None,
    cli_model: str | None = None,
    cli_config_file: str | None = None,
) -> Config:
    """Resolve Config from all sources. CLI args take highest precedence."""
    # 1. Gather TOML
    project_toml = _load_toml(pathlib.Path.cwd() / "redforge.toml")
    user_toml = _load_toml(pathlib.Path.home() / ".redforge" / "config.toml")
    override_toml: dict = {}
    if cli_config_file:
        override_toml = _load_toml(pathlib.Path(cli_config_file))

    # Merge TOMLs — later sources override earlier
    merged: dict = {}
    for src in (user_toml, project_toml, override_toml):
        _deep_merge(merged, src)

    # 2. Resolve targets_dir: CLI > env > TOML > default ./targets
    targets_dir_raw: str | None = (
        cli_targets_dir
        or os.environ.get("REDFORGE_TARGETS_DIR")
        or merged.get("run", {}).get("targets_dir")
        or "./targets"
    )
    targets_dir = pathlib.Path(targets_dir_raw).resolve()

    # 3. Resolve provider
    provider: str = (
        cli_provider
        or os.environ.get("REDFORGE_PROVIDER")
        or merged.get("provider", {}).get("default", "anthropic")
    )

    # 4. Resolve model (provider-specific; CLI or env wins)
    model: str | None = cli_model or os.environ.get("REDFORGE_MODEL")

    # 5. Build the sub-configs from TOML + defaults
    run_cfg_dict = merged.get("run", {})
    run_cfg = RunConfig(
        max_parallel_specialists=int(run_cfg_dict.get("max_parallel_specialists", 6)),
        max_turns_per_agent=int(run_cfg_dict.get("max_turns_per_agent", 40)),
        max_tokens_per_agent=int(run_cfg_dict.get("max_tokens_per_agent", 200_000)),
        per_call_timeout_seconds=int(run_cfg_dict.get("per_call_timeout_seconds", 120)),
        agent_roster=list(run_cfg_dict.get("agent_roster", [])),
    )

    sandbox_cfg_dict = merged.get("sandbox", {})
    sandbox_cfg = SandboxConfig(
        mode=sandbox_cfg_dict.get("mode", "strict"),
        allow_shell=bool(sandbox_cfg_dict.get("allow_shell", False)),
        shell_timeout_seconds=int(sandbox_cfg_dict.get("shell_timeout_seconds", 30)),
        shell_max_output_bytes=int(sandbox_cfg_dict.get("shell_max_output_bytes", 65_536)),
    )

    report_cfg_dict = merged.get("report", {})
    report_cfg = ReportConfig(
        emit_hardening_section=bool(report_cfg_dict.get("emit_hardening_section", True)),
        emit_duplicate_clusters=bool(report_cfg_dict.get("emit_duplicate_clusters", True)),
    )

    return Config(
        targets_dir=targets_dir,
        provider=provider,
        model=model,
        run=run_cfg,
        sandbox=sandbox_cfg,
        report=report_cfg,
        provider_overrides=merged.get("provider", {}),
    )


def _deep_merge(dst: dict, src: dict) -> None:
    """In-place deep merge src into dst. Lists are replaced, not concatenated."""
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
