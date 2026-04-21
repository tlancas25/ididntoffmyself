"""rfatk CLI entry point.

Why this exists
---------------
Single-binary user interface for the CLI: argparse subparsers for `init`,
`validate`, `report`, `attack`, and `doctor`. At M1, `init`/`validate`/`report`
work end-to-end (no LLM); `attack` and `doctor` print clean "coming in M2/M5"
messages so the surface is stable from day one.

Design rules
------------
- Every subcommand is a plain function `cmd_<name>(args, console) -> int` (exit code).
- Rich console handles pretty output AND plain output when stderr is not a TTY.
- Errors are user-facing strings — no Python tracebacks leak unless --debug.
- Exit codes: 0=ok, 1=user error (bad args, missing file), 2=validation error,
  3=not-implemented-yet (attack/doctor at M1), 4=internal/crash.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import traceback

from rich.console import Console
from rich.table import Table

from redforge_attack import __version__
from redforge_attack.config import Config, load_config
from redforge_attack.synthesizer import synthesize
from redforge_attack.target import create_target, target_metadata
from redforge_attack.validator import validate_file


# -----------------------------------------------------------------------------
# argparse wiring
# -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rfatk",
        description="redforge-attack — multi-agent AI red-team CLI.",
    )
    p.add_argument("--version", action="version", version=f"rfatk {__version__}")
    p.add_argument(
        "--debug", action="store_true",
        help="Print full Python tracebacks on error.",
    )
    p.add_argument(
        "--config", metavar="FILE",
        help="Path to a redforge.toml override (beyond ./redforge.toml and ~/.redforge/config.toml).",
    )
    p.add_argument(
        "--targets-dir", metavar="DIR",
        help="Override the directory where target folders are created/read (default: ./targets).",
    )

    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    # ---------------- init ----------------
    init = sub.add_parser(
        "init",
        help="Scaffold a new target folder under targets/.",
        description="Create a new target trial folder with the canonical skeleton "
                    "(target.yaml, intake/, agents/, evidence/, placeholder report.md).",
    )
    init.add_argument("name", help="Target name (will be slugified).")
    init.add_argument(
        "--target-type", default="code", choices=["code", "host"],
        help="code: scan source on disk (default). host: scan the running machine (Windows 10+; uses host-scan sandbox).",
    )
    init.add_argument(
        "--provenance", required=True,
        choices=["vibe", "human", "mixed", "unknown"],
        help="Code provenance — required for vibe-vs-human comparisons post-trial.",
    )
    init.add_argument(
        "--source", required=True,
        help="repo URL | local path | container digest | live endpoint | MCP URL",
    )
    init.add_argument(
        "--scope-in", nargs="*", default=[],
        help="In-scope paths/URLs/endpoints.",
    )
    init.add_argument(
        "--scope-out", nargs="*", default=[],
        help="Explicitly excluded from scope.",
    )
    init.add_argument(
        "--surfaces", nargs="*", default=[],
        help="User-declared surfaces (empty = let recon decide).",
    )
    init.add_argument("--granted-by", default="user", help="Authorization handle.")
    init.add_argument(
        "--auth-note", default="owner of assets under test",
        help="Free text describing how authorization was granted.",
    )
    init.add_argument("--notes", default="", help="Free-text notes.")
    init.set_defaults(func=cmd_init)

    # ---------------- validate ----------------
    val = sub.add_parser(
        "validate",
        help="Lint a findings.json file against the schema.",
        description="Validate a findings.json file (written by a specialist agent). "
                    "Exits non-zero on errors; prints warnings to stderr.",
    )
    val.add_argument("path", help="Path to findings.json")
    val.set_defaults(func=cmd_validate)

    # ---------------- report ----------------
    rep = sub.add_parser(
        "report",
        help="(Re)synthesize report.md for a target folder.",
        description="Aggregate agents/*/findings.json into report.md, detect attack "
                    "chains, emit Fix-These-First candidates and duplicate-cluster advisories.",
    )
    rep.add_argument("target_folder", help="Path to targets/<slug>-<ts>/")
    rep.set_defaults(func=cmd_report)

    # ---------------- attack (M2: single-agent; M3: full orchestrator) ----------------
    atk = sub.add_parser(
        "attack",
        help="Run one agent against a target (M2: single-agent; M3 adds parallel orchestrator).",
        description=(
            "Run one specialist agent against a target's intake/. At M2 this runs "
            "exactly one agent specified via --agents (default: recon). Full parallel "
            "orchestration lands in M3."
        ),
    )
    atk.add_argument("target_folder", help="Path to targets/<slug>-<ts>/")
    atk.add_argument(
        "--provider",
        help=(
            "anthropic | openai | openrouter | gemini | moonshot | deepseek | "
            "xai | groq | together | cerebras | ollama | llamacpp | <custom>. "
            "Custom names can be defined under [provider.<name>] in redforge.toml "
            "with kind=openai_compat + base_url + api_key_env."
        ),
    )
    atk.add_argument("--model", help="Provider-specific model id. Default: claude-haiku-4-5 for recon/specialist, claude-sonnet-4-5 for synthesizer.")
    atk.add_argument(
        "--agents", default="auto",
        help=(
            "Comma-separated agent ids OR 'auto' for the default roster "
            "(recon + 16 specialists + synthesizer). Single-agent mode: pass "
            "just the one id (e.g. 'recon' or 'injection'). Add auxiliary "
            "agents by appending, e.g. 'auto,baseline-compare'."
        ),
    )
    atk.add_argument(
        "--no-recon", action="store_true",
        help="Skip the recon phase. Specialists run without an upfront surface map.",
    )
    atk.add_argument(
        "--no-synthesizer", action="store_true",
        help="Skip the synthesizer AGENT pass (mechanical report.md is still written).",
    )
    atk.add_argument(
        "--max-parallel", type=int, default=None,
        help="Concurrent specialists cap. Default: redforge.toml [run].max_parallel_specialists or 6.",
    )
    atk.add_argument(
        "--api-key",
        help=(
            "Explicit API key. Default: vendor-specific env var — "
            "ANTHROPIC_API_KEY | OPENAI_API_KEY | OPENROUTER_API_KEY | "
            "GEMINI_API_KEY | MOONSHOT_API_KEY | DEEPSEEK_API_KEY | "
            "XAI_API_KEY | GROQ_API_KEY | TOGETHER_API_KEY | CEREBRAS_API_KEY."
        ),
    )
    atk.add_argument("--max-turns", type=int, default=40, help="Max turns in the tool-use loop (default 40).")
    atk.add_argument("--max-tokens-per-call", type=int, default=4096, help="Max tokens per provider call (default 4096).")
    atk.add_argument("--max-tokens-budget", type=int, default=200_000, help="Total input+output token budget across the loop (default 200k).")
    atk.add_argument("--dry-run", action="store_true", help="[M2 NOT IMPLEMENTED] Simulate with no API calls.")
    atk.add_argument("--allow-shell", action="store_true", help="[code-scan] Enable run_bash tool (use only on disposable VMs).")
    atk.add_argument(
        "--allow-admin", action="store_true",
        help="[host-scan] Allow commands requiring admin elevation (SAM hive reads, full socket attribution, etc.). Run rfatk from an elevated PowerShell for effect.",
    )
    atk.add_argument(
        "--allow-network-probe", action="store_true",
        help="[host-scan] Allow commands that send packets outside this machine (Test-NetConnection, Resolve-DnsName against arbitrary hosts, local-subnet sweep).",
    )
    atk.set_defaults(func=cmd_attack)

    # ---------------- doctor (placeholder for M5) ----------------
    doc = sub.add_parser(
        "doctor",
        help="[coming in M5] Sanity-check config + providers reachable.",
        description="Verify environment, assert no Claude Code auth reuse, "
                    "probe each configured provider. Not yet implemented.",
    )
    doc.add_argument("--provider", help="Check only this provider.")
    doc.add_argument("--paranoid", action="store_true",
                     help="Extra checks: confirm ~/.claude/ is NOT being read.")
    doc.set_defaults(func=cmd_doctor)

    return p


# -----------------------------------------------------------------------------
# Subcommand handlers
# -----------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, console: Console, config: Config) -> int:
    try:
        folder = create_target(
            name=args.name,
            provenance=args.provenance,
            source=args.source,
            targets_dir=config.targets_dir,
            scope_in=args.scope_in,
            scope_out=args.scope_out,
            granted_by=args.granted_by,
            auth_note=args.auth_note,
            surfaces=args.surfaces,
            notes=args.notes,
            target_type=args.target_type,
        )
    except ValueError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1
    except FileExistsError as e:
        console.print(f"[red]error:[/red] {e}")
        console.print(
            "[yellow]hint:[/yellow] one folder = one trial. "
            "If you meant to re-scan, just re-run this command — a new timestamped folder will be created."
        )
        return 1

    console.print(f"[green]created:[/green] {folder}")
    console.print(f"  target.yaml  provenance={args.provenance}")
    console.print("  intake/      drop source tree / URLs / prior reports here")
    console.print("  agents/      (populated by specialists during rfatk attack)")
    console.print("  evidence/    (populated by specialists during rfatk attack)")
    console.print("  report.md    (populated by synthesizer)")
    console.print()
    console.print(f"[bold]next:[/bold] put target materials into [cyan]{folder.name}/intake/[/cyan], then run:")
    console.print(f"  [cyan]rfatk attack {folder}[/cyan]")
    return 0


def cmd_validate(args: argparse.Namespace, console: Console, config: Config) -> int:
    path = pathlib.Path(args.path)
    try:
        errors, warnings, count = validate_file(path)
    except FileNotFoundError:
        console.print(f"[red]error:[/red] file not found: {path}")
        return 1
    except json.JSONDecodeError as e:
        console.print(f"[red]error:[/red] could not parse JSON in {path}: {e}")
        return 2

    if warnings:
        err_console = Console(stderr=True)
        err_console.print(f"[yellow]warnings ({len(warnings)}, non-fatal):[/yellow]")
        for w in warnings:
            err_console.print(f"  [yellow]{w}[/yellow]")

    if errors:
        console.print(f"[red]errors ({len(errors)}):[/red]")
        for e in errors:
            console.print(f"  [red]{e}[/red]")
        return 2

    tail = f" ({len(warnings)} warnings)" if warnings else ""
    console.print(f"[green]OK[/green] — {count} finding(s) valid{tail}")
    return 0


def cmd_report(args: argparse.Namespace, console: Console, config: Config) -> int:
    target = pathlib.Path(args.target_folder)
    try:
        stats = synthesize(target)
    except FileNotFoundError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1

    table = Table(title=f"synthesis stats — {target.name}", show_header=False, box=None)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("total findings", str(stats["total"]))
    table.add_row("main", str(stats["main"]))
    table.add_row("hardening", str(stats["hardening"]))
    table.add_row("cross-agent chains", str(stats["chains"]))
    table.add_row("suspected dup clusters", str(stats["clusters"]))
    table.add_row("fix-these-first candidates", str(stats["ftf_candidates"]))
    console.print(table)
    console.print(f"[green]wrote:[/green] {target.resolve() / 'report.md'}")
    return 0


def cmd_attack(args: argparse.Namespace, console: Console, config: Config) -> int:
    # Lazy imports so `rfatk --help` stays snappy and doesn't require
    # the LLM SDKs to be installed for non-attack commands.
    from redforge_attack.default_roster import DEFAULT_CODE_ROSTER, HOST_SCAN_ROSTER
    from redforge_attack.target import target_metadata

    target = pathlib.Path(args.target_folder).resolve()
    if not (target / "target.yaml").exists():
        console.print(f"[red]error:[/red] not a target folder (missing target.yaml): {target}")
        return 1

    # Read target_type from target.yaml. Default to 'code' for backward-compat
    # with pre-M7a targets that don't have the field.
    try:
        meta = target_metadata(target)
        target_type = meta.get("target_type", "code")
    except FileNotFoundError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1
    if target_type not in ("code", "host"):
        console.print(f"[red]error:[/red] invalid target_type in target.yaml: {target_type!r}")
        return 1

    # ----- Resolve agent list -----
    raw = [a.strip() for a in args.agents.split(",") if a.strip()]
    if not raw:
        raw = ["auto"]

    # Expand "auto" to the default roster for this target_type.
    default_roster = HOST_SCAN_ROSTER if target_type == "host" else DEFAULT_CODE_ROSTER
    expanded: list[str] = []
    for a in raw:
        if a == "auto":
            expanded.extend(default_roster)
        else:
            expanded.append(a)

    # Dedupe while preserving order.
    seen: set[str] = set()
    agent_ids: list[str] = []
    for a in expanded:
        if a not in seen:
            seen.add(a)
            agent_ids.append(a)

    # If user included "recon" or "synthesizer" in --agents, respect that as
    # "yes run those phases" — they're handled separately by orchestrator
    # flags, not as specialists in the parallel phase.
    run_recon = "recon" in agent_ids or not args.no_recon
    run_synthesizer = "synthesizer" in agent_ids or not args.no_synthesizer
    specialist_ids = [a for a in agent_ids if a not in ("recon", "synthesizer")]

    # Single-agent fast-path: user asked for exactly one thing that isn't
    # the auto roster, AND it's not recon/synthesizer. Skip recon + synth.
    single_agent_mode = (
        len(raw) == 1
        and raw[0] not in ("auto",)
        and raw[0] not in ("recon", "synthesizer")
    )
    if single_agent_mode:
        run_recon = False
        run_synthesizer = False

    if args.dry_run:
        console.print("[yellow]warning:[/yellow] --dry-run is not yet implemented (M5).")
        return 3

    from redforge_attack.providers import registry

    provider_name = args.provider or config.provider
    try:
        provider = registry.build_provider(
            provider_name,
            api_key=args.api_key,
            config_overrides=config.provider_overrides,
        )
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]error:[/red] {e}")
        return 1

    # ----- Per-role model resolution -----
    vendor_cfg = (config.provider_overrides or {}).get(provider_name, {}) or {}

    def _resolve_model(role: str) -> str:
        return (
            args.model
            or config.model
            or vendor_cfg.get(f"model_{role}")
            or registry.default_model_for(provider_name, role)
            or ""
        )

    model_recon = _resolve_model("recon")
    model_specialist = _resolve_model("specialist")
    model_synthesizer = _resolve_model("synthesizer")
    if not (model_specialist or provider_name == "llamacpp"):
        console.print(
            f"[red]error:[/red] no specialist model resolved for provider {provider_name!r}. "
            f"Pass --model or set [provider.{provider_name}].model_specialist in redforge.toml."
        )
        return 1

    # ----- Concurrency cap -----
    max_parallel = args.max_parallel or config.run.max_parallel_specialists

    # ----- Pre-run summary -----
    console.print(f"[bold]rfatk attack[/bold] — provider=[cyan]{provider.name}[/cyan] target_type=[cyan]{target_type}[/cyan]")
    console.print(f"  target:            {target}")
    console.print(f"  api-key:           source=[dim]{provider.api_key_source}[/dim] prefix=[dim]{provider.api_key_prefix}[/dim]")
    console.print(f"  recon model:       [cyan]{model_recon}[/cyan] " + ("(will run)" if run_recon else "(skipped)"))
    console.print(f"  specialist model:  [cyan]{model_specialist}[/cyan]")
    console.print(f"  synth model:       [cyan]{model_synthesizer}[/cyan] " + ("(agent pass)" if run_synthesizer else "(mechanical only)"))
    console.print(f"  specialists:       {specialist_ids or '(none)'}")
    console.print(f"  max-parallel:      {max_parallel}")
    console.print(f"  max-turns/agent:   {args.max_turns}")
    console.print(f"  tokens/call:       {args.max_tokens_per_call}  budget/agent: {args.max_tokens_budget:,}")
    if target_type == "host":
        if args.allow_admin:
            console.print("  [red]admin:             ENABLED (SAM hive reads, full socket attribution, etc.)[/red]")
        if args.allow_network_probe:
            console.print("  [red]network-probe:     ENABLED (local-subnet sweep, DNS probes, Test-NetConnection)[/red]")
    elif args.allow_shell:
        console.print("  [red]shell:             ENABLED (run_bash available). Only safe on disposable VMs.[/red]")
    console.print()

    # ----- Run the trial (single-agent fast-path uses the same orchestrator) -----
    from redforge_attack.orchestrator import run_trial

    def _progress(event: str, details: str) -> None:
        color = {
            "phase": "bold blue",
            "agent_start": "dim cyan",
            "agent_done": "green",
            "agent_failed": "red",
        }.get(event, "white")
        console.print(f"[{color}][{event}][/{color}] {details}")

    try:
        trial = run_trial(
            target_dir=target,
            provider=provider,
            model_recon=model_recon or model_specialist,
            model_specialist=model_specialist,
            model_synthesizer=model_synthesizer or model_specialist,
            specialist_ids=specialist_ids,
            max_parallel=max_parallel,
            max_turns=args.max_turns,
            max_tokens_per_call=args.max_tokens_per_call,
            max_tokens_budget=args.max_tokens_budget,
            allow_shell=args.allow_shell,
            run_recon=run_recon,
            run_synthesizer_agent=run_synthesizer,
            progress=_progress,
            target_type=target_type,
            allow_admin=args.allow_admin,
            allow_network_probe=args.allow_network_probe,
        )
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        console.print(f"[red]error:[/red] trial failed: {type(e).__name__}: {e}")
        return 4

    # ----- Results summary -----
    console.print()
    table = Table(title=f"trial complete — {target.name}", show_header=False, box=None)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("agents run", str(
        (1 if trial.recon else 0) + len(trial.specialists) + (1 if trial.synthesizer else 0)
    ))
    table.add_row("failures", str(len(trial.failures)))
    table.add_row("total tool calls", str(trial.total_tool_calls))
    table.add_row("sandbox violations", str(trial.total_sandbox_violations))
    table.add_row("input tokens", f"{trial.total_input_tokens:,}")
    table.add_row("output tokens", f"{trial.total_output_tokens:,}")
    console.print(table)

    stats = trial.synth_stats
    if stats:
        console.print()
        console.print("[bold]synthesis:[/bold] "
                      f"{stats.get('total', 0)} total, "
                      f"[green]{stats.get('main', 0)} main[/green] · "
                      f"[yellow]{stats.get('hardening', 0)} hardening[/yellow] · "
                      f"{stats.get('chains', 0)} chains · "
                      f"{stats.get('clusters', 0)} dup-clusters · "
                      f"{stats.get('ftf_candidates', 0)} Fix-These-First")

    if trial.failures:
        console.print()
        console.print("[red]failed agents:[/red]")
        for aid, err in trial.failures:
            console.print(f"  [red]{aid}[/red]: {err}")

    console.print()
    console.print(f"[green]report:[/green] {target / 'report.md'}")
    return 0 if not trial.failures else 5  # Partial-success exit code


def cmd_doctor(args: argparse.Namespace, console: Console, config: Config) -> int:
    console.print(
        "[yellow]not yet implemented:[/yellow] [bold]rfatk doctor[/bold] lands in M5 "
        "once the provider layer is in place."
    )
    console.print()
    console.print("It will verify:")
    console.print("  - ANTHROPIC_API_KEY / OPENAI_API_KEY / OLLAMA_HOST resolution")
    console.print("  - [bold red]no reuse of ~/.claude/ auth artifacts[/bold red] (TOS safety)")
    console.print("  - provider reachability (network + auth round-trip)")
    return 3


# -----------------------------------------------------------------------------
# Entry
# -----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    try:
        config = load_config(
            cli_targets_dir=args.targets_dir,
            cli_config_file=args.config,
        )
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        console.print(f"[red]error:[/red] could not load config: {e}")
        return 1

    try:
        return args.func(args, console, config)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        console.print(f"[red]error:[/red] {type(e).__name__}: {e}")
        return 4


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
