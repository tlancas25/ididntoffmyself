"""Trial orchestrator — recon → parallel specialists → synthesizer.

Why this exists
---------------
The single-agent path (M2) validated the provider + sandbox + agent-loop
stack. A real trial runs recon first (to inform specialist selection), then
fans out ~10-16 specialists in parallel, then runs the synthesizer (both
mechanical — `synthesize()` — and agentic — the `synthesizer` brief).

Design
------
- **Threading, not asyncio.** The agent loop and providers (Anthropic SDK,
  openai SDK) are sync. A ThreadPoolExecutor with a size cap is a simpler
  fit than `asyncio.to_thread` wrappers, gives us natural I/O parallelism
  (HTTP requests release the GIL), and integrates cleanly with Rich's
  progress live-UI.

- **Semaphore == pool size.** The pool is the semaphore. `max_workers`
  caps concurrent specialists so we don't blow through vendor rate limits.

- **Partial-failure tolerance.** One specialist raising doesn't abort the
  trial. Failures are collected and surfaced in the return value so the
  synthesizer still runs over whatever succeeded.

- **Synthesizer pass runs twice.** Once mechanically (`synthesize()` reads
  findings.json, emits report.md), then optionally the `synthesizer` AGENT
  brief (which reads report.md + produces the judgment layer in
  `agents/synthesizer/notes.md`). We re-run the mechanical synthesis AFTER
  the agent pass in case it appended findings.
"""

from __future__ import annotations

import concurrent.futures
import pathlib
from dataclasses import dataclass, field
from typing import Callable

from redforge_attack.agent_loop import AgentRunResult, run_agent
from redforge_attack.prompt_loader import load_system_prompt
from redforge_attack.providers.base import LLMProvider
from redforge_attack.synthesizer import synthesize
from redforge_attack.tools import host_sandbox, sandbox
from redforge_attack.tools.host_schemas import default_host_tools
from redforge_attack.tools.schemas import default_tools


ProgressCallback = Callable[[str, str], None]  # (event_name, details)


@dataclass
class TrialResult:
    recon: AgentRunResult | None = None
    specialists: list[AgentRunResult] = field(default_factory=list)
    synthesizer: AgentRunResult | None = None
    synth_stats: dict = field(default_factory=dict)
    failures: list[tuple[str, str]] = field(default_factory=list)  # (agent_id, error_string)

    @property
    def total_input_tokens(self) -> int:
        all_runs = [self.recon] + self.specialists + [self.synthesizer]
        return sum(r.input_tokens for r in all_runs if r is not None)

    @property
    def total_output_tokens(self) -> int:
        all_runs = [self.recon] + self.specialists + [self.synthesizer]
        return sum(r.output_tokens for r in all_runs if r is not None)

    @property
    def total_tool_calls(self) -> int:
        all_runs = [self.recon] + self.specialists + [self.synthesizer]
        return sum(r.tool_calls_made for r in all_runs if r is not None)

    @property
    def total_sandbox_violations(self) -> int:
        all_runs = [self.recon] + self.specialists + [self.synthesizer]
        return sum(r.sandbox_violations for r in all_runs if r is not None)


def run_trial(
    *,
    target_dir: pathlib.Path,
    provider: LLMProvider,
    model_recon: str,
    model_specialist: str,
    model_synthesizer: str,
    specialist_ids: list[str],
    max_parallel: int = 6,
    max_turns: int = 40,
    max_tokens_per_call: int = 4096,
    max_tokens_budget: int = 200_000,
    allow_shell: bool = False,
    run_recon: bool = True,
    run_synthesizer_agent: bool = True,
    progress: ProgressCallback | None = None,
    target_type: str = "code",
    allow_admin: bool = False,
    allow_network_probe: bool = False,
) -> TrialResult:
    """Run a full trial: recon → parallel specialists → synthesizer.

    Args:
      target_dir: resolved Path to `targets/<slug>-<ts>/`.
      provider: any LLMProvider (Anthropic, OpenAI-compat, ...).
      model_*: per-role model ids. Specialist model is shared across the
        parallel specialists; synthesizer typically uses a smarter/bigger
        model.
      specialist_ids: which specialists to run in the parallel phase. Do
        NOT include "recon" or "synthesizer" here — those are handled by
        the `run_recon` / `run_synthesizer_agent` flags.
      max_parallel: concurrency cap for the specialist phase. Tune to
        vendor rate limits. Default 6.
      allow_shell: propagated into the sandbox; enables run_bash tool.
      progress: optional callback invoked with (event_name, details)
        for live-UI integration. event_name ∈ {"phase", "agent_start",
        "agent_done", "agent_failed"}.

    Returns:
      TrialResult — per-agent runs + mechanical synth stats + any failures.
    """
    target_dir = pathlib.Path(target_dir).resolve()
    if not (target_dir / "target.yaml").exists():
        raise FileNotFoundError(f"not a target folder (missing target.yaml): {target_dir}")

    if target_type not in ("code", "host"):
        raise ValueError(f"target_type must be 'code' or 'host', got {target_type!r}")

    tools = default_host_tools() if target_type == "host" else default_tools(allow_shell=allow_shell)
    result = TrialResult()

    def _make_ctx(aid: str):
        """Build the per-agent tool context matching target_type."""
        if target_type == "host":
            return host_sandbox.HostToolContext(
                target_dir=target_dir,
                agent_id=aid,
                allow_admin=allow_admin,
                allow_network_probe=allow_network_probe,
            )
        intake_dir = target_dir / "intake"
        return sandbox.ToolContext(
            target_dir=target_dir,
            intake_dir=intake_dir,
            agent_id=aid,
            allow_shell=allow_shell,
        )

    # ----- 1. Recon phase (sequential; its output informs specialists) -----
    if run_recon:
        _notify(progress, "phase", "recon")
        try:
            result.recon = _run_one(
                target_dir=target_dir,
                provider=provider,
                model=model_recon,
                agent_id="recon",
                tools=tools,
                allow_shell=allow_shell,
                max_turns=max_turns,
                max_tokens_per_call=max_tokens_per_call,
                max_tokens_budget=max_tokens_budget,
                progress=progress,
                target_type=target_type,
                tool_context=_make_ctx("recon"),
            )
        except Exception as e:
            result.failures.append(("recon", f"{type(e).__name__}: {e}"))
            _notify(progress, "agent_failed", f"recon — {type(e).__name__}: {e}")

    # ----- 2. Specialist parallel fan-out -----
    _notify(
        progress,
        "phase",
        f"specialists (n={len(specialist_ids)}, max_parallel={max_parallel})",
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as pool:
        future_to_id: dict[concurrent.futures.Future, str] = {}
        for aid in specialist_ids:
            fut = pool.submit(
                _run_one,
                target_dir=target_dir,
                provider=provider,
                model=model_specialist,
                agent_id=aid,
                tools=tools,
                allow_shell=allow_shell,
                max_turns=max_turns,
                max_tokens_per_call=max_tokens_per_call,
                max_tokens_budget=max_tokens_budget,
                progress=progress,
                target_type=target_type,
                tool_context=_make_ctx(aid),
            )
            future_to_id[fut] = aid

        for fut in concurrent.futures.as_completed(future_to_id):
            aid = future_to_id[fut]
            try:
                result.specialists.append(fut.result())
            except Exception as e:
                result.failures.append((aid, f"{type(e).__name__}: {e}"))
                _notify(progress, "agent_failed", f"{aid} — {type(e).__name__}: {e}")

    # ----- 3. Mechanical synthesis — writes report.md -----
    _notify(progress, "phase", "synthesizer (mechanical)")
    result.synth_stats = synthesize(target_dir)

    # ----- 4. Synthesizer agent (judgment layer in agents/synthesizer/notes.md) -----
    if run_synthesizer_agent:
        _notify(progress, "phase", "synthesizer (agent)")
        try:
            result.synthesizer = _run_one(
                target_dir=target_dir,
                provider=provider,
                model=model_synthesizer,
                agent_id="synthesizer",
                tools=tools,
                allow_shell=allow_shell,
                max_turns=max_turns,
                max_tokens_per_call=max_tokens_per_call,
                max_tokens_budget=max_tokens_budget,
                progress=progress,
                target_type=target_type,
                tool_context=_make_ctx("synthesizer"),
            )
            # Re-run mechanical synthesis in case the synthesizer agent used
            # submit_finding (it shouldn't, but defensive).
            result.synth_stats = synthesize(target_dir)
        except Exception as e:
            result.failures.append(("synthesizer", f"{type(e).__name__}: {e}"))
            _notify(progress, "agent_failed", f"synthesizer — {type(e).__name__}: {e}")

    return result


def _run_one(
    *,
    target_dir: pathlib.Path,
    provider: LLMProvider,
    model: str,
    agent_id: str,
    tools: list[dict],
    allow_shell: bool,
    max_turns: int,
    max_tokens_per_call: int,
    max_tokens_budget: int,
    progress: ProgressCallback | None,
    target_type: str = "code",
    tool_context=None,
) -> AgentRunResult:
    _notify(progress, "agent_start", agent_id)

    system_prompt = load_system_prompt(agent_id, target_type=target_type)
    target_meta = (target_dir / "target.yaml").read_text(encoding="utf-8")
    user_prompt = _build_user_prompt(agent_id, target_meta, target_dir, target_type=target_type)

    r = run_agent(
        agent_id=agent_id,
        target_dir=target_dir,
        provider=provider,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=tools,
        allow_shell=allow_shell,
        max_turns=max_turns,
        max_tokens_per_call=max_tokens_per_call,
        max_tokens_budget=max_tokens_budget,
        tool_context=tool_context,
    )
    _notify(
        progress,
        "agent_done",
        f"{agent_id} stop={r.stop_reason} turns={r.turns} "
        f"tool_calls={r.tool_calls_made} tok_in={r.input_tokens} tok_out={r.output_tokens} "
        f"violations={r.sandbox_violations}",
    )
    return r


def _build_user_prompt(agent_id: str, target_meta: str, target_dir: pathlib.Path, *, target_type: str = "code") -> str:
    """Per-agent kickoff message. Recon + synthesizer are slightly different."""
    base_header = (
        f"You are the `{agent_id}` agent in a REDFORGE red-team trial.\n\n"
        f"## Target metadata (target.yaml)\n\n```yaml\n{target_meta}```\n\n"
    )
    if agent_id == "recon" and target_type == "host":
        return (
            base_header
            + "## Your task\n\n"
            "Fingerprint the running machine. Use `run_system_query` to "
            "enumerate: OS build + patch level, domain membership, installed "
            "software, user accounts + groups, mounted drives, Defender state, "
            "BitLocker state, network adapters + IP config, firewall profiles. "
            "For each significant surface detected, call `submit_finding` with "
            "severity INFO and `exploitable_now: false` — recon findings are "
            "surface markers, not exploits. Call `write_notes` to record the "
            "full fingerprint, notable processes, external integrations, and "
            "your phase-2 specialist recommendations.\n\n"
            "**DO NOT** query anything under the user's Documents, Downloads, "
            "Pictures, or Videos folders. Those are operator-excluded.\n\n"
            "Stop when the map is complete — do not loop.\n\nBegin."
        )
    if agent_id == "recon":
        return (
            base_header
            + "## Your task\n\n"
            "Map the attack surface of the code under `intake/`. Use "
            "`read_file`, `glob`, `grep` to explore. For each surface you "
            "detect (see the bundled `roster.yaml` / your brief), call "
            "`submit_finding` with severity INFO and `exploitable_now: false` "
            "— recon findings are surface markers, not exploits. Call "
            "`write_notes` to record the framework fingerprint, entry points, "
            "auth model, data-flow highlights, external integrations, recon "
            "gaps, and your phase-2 specialist recommendations.\n\n"
            "Stop when the map is complete — do not loop.\n\nBegin."
        )

    if agent_id == "synthesizer":
        # List the available findings files so the synthesizer knows what to read.
        agents_root = target_dir / "agents"
        agent_dirs = sorted([p.name for p in agents_root.iterdir() if p.is_dir()]) if agents_root.exists() else []
        return (
            base_header
            + "## Your task\n\n"
            "The mechanical synthesizer has already written `report.md` at the "
            "target folder root. Your job is the judgment layer — write "
            "`agents/synthesizer/notes.md` via `write_notes`.\n\n"
            f"Available agent directories: {agent_dirs}\n\n"
            "Use `read_file` to read:\n"
            "  - `../report.md` (the mechanical output — but note: read_file "
            "is scoped to intake/, so the report.md cannot be read directly; "
            "instead, rely on per-agent findings.json files in "
            "`agents/<id>/findings.json`).\n"
            "  - Each `agents/<id>/findings.json` and `agents/<id>/notes.md`.\n\n"
            "Structure your notes.md with the six sections from your brief: "
            "(1) Fix These First — curated final cut, (2) Duplicate cluster "
            "resolution, (3) Under-reporting / over-reporting check, "
            "(4) Missed cross-agent chains, (5) Structural observations, "
            "(6) Improvement seeds for next trial.\n\n"
            "DO NOT alter specialist findings.json. Be opinionated and "
            "compact. Stop when done.\n\nBegin."
        )

    # Host specialist brief
    if target_type == "host":
        return (
            base_header
            + "## Your task\n\n"
            f"Follow your binding brief above for specialist `{agent_id}`. "
            "Use `run_system_query` to ask the machine targeted questions — "
            "every command must be on the REDFORGE host-scan allowlist, "
            "single-command, no pipelines / redirections / subshells.\n\n"
            "**DO NOT** query anything under the user's Documents, Downloads, "
            "Pictures, or Videos folders — those are operator-excluded and "
            "your tool will reject any such command.\n\n"
            "Record every distinct finding via `submit_finding` with a "
            "`hardening_plan` field (see bundled schema). Follow the §1 "
            "CRITICAL reserve, §3 NOVEL tightening, §4 required fields. "
            "Record hypotheses and phase-2 recommendations via `write_notes`. "
            "Stop when your brief is complete.\n\nBegin."
        )

    # Default: code-scan specialist brief
    return (
        base_header
        + "## Your task\n\n"
        "Follow your binding brief above (per the `specialists.md` section "
        f"for `{agent_id}`). Use the file tools (`read_file`, `glob`, `grep`) "
        "to explore `intake/`. **Read other agents' `findings.json` before "
        "finalizing yours** — if someone else has already written up a bug, "
        "reference their id in `attack_chain` and add your lens' impact to "
        "your `notes.md` rather than emitting a duplicate (§2).\n\n"
        "Record every distinct finding via `submit_finding` (follow the §1 "
        "CRITICAL reserve, §3 NOVEL tightening, §4 required fields). "
        "Record hypotheses, dead-ends, and lens-specific consequences via "
        "`write_notes`. Stop when you have completed your brief — do not "
        "loop indefinitely.\n\nBegin."
    )


def _notify(cb: ProgressCallback | None, event: str, details: str) -> None:
    if cb is not None:
        try:
            cb(event, details)
        except Exception:
            pass  # A callback raising must not break the trial.
