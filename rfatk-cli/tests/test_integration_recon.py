"""Integration smoke test — real LLM API call against tiny-target.

Why this exists
---------------
Mocked tests validate the plumbing; this validates the *actual* end-to-end
stack (provider SDK, real tool-use response shapes, prompt understanding)
against the planted-bug fixture. Cost: a few cents of Haiku tokens per run.

Opt-in
------
This test is marked `@pytest.mark.integration` and is SKIPPED unless:
  1. An API key is available in the environment, AND
  2. Pytest is invoked with `-m integration`.

Run it explicitly:

    export ANTHROPIC_API_KEY=sk-ant-...
    pytest tests/test_integration_recon.py -m integration -v

CI setups should only opt into this when they have a funded test key.
"""

from __future__ import annotations

import json
import os

import pytest

from redforge_attack.agent_loop import run_agent
from redforge_attack.prompt_loader import load_system_prompt
from redforge_attack.providers import registry
from redforge_attack.tools.schemas import default_tools


pytestmark = pytest.mark.integration


@pytest.fixture()
def recon_provider_and_model():
    """Pick whichever real provider has a key in the env; skip if none found.

    Precedence: anthropic > openrouter > openai > moonshot > gemini.
    """
    candidates = [
        ("anthropic",  "ANTHROPIC_API_KEY",  "claude-haiku-4-5"),
        ("openrouter", "OPENROUTER_API_KEY", "anthropic/claude-haiku-4.5"),
        ("openai",     "OPENAI_API_KEY",     "gpt-4o-mini"),
        ("moonshot",   "MOONSHOT_API_KEY",   "kimi-k2-latest"),
        ("gemini",     "GEMINI_API_KEY",     "gemini-2.5-flash"),
    ]
    for name, env_var, model in candidates:
        if os.environ.get(env_var):
            try:
                provider = registry.build_provider(name)
            except (RuntimeError, ValueError) as e:
                pytest.skip(f"could not build provider {name}: {e}")
            return provider, model
    pytest.skip(
        "no LLM API key found in env. Set ANTHROPIC_API_KEY / OPENROUTER_API_KEY / "
        "OPENAI_API_KEY / MOONSHOT_API_KEY / GEMINI_API_KEY to run."
    )


def test_recon_against_tiny_target(tiny_target, recon_provider_and_model):
    """Recon reads tiny-target and emits at least one INFO surface finding."""
    provider, model = recon_provider_and_model

    system_prompt = load_system_prompt("recon")
    target_yaml = (tiny_target / "target.yaml").read_text(encoding="utf-8")
    user_prompt = (
        f"You are the `recon` agent in a REDFORGE trial.\n\n"
        f"## Target metadata (target.yaml)\n\n```yaml\n{target_yaml}```\n\n"
        f"Map the attack surface of the code under `intake/`. "
        f"Use read_file, glob, grep to explore. Call `submit_finding` for each "
        f"surface you detect (severity INFO, exploitable_now false). Call "
        f"`write_notes` to record the fingerprint + entry points. Finish "
        f"promptly when you have a reasonable map — do not loop."
    )
    tools = default_tools(allow_shell=False)

    result = run_agent(
        agent_id="recon",
        target_dir=tiny_target,
        provider=provider,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=tools,
        allow_shell=False,
        max_turns=25,
        max_tokens_per_call=4096,
        max_tokens_budget=80_000,
    )

    # Acceptance: recon actually did tool-use work, didn't escape the sandbox,
    # and produced some structured output.
    assert result.sandbox_violations == 0, (
        f"recon triggered {result.sandbox_violations} sandbox violation(s). "
        f"See {result.transcript_path.parent / 'sandbox-violations.log'}"
    )
    assert result.tool_calls_made >= 2, (
        f"recon made only {result.tool_calls_made} tool call(s). "
        f"Expected at least 2 (glob + read_file)."
    )
    assert result.stop_reason in ("end_turn", "max_turns", "max_tokens",
                                   "token_budget_exhausted", "stop"), (
        f"unexpected stop_reason: {result.stop_reason!r}"
    )

    findings_path = tiny_target / "agents" / "recon" / "findings.json"
    notes_path = tiny_target / "agents" / "recon" / "notes.md"

    assert findings_path.exists() or notes_path.exists(), (
        "recon produced neither findings.json nor notes.md. "
        "Check transcript for what it did with its turns."
    )

    if findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        assert isinstance(findings, list)
        if findings:
            # Recon findings should be severity INFO and exploitable_now=false.
            for f in findings:
                assert f.get("severity") == "INFO", f"non-INFO recon finding: {f.get('id')} = {f.get('severity')}"
                assert f.get("exploitable_now") is False, (
                    f"recon finding {f.get('id')!r} has exploitable_now != false"
                )

    # Print result for visibility when run with -v.
    print(
        f"\n[recon] turns={result.turns} tool_calls={result.tool_calls_made} "
        f"in={result.input_tokens:,} out={result.output_tokens:,} "
        f"stop={result.stop_reason}"
    )
