"""Agent-loop integration tests using a scripted LLMProvider.

Why this exists
---------------
The agent loop (agent_loop.run_agent) is the glue between the provider and
the sandbox. We can exercise the whole loop — multi-turn tool-use, sandbox
errors, transcript writing, findings persistence, token accounting — without
spending API tokens by plugging in a `ScriptedProvider` that plays a
pre-recorded sequence of AssistantTurns.

The scripted turns cover:
  1. Model calls glob to list files
  2. Model calls read_file on two files
  3. Model submits a finding via submit_finding
  4. Model writes notes
  5. Model ends the conversation (stop_reason=end_turn)
"""

from __future__ import annotations

import json
import pathlib

from redforge_attack.agent_loop import run_agent
from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn, ToolCall


class ScriptedProvider(LLMProvider):
    """LLMProvider that returns a pre-recorded sequence of AssistantTurns."""

    name = "scripted"

    def __init__(self, script: list[AssistantTurn]):
        self._script = list(script)
        self._idx = 0
        self.chat_calls = 0
        self.last_kwargs: dict | None = None

    def chat(self, **kwargs) -> AssistantTurn:
        self.chat_calls += 1
        self.last_kwargs = kwargs
        if self._idx >= len(self._script):
            # Provider ran out of scripted responses — usually means the agent
            # didn't stop when expected. Return a clean end.
            return AssistantTurn(text="(script exhausted)", tool_calls=[], stop_reason="end_turn", usage={})
        turn = self._script[self._idx]
        self._idx += 1
        return turn

    def capabilities(self) -> dict:
        return {"parallel_tool_calls": True, "native_tool_use": True, "max_context": 200_000}


def _make_script() -> list[AssistantTurn]:
    return [
        # Turn 1: glob for python files
        AssistantTurn(
            text="Let me list the python files.",
            tool_calls=[ToolCall(id="c1", name="glob", arguments={"pattern": "*.py"})],
            stop_reason="tool_use",
            usage={"input_tokens": 100, "output_tokens": 20},
        ),
        # Turn 2: read db.py
        AssistantTurn(
            text="Reading db.py to check for SQLi.",
            tool_calls=[ToolCall(id="c2", name="read_file", arguments={"path": "db.py"})],
            stop_reason="tool_use",
            usage={"input_tokens": 150, "output_tokens": 25},
        ),
        # Turn 3: submit a finding + write notes in parallel
        AssistantTurn(
            text="Found the SQLi — recording it.",
            tool_calls=[
                ToolCall(
                    id="c3",
                    name="submit_finding",
                    arguments={
                        "finding": {
                            "id": "scripted-sqli",
                            "title": "SQL injection in find_user_by_email",
                            "surface": "injection",
                            "severity": "HIGH",
                            "exploitable": True,
                            "exploitable_now": True,
                            "requires_future_change": None,
                            "reproduction_status": "code-path-traced",
                            "root_cause_confidence": "high",
                            "confidence": "high",
                            "target_refs": ["db.py:40"],
                            "description": "find_user_by_email uses an f-string to concat `email` into a SQL query, allowing injection.",
                            "impact": "Attacker can recover arbitrary rows including bearer tokens.",
                            "reproduction": "POST /login with email=\"' OR 1=1 --\"",
                            "evidence_paths": [],
                            "remediation": "Use a parameterized query with a `?` placeholder.",
                            "cwe": ["CWE-89"],
                            "attack_chain": [],
                            "novel_pattern": False,
                        },
                    },
                ),
                ToolCall(
                    id="c4",
                    name="write_notes",
                    arguments={"content": "## Recon\n- db.py has one param and one concat; concat is the bug."},
                ),
            ],
            stop_reason="tool_use",
            usage={"input_tokens": 300, "output_tokens": 150},
        ),
        # Turn 4: end
        AssistantTurn(
            text="Done. Submitted 1 finding.",
            tool_calls=[],
            stop_reason="end_turn",
            usage={"input_tokens": 50, "output_tokens": 15},
        ),
    ]


def test_agent_loop_runs_scripted_provider_end_to_end(tiny_target):
    provider = ScriptedProvider(_make_script())

    result = run_agent(
        agent_id="scripted-specialist",
        target_dir=tiny_target,
        provider=provider,
        model="fake-model",
        system_prompt="You are a scripted test agent.",
        user_prompt="find bugs in the target",
        tools=[],  # Tools are gated by the sandbox, not the schema list; scripted provider ignores this.
        allow_shell=False,
        max_turns=10,
        max_tokens_per_call=4096,
        max_tokens_budget=200_000,
    )

    # Loop sanity
    assert result.agent_id == "scripted-specialist"
    assert result.stop_reason == "end_turn"
    assert result.turns == 4
    assert result.tool_calls_made == 4  # glob + read_file + submit_finding + write_notes
    assert result.sandbox_violations == 0

    # Token accounting (sum of all scripted usage)
    assert result.input_tokens == 100 + 150 + 300 + 50
    assert result.output_tokens == 20 + 25 + 150 + 15

    # Transcript written
    assert result.transcript_path.exists()
    lines = result.transcript_path.read_text(encoding="utf-8").strip().splitlines()
    # 1 kickoff + 4 assistant_turn + 4 tool_result (the glob/read_file/submit/write) + 1 run_summary
    #   = 10. submit_finding + write_notes ran in one turn -> 2 tool_results.
    assert len(lines) == 10
    records = [json.loads(l) for l in lines]
    assert records[0]["type"] == "kickoff"
    assert records[-1]["type"] == "run_summary"

    # Findings persisted via the output tool
    findings_path = tiny_target / "agents" / "scripted-specialist" / "findings.json"
    assert findings_path.exists()
    findings = json.loads(findings_path.read_text())
    assert len(findings) == 1
    assert findings[0]["id"] == "scripted-sqli"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["surface"] == "injection"

    # Notes persisted
    notes_path = tiny_target / "agents" / "scripted-specialist" / "notes.md"
    assert notes_path.exists()
    assert "db.py" in notes_path.read_text()


def test_agent_loop_handles_sandbox_violation(tiny_target):
    """When the model requests an out-of-scope file, dispatch returns is_error=True
    and the loop continues (doesn't crash). The violation is counted + logged.
    """
    script = [
        AssistantTurn(
            text="Trying a traversal...",
            tool_calls=[ToolCall(id="x1", name="read_file", arguments={"path": "../../../etc/passwd"})],
            stop_reason="tool_use",
            usage={"input_tokens": 30, "output_tokens": 10},
        ),
        AssistantTurn(
            text="Noted — that path is outside intake. Ending.",
            tool_calls=[],
            stop_reason="end_turn",
            usage={"input_tokens": 40, "output_tokens": 10},
        ),
    ]
    provider = ScriptedProvider(script)

    result = run_agent(
        agent_id="evil-specialist",
        target_dir=tiny_target,
        provider=provider,
        model="fake-model",
        system_prompt="scripted",
        user_prompt="go",
        tools=[],
        max_turns=5,
    )

    assert result.stop_reason == "end_turn"
    assert result.sandbox_violations == 1
    violations_log = tiny_target / "agents" / "evil-specialist" / "sandbox-violations.log"
    assert violations_log.exists()
    assert "1 sandbox violation" in violations_log.read_text()


def test_agent_loop_respects_max_turns(tiny_target):
    """If the model keeps asking for tools forever, max_turns caps it."""
    # An endless stream of tool-use turns.
    infinite = AssistantTurn(
        text="more...",
        tool_calls=[ToolCall(id="loop", name="glob", arguments={"pattern": "*"})],
        stop_reason="tool_use",
        usage={"input_tokens": 10, "output_tokens": 5},
    )
    provider = ScriptedProvider([infinite] * 100)

    result = run_agent(
        agent_id="runaway",
        target_dir=tiny_target,
        provider=provider,
        model="fake",
        system_prompt="x",
        user_prompt="x",
        tools=[],
        max_turns=3,
    )
    assert result.turns == 3
    assert result.stop_reason in ("max_turns", "tool_use")  # we break out at max_turns
