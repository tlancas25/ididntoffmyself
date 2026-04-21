"""Provider-agnostic tool-use message loop for a single specialist agent.

Why this exists
---------------
One specialist = one LLM reasoning loop with a system prompt (from the
bundled prompts/), a user prompt (its specific kickoff), and a set of
sandbox-bound tools. The loop is:

    1. Seed messages with [user: kickoff]
    2. provider.chat(messages, tools) -> AssistantTurn
    3. If stop_reason != "tool_use" OR tool_calls empty: done.
    4. Append assistant turn (text + tool_calls) to messages.
    5. dispatch each tool_call via sandbox -> ToolResult.
    6. Append each tool result to messages ({role: "tool", ...}).
    7. Loop to step 2 until stop / max_turns / max_tokens budget exhausted.

We also write `transcript.jsonl` for every turn so `--replay` mode (M5) can
reconstitute a prior run deterministically with zero API spend. The transcript
is the ground truth; findings.json is what the agent chose to declare.
"""

from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass, field

from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn, ToolCall, ToolResult
from redforge_attack.tools import dispatch, sandbox


@dataclass
class AgentRunResult:
    """Result of running one specialist through the tool-use loop."""
    agent_id: str
    stop_reason: str
    turns: int
    tool_calls_made: int
    sandbox_violations: int
    input_tokens: int
    output_tokens: int
    final_text: str
    transcript_path: pathlib.Path
    messages: list[dict] = field(default_factory=list)


def run_agent(
    *,
    agent_id: str,
    target_dir: pathlib.Path,
    provider: LLMProvider,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tools: list[dict],
    allow_shell: bool = False,
    max_turns: int = 40,
    max_tokens_per_call: int = 4096,
    max_tokens_budget: int = 200_000,
    temperature: float = 0.0,
    tool_context=None,  # ToolContext | HostToolContext | None
) -> AgentRunResult:
    """Run one specialist agent through the tool-use loop.

    Side effects:
      - Creates `target_dir/agents/<agent_id>/` if missing.
      - Writes `transcript.jsonl` (one JSON object per line: turn records).
      - Does NOT write `findings.json` — that's the agent's job via a final
        tool call or textual output. The orchestrator / caller persists
        agent-produced findings.

    Args:
      target_dir: resolved path to the target folder (`targets/<slug>-<ts>`).
      provider: any LLMProvider implementation.
      model: provider-specific model id.
      system_prompt: text prepended out-of-band (e.g. the specialist brief).
      user_prompt: the kickoff message (target metadata + what-to-do).
      tools: OpenAI-format tool schemas (see tools.schemas.default_tools()).
      allow_shell: propagated into sandbox.ToolContext for run_bash gating.
      max_turns: hard cap on assistant turns (prevents runaway loops).
      max_tokens_per_call: max_tokens passed to provider per turn.
      max_tokens_budget: total input+output token budget across the loop.
    """
    target_dir = pathlib.Path(target_dir).resolve()

    agent_dir = target_dir / "agents" / agent_id
    agent_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = agent_dir / "transcript.jsonl"
    # Truncate any prior transcript (one folder = one trial; re-runs overwrite agent dirs).
    transcript_path.write_text("", encoding="utf-8")

    if tool_context is not None:
        ctx = tool_context
    else:
        # Default: code-scan context with intake/ as the root.
        intake_dir = target_dir / "intake"
        if not intake_dir.exists():
            raise FileNotFoundError(f"intake/ not found under {target_dir}")
        ctx = sandbox.ToolContext(
            target_dir=target_dir,
            intake_dir=intake_dir,
            agent_id=agent_id,
            allow_shell=allow_shell,
        )

    messages: list[dict] = [{"role": "user", "content": user_prompt}]
    _append_transcript(transcript_path, {"type": "kickoff", "user_prompt": user_prompt, "ts": time.time()})

    total_input = 0
    total_output = 0
    total_tool_calls = 0
    sandbox_violations = 0
    turns = 0
    stop_reason = "unknown"
    final_text = ""

    for turn_idx in range(max_turns):
        turns = turn_idx + 1
        if total_input + total_output >= max_tokens_budget:
            stop_reason = "token_budget_exhausted"
            break

        turn: AssistantTurn = provider.chat(
            model=model,
            system=system_prompt,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens_per_call,
            temperature=temperature,
        )
        total_input += int(turn.usage.get("input_tokens", 0))
        total_output += int(turn.usage.get("output_tokens", 0))
        final_text = turn.text
        stop_reason = turn.stop_reason

        _append_transcript(transcript_path, {
            "type": "assistant_turn",
            "turn": turns,
            "text": turn.text,
            "tool_calls": [
                {"id": c.id, "name": c.name, "arguments": c.arguments}
                for c in turn.tool_calls
            ],
            "stop_reason": turn.stop_reason,
            "usage": turn.usage,
            "ts": time.time(),
        })

        # Append assistant message in canonical format so next call sees the history.
        assistant_msg: dict = {"role": "assistant"}
        if turn.text:
            assistant_msg["content"] = turn.text
        if turn.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": c.id,
                    "type": "function",
                    "function": {
                        "name": c.name,
                        "arguments": json.dumps(c.arguments),
                    },
                }
                for c in turn.tool_calls
            ]
        messages.append(assistant_msg)

        if stop_reason != "tool_use" or not turn.tool_calls:
            # Model is done — either end_turn, max_tokens, or ran out of stuff to ask.
            break

        # Dispatch each tool call via the sandbox.
        for call in turn.tool_calls:
            total_tool_calls += 1
            result: ToolResult = dispatch.dispatch(call, ctx)
            if result.is_error and result.content.startswith("sandbox_violation"):
                sandbox_violations += 1
            _append_transcript(transcript_path, {
                "type": "tool_result",
                "turn": turns,
                "tool_call_id": result.tool_call_id,
                "tool_name": call.name,
                "is_error": result.is_error,
                "content_preview": result.content[:500],
                "ts": time.time(),
            })
            messages.append({
                "role": "tool",
                "tool_call_id": result.tool_call_id,
                "content": result.content,
                "is_error": result.is_error,
            })
    else:
        # Exited via the `for`'s natural termination — hit max_turns.
        stop_reason = stop_reason if stop_reason != "tool_use" else "max_turns"

    # Log sandbox violations to a dedicated audit file for post-trial review.
    if sandbox_violations:
        (agent_dir / "sandbox-violations.log").write_text(
            f"{sandbox_violations} sandbox violation(s) occurred during this run.\n"
            "See transcript.jsonl for specifics (filter by is_error=true).\n",
            encoding="utf-8",
        )

    _append_transcript(transcript_path, {
        "type": "run_summary",
        "agent_id": agent_id,
        "turns": turns,
        "stop_reason": stop_reason,
        "tool_calls_made": total_tool_calls,
        "sandbox_violations": sandbox_violations,
        "input_tokens": total_input,
        "output_tokens": total_output,
        "ts": time.time(),
    })

    return AgentRunResult(
        agent_id=agent_id,
        stop_reason=stop_reason,
        turns=turns,
        tool_calls_made=total_tool_calls,
        sandbox_violations=sandbox_violations,
        input_tokens=total_input,
        output_tokens=total_output,
        final_text=final_text,
        transcript_path=transcript_path,
        messages=messages,
    )


def _append_transcript(path: pathlib.Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
