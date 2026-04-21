"""Canonical dataclass types shared across the package.

Why this exists
---------------
M1 lives with dicts (preserving the dev-workspace findings.json shape). As
providers and the agent loop land in M2+, these dataclasses give the rest of
the package type-safe boundaries for tool-call plumbing and finding I/O.

Currently used by:
- `providers.base` — `ToolCall`, `ToolResult`, `AssistantTurn` (added in M2).
- `cli` — `Config` imported from `config.py`.

Findings + Target are kept as dicts for now (synthesizer operates on dicts
and the round-trip through JSON is lossless). They may grow into dataclasses
in a later milestone if the rest of the package wants stricter typing.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolCall:
    """One tool-use request from the model in a single turn."""
    id: str
    name: str
    arguments: dict  # already JSON-parsed


@dataclass(frozen=True)
class ToolResult:
    """Result of dispatching a ToolCall. Errors go back as tool_result, not exceptions."""
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class AssistantTurn:
    """One full assistant message — text + any tool calls it wants to make."""
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str  # "end_turn" | "tool_use" | "max_tokens" | ...
    usage: dict = field(default_factory=dict)  # {"input_tokens": int, "output_tokens": int}
