"""LLMProvider abstract base class — canonical tool-use contract.

Why this exists
---------------
The agent loop is provider-agnostic. It pushes OpenAI-format messages + tools
at `provider.chat(...)` and receives a normalized `AssistantTurn` back. Each
concrete provider (anthropic.py, openai.py, ollama.py, llamacpp.py) adapts
between the canonical LCD shape and its native wire format.

Message shape (OpenAI-canonical, accepted by every provider adapter):

    messages = [
        {"role": "user",      "content": "<text>"},
        {"role": "assistant", "content": "<text>"},
        {"role": "assistant", "tool_calls": [
            {"id": "call_xxx", "type": "function",
             "function": {"name": "read_file", "arguments": '{"path": "..."}'}}]},
        {"role": "tool", "tool_call_id": "call_xxx", "content": "<result>"},
    ]

Tool shape (OpenAI-canonical):

    tools = [{"type": "function", "function": {"name": "read_file", "parameters": {...}}}]

AssistantTurn shape (normalized return):

    AssistantTurn(
        text="<any text the model emitted this turn>",
        tool_calls=[ToolCall(id="call_xxx", name="read_file", arguments={"path": "..."})],
        stop_reason="tool_use" | "end_turn" | "max_tokens" | ...,
        usage={"input_tokens": N, "output_tokens": M},
    )
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from redforge_attack.schema import AssistantTurn


class LLMProvider(ABC):
    """Contract implemented by each backend."""

    name: str = "base"

    @abstractmethod
    def chat(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict],
        tools: list[dict],
        max_tokens: int,
        temperature: float = 0.0,
    ) -> AssistantTurn:
        """Run one turn of the conversation. Returns AssistantTurn.

        Implementations MUST:
        - Accept OpenAI-format messages and tools.
        - Normalize their native response into AssistantTurn.
        - NOT mutate `messages` in place.
        - NOT read ambient credentials (e.g. ~/.claude/, ~/.config/claude/).
          API keys come from the caller or explicit env vars only.
        """
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> dict:
        """Return provider/model capability flags.

        Keys:
          parallel_tool_calls: bool  — can emit multiple tool_use in one turn
          native_tool_use:     bool  — has first-class tool-use (vs prompted JSON)
          max_context:         int   — realistic input+output budget
        """
        raise NotImplementedError
