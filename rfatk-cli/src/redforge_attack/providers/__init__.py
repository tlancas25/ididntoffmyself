"""LLM provider backends.

Each provider adapts the canonical OpenAI-shape messages + function-schema
tool format to its native wire format, and returns normalized AssistantTurn
objects so the agent loop is provider-agnostic.
"""

from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn, ToolCall, ToolResult

__all__ = ["LLMProvider", "AssistantTurn", "ToolCall", "ToolResult"]
