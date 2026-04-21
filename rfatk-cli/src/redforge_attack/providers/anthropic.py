"""Anthropic Messages API provider.

Why this exists
---------------
Anthropic is the default backend for REDFORGE. This adapter wraps the
`anthropic` Python SDK's Messages API, converting:
- canonical OpenAI-format messages + tools -> Anthropic wire shape
- Anthropic response -> normalized AssistantTurn

TOS-safety hard rules
---------------------
1. API key comes ONLY from: explicit constructor arg > ANTHROPIC_API_KEY env.
   We never call `anthropic.Anthropic()` with no args (the SDK would then
   read the env itself, which is fine, but we want to *know* where the key
   came from for `rfatk doctor`).
2. We never read ~/.claude/, ~/.config/claude/, or any Claude Code OAuth
   artifact. Those belong to Claude Code, not us. Claude Max session
   credentials are scoped to Anthropic's own products.

If the user wants to supply a key via `~/.redforge/config.toml` they can,
and we pass it explicitly to the SDK. The source is recorded for reporting.
"""

from __future__ import annotations

import json
import os

from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn, ToolCall

# Keep SDK import local so the package still imports if anthropic isn't installed
# (tests can run without the SDK if they mock this provider).


# --- Shape conversion helpers ------------------------------------------------


def _openai_tools_to_anthropic(tools: list[dict]) -> list[dict]:
    """OpenAI `{type:function, function:{name, description, parameters}}` ->
    Anthropic `{name, description, input_schema}`."""
    out: list[dict] = []
    for t in tools:
        if t.get("type") != "function":
            continue
        fn = t.get("function") or {}
        out.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return out


def _openai_messages_to_anthropic(messages: list[dict]) -> list[dict]:
    """Convert OpenAI-shape messages to Anthropic shape.

    OpenAI:
      - {role:"user"|"assistant", content:"<text>"}
      - {role:"assistant", tool_calls:[{id,type:"function",function:{name,arguments:JSON}}]}
      - {role:"tool", tool_call_id, content}

    Anthropic:
      - {role:"user"|"assistant", content:"<text>" | [blocks...]}
      - assistant with tool calls: {role:"assistant", content:[{type:"text",text:...},
                                     {type:"tool_use", id, name, input:dict}]}
      - tool results go in a USER message: {role:"user", content:[
          {type:"tool_result", tool_use_id, content:"...", is_error?:bool}]}
    """
    out: list[dict] = []
    buffered_tool_results: list[dict] = []

    def _flush_tool_results() -> None:
        if buffered_tool_results:
            out.append({"role": "user", "content": list(buffered_tool_results)})
            buffered_tool_results.clear()

    for msg in messages:
        role = msg.get("role")
        if role == "tool":
            # Collapse consecutive tool results into one user message
            is_error = bool(msg.get("is_error", False))
            buffered_tool_results.append({
                "type": "tool_result",
                "tool_use_id": msg["tool_call_id"],
                "content": msg.get("content", ""),
                "is_error": is_error,
            })
            continue
        _flush_tool_results()

        if role == "user":
            out.append({"role": "user", "content": msg.get("content", "")})
        elif role == "assistant":
            blocks: list[dict] = []
            text = msg.get("content")
            if isinstance(text, str) and text:
                blocks.append({"type": "text", "text": text})
            for tc in msg.get("tool_calls", []) or []:
                fn = tc.get("function") or {}
                args_raw = fn.get("arguments", "{}")
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw) if args_raw.strip() else {}
                    except json.JSONDecodeError:
                        args = {}
                else:
                    args = args_raw or {}
                blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", ""),
                    "name": fn.get("name", ""),
                    "input": args,
                })
            if not blocks:
                # Empty assistant message — Anthropic rejects these; skip.
                continue
            out.append({"role": "assistant", "content": blocks})
        # Ignore other roles (e.g. "system" lives out-of-band in chat())

    _flush_tool_results()
    return out


def _response_to_turn(resp: object) -> AssistantTurn:
    """Map an anthropic.Message response into AssistantTurn."""
    text_bits: list[str] = []
    tool_calls: list[ToolCall] = []
    content = getattr(resp, "content", [])
    for block in content:
        btype = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
        if btype == "text":
            t = getattr(block, "text", None) or (block.get("text", "") if isinstance(block, dict) else "")
            if t:
                text_bits.append(t)
        elif btype == "tool_use":
            bid = getattr(block, "id", None) or block.get("id", "")
            bname = getattr(block, "name", None) or block.get("name", "")
            binput = getattr(block, "input", None)
            if binput is None and isinstance(block, dict):
                binput = block.get("input", {})
            if not isinstance(binput, dict):
                binput = {}
            tool_calls.append(ToolCall(id=bid, name=bname, arguments=binput))
    usage_obj = getattr(resp, "usage", None)
    usage = {}
    if usage_obj is not None:
        usage = {
            "input_tokens": getattr(usage_obj, "input_tokens", 0),
            "output_tokens": getattr(usage_obj, "output_tokens", 0),
        }
    return AssistantTurn(
        text="".join(text_bits),
        tool_calls=tool_calls,
        stop_reason=getattr(resp, "stop_reason", "") or "",
        usage=usage,
    )


# --- Provider --------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API backend. Requires `anthropic>=0.39`."""

    name = "anthropic"

    def __init__(self, *, api_key: str | None = None, api_key_source: str | None = None):
        """Create the provider.

        Args:
            api_key: explicit API key. If None, reads ANTHROPIC_API_KEY env.
            api_key_source: label describing where the key came from (for
                `rfatk doctor` reporting). Optional.
        """
        # Import locally so package-level imports don't break if SDK is absent.
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK not installed. `pip install anthropic>=0.39` "
                "or `pip install redforge-attack` (it's a core dep)."
            ) from e
        from anthropic import Anthropic

        resolved_key, resolved_src = _resolve_api_key(api_key, api_key_source)
        if not resolved_key:
            raise RuntimeError(
                "No Anthropic API key found. Set ANTHROPIC_API_KEY env var, "
                "pass --api-key, or put api_key in [provider.anthropic] of your "
                "redforge.toml. Get a key at "
                "https://console.anthropic.com/settings/keys. "
                "REDFORGE does NOT reuse Claude Code / Claude Max credentials."
            )

        # Pass the key explicitly. Never call Anthropic() with no args — we
        # want the source to be traceable, and we want to be robust against
        # future SDK changes that might auto-read unexpected files.
        self._client = Anthropic(api_key=resolved_key)
        self._api_key_source = resolved_src
        self._api_key_prefix = resolved_key[:12] + "..." if len(resolved_key) > 12 else "***"

    @property
    def api_key_source(self) -> str:
        return self._api_key_source

    @property
    def api_key_prefix(self) -> str:
        return self._api_key_prefix

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
        anth_messages = _openai_messages_to_anthropic(messages)
        anth_tools = _openai_tools_to_anthropic(tools)

        kwargs: dict = {
            "model": model,
            "system": system,
            "messages": anth_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if anth_tools:
            kwargs["tools"] = anth_tools

        resp = self._client.messages.create(**kwargs)
        return _response_to_turn(resp)

    def capabilities(self) -> dict:
        return {
            "parallel_tool_calls": True,
            "native_tool_use": True,
            "max_context": 200_000,
        }


# --- API key resolution -----------------------------------------------------


# Paths we explicitly refuse to read (TOS-safety).
REFUSED_PATHS: tuple[str, ...] = (
    "~/.claude",
    "~/.config/claude",
    "~/Library/Application Support/Claude",
    "~/AppData/Roaming/Claude",
    "~/AppData/Local/Claude",
)


def _resolve_api_key(
    explicit: str | None, source_hint: str | None
) -> tuple[str | None, str]:
    """Resolve the Anthropic API key with transparent source tracking.

    Precedence:
      1. explicit (passed by caller — typically from --api-key or redforge.toml)
      2. ANTHROPIC_API_KEY env var
      3. None

    Source hint is preserved and returned as the "source" label. We do NOT
    consult ~/.claude/ or any Claude Code OAuth artifact.
    """
    if explicit:
        return explicit, source_hint or "explicit"
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        return env_key, "ANTHROPIC_API_KEY env"
    return None, "not-found"


def assert_no_claude_code_auth_reuse() -> dict:
    """Confirm no Claude Code auth artifact is being consulted.

    Returns a dict describing each REFUSED_PATHS entry's existence on disk.
    rfatk doctor --paranoid surfaces this to the user.
    """
    import pathlib as _p
    report = {}
    for path in REFUSED_PATHS:
        expanded = _p.Path(_p.Path(path).expanduser())
        report[str(expanded)] = expanded.exists()
    return report
