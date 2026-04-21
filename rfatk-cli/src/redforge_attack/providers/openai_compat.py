"""OpenAI-compatible provider — one adapter, many vendors.

Why this exists
---------------
A huge chunk of the modern LLM ecosystem speaks the OpenAI Chat Completions
wire format. By parameterizing `base_url` and `api_key` (and the env var
that backs it), this one adapter covers:

  - OpenAI           (api.openai.com/v1)          — gpt-4o, gpt-5, o1, o3
  - OpenRouter       (openrouter.ai/api/v1)       — proxies ~300 models
  - Google Gemini    (generativelanguage.googleapis.com/v1beta/openai/)
                                                    — gemini-2.5 family
  - Moonshot Kimi    (api.moonshot.ai/v1)         — kimi-k2, kimi-k1.5
  - DeepSeek         (api.deepseek.com/v1)
  - xAI Grok         (api.x.ai/v1)
  - Groq             (api.groq.com/openai/v1)
  - Together AI      (api.together.xyz/v1)
  - Cerebras         (api.cerebras.ai/v1)
  - Ollama (local)   (localhost:11434/v1)         — OpenAI-compat mode
  - llama-server     (localhost:8080/v1)          — llama.cpp HTTP mode

Same canonical OpenAI-function-call-shape messages + tools go in, same
`AssistantTurn` (text + tool_calls) comes out. Vendor-specific quirks
(header names, rate-limit shapes) are isolated inside this class.

TOS-safety hard rules (same as Anthropic adapter)
-------------------------------------------------
1. API key comes only from: explicit constructor arg > named env var.
2. We never pass `OpenAI()` with no args against an unknown base_url.
3. We never read `~/.claude/` or any Claude Code OAuth artifact —
   those are scoped to Anthropic's own products.
"""

from __future__ import annotations

import json
import os

from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn, ToolCall


# --- Shape conversion -------------------------------------------------------


def _assistant_turn_from_openai(resp: object) -> AssistantTurn:
    """Map an openai.ChatCompletion response to AssistantTurn."""
    choice = resp.choices[0]
    msg = choice.message

    text = msg.content or ""
    tool_calls: list[ToolCall] = []
    for tc in (msg.tool_calls or []):
        fn = tc.function
        args_raw = fn.arguments
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) and args_raw.strip() else {}
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        tool_calls.append(ToolCall(id=tc.id, name=fn.name, arguments=args))

    finish = choice.finish_reason or ""
    # Normalize OpenAI finish_reason into our canonical set.
    if finish == "tool_calls":
        stop_reason = "tool_use"
    elif finish == "stop":
        stop_reason = "end_turn"
    elif finish == "length":
        stop_reason = "max_tokens"
    else:
        stop_reason = finish or "end_turn"

    usage = {}
    if getattr(resp, "usage", None) is not None:
        usage = {
            "input_tokens": getattr(resp.usage, "prompt_tokens", 0),
            "output_tokens": getattr(resp.usage, "completion_tokens", 0),
        }

    return AssistantTurn(
        text=text,
        tool_calls=tool_calls,
        stop_reason=stop_reason,
        usage=usage,
    )


def _messages_with_system(system: str, messages: list[dict]) -> list[dict]:
    """OpenAI keeps system prompts inline (role=system as first message)."""
    if system:
        return [{"role": "system", "content": system}] + list(messages)
    return list(messages)


# --- Provider ---------------------------------------------------------------


class OpenAICompatProvider(LLMProvider):
    """Generic OpenAI-compatible HTTP provider.

    Use named factories in `redforge_attack.providers.registry` for built-in
    vendors (OpenAI, OpenRouter, Gemini, Moonshot, etc.) rather than
    instantiating this directly.
    """

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key: str | None = None,
        api_key_env: str | None = None,
        api_key_source: str | None = None,
        default_headers: dict[str, str] | None = None,
        parallel_tool_calls_supported: bool = True,
        max_context: int = 128_000,
    ):
        """Create the provider.

        Args:
            name: short identifier for logs ("openrouter", "gemini", ...).
            base_url: the vendor's OpenAI-compat endpoint root.
            api_key: explicit key (wins).
            api_key_env: env var to read if api_key is None (e.g. "OPENROUTER_API_KEY").
            api_key_source: human label for rfatk doctor output.
            default_headers: extra HTTP headers the vendor wants
                (e.g. OpenRouter's HTTP-Referer / X-Title).
            parallel_tool_calls_supported: hint for capabilities().
            max_context: the model-family context ceiling; used by budget guards.
        """
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError(
                "openai SDK not installed. `pip install openai>=1.40` "
                "or install the full redforge-attack (it's a core dep)."
            ) from e

        resolved_key, resolved_src = _resolve_key(api_key, api_key_env, api_key_source)
        if not resolved_key:
            env_hint = f" (set {api_key_env})" if api_key_env else ""
            raise RuntimeError(
                f"No API key found for provider {name!r}{env_hint}. "
                f"Pass --api-key or set the env var."
            )

        self.name = name
        self._client = OpenAI(
            api_key=resolved_key,
            base_url=base_url,
            default_headers=default_headers or None,
        )
        self._api_key_source = resolved_src
        self._api_key_prefix = (resolved_key[:12] + "...") if len(resolved_key) > 12 else "***"
        self._base_url = base_url
        self._parallel_supported = parallel_tool_calls_supported
        self._max_context = max_context

    @property
    def api_key_source(self) -> str:
        return self._api_key_source

    @property
    def api_key_prefix(self) -> str:
        return self._api_key_prefix

    @property
    def base_url(self) -> str:
        return self._base_url

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
        kwargs: dict = {
            "model": model,
            "messages": _messages_with_system(system, messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            if self._parallel_supported:
                kwargs["parallel_tool_calls"] = True

        resp = self._client.chat.completions.create(**kwargs)
        return _assistant_turn_from_openai(resp)

    def capabilities(self) -> dict:
        return {
            "parallel_tool_calls": self._parallel_supported,
            "native_tool_use": True,
            "max_context": self._max_context,
        }


# --- Key resolution ---------------------------------------------------------


def _resolve_key(
    explicit: str | None,
    env_var: str | None,
    source_hint: str | None,
) -> tuple[str | None, str]:
    """Resolve an API key: explicit > env_var > None.

    Never reads ambient credential files. For OpenAI-compat vendors the
    only valid sources are explicit injection (CLI / config) and the
    named environment variable the vendor publishes.
    """
    if explicit:
        return explicit, source_hint or "explicit"
    if env_var:
        v = os.environ.get(env_var)
        if v:
            return v, f"{env_var} env"
    return None, "not-found"
