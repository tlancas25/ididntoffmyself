"""Provider registry — maps `--provider <name>` to a factory.

Why this exists
---------------
Users say `--provider openrouter`, not "instantiate OpenAICompatProvider with
base_url=https://openrouter.ai/api/v1". This registry is the name → factory
mapping, with sensible per-vendor defaults (base URL, env var, parallel
tool-call support, context window, extra headers).

Three tiers:

  1. **Dedicated built-ins** — providers that use their own adapter because
     OpenAI-compat isn't a great fit (currently: Anthropic).

  2. **OpenAI-compat built-ins** — vendors for which we know the base URL
     and their official env var:
        openai, openrouter, gemini, moonshot, deepseek, xai, groq,
        together, cerebras, ollama, llamacpp.
     All use `OpenAICompatProvider` with sensible defaults.

  3. **User-defined** — redforge.toml can declare:
        [provider.mycorp]
        kind = "openai_compat"
        base_url = "https://llm.mycorp.internal/v1"
        api_key_env = "MYCORP_LLM_KEY"
     and `--provider mycorp` then wires it up.

Every factory ultimately returns `LLMProvider`. All API-key sourcing goes
through the provider's own TOS-safe resolver (explicit > env > none).
"""

from __future__ import annotations

from redforge_attack.providers.base import LLMProvider


# --- Built-in OpenAI-compat vendors ----------------------------------------
#
# Each entry here is the *default* configuration for a vendor. The user can
# override model, base_url, env var, or headers in their redforge.toml.

BUILTIN_OPENAI_COMPAT: dict[str, dict] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 128_000,
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "parallel_tool_calls_supported": True,  # model-dependent but OpenRouter passes it through
        "max_context": 200_000,
        "default_headers": {
            # OpenRouter recommends identifying your app for rate-limit + analytics.
            "HTTP-Referer": "https://github.com/redforge/redforge-attack",
            "X-Title": "redforge-attack",
        },
    },
    "gemini": {
        # Google ships an OpenAI-compat shim for Gemini.
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key_env": "GEMINI_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 1_000_000,
    },
    "moonshot": {
        "base_url": "https://api.moonshot.ai/v1",
        "api_key_env": "MOONSHOT_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 200_000,
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 128_000,
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "api_key_env": "XAI_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 256_000,
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 128_000,
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "api_key_env": "TOGETHER_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 128_000,
    },
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "api_key_env": "CEREBRAS_API_KEY",
        "parallel_tool_calls_supported": True,
        "max_context": 128_000,
    },
    "ollama": {
        # Local; OpenAI-compat mode on the default Ollama daemon.
        "base_url": "http://localhost:11434/v1",
        "api_key_env": "OLLAMA_API_KEY",  # Ollama accepts any value; dummy env.
        "parallel_tool_calls_supported": False,  # model-dependent; safe default.
        "max_context": 32_000,
    },
    "llamacpp": {
        # llama-server (llama.cpp HTTP server) in OpenAI-compat mode.
        "base_url": "http://localhost:8080/v1",
        "api_key_env": "LLAMACPP_API_KEY",
        "parallel_tool_calls_supported": False,  # via grammar; conservative.
        "max_context": 32_000,
    },
}


# --- Default per-role model choice -----------------------------------------
#
# Called when the user hasn't specified a model for the current role (recon |
# specialist | synthesizer) via CLI flag or redforge.toml. These are sane
# cost/quality picks per vendor; override any of them in your redforge.toml.

DEFAULT_MODELS: dict[str, dict[str, str]] = {
    "anthropic": {
        "recon":        "claude-haiku-4-5",
        "specialist":   "claude-haiku-4-5",
        "synthesizer":  "claude-sonnet-4-5",
    },
    "openai": {
        "recon":        "gpt-4o-mini",
        "specialist":   "gpt-4o-mini",
        "synthesizer":  "gpt-5",
    },
    "openrouter": {
        # OpenRouter accepts vendor-prefixed model ids. Pick reasonable defaults.
        "recon":        "anthropic/claude-haiku-4.5",
        "specialist":   "anthropic/claude-haiku-4.5",
        "synthesizer":  "anthropic/claude-sonnet-4.5",
    },
    "gemini": {
        "recon":        "gemini-2.5-flash",
        "specialist":   "gemini-2.5-flash",
        "synthesizer":  "gemini-2.5-pro",
    },
    "moonshot": {
        "recon":        "kimi-k2-latest",
        "specialist":   "kimi-k2-latest",
        "synthesizer":  "kimi-k2-latest",
    },
    "deepseek": {
        "recon":        "deepseek-chat",
        "specialist":   "deepseek-chat",
        "synthesizer":  "deepseek-reasoner",
    },
    "xai": {
        "recon":        "grok-4-mini",
        "specialist":   "grok-4-mini",
        "synthesizer":  "grok-4",
    },
    "groq": {
        "recon":        "llama-3.3-70b-versatile",
        "specialist":   "llama-3.3-70b-versatile",
        "synthesizer":  "llama-3.3-70b-versatile",
    },
    "together": {
        "recon":        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "specialist":   "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "synthesizer":  "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    },
    "cerebras": {
        "recon":        "llama-3.3-70b",
        "specialist":   "llama-3.3-70b",
        "synthesizer":  "llama-3.3-70b",
    },
    "ollama": {
        "recon":        "llama3.1:70b",
        "specialist":   "llama3.1:70b",
        "synthesizer":  "llama3.1:70b",
    },
    "llamacpp": {
        "recon":        "",  # Model loaded by llama-server; model id often blank.
        "specialist":   "",
        "synthesizer":  "",
    },
}


# --- Build a provider by name ----------------------------------------------


def build_provider(
    name: str,
    *,
    api_key: str | None = None,
    config_overrides: dict | None = None,
) -> LLMProvider:
    """Return an LLMProvider for `name`, applying any user TOML overrides.

    Resolution:
      1. Dedicated adapters (currently: anthropic).
      2. Built-in OpenAI-compat vendors (names in BUILTIN_OPENAI_COMPAT).
      3. User-defined providers (config_overrides[name] with kind="openai_compat").

    Raises ValueError for unknown names.
    """
    config_overrides = config_overrides or {}
    vendor_override = (config_overrides.get(name) or {})

    # 1. Anthropic — dedicated adapter
    if name == "anthropic":
        from redforge_attack.providers.anthropic import AnthropicProvider
        key_from_config = vendor_override.get("api_key")
        key_source = None
        if api_key:
            key_source = "CLI --api-key"
        elif key_from_config:
            api_key = key_from_config
            key_source = f"redforge.toml [provider.{name}]"
        return AnthropicProvider(api_key=api_key, api_key_source=key_source)

    # 2. Built-in OpenAI-compat vendor (possibly with per-user overrides)
    if name in BUILTIN_OPENAI_COMPAT:
        spec = {**BUILTIN_OPENAI_COMPAT[name], **vendor_override}
        return _build_openai_compat(name, spec, api_key)

    # 3. User-defined provider in redforge.toml
    if vendor_override.get("kind") == "openai_compat":
        spec = dict(vendor_override)
        if "base_url" not in spec:
            raise ValueError(f"user-defined provider {name!r} must specify base_url in redforge.toml")
        return _build_openai_compat(name, spec, api_key)

    known = ["anthropic"] + sorted(BUILTIN_OPENAI_COMPAT.keys())
    raise ValueError(
        f"unknown provider {name!r}. Known: {', '.join(known)}. "
        f"Or define a custom one in redforge.toml:\n"
        f"  [provider.{name}]\n"
        f"  kind = \"openai_compat\"\n"
        f"  base_url = \"https://...\"\n"
        f"  api_key_env = \"YOUR_ENV_VAR\""
    )


def _build_openai_compat(name: str, spec: dict, explicit_key: str | None) -> LLMProvider:
    from redforge_attack.providers.openai_compat import OpenAICompatProvider
    return OpenAICompatProvider(
        name=name,
        base_url=spec["base_url"],
        api_key=explicit_key or spec.get("api_key"),
        api_key_env=spec.get("api_key_env"),
        api_key_source=("CLI --api-key" if explicit_key else
                        (f"redforge.toml [provider.{name}].api_key" if spec.get("api_key") else None)),
        default_headers=spec.get("default_headers"),
        parallel_tool_calls_supported=bool(spec.get("parallel_tool_calls_supported", True)),
        max_context=int(spec.get("max_context", 128_000)),
    )


def default_model_for(provider: str, role: str) -> str:
    """Return the default model id for (provider, role). Role is one of
    'recon' | 'specialist' | 'synthesizer'. Empty string means the vendor
    loads the model out-of-band (llama-server, etc.).
    """
    return DEFAULT_MODELS.get(provider, {}).get(role, "")


def known_provider_names() -> list[str]:
    return sorted(["anthropic"] + list(BUILTIN_OPENAI_COMPAT.keys()))
