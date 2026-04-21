# redforge-attack (`rfatk`) — CLI DEMO VERSION

**Multi-agent AI red-team CLI** — the standalone, BYO-API-key, packaged distribution of REDFORGE.

Spawns parallel LLM-backed specialist agents (recon + up to 16 code specialists + up to 9 host specialists + synthesizer + alert-triage) against a target codebase OR the running machine, producing a severity-calibrated findings bundle with a prioritized hardening plan.

> **Status: v0.1.0-alpha.** M7b shipped; 144+ tests passing. M8 (first live self-scan trial) in flight at time of writing.
>
> © 2026 BlaFrost Softwares Corp. Proprietary. Not for public use. See root `../LICENSE`.
> Lead developer: Terrell A. Lancaster
> Powered by: Claude Code running Opus 4.7 (Anthropic PBC)

The sibling `../claude-code-native/` distribution runs the same methodology INSIDE Claude Code using operator's Claude Max seat (no per-trial API cost, max Claude capacity). This `rfatk-cli/` distribution is the packaged-for-external-use version.

---

## Install

From the repo root (`ididntoffmyself/`):

```bash
pipx install -e ./rfatk-cli
rfatk --help
```

Or with a dev venv:

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -e ./rfatk-cli
.venv\Scripts\rfatk.exe --help
```

Python 3.10+ required.

---

## Bring your own API key

`rfatk` requires **you** to provide an API key for whichever LLM backend you choose. The tool **does not** and **will not** reuse any Claude Code, Claude.ai, or Claude Max session credentials — those are scoped to Anthropic's own products, and piggybacking on them from third-party tooling is a TOS gray area.

Get an Anthropic API key at <https://console.anthropic.com/settings/keys> and export it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
rfatk doctor
```

Pick any supported vendor — the CLI speaks OpenAI's Chat Completions wire format to all non-Anthropic backends, so one adapter covers OpenAI, OpenRouter, Gemini, Moonshot Kimi, DeepSeek, xAI, Groq, Together, Cerebras, Ollama (local), and llama-server (local). Each vendor has a default env var:

| Provider       | `--provider` name | API key env var       | Get key at                                      |
|----------------|-------------------|-----------------------|-------------------------------------------------|
| Anthropic      | `anthropic`       | `ANTHROPIC_API_KEY`   | <https://console.anthropic.com/settings/keys>   |
| OpenAI         | `openai`          | `OPENAI_API_KEY`      | <https://platform.openai.com/api-keys>          |
| OpenRouter     | `openrouter`      | `OPENROUTER_API_KEY`  | <https://openrouter.ai/keys>                    |
| Google Gemini  | `gemini`          | `GEMINI_API_KEY`      | <https://aistudio.google.com/apikey>            |
| Moonshot Kimi  | `moonshot`        | `MOONSHOT_API_KEY`    | <https://platform.moonshot.ai/console/api-keys> |
| DeepSeek       | `deepseek`        | `DEEPSEEK_API_KEY`    | <https://platform.deepseek.com/api_keys>        |
| xAI Grok       | `xai`             | `XAI_API_KEY`         | <https://console.x.ai/>                         |
| Groq           | `groq`            | `GROQ_API_KEY`        | <https://console.groq.com/keys>                 |
| Together AI    | `together`        | `TOGETHER_API_KEY`    | <https://api.together.ai/settings/api-keys>     |
| Cerebras       | `cerebras`        | `CEREBRAS_API_KEY`    | <https://cloud.cerebras.ai/platform/apikeys>    |
| Ollama (local) | `ollama`          | `OLLAMA_API_KEY`*     | Run `ollama serve` — `*` env var value is ignored (any string works) |
| llama.cpp      | `llamacpp`        | `LLAMACPP_API_KEY`*   | Run `llama-server`; `*` same — dummy is fine     |

You can also register a **custom** OpenAI-compatible endpoint in `redforge.toml` (see below) and invoke it as `--provider <your-name>`.

`rfatk doctor` (coming in M5) will confirm which source the key came from and assert that `~/.claude/` is **not** being read.

---

## Quickstart

```bash
# 1. Scaffold a target trial folder
rfatk init my-app --provenance vibe --source ./path/to/code \
       --scope-in src/ --surfaces web api prompt-injection

# 2. Run the trial (spawns recon → 16 specialists → synthesizer)
rfatk attack targets/my-app-20260420T....

# 3. Read the raw bundle
cat targets/my-app-.../report.md
```

The trial folder contains: target metadata, per-agent `findings.json` + `notes.md`, PoC `evidence/`, and a unified `report.md` with `Fix These First` + main findings + Hardening Recommendations + cross-agent attack chains + suspected duplicate clusters.

---

## Authorized use only

`rfatk` is a red-team offensive tool. You must own the target or have written authorization to test it. The `target.yaml` captures an explicit authorization note at intake — fill it honestly.

See Anthropic's [Usage Policies](https://www.anthropic.com/legal/aup) and `docs/TOS.md` in this repo.

---

## Providers

Two adapters cover every supported vendor:

- **`anthropic`** — dedicated adapter using the native Messages API (best fit for Claude's tool-use semantics).
- **`openai_compat`** — one adapter, many vendors, configured via `base_url` + `api_key_env`. Covers OpenAI, OpenRouter, Gemini, Moonshot, DeepSeek, xAI, Groq, Together, Cerebras, and any local OpenAI-compat server (Ollama `/v1`, llama-server, LM Studio, vLLM).

| Provider      | Tool-use      | Parallel calls | Default context | Cost profile       |
|---------------|--------------|----------------|-----------------|--------------------|
| Anthropic     | native       | yes            | 200k            | Premium            |
| OpenAI        | native       | yes            | 128k            | Premium            |
| OpenRouter    | passthrough  | model-dependent| up to 200k      | Usage-based        |
| Gemini        | native       | yes            | 1M              | Low-mid            |
| Moonshot Kimi | native       | yes            | 200k            | Mid                |
| DeepSeek      | native       | yes            | 128k            | Low                |
| xAI Grok      | native       | yes            | 256k            | Premium            |
| Groq          | native       | yes            | 128k            | Low (fast)         |
| Together AI   | native       | yes            | 128k            | Low                |
| Cerebras      | native       | yes            | 128k            | Low (fastest)      |
| Ollama        | model-dep.   | model-dep.     | model-dep.      | Free (local)       |
| llama.cpp     | grammar      | no             | model-dep.      | Free (air-gapped)  |

For the AI4.io demo I recommend **Anthropic** (best tool-use quality) with **Haiku 4.5** for specialists and **Sonnet 4.5** for the synthesizer. Air-gap demo: **Ollama + `llama3.1:70b`**.

### Configuring vendors via `redforge.toml`

Drop a `redforge.toml` next to your working directory or at `~/.redforge/config.toml`. The CLI merges project > user > built-in defaults.

```toml
[provider]
default = "anthropic"                 # which vendor to use unless --provider overrides

[provider.anthropic]
# api_key reads ANTHROPIC_API_KEY env by default; pass api_key = "..." here to hard-pin.
model_recon       = "claude-haiku-4-5"
model_specialist  = "claude-haiku-4-5"
model_synthesizer = "claude-sonnet-4-5"

[provider.openrouter]
# Already a known built-in; override models to any OpenRouter-supported id.
model_recon       = "anthropic/claude-haiku-4.5"
model_specialist  = "moonshot/kimi-k2"
model_synthesizer = "anthropic/claude-sonnet-4.5"

[provider.gemini]
model_recon       = "gemini-2.5-flash"
model_specialist  = "gemini-2.5-flash"
model_synthesizer = "gemini-2.5-pro"

[provider.moonshot]
model_recon       = "kimi-k2-latest"
model_specialist  = "kimi-k2-latest"
model_synthesizer = "kimi-k2-latest"

# Custom / self-hosted vendor — any OpenAI-compat endpoint works.
[provider.mycorp]
kind        = "openai_compat"
base_url    = "https://llm.internal.mycorp/v1"
api_key_env = "MYCORP_LLM_KEY"
model_recon       = "internal-llm-70b"
model_specialist  = "internal-llm-70b"
model_synthesizer = "internal-llm-70b"

[run]
max_parallel_specialists = 6     # default is 6; raise with care — rate limits bite
max_turns_per_agent      = 40
max_tokens_budget        = 200000

[sandbox]
allow_shell = false              # opt-in via --allow-shell. Only on disposable VMs.
```

Invocation is the same regardless of vendor:

```bash
rfatk attack targets/my-app-... --provider anthropic
rfatk attack targets/my-app-... --provider openrouter --model moonshot/kimi-k2
rfatk attack targets/my-app-... --provider gemini
rfatk attack targets/my-app-... --provider mycorp     # the custom one above
```

---

## License

Proprietary. © 2026 BlaFrost Softwares Corp. All rights reserved. See root `../LICENSE` for full terms.

---

## Acknowledgements

`rfatk` is the property of **BlaFrost Softwares Corp**. Lead developer: **Terrell A. Lancaster**. Powered by **Claude Code running Opus 4.7** (Anthropic PBC).

Not affiliated with, endorsed by, or owned by Anthropic. `rfatk` is a third-party tool that calls LLM provider APIs when the user provides their own key. The tool explicitly refuses to read Claude Code OAuth credentials (`~/.claude/` and equivalents) to stay clear of Anthropic's consumer-product TOS.

All provider marks (Anthropic / OpenAI / Google Gemini / Moonshot / xAI / DeepSeek / Groq / Together / Cerebras / Ollama / llama.cpp) are property of their respective owners and are named here only to document supported backends.
