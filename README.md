# REDFORGE — Agentic AI Red-Team Platform

> **Proprietary. Not for public use.**
> © 2026 BlaFrost Softwares Corp. All rights reserved.
> Lead developer: Terrell A. Lancaster
> Powered by: Claude Code running Opus 4.7 (Anthropic)

---

## What this is

REDFORGE is an **AI-agent-driven offensive-security platform** built to find the attacks humans and traditional tools miss — **before** they ship, and on systems already in production.

We don't run a scanner. We run a **team of specialist attacker-agents**, each briefed on one surface (auth, injection, LLM misuse, credential exposure, persistence, network posture, etc.), all operating in parallel under a severity-calibrated methodology, coordinated by a synthesizer that produces an actionable, prioritized deliverable.

Two things make this different from every other tool in the field:

1. **Agentic AI, not static software.** A SAST scanner finds what its rules match. Our agents *read the code, reason about it, test hypotheses, chain primitives together, and adapt when an attack surface doesn't behave as expected.* They are continuously learning — every trial improves the prompts, the roster, and the calibration for the next trial.

2. **Attack-before-attackers.** The platform can be pointed at source code, live endpoints, container images, MCP servers, agentic AI workflows, or *the running machine itself.* The machine-scan mode (see `rfatk-cli/docs/self-scan-quickstart.md`) runs a 9-specialist audit against a host's live configuration, network posture, and persistence surfaces — producing a prioritized hardening plan mapped to concrete commands.

The goal: **catch zero-day-class exploits before adversaries do**, by combining the pattern-recognition strength of large language models with a rigorous multi-specialist methodology that refuses to declare "done" until every lens has been applied.

---

## How it works (the short version)

1. **Target intake** — the target is handed over in whatever form is available (source tree, live URL, MCP server, container digest, or the running machine). Intake captures provenance, scope, and an explicit authorization note.

2. **Recon** — the first agent fingerprints the target: framework/stack for code, OS/services/firewall for hosts. Its output drives which specialists run next.

3. **Parallel specialist fan-out** — up to 16 specialists (code trials) or 9 specialists (host trials) run concurrently, each with its own tool-use loop. Every specialist has a binding calibration brief: §1 CRITICAL reserve (three-criterion gate), §3 NOVEL tightening, §4 new schema fields (`exploitable_now`, `requires_future_change`, `reproduction_status`, `root_cause_confidence`).

4. **Synthesizer** — aggregates per-agent findings, detects cross-agent attack chains, flags suspected duplicate clusters (fuzzy token overlap), and partitions findings into main / hardening / Fix-These-First sections.

5. **Alert triage (host mode)** — captures Defender/EDR baseline before the scan, diffs after, and classifies every new alert as scan-induced noise vs scan-exposed pre-existing issue vs uncertain.

6. **Hardening plan** — every host finding carries a structured `hardening_plan` (immediate command + durable config + monitoring + compensating controls + estimated effort). The synthesizer emits a prioritized "Hardening Plan (prioritized)" section at the top of the report grouped by effort bucket.

---

## Why agentic AI digs deeper than any static tool

- **Static analyzers (SAST):** match syntactic patterns. They miss the SSRF that requires three primitives to chain. They miss the "env-var presence used as auth enable/disable" idiom because the symbol names differ across frameworks. They miss LLM-output-trust bugs entirely because their AST doesn't model prompt semantics.

- **DAST / fuzzers:** explore state space blindly. They miss the business-logic race condition that requires knowing the workflow. They miss the prompt-injection chain that pivots from user input through a RAG retrieval to a downstream tool call.

- **Our agents:** read the code, read the recon map, form a hypothesis, execute a concrete tool call to test it, and iterate. They *know what they're looking for at a semantic level.* When one agent finds a cron auth bypass and another agent finds a tenant-hint header honored as authoritative, the synthesizer cross-links them into an attack chain that neither tool alone would surface.

- **They learn across trials.** Novel patterns one specialist discovers feed forward into detector rules that ship with the next version. This is how we outpace traditional tooling — the platform's capability compounds.

See `docs/agentic-advantage.md` for a fuller treatment with concrete examples from the first trial (CRITICAL findings + 22 cross-agent chains against a real Next.js monorepo).

---

## Repository layout

This monorepo holds **two distributions** of REDFORGE — separated because they'll both feed additional security tools BlaFrost builds on top of this foundation.

```
ididntoffmyself/
├── README.md                       ← you are here
├── LICENSE                         ← proprietary, BlaFrost Softwares Corp
├── docs/
│   ├── vision.md                   ← preventative cyber pivot + product strategy
│   ├── methodology.md              ← severity calibration, dedup rules, roster design
│   └── agentic-advantage.md        ← why multi-agent > static / DAST
│
├── claude-code-native/             ← DEV VERSION: runs INSIDE Claude Code
│   │                                  (uses Claude Code's native tools +
│   │                                  operator's Claude subscription session)
│   ├── README.md                   ← how to use this in a Claude Code session
│   ├── agent-roster.md             ← the 16 code + 9 host specialists + metadata
│   ├── host-scan-scoping.md        ← host-trial approvals + allowlist design + alert-triage protocol
│   ├── prompts/                    ← the binding agent briefs (THIS IS THE IP)
│   │   ├── recon.md
│   │   ├── synthesizer.md
│   │   ├── specialists.md          ← 16 code-trial specialists
│   │   ├── host_recon.md
│   │   ├── host_specialists.md     ← 9 host-trial specialists
│   │   ├── targets_schema.md       ← findings.json + target.yaml contract
│   │   └── roster.yaml             ← machine-readable roster for selection logic
│   └── workspace-template/         ← drop-in template for a new trial workspace
│       ├── README.md               ← workspace rules (no-git, no-secrets, etc.)
│       ├── MEMORY.md               ← schema for session handoff log
│       └── targets/README.md       ← target folder schema
│
└── rfatk-cli/                      ← CLI DEMO VERSION: standalone Python package
    │                                  (uses any LLM provider via BYO API key —
    │                                  Anthropic, OpenAI, OpenRouter, Gemini,
    │                                  Moonshot, DeepSeek, xAI, Groq, Together,
    │                                  Cerebras, Ollama, llama.cpp)
    ├── README.md
    ├── pyproject.toml
    ├── src/redforge_attack/        ← full Python source (sandbox + providers + agent loop + orchestrator)
    ├── tests/                      ← 144+ tests (sandbox containment, provider conversion, orchestrator parallelism)
    └── docs/
        └── self-scan-quickstart.md ← end-to-end M8 trial invocation
```

### Which distribution do I use?

| Scenario | Use |
|---|---|
| Internal BlaFrost engineer with Claude Max seat, in Claude Code | `claude-code-native/` — zero incremental cost, max Claude capacity |
| External demo, conference, client trial, CI integration | `rfatk-cli/` — BYO API key, any provider |
| Building ANOTHER security tool on top of the methodology | Both directories' prompts are reusable; lift the ones you need |

---

## Current capability matrix

| Capability                                   | claude-code-native | rfatk-cli |
|----------------------------------------------|--------------------|-----------|
| Code red-team (web app / MCP / agentic AI)   | ✓                  | ✓         |
| Host red-team (Windows machine self-scan)    | ✓                  | ✓         |
| LAN / local-subnet sweep                     | ✓                  | ✓         |
| Hardening plan output                        | ✓                  | ✓         |
| Alert-triage (Defender / EDR noise classify) | ✓                  | ✓         |
| Multi-provider (Claude / GPT / Gemini / ...) | n/a — uses Claude directly | ✓ (12 providers) |
| Air-gap mode (Ollama / llama.cpp)            | no                 | ✓         |
| Sandbox-enforced tool allowlist              | honor-system       | code-enforced |
| Parallel orchestration                       | Agent tool         | ThreadPool |

Both distributions implement the same methodology and produce the same deliverable (`report.md` with Fix-These-First + Hardening Plan + main findings + chains + duplicate clusters).

---

## Proven trials

- **Trial #1 — keyvectra Next.js monorepo (code scan).** 4 sibling projects, 203 route files, ~50k LOC. Output: 147 findings (after calibration update: ~90-110 distinct), 22 cross-agent chains, 13 CRITICAL → refined to 6-8 after §1 calibration was tightened. Headline findings: NEXTJS-004 env-gated fail-open auth (CRITICAL, confirmed on two sibling CRMs), cross-tenant slug-header spoof, cron-auth length-comparison bypass, Meta-publishing agent no-auth.

- **Trial #2 — self-scan of the lead developer's Windows 11 laptop (host scan).** In flight at the time this README was written. Full admin elevation + local-subnet sweep + alert-triage active. Results + scrubbed Defender export will be posted separately.

---

## Zero-day catch philosophy

We will not catch every zero-day. Nothing will. What we CAN do:

1. **Reduce the class of zero-day-adjacent bugs** that ship to production by running a competent AI red-team before launch.
2. **Catch the chains** — our unique strength. Most "zero-day" disclosures are actually the chaining of two or three known primitives that no single static tool ever cross-referenced. Multi-specialist + cross-agent-chain detection is explicitly designed for this.
3. **Learn continuously.** Every confirmed novel pattern upgrades the roster. The platform's capability-over-time curve is the product's moat.

---

## Legal + use posture

- **Proprietary.** This code and these prompts are intellectual property of BlaFrost Softwares Corp. They are not licensed for public use, redistribution, or commercial use by any party other than BlaFrost.
- **Ownership:** Terrell A. Lancaster, lead developer.
- **Powered by:** Claude Code, running Opus 4.7, provided by Anthropic PBC. This project is NOT affiliated with, endorsed by, or owned by Anthropic. All API-key sourcing in `rfatk-cli` is bring-your-own; the tool explicitly refuses to read Claude Code OAuth artifacts (TOS compliance).
- **Authorized use only.** Every trial requires an explicit authorization note in `target.yaml`. Running REDFORGE against assets you do not own or have written permission to test is out-of-scope of this project's intended use.
- **Model credits:** Claude (Anthropic), OpenAI GPT, Google Gemini, Moonshot Kimi, xAI Grok, DeepSeek, Groq, Together, Cerebras — all vendor marks are property of their respective owners and are named here only to document provider support.

---

## Status

| Milestone | Status |
|---|---|
| M1 — CLI skeleton + core tools ported | ✓ shipped |
| M2 — Provider layer + sandbox + agent loop + 62 tests | ✓ shipped |
| M3 — Orchestrator (parallel specialists + partial-failure) | ✓ shipped |
| M7a — Host sandbox + 4 host specialists + alert-triage | ✓ shipped |
| M7b — Remaining 5 host specialists + 144 tests total | ✓ shipped |
| M8 — First live self-scan trial | In flight |
| M9 — Scrubbed findings + Defender export published here | Pending trial complete |
| Polish — `--dry-run`, `--replay`, `rfatk doctor`, llama.cpp GBNF grammar, PyPI packaging | Backlog |

---

## For the BlaFrost team reading this first

- Start at `docs/vision.md` for the strategic frame.
- Then `docs/methodology.md` for how the platform actually works end-to-end.
- Then `docs/agentic-advantage.md` for the "why this > SAST" story you'll repeat to investors and customers.
- Then decide: do you want to use `claude-code-native/` (fast, internal, Claude Max seats) or `rfatk-cli/` (packaged, BYO-key, distributable). Each has its own README with operational instructions.
- Binding rules: `claude-code-native/host-scan-scoping.md` § Alert-triage protocol. Respect the off-limits folders at every layer — even if you're the operator.

If you're standing up a new trial and don't know what to do, the quickstart is `rfatk-cli/docs/self-scan-quickstart.md`. For code-scan trials, create a target folder via `rfatk init <name> --target-type code --provenance ...`.
