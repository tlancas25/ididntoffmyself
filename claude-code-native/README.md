# `claude-code-native/` — REDFORGE running inside Claude Code

> © 2026 BlaFrost Softwares Corp. Internal team use. See root `LICENSE`.

This is the REDFORGE methodology package intended to be **used from within Claude Code**. It gives Claude Code (and any LLM operating in a Claude-Code-like harness with native file/shell/Agent tools) the full binding briefs, schema, and methodology to act as a senior multi-specialist red team.

This is what BlaFrost engineers use internally with their Claude Max seats — **no API key cost per trial**, max Claude capacity, native Claude Code tools (Agent, Bash, Read, Grep, Glob, Write).

The standalone Python CLI distribution (BYO API key, 12 providers, PyInstaller / pipx installable) lives in the sibling `rfatk-cli/` directory.

---

## What's in this folder

```
claude-code-native/
├── README.md                       ← you are here
├── agent-roster.md                 ← all 25 specialists + metadata
├── host-scan-scoping.md            ← host-trial approvals + allowlist design + alert-triage protocol
├── prompts/                        ← THE INTELLECTUAL PROPERTY
│   ├── recon.md                    ← code-trial recon brief
│   ├── synthesizer.md              ← synthesizer (code + host) brief
│   ├── specialists.md              ← 16 code specialists' binding briefs
│   ├── host_recon.md               ← host-trial recon brief
│   ├── host_specialists.md         ← 9 host specialists' binding briefs
│   ├── targets_schema.md           ← target.yaml + findings.json contract
│   └── roster.yaml                 ← machine-readable roster for selection logic
└── workspace-template/
    ├── README.md                   ← workspace rules (no-git, no-secrets, etc.)
    ├── MEMORY.md                   ← schema for session handoff log
    └── targets/README.md           ← target-folder schema (intake/agents/evidence/report.md)
```

---

## How to use this

1. **Copy `workspace-template/` into a new scratch folder** somewhere convenient. This becomes your per-project dev workspace. The template's README locks in the safety rules (no git in the workspace, no secrets in summaries, everything is a file, one target = one folder).

2. **Launch Claude Code in that workspace.** Claude Code reads MEMORY.md and the workspace README on first session-start.

3. **Point Claude at a target.** Either a codebase (code trial) or the running machine (host trial).

4. **Claude scaffolds the target folder:**
   ```
   targets/<slug>-<YYYYMMDDTHHMMSSZ>/
     target.yaml      # provenance, scope, authorization note
     intake/          # source tree / URLs / prior reports (code trial only)
     agents/          # populated by the trial
     evidence/        # PoCs + baseline snapshots
     report.md        # the deliverable
   ```

5. **Claude runs the trial.** The flow is:

   | Phase | What happens |
   |---|---|
   | Recon | Claude acts as the `recon` agent itself. Reads prompts/recon.md or prompts/host_recon.md. Produces `agents/recon/findings.json` + `notes.md`. |
   | Specialists | Claude spawns up to 6 specialists in PARALLEL using the native `Agent` tool. Each subagent gets its binding brief from `prompts/specialists.md` or `prompts/host_specialists.md`. Concurrency is capped by operator preference. |
   | Synthesizer | Claude aggregates findings, detects chains, computes duplicate clusters, emits `report.md`. Then runs itself as the synthesizer agent to add the judgment layer in `agents/synthesizer/notes.md`. |
   | Alert-triage (host only) | Claude runs `alert-triage` last with a baseline/post-scan diff and classification. |

6. **Read the deliverable.** Everything is in the target folder. The `Hardening Plan (prioritized)` section at the top of report.md is the work queue.

---

## Why this distribution exists (separately from rfatk-cli)

Two reasons:

1. **Zero incremental API cost for internal use.** BlaFrost engineers are on Claude Max seats. Running the trial inside Claude Code uses those seats — no per-trial token bill. Great for daily work.

2. **Max Claude capacity.** Claude Code sessions get the best available Claude model, native tool use, and (for the foreseeable future) first-look access to new capabilities (Opus 4.7 at time of writing, future 1M-context, etc.). Running inside Claude Code means the methodology always has the sharpest model driving it.

The flip side is that this distribution is **not runnable outside Claude Code** — it's not a standalone binary. For external customers, the AI4.io conference demo, or CI integrations, use `rfatk-cli/` with its BYO-key provider layer.

---

## Honor-system sandbox

Unlike `rfatk-cli/`, which hard-enforces the path sandbox and command allowlist in Python, the Claude-Code-native distribution is **honor-system**:

- The operator and Claude both agree to respect the excluded folders (`Documents`, `Downloads`, `Pictures`, `Videos`) and the read-only command allowlist.
- Claude Code's own permission model is the secondary guard — users see every Bash command and approve / deny it.
- The methodology briefs in `prompts/` restate the rules so every specialist agent carries them.

This is fine for internal use where the operator is the lead developer. For external distribution, use `rfatk-cli/` which enforces everything in code.

---

## Current roster

**Code trials (16 specialists):**
- Web: `auth-session`, `authz-idor`, `injection`, `ssrf-network`, `xss-client`, `file-handling`, `business-logic`, `api-surface`
- AI / agentic: `prompt-injection`, `mcp-tool-abuse`, `agent-autonomy`, `llm-output-trust`
- Infra / supply: `secrets-hunt`, `ci-cd`, `container-infra`, `dependency-supply`

**Host trials (9 specialists):**
- `services-startup`, `network-listening`, `network-posture`, `alert-triage`
- `windows-config-audit`, `firewall-audit`, `local-subnet-sweep`, `credentials-exposure`, `persistence-hunt`

**Auxiliary (both trial types):**
- `baseline-compare` — diff against a prior pentest/scan report if supplied
- `recon`, `synthesizer` — meta

See `agent-roster.md` for the full metadata (surface, covers, role) per specialist.

---

## Methodology summary (binding rules)

See `/docs/methodology.md` at the repo root for the full treatment. Short version:

- **§1 CRITICAL reserve** — exploitable today + unauth/single-session + direct impact. Miss any → HIGH.
- **§2 Dedup** — one primary per root cause; cross-link via `attack_chain`, not duplicate entries.
- **§3 NOVEL** — only for generalizable-detector-worthy patterns or SAST-uncatchable chains.
- **§4 Required fields** — `exploitable_now`, `requires_future_change`, `reproduction_status`, `root_cause_confidence`.
- **§5 No speculative chaining** — severity = weakest actually-present link.
- **§6 Hardening separate** — `exploitable_now: false` routes to its own section.
- **Hardening plan required on host findings** — `immediate`, `configuration`, `monitoring`, `compensating_controls`, `estimated_effort`.

---

## When to update the prompts

Any time a trial surfaces a **novel pattern** worth adding to the detector library, the relevant specialist brief in `prompts/` gets a new bullet. Any time a trial shows a specialist under/over-reporting, the calibration section gets tightened.

Prompts in this folder are version-controlled in git. The commit message convention:

```
prompts: <agent-id> — <what changed> (from trial <slug>)
```

E.g. `prompts: auth-session — add env-presence-as-auth pattern (from trial keyvectra-20260420)`.
