# Target folder schema

Each authorized attack trial runs against one target and lives in its own folder under `./targets/`. Findings, evidence, and the raw-bundle report are all local to that folder — the CLI performs analysis offline against the target's `intake/`; the only outbound network is the user's configured LLM provider (unless `--provider ollama` / `llamacpp` is used, in which case the run is fully air-gapped).

## Folder schema

```
targets/
  <target-slug>-<YYYYMMDDTHHMMSSZ>/
    target.yaml       # metadata — name, provenance (vibe|human), scope, intake form, authorization note
    intake/           # original materials the user handed over (source tree, URLs, container images, OpenAPI specs, prior red-team reports)
    agents/           # per-specialist-agent output — one subdir per agent
      <agent-id>/
        findings.json # structured findings per schema below
        notes.md      # free-form agent reasoning / dead ends / cross-lens consequences
    evidence/         # PoCs, request/response captures, screenshots, curl scripts
    report.md         # raw bundle — Fix-These-First, Main, Hardening Recommendations, chains, duplicate clusters
```

## Rules

1. **Local-only.** Nothing in a target folder ever leaves this workspace. No external uploads — not for rendering, not for diff, not for analysis. Use local tools.
2. **Every finding is a file** (workspace rule #3). The conversation transcript is not a record; these files are.
3. **One folder = one trial.** Re-running against the same target creates a new timestamped folder. Never overwrite a prior trial.
4. **Provenance recorded at intake.** `target.yaml` must record `provenance: vibe|human|mixed|unknown` before attacks begin. Stats questions come after trials and depend on this.
5. **Authorization note at intake.** `target.yaml` must record how the user authorized attack on this target and the declared scope. Nothing transitively reachable is in scope unless explicitly listed.
6. **Redact in summaries, preserve in raw.** If a PoC reveals a real secret, the raw evidence stays under `evidence/`, but `report.md` and all agent output must never name the value (workspace rule #2).

## target.yaml schema

```yaml
target_id: <slug>
timestamp: <ISO-8601 UTC>
provenance: vibe | human | mixed | unknown
code_source: <repo URL | local path | container digest | live endpoint>
scope:
  in:
    - <path/URL/endpoint>
  out:
    - <what's explicitly excluded>
authorization:
  granted_by: <user handle>
  granted_at: <ISO-8601 UTC>
  note: <free text — how authorization was expressed>
surfaces_declared:
  - web
  - mcp
  - agentic-ai
  - ci-cd
  - supply-chain
  - ...
notes: <free text>
```

## Per-agent findings (required structure)

Each specialist agent writes `agents/<agent-id>/findings.json` as a JSON array. Each finding object:

```json
{
  "id": "<agent-id>-<short-slug>",
  "title": "<one-line>",
  "surface": "auth | injection | idor | ssrf | xss | file-handling | business-logic | api | prompt-injection | mcp-tool-abuse | agent-autonomy | secrets | ci-cd | container | dependency",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "exploitable": true,
  "exploitable_now": true,
  "requires_future_change": null,
  "reproduction_status": "verified | code-path-traced | theoretical",
  "root_cause_confidence": "high | medium | low",
  "confidence": "high | medium | low",
  "target_refs": ["<file:line>", "<URL>", "<endpoint>"],
  "description": "<full technical description>",
  "impact": "<what an attacker gains>",
  "reproduction": "<steps / curl — reference evidence/ paths for PoCs>",
  "evidence_paths": ["evidence/<file>"],
  "remediation": "<fix guidance>",
  "cwe": ["CWE-xxx"],
  "attack_chain": ["<finding-id>", "..."],
  "novel_pattern": true,
  "discovered_at": "<ISO-8601 UTC>"
}
```

Plus `agents/<agent-id>/notes.md` — free-form reasoning, dead-ends, hypotheses, lens-specific consequences when deduping another agent's finding.

## Severity + NOVEL calibration (binding — post-trial-#1 review 2026-04-20)

Summarized here; full binding brief in bundled `specialists.md`.

- **§1 CRITICAL reserve.** Only when ALL THREE hold: (1) exploitable today as-written, (2) unauth/single-session, (3) direct impact (exfil, code-exec, priv-esc, autonomous third-party action).
- **§2 Dedupe across specialists.** One primary finding per root cause. Others fold into primary's `notes.md` as lens-specific consequences.
- **§3 `novel_pattern: true`** only for (1) generalizable detector-rule-worthy patterns OR (2) multi-step chains SAST cannot catch. Standard bugs are not novel.
- **§4 Required new fields** `exploitable_now`, `requires_future_change`, `reproduction_status`, `root_cause_confidence` (see schema above).
- **§5 No speculative chaining.** Score severity on weakest actually-present link.
- **§6** `exploitable_now: false` → Hardening Recommendations, not main list.
- **§7** Label reproduction honestly (default `code-path-traced`).

## `report.md` structure (written by the synthesizer — `rfatk report`)

1. **Header** — provenance, counts (main / hardening / chains / dup-clusters / fix-these-first-candidates).
2. **Fix These First (candidates)** — CRITICAL + `exploitable_now: true`. Synthesizer agent curates the final 5-10 in `agents/synthesizer/notes.md` using the full §1 test.
3. **Agents run** — per-agent tally.
4. **Findings (main)** — sorted severity → exploitable-now → confidence. Only `exploitable_now != false`.
5. **Hardening Recommendations** — `exploitable_now: false` findings. Posture improvements, not exploits. Still important, not in fix-now list.
6. **Cross-agent attack chains** — multi-agent chains via `attack_chain` field. Links point to post-dedup primary IDs.
7. **Suspected duplicate clusters** — surface-scoped token-overlap (≥3 shared significant tokens). Advisory; synthesizer resolves.

## Novel-pattern tagging

When a specialist identifies a generalizable detector-rule-worthy pattern (or a multi-step chain SAST cannot catch), it flags `novel_pattern: true` on the finding per §3. The synthesizer surfaces these in `report.md` for downstream prioritization. In the `rfatk` CLI this is a reporting tag only — no automatic queue mutation. Consumers can filter `findings.json` across trials to drive their own detector-rule authoring pipeline.
