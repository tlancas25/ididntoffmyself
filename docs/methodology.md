# Methodology — how REDFORGE actually works

> © 2026 BlaFrost Softwares Corp. Internal reference.

This document is the single source of truth for the REDFORGE methodology — the rules every specialist agent is bound by, the severity calibration, the dedup protocol, the `hardening_plan` schema, and the expected output shape. Both distributions (`claude-code-native/` and `rfatk-cli/`) enforce these rules; the binding prompts live at `claude-code-native/prompts/`.

## Core loop

```
  TARGET INTAKE
      │
      │   target.yaml with provenance, scope, authorization
      ▼
  RECON (sequential, 5–15 min)
      │
      │   Machine / codebase fingerprint → surfaces present
      │   Phase-2 specialist recommendations
      ▼
  PARALLEL SPECIALISTS (concurrent, ~20–40 min)
      │
      │   Up to N specialists run in parallel (default cap = 6).
      │   Each with a binding brief, its own tool-use loop, and its
      │   own findings.json + notes.md output.
      │
      │   Specialists READ EACH OTHER'S findings.json as they write —
      │   so duplicates are referenced, not re-emitted (§2 dedupe).
      ▼
  SYNTHESIZER (mechanical + agentic)
      │
      │   Mechanical: partition main vs hardening, detect cross-agent
      │              chains, compute fuzzy dedup clusters, emit report.md.
      │   Agentic:    apply §1 three-criterion test to curate Fix-These-First,
      │              resolve dedup clusters, flag over/under-reporting,
      │              propose improvements for next trial.
      │
      │   Output: report.md + agents/synthesizer/notes.md
      ▼
  ALERT-TRIAGE (host mode only, runs last)
      │
      │   Diff baseline vs post-scan: Defender detections, Security event
      │   log, Sysmon, PowerShell-Operational. Classify each new alert as
      │   scan-noise / scan-exposed-real / concurrent-benign / uncertain.
      ▼
  DELIVERABLE
      │
      │   report.md with Fix-These-First + Hardening Plan + main findings
      │   + cross-agent chains + duplicate clusters + alert-triage summary.
```

Two trial types share this loop:

- **Code trial** (`target_type: code`) — target is source on disk under `intake/`.
  Roster: 16 specialists (auth-session, authz-idor, injection, ssrf-network, xss-client, file-handling, business-logic, api-surface, prompt-injection, mcp-tool-abuse, agent-autonomy, llm-output-trust, secrets-hunt, ci-cd, container-infra, dependency-supply).

- **Host trial** (`target_type: host`) — target is the running machine.
  Roster: 9 specialists (services-startup, network-listening, network-posture, alert-triage, windows-config-audit, firewall-audit, local-subnet-sweep, credentials-exposure, persistence-hunt).

## Severity calibration (BINDING on every finding)

These rules were written after trial #1 produced 13 CRITICAL / 147 findings against keyvectra — impressive volume but poor triage signal. The new rules produce 6–8 CRITICAL / ~90–110 distinct findings for comparable codebases. Signal over volume.

### §1 — CRITICAL reserve (three-criterion gate)

Assign `severity: "CRITICAL"` ONLY when ALL THREE hold:

1. **Exploitable TODAY** with the code / system as written — not "if a future fetch sink is added," not "if env var Y is unset."

2. **Unauth or single-session attacker** — no phishing chain, no insider assumption, no pre-acquired OAuth tokens.
   (For host findings: "logged-in standard user escalating to admin" satisfies #2.)

3. **Direct impact** — data exfiltration, code execution, privilege escalation, or autonomous action against third-party systems (publish / email / pay / exfil credentials / persist across reboot).

Missing any single criterion → HIGH at best. When in doubt, HIGH.

### §2 — Dedupe across specialists

Same root-cause defect = ONE primary finding. If another specialist has already written up a bug you were going to report, reference their id in `attack_chain` and add YOUR lens' impact to your `notes.md`. Do not emit a duplicate.

The cross-agent chains section and the duplicate-cluster advisory in report.md surface the multi-lens view.

### §3 — `novel_pattern: true` tightening

Mark NOVEL ONLY when:

1. **Generalizable pattern** worth becoming a detector rule (env-presence-as-auth, caller-hint-as-authoritative-tenant, plaintext→`<br>`-shim→HTML, cron-auth length-comparison bypass), OR
2. **Multi-step chain** single-pass SAST cannot catch.

Standard bugs (missing .dockerignore, hardcoded API key, cookie-not-HttpOnly, unpinned base image, build-arg literal) are NOT novel — they're textbook.

### §4 — Required schema fields

Every finding carries:

- `exploitable_now: true|false` — today, as-written.
- `requires_future_change: "<one-line>" | null` — what unlocks the exploit if `exploitable_now: false`.
- `reproduction_status: "verified" | "code-path-traced" | "theoretical"` — default code-path-traced for static review.
- `root_cause_confidence: "high" | "medium" | "low"`.

### §5 — No speculative chain-primitive inflation

When describing chained impact, list the gates between current state and full exploitation. Score severity on the weakest ACTUALLY-PRESENT link. Use "if a future change introduces X, this becomes..." — NOT "attacker obtains..."

### §6 — Hardening Recommendations is a separate section

`exploitable_now: false` findings route to a dedicated Hardening Recommendations section. Not in the main fix-now list, still in the report. Severity calibrated against posture scale (usually LOW / MEDIUM).

### §7 — Reproduction label honesty

Default to `code-path-traced` for static review. Only mark `verified` if you actually executed the steps and observed the output. The difference matters for defender triage.

### §8 — Root-cause confidence

`high | medium | low`. Did you trace full causation or infer from partial evidence?

### §9 — "Fix These First" executive summary

5–10 findings meeting all §1 criteria, with one-line impact + fix-complexity (minutes / hours / days). Synthesizer's mechanical pass emits candidates; synthesizer agent curates the final cut.

### §10 — Cross-agent chains stay

Genuinely valuable analytical output. Links must point to post-dedup primary IDs.

## `hardening_plan` schema (host findings; optional on code findings)

Every host-scan finding carries:

```json
"hardening_plan": {
  "immediate": "<one-liner command that fixes it now>",
  "configuration": "<durable config: GP / registry / SDDL / firewall rule>",
  "monitoring": "<audit policy + event ID / Sysmon rule for regression>",
  "compensating_controls": "<WDAC / LAPS / network segmentation / etc.>",
  "estimated_effort": "minutes | hours | days | weeks"
}
```

The synthesizer emits a **Hardening Plan (prioritized)** section at the top of report.md, grouped by `estimated_effort`. Copy-paste commands live in the `immediate` field. This IS the deliverable — the work queue the operator executes top-down.

## Output shape (report.md)

```
# Trial report (raw bundle) — <target>

Header: counts (main / hardening / chains / dup-clusters / fix-these-first candidates)

## Hardening Plan (prioritized)       ← host-scan only; empty for code-scan unless authors add plans
    ### Effort: minutes
    ### Effort: hours
    ### Effort: days

## Fix These First (candidates)       ← CRITICAL + exploitable_now=true
    - synthesizer agent curates to final cut in agents/synthesizer/notes.md

## Agents run                          ← per-agent tally (Critical / High counts)

## Findings (main)                     ← exploitable_now != false; severity-sorted
    - each finding: severity tag, agent, surface, refs, description,
      impact, reproduction, evidence, remediation, CWE, hardening_plan (if present)

## Hardening Recommendations           ← exploitable_now=false; posture improvements

## Cross-agent attack chains           ← multi-agent chains via attack_chain field

## Suspected duplicate clusters        ← surface-scoped token-overlap; synthesizer resolves
```

And `agents/synthesizer/notes.md` is the opinionated human-layer review:

```
1. Fix These First — curated final cut (5-10 findings)
2. Duplicate cluster resolution (which cluster-member is the primary)
3. Under-reporting / over-reporting check (which specialists need prompt tuning)
4. Missed cross-agent chains (single most devastating path)
5. Structural observations (novel-pattern themes, recurring anti-patterns)
6. Improvement seeds for next trial (prompts to sharpen, specialists to add)
```

## Alert-triage protocol (host mode)

The `alert-triage` specialist answers "is this Defender alert real or noise?" It runs in four steps:

1. **Baseline snapshot** (BEFORE any invasive enumeration) — `capture_baseline()` writes `evidence/alert-triage-baseline/*.txt` with Defender detection state + event-log high-water marks + Sysmon state.

2. **Post-scan delta** — re-query the same surfaces after the rest of the specialists complete. Diff.

3. **Classify each new alert:**
   - **scan-induced noise** — alerting process == our scan; pattern matches something our scan did.
   - **scan-exposed pre-existing issue** — scan triggered it, but the issue was there before (e.g. EICAR in a forgotten folder).
   - **concurrent benign** — unrelated to our scan.
   - **uncertain** — can't correlate; flag for manual review.

4. **Verify noise** — for each "scan-induced noise" entry, confirm the exact triggering command is in `transcript.jsonl` at the right timestamp AND the alert pattern matches a pre-registered expected scan artifact. If EITHER fails → upgrade to "uncertain."

The report surfaces a summary: "18 Defender alerts during scan; 15 verified noise; 3 scan-exposed pre-existing issues (tracked as findings)."

## Target shape guarantees

For comparable codebase complexity to keyvectra (~50k LOC, ~200 routes):

- 6–8 CRITICAL
- 25–35 HIGH
- 30–40 MEDIUM
- 15–25 LOW
- 10–15 INFO
- ~90–110 total distinct findings
- Separate Hardening Recommendations list (10–30 items typical)
- 5–15 cross-agent attack chains
- 0–20 duplicate cluster advisories (synthesizer resolves)

For host scans of a typical developer Windows machine:

- Depends HEAVILY on hygiene. A well-hardened corporate laptop: 0–2 CRITICAL, 5–10 HIGH, 10–30 MEDIUM/LOW.
- A default-configured personal laptop: 2–5 CRITICAL is typical.
- Hardening Plan typically 20–60 items.

These are planning numbers, not contracts. Actual volume varies.
