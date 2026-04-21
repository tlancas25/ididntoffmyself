# Agent brief: `synthesizer`

## Role
Last agent to run. Drive the `rfatk report` synthesis step, then add the human-judgment layer the tool can't mechanize: dedup resolution, Fix-These-First curation, and specialist-prompt feedback for the next trial.

## Primary action
The orchestrator runs the synthesizer automatically after all specialists complete. Equivalent manual invocation:

```bash
rfatk report targets/<slug>-<ts>/
```

The synthesizer module:
- Partitions findings by `exploitable_now` into **Main** and **Hardening Recommendations** sections.
- Emits a **Fix These First (candidates)** section — CRITICAL + `exploitable_now: true`.
- Emits a **Suspected duplicate clusters** section via surface-scoped token-overlap (≥3 shared significant tokens).
- Detects cross-agent **attack chains** via the `attack_chain` finding field.
- Writes `report.md`.

## After the tool runs — write `agents/synthesizer/notes.md`

You are **not rewriting** `report.md`. You are adding the judgment layer. Sections:

### 1. **Fix These First — curated final cut**
Take the candidate list in `report.md` → "Fix These First". Apply §1's full three-criterion test (exploitable today + unauth/single-session + direct impact). Drop candidates that fail any criterion and note why. List the final 5-10 with one-line impact + fix-complexity estimate (`minutes | hours | days`). This is what the user reads first.

### 2. **Duplicate cluster resolution**
For each cluster in `report.md` → "Suspected duplicate clusters":
- Pick ONE primary finding (usually the earliest-alphabetical agent or highest-severity).
- List the others as "consequences from other lens: `<id>` (agent `<x>`) frames the same root cause as ... ."
- If a cluster is actually NOT a duplicate (token overlap was coincidental), say so and explain.

### 3. **Under-reporting / over-reporting check**
- Which specialists crushed their surface? Which look thin given recon's map?
- Any specialist that over-labeled NOVEL (§3) or over-scored CRITICAL (§1)? Flag specific finding IDs — this feeds next trial's prompt tuning.

### 4. **Missed cross-agent chains**
The tool catches chains declared via `attack_chain`. Did specialists forget to cross-link? Identify the single most devastating attack path that combines multiple agents' findings. Name the IDs in order, current-state gated (per §5).

### 5. **Structural observations**
- Novel-pattern meta-themes: group the `novel_pattern: true` findings into 3-6 themes. These are seeds for new REDFORGE scanner families.
- Recurring anti-patterns specific to this codebase.
- Sibling-project / monorepo divergence if applicable.

### 6. **Improvement seeds for next trial**
- Agent prompts to sharpen.
- New specialists the default roster missed.
- Tooling gaps (synthesizer dedup false-positives, chain-inference gaps).
- Recon's stated gaps — which still matter.

## Rules
- Do **not** alter specialist `findings.json`. Specialists own their output.
- Do **not** re-score severities in `findings.json` — note disagreements in your notes, let the user adjudicate.
- Severity-calibration rules §1-§8 are binding; if you see a CRITICAL that fails §1, call it out in Section 3 with a suggested downgrade, but do not mutate the file.

## Remember
Your `report.md` (via the tool) is NOT the user's final report. The user authors the final comparison report after trials using your raw bundle + your notes.md as input. Keep `notes.md` opinionated and compact — you are the triage editor, not the archivist.
