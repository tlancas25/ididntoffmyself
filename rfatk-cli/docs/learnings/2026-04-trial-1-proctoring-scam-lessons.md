# Trial #1 Lessons — Proctoring-Scam + Timestomp Anti-Forensics

**Date of trial:** 2026-04-20 (scan + IR), 2026-04-21 (two-round forensic correction)
**Captured as training data:** 2026-04-21

This is one of the most important learning documents in the REDFORGE project: the first real-world host-scan trial taught the tool more than any synthetic fixture could. The attacker used specific anti-forensic techniques that fooled the first investigation pass, and the investigation got the initial-access theory wrong **twice** before correcting. Every lesson here is baked into the tool's specialist prompts, schema, and roster.

## The trial in three sentences

The lead developer's personal laptop was the target of a social-engineering proctoring scam on 2025-08-29 (attacker handle `dr.jamespaul` inside remote-control software posing as an online exam proctor); re-victimization on 2025-09-08 after an OS reinstall; attacker sustained SYSTEM access for ~7 months through the operator's proctored coursework, tolerated because the operator believed the proctoring software was required. REDFORGE's first host-scan found the residual persistence in April 2026 after the operator had started manual cleanup. Three successive investigation theories (MAS script → pre-compromised hardware → proctoring scam) tracked the evidence — the first two were wrong, and correcting them produced new tool capabilities.

## What the tool got RIGHT on first run

1. **9 specialists in parallel identified the active compromise within minutes** of first dispatch — persistence-hunt caught ScreenConnect + LSA Auth Package; network-posture independently caught 2 more C2 channels.
2. **Severity §1 calibration held** — 6 CRITICAL findings, every one satisfied exploitable-today + unauth/single-session + direct-impact.
3. **Dedup clustering correctly merged** 4-way overlapping Defender-exclusion findings from different specialists.
4. **Alert-triage surfaced the "zero Defender detections despite 3 active C2 channels" insight**, which became the headline for the MSRC vulnerability disclosure.
5. **Hardening plan structure worked** — Fix-These-First + Minutes/Hours/Days buckets shipped as designed.

## What the tool got WRONG — and what it taught us

### Wrong Theory #1 (original 2026-04-20): MAS script as initial access

The synthesizer claimed PowerShell `irm https://get.activated.win | iex` was the "most likely initial access vector." Rationale: multiple runs predated most payload drops, invoked `iex` with admin, and trojanized MAS clones are real. Temporally impossible — earliest MAS run was 28 min after current-OS OOBE, while ScreenConnect files claimed June 2025 dates.

**Lesson → tool capability added:**
- The synthesizer and specialists will now cross-check timestamps against source-install dates by default. The `investigator` meta-specialist's Section 1 ("Theory consistency check") catches this pattern.

### Wrong Theory #2 (2026-04-21 morning): Pre-compromised thrift hardware

After ruling out MAS, the theory became "machine arrived backdoored from thrift store; LSA Auth Package survived the pre-sale reset." Every piece of evidence fit — until we found the timestomp.

**Lesson → tool capability added:**
- Parent-directory `$SI` mismatch check is now mandatory in the `forensic-deepdive` specialist. A file cannot predate its parent directory's `$SI CreationTime`; if it does, `SetFileTime()` was called — proof positive of timestomp without needing `$FN` MFT attribute access.
- The specific attacker pattern ("backdate attacker files to before the OS install date, so investigators conclude pre-existing compromise") is now documented as a known misdirection tactic in `investigator.md` Section 2.

### Correct Theory #3 (2026-04-21 evening): Proctoring-scam re-victimization + timestomp

Key breakthroughs:

1. **Operator recollection** surfaced the true initial access vector (`dr.jamespaul` social-engineering on 2025-08-29 → UltraViewer + secondary tool → %TEMP% wipe). The tool had no way to discover this from forensic artifacts alone — the TEMP wipe and March 2026 operator cleanup erased those traces.
2. **Parent-directory `$SI` CreationTime = 2026-01-07** on the ScreenConnect folder proved the DLL's apparent 2025-06-09 timestamp was stomped. 2026-01-07 matched the independently-verified `game.exe`/AsyncRAT drop — evidence of a coordinated multi-payload push.
3. **Operator had tolerated the malware during coursework** (Sep 2025 – Mar 2026) thinking it was required proctoring software. The "10-month dwell time" framing was misleading — real active attacker dwell was ~7 months; operator had been actively cleaning up for the final month+.

**Lessons → tool capabilities added:**
- **Operator-context intake** is now first-class. Recon solicits operator narrative; every specialist can reference it; `investigator` weights operator memory against attacker-controllable timestamps.
- **Coordinated-push clustering** is an automatable detection (Technique 4 in `forensic-deepdive.md`): group file creations by hour; ≥3 suspect files in the same hour = push.
- **Impersonation-name fingerprint** is automatable (Technique 5 in `forensic-deepdive.md`): fuzzy-match filenames against a catalog of legitimate products; flag + (signature mismatch + attacker-typical path + timestomp) = confirmed impersonation.
- **Defender tolerated-malware pattern** (Technique 6): repeated `ThreatID` detections with files still present on disk = either operator-whitelisted (check context) or attacker re-adding exclusions (tampering loop).

## New specialists added to the roster

1. **`forensic-deepdive`** — runs AFTER all other host specialists. Systematically checks every flagged attacker file for the six anti-forensics techniques above. Full brief: `prompts/forensic-deepdive.md`.

2. **`investigator`** — meta-review. Runs LAST. Reviews all findings collectively for adversary misdirection, theory contradictions, operator-narrative alignment, and theory stability. Flags `⚠️ CRITICAL: REPORT CORRECTION REQUIRED` if the synthesizer's primary root cause is invalidated. Full brief: `prompts/investigator.md`.

Both are registered in `prompts/roster.yaml` with `runs_after` ordering.

## New schema fields (all optional)

- `anti_forensics: [list of T-codes]` — e.g., `["T1070.006-timestomp", "T1070.004-temp-wipe"]`
- `misdirection_indicators: [list of strings]` — what false theory the attacker wanted the investigator to land on
- `install_trace_status: "traced" | "no_install_traces_expected_portable" | "no_install_traces_suspicious" | "timestomped"`
- `operator_narrative_aligned: bool | null` — does this finding align with operator recollection?

Validator warns if missing on findings with `anti_forensics` populated; no hard requirement to avoid churn on existing trials.

## New binding calibration rule

**§8 (added 2026-04-21)** — **Never let a timestamp be the sole basis of a root-cause theory.** Always cross-check file `$SI CreationTime` against parent-dir `$SI`, `MsiInstaller` events, `7045` events, and operator narrative. Parent-dir `$SI` wins unless the parent is also stomped (which is rare and itself evidence of sophisticated tradecraft).

## Meta-lessons (for the tool roadmap)

1. **Adversary deception is a first-class investigation concern, not a footnote.** Future specialists should assume the attacker may have planted misleading artifacts — don't treat filesystem state as ground truth.

2. **Operator context is signal, not noise.** The forensic breakthrough came from operator memory, not from any query the tool could have run. Every future host trial starts with an explicit operator-context intake step.

3. **Theory stability matters more than theory novelty.** A trial that publishes with one firm theory and is proven wrong costs more credibility than a trial that publishes with two plausible theories and admits uncertainty. The `investigator` meta-specialist institutionalizes this.

4. **"Tolerated" malware is as real as "unknown" malware.** Operators under social pressure (coursework requirements, job dependency on specific software, regulatory compliance tools) will tolerate suspicious software. Detection patterns should treat repeated detections without remediation as signal.

5. **Real-world trials are the best training data.** This trial's attack sequence, tradecraft signatures, and misdirection patterns are now encoded as detection rules, prompt-level techniques, and schema fields. A synthetic fixture wouldn't have produced `SetFileTime()`-based timestomp + parent-directory-mismatch detection as a deliverable — the attacker did.

## Reference trial

- Public trial artifacts: `https://github.com/tlancas25/ididntoffmyself/tree/main/docs/trials/2026-04-20-first-host-scan`
- Three corrections documented in-repo: commit `4824f16` (initial), `a6035e4` (v1 correction), `c71b7cc` (v2 correction).
- Full forensic evidence preserved locally (not in repo): `redforge-dev/targets/my-machine-20260421T020000Z/evidence/forensic-followup-install-vector/`.

## Never forget

**The attacker made the "pre-existing compromise" theory LOOK correct.** The June 2025 timestamps were deliberately planted. The missing install traces were a consequence of the timestomp (if the install had happened June 2025, the logs would have rolled over by April 2026 — consistent with what we saw). Every piece of evidence fit the wrong theory. Only the **parent-directory `$SI`** broke the spell.

That's the discipline REDFORGE needs to encode: **check parent-directory `$SI` on every attacker file, every trial, no exceptions.** It's a one-line check with deterministic, high-signal output. If we'd had this in our roster on Day 0, the trial would have surfaced the correct initial-access vector in the first pass.
