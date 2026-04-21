# Workspace memory — session handoff log

> © 2026 BlaFrost Softwares Corp. Internal.

Read this file first on any new Claude Code session in this workspace. It's the source of truth for what's in flight. Entries are reverse-chronological (newest first).

---

## Entry schema

Every entry follows this shape. Copy it verbatim when appending.

```
### YYYY-MM-DD — short title

- **kind:** decision | scan | prototype | deferred | promoted | methodology-update
- **status:** draft | in-progress | ready-to-promote | promoted | deferred | invalidated
- **files:** paths relative to this workspace (or to the repo when cross-referencing prompts)
- **summary:** 1–3 sentences of what happened and why it matters
- **reasoning:** the WHY — what problem this solves, why this shape, alternatives considered
- **evidence:** if a scan — path to the raw output and the summary
- **open questions:** bullets — unresolved decisions
```

---

## Current state snapshot

_Template workspace — no trials in flight._

Populate this section with active-trial references as trials start:

- **Active trials:** `targets/<slug>-<ts>/` — status, specialist ids pending, synthesizer done/not
- **Queued:** trials scheduled but not started
- **Promoted upstream:** references to the BlaFrost repo / customer deliverable once the trial has been scrubbed + published

---

## Log (newest first)

_Empty — append entries as work progresses._

---

## Appendix — checklist for session end

Before ending a Claude Code session:

- [ ] Append a new MEMORY.md entry per the schema above
- [ ] Confirm every active trial's `target.yaml` reflects current state
- [ ] Confirm no secrets are in any `report.md` or `notes.md` (raw only under `evidence/`)
- [ ] If a trial completed: scrub + move curated output to the BlaFrost repo `docs/trials/`
- [ ] If a novel pattern was discovered: append to the relevant specialist brief in the repo and commit with message `prompts: <agent-id> — <change> (from trial <slug>)`
