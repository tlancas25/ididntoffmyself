# Workspace template (drop-in scratch dir for a new trial)

> © 2026 BlaFrost Softwares Corp. Internal.

Copy this entire `workspace-template/` folder to a new location (e.g. `~/dev/my-new-trial-workspace/`) and launch Claude Code in that folder. This is a scratch workspace — not a git repo.

## Rules (binding for every trial)

1. **No git in this directory.** No `.git`, no hooks, no `git init`. The workspace is local-only. Findings / evidence / target material lives here and never leaves the machine. Only scrubbed, curated outputs should ever make it to the public-facing repo.
2. **No secrets ever** in `report.md` or any summary. Raw evidence that contains secrets stays under `targets/*/evidence/` and never gets committed.
3. **Every finding / prototype lives as a file.** Nothing in-conversation-only. Claude and operator both need to be able to reload state from files.
4. **MEMORY.md is the handoff log** between sessions. Append new entries in reverse-chronological order (newest at top). Context resets clean when session resets; MEMORY.md is how continuity survives.
5. **One folder = one trial.** `targets/<slug>-<timestamp>/` is immutable once a trial starts. Re-running creates a new timestamped folder.
6. **Excluded folders are off-limits.** For host-scan trials the standard excluded folders are `C:\Users\<operator>\Documents`, `Downloads`, `Pictures`, `Videos`. Set per-trial in `target.yaml`.

## What's in here on first use

```
<your-workspace>/
├── README.md        ← this file, the binding rules
├── MEMORY.md        ← empty log; schema at the top
└── targets/
    └── README.md    ← the per-target folder schema
```

## What Claude does at session-start

1. Reads this README (the rules).
2. Reads `MEMORY.md` (the handoff log).
3. If there are active target folders under `targets/`, reads each target's `target.yaml` and last-known state.
4. If the operator provides a target (code or host), scaffolds a new `targets/<slug>-<ts>/` folder and starts the trial.

## Where things live

| Path | What it holds |
|---|---|
| `MEMORY.md` | Running session log. Decision log, current state, open questions. |
| `targets/<slug>-<ts>/target.yaml` | Trial metadata: provenance, scope, authorization, declared surfaces. |
| `targets/<slug>-<ts>/intake/` | Original materials the operator handed over (source tree, URLs, prior reports). Code trials only. |
| `targets/<slug>-<ts>/agents/<id>/findings.json` | Structured findings from specialist `<id>`. |
| `targets/<slug>-<ts>/agents/<id>/notes.md` | Free-form specialist notes, hypotheses, dead-ends. |
| `targets/<slug>-<ts>/evidence/` | PoCs, captures, baseline snapshots, screenshots. |
| `targets/<slug>-<ts>/report.md` | Synthesizer deliverable: Fix-These-First + Hardening Plan + main findings + chains + duplicate clusters. |
| `notes/session-YYYY-MM-DD.md` | Free-form session scratch, ideas not yet ready for MEMORY.md. |

## Getting the prompts

The 7 binding prompt files (`recon.md`, `synthesizer.md`, `specialists.md`, `host_recon.md`, `host_specialists.md`, `targets_schema.md`, `roster.yaml`) live in the sibling `claude-code-native/prompts/` folder of this repo. The workspace references them by path; the workspace itself does not duplicate them.

When operating inside Claude Code, the operator instructs Claude to "read the prompts from `<repo>/claude-code-native/prompts/<file>.md`" for whichever agent is being run.

## Legal

Proprietary. BlaFrost Softwares Corp. See repo root `LICENSE`.
