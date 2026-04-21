# redforge-live state directory

This directory holds the persistent state of the live watchdog. Everything here is generated + updated by `watchdog/watch.ps1` and the Claude Code triage sessions.

**This directory is gitignored by default.** It contains machine-specific state that should not be committed to the repo (and may contain off-record intel classifications). If you want to share state for debugging, scrub it first.

## Files

| File | Writer | Purpose |
|---|---|---|
| `baseline.json` | `watch.ps1 -BaselineOnly` (initial) + Claude triage (ongoing) | Full snapshot of known-good system state. Updated by Claude when a diff item is classified benign. |
| `incoming-diff.json` | `watch.ps1` | The changed state keys from the current cycle. Written pre-triage, consumed by Claude, deleted post-triage. |
| `alerts.jsonl` | Claude triage | Append-only structured alert log. Each line = one classification entry (see schema below). |
| `alerts.md` | Claude triage | Human-readable running log. Rewritten each cycle. |
| `last-run.txt` | `watch.ps1` | ISO-8601 timestamp of last successful cycle. |

## `alerts.jsonl` schema

```jsonl
{
  "timestamp": "ISO-8601 UTC",
  "cycle_id": "monotonic cycle counter or timestamp-based id",
  "state_key": "services | scheduledTasks | runKeys | lsaAuthPackages | defender | listeningTcp | establishedOut | fileCanaries | recentServiceInstall",
  "classification": "benign | suspicious | malicious",
  "summary": "one-line human summary",
  "details": "full technical description",
  "affected_artifact": "file path, service name, registry key, or ip:port",
  "reasoning": "why Claude classified it this way",
  "recommended_actions": ["PowerShell one-liner 1", "PowerShell one-liner 2"],
  "auto_benign_because": null
}
```

- `recommended_actions` is populated only when `classification == "malicious"`.
- `auto_benign_because` is populated when Claude auto-classifies benign based on an auto-memory pattern (e.g., "matches known-Zoom-update pattern"). Empty otherwise.

## Baseline structure

```json
{
  "snapshotTime": "ISO-8601 UTC",
  "services": [...],
  "scheduledTasks": [...],
  "runKeys": [...],
  "lsaAuthPackages": [...],
  "defender": {...},
  "listeningTcp": [...],
  "establishedOut": [...],
  "fileCanaries": [...],
  "recentServiceInstall": [...],
  "outbound_allowlist": [
    "*.microsoft.com",
    "*.github.com",
    "..."
  ]
}
```

## Rotation

- `alerts.jsonl` should be rotated monthly by the operator (move to `alerts-YYYY-MM.jsonl.bak`). No automatic rotation in v0.1.
- `baseline.json` is single-file, overwritten each triage cycle.
