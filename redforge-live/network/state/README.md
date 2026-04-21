# redforge-live — network state directory

This directory in the REPO is a placeholder. The live state lives at `C:\redforge-live\state\` after install (not committed to git).

## Files the installed tool creates

| File | Writer | Purpose |
|---|---|---|
| `baseline.json` | `watcher.ps1` (learning mode), Claude triage (benign classification) | Process-to-destinations map. Nested object: `{ processName: ["ip:port", "ip:port", ...] }` |
| `triage-queue.jsonl` | `watcher.ps1` (on anomaly) | Pending anomalies awaiting batch triage. Drained by `triage-invoke.ps1`. |
| `alerts.jsonl` | `watcher.ps1` (IoC matches), Claude triage | Classified alerts. Schema in `prompts/learning-firewall-triage.md`. |
| `alerts.md` | Claude triage | Human-readable running narrative. |
| `firewall-rules.jsonl` | `watcher.ps1`, `firewall-manage.ps1` | Log of every firewall rule created by redforge-live + reason. |
| `mode.txt` | `install.ps1` (initial), tray menu (user toggle) | `Learning` or `Enforcing`. Watcher reads on startup and on tray-menu action. |
| `config.json` | `install.ps1` (initial), operator-editable | Learning duration, observation interval, triage interval, IoC list, auto-block toggles. |

## `baseline.json` schema

```json
{
  "chrome": [
    "142.250.190.14:443",
    "172.217.11.142:443",
    "142.250.72.78:443"
  ],
  "svchost": [
    "20.190.191.66:443",
    "52.109.40.97:443"
  ],
  "claude": [
    "52.223.16.192:443"
  ]
}
```

Entries added either by watcher (during learning mode or pre-classify benign) or by Claude triage (benign classification).

## `alerts.jsonl` schema

Each line is a single JSON object. Fields:

- `timestamp` — ISO-8601 UTC when the alert was written
- `cycle` — identifier for the triage batch (timestamp of the batch)
- `severity` — `CRITICAL | HIGH | MEDIUM | LOW | INFO`
- `classification` — `benign | suspicious | malicious`
- `process` — process name
- `process_binary` — full path to the owning process executable (if resolvable)
- `address` — remote IP
- `port` — remote port
- `pid` — owning PID at the time of observation
- `summary` — one-line description
- `reasoning` — Claude's justification
- `recommended_actions` — array of PowerShell one-liners for operator review
- `auto_benign_because` — if auto-classified benign via a pattern in auto-memory, the pattern reference; else `null`
- `action_taken` — for IoC-match auto-blocks: array of actions taken by the watcher (firewall rule created, process killed)

## `firewall-rules.jsonl` schema

```jsonl
{"timestamp":"2026-04-21T16:00:00Z","rule":"RedforgeLive-Block-95.214.234.238-20260421","address":"95.214.234.238","port":0,"reason":"IoC-auto-block"}
```

## Rotation

- `alerts.jsonl` and `firewall-rules.jsonl` grow unbounded. Rotate monthly by renaming to `<file>-YYYY-MM.bak` and truncating.
- `baseline.json` is single-file, rewritten each update.
- `triage-queue.jsonl` is truncated after each successful Claude triage run.

## Backup

Operator can snapshot the full `C:\redforge-live\state\` dir for reference:

```powershell
Copy-Item C:\redforge-live\state C:\redforge-live\state-snapshot-$(Get-Date -Format yyyyMMdd) -Recurse
```
