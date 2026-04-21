# redforge-live — learning-firewall architecture

## Layer stack

```
┌─────────────────────────────────────────────────────────────┐
│  Tray UI (System.Windows.Forms.NotifyIcon from PowerShell)  │  ← user-facing
├─────────────────────────────────────────────────────────────┤
│  Event loop (Timer, 10-sec cadence)                          │
│  - Observe-Connections                                       │
│  - Pre-classify against known-good ranges                    │
│  - Enqueue anomalies                                         │
├─────────────────────────────────────────────────────────────┤
│  Batch triage (Timer, 5-min cadence)                         │
│  - Drain triage-queue.jsonl                                  │
│  - Invoke `claude -p` with queue + baseline                  │
│  - Parse Claude's classification                             │
│  - Write alerts.jsonl                                        │
│  - For malicious: fire balloon + offer block action          │
├─────────────────────────────────────────────────────────────┤
│  Enforcement (on operator click OR auto-block list)          │
│  - firewall-manage.ps1 New-Block-Rule                        │
│  - Tags rule with "RedforgeLive-" prefix for later audit     │
├─────────────────────────────────────────────────────────────┤
│  State persistence                                           │
│  - baseline.json (learned process-destination graph)         │
│  - alerts.jsonl (triage verdicts)                            │
│  - triage-queue.jsonl (pending anomalies)                    │
│  - firewall-rules.jsonl (rules we've created)                │
│  - mode.txt (Learning | Enforcing)                           │
└─────────────────────────────────────────────────────────────┘

Connection sources (ingest):
  - Get-NetTCPConnection -State Established  (10s polling)
  - Get-DnsClientCache                        (10s polling)
  - NetLimiter log tail                       (log-tail, future)
  - Windows Firewall audit log                (Event ID 5156, future)
```

## Learning algorithm

### Baseline phase (first 14 days)

1. Every 10s, snapshot `Get-NetTCPConnection -State Established`.
2. For each `(ProcessName, RemoteAddress, RemotePort)` tuple, increment a counter in the per-process graph.
3. Collapse by `(ProcessName, RemoteAddressAggregated)` — where "aggregated" = CIDR /24 for private ranges, exact address for public ranges (CDNs use rotating IPs so /24 is a reasonable bucket).
4. At end of day 14: freeze baseline. Every observed `(process, aggregated-dest)` pair is "known good."

### Enforcement phase (day 15+)

1. Every 10s, observe.
2. For each observation, check the baseline:
   - `(process, exact-dest)` known → ignore.
   - `(process, /24 of dest)` known → low-confidence match, add to quiet-log, no alert.
   - `process` known but `dest` is new → **anomaly**, pre-classify.
3. Pre-classification (in PowerShell, no LLM):
   - Destination in known-benign ranges (Microsoft AS-8075, Google AS-15169, Cloudflare AS-13335, GitHub AS-36459, Anthropic, operator-configured allowlist) → silent-add to baseline, no alert.
   - Destination in **known-malicious list** (Trial #1 IoCs + any operator-added) → **auto-block** without waiting for Claude.
   - Else → **enqueue for Claude triage**.

### Claude triage (batched every 5 min)

1. Read `triage-queue.jsonl`, dedupe to unique anomalies.
2. Spawn `claude -p --dangerously-skip-permissions "Resume redforge-live network triage. Read triage-queue.jsonl + baseline.json + prompts/learning-firewall-triage.md. Classify each and write to alerts.jsonl."`
3. Truncate triage-queue.jsonl after successful Claude run.
4. Parse alerts.jsonl for new entries; fire tray balloons for each malicious.

## Graceful degradation

- **Claude unavailable** (no API key, network out, rate-limited): queue keeps filling, operator sees "N anomalies pending triage" in tray menu. Operator can manually trigger retry or review queue.
- **High anomaly rate** (>50/5min): switch to "conservative learning" — everything non-obviously-malicious gets silent-added to baseline, no Claude call. Tray icon turns yellow. Operator must explicitly "kick" the firewall out of conservative mode.
- **PowerShell process crash**: Scheduled Task restarts it on next logon. State files persist across crashes.

## Enforcement rules (Windows Firewall)

Rule naming convention: `RedforgeLive-<classification>-<dest-or-range>-<yyyymmdd>`

Examples:
```
RedforgeLive-Block-95.214.234.238-20260421        (IoC, exact address)
RedforgeLive-Block-edgeserv.ru-20260421            (domain-based block via HOSTS)
RedforgeLive-Observe-20.190.191.0-24-20260421      (observation-only, log-and-pass)
```

Block rules:
```powershell
New-NetFirewallRule -DisplayName "RedforgeLive-Block-<dest>-<date>" `
                    -Direction Outbound `
                    -Action Block `
                    -RemoteAddress <dest> `
                    -Enabled True `
                    -Group "RedforgeLive"
```

All redforge-live-created rules belong to the `"RedforgeLive"` group, so the operator can audit/remove-all via:
```powershell
Get-NetFirewallRule -Group "RedforgeLive"
Remove-NetFirewallRule -Group "RedforgeLive"
```

## Pre-classification rules (no LLM)

Short-circuit Claude for:

### Known-good (silent-add to baseline)

- Microsoft: `13.64.0.0/11`, `20.0.0.0/8`, `40.0.0.0/8`, `52.0.0.0/8`, `131.253.0.0/16`, `*.microsoft.com`, `*.azure.com`, `*.office.com`, `*.live.com`, `*.outlook.com`
- Google: `8.8.8.8`, `8.8.4.4`, `*.google.com`, `*.googleapis.com`, `*.gstatic.com`, `64.233.0.0/16`, `142.250.0.0/15`
- Cloudflare: `1.1.1.1`, `1.0.0.1`, `104.16.0.0/13`
- GitHub: `140.82.112.0/20`, `*.github.com`, `*.githubusercontent.com`
- Anthropic: `*.anthropic.com`, `api.anthropic.com`, `claude.ai`
- Operator-local LAN: `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`
- Tailscale CGNAT: `100.64.0.0/10`

### Known-malicious (auto-block + CRITICAL alert)

(From Trial #1 — permanent IoCs)

- `95.214.234.238`, `64.74.162.109`, `130.12.180.159`
- DNS resolution of `edgeserv.ru`
- Process names matching `ScreenConnect.*` (not installed on this box anymore)
- RegAsm.exe, MSBuild.exe, InstallUtil.exe making OUTBOUND connections (LOLBin proxy execution — T1218.009)

### Process-signature heuristics (fast-classify before LLM)

Boost suspicion score when:

- Destination port is non-standard and not in the process's known-port set (process X always uses 443; now suddenly using 56009 = suspicious).
- Process binary is unsigned.
- Process binary is in user-writable path (`%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`).
- Process started in the last 60 seconds (newly-launched + external connection = suspicious).

Pre-score in PowerShell; Claude sees score + context and decides.

## Why 14-day learning window

- **Weekly patterns** (Zoom meetings Monday, backups Sunday, updates mid-week) need 2 full weeks for representation.
- **Monthly patterns** (end-of-month report generation, billing systems) — missed. Accept that; those get flagged as anomalies in month 2, Claude classifies them benign, baseline expands.
- **Shorter window** (3-7 days) too many false positives from weekly-only patterns.
- **Longer window** (30 days) delays enforcement unacceptably.

Adjustable via `state/config.json` → `LearningDurationDays`.

## What this does NOT do

- **Does not intercept traffic inline.** Uses Windows Firewall for enforcement, which is post-socket-bind. Means a process's FIRST packet to a bad destination may get out before the rule applies. Mitigation: pre-classify checks against known-malicious list run *before* `New-NetFirewallRule`, but there's a ~10-sec max lag (10s observation cadence) from first-connection-observation to block.
- **Does not inspect packet contents.** Layer-7 payload inspection requires pcap/WinDivert and a kernel filter. Out of scope for PowerShell-hosted v0.1.
- **Does not learn time-of-day patterns.** Zoom at 2am would look the same as Zoom at 2pm. Phase 2 could add temporal profiling — but start simple.
- **Does not correlate process-to-process.** If proc A spawns proc B which makes an outbound connection, A doesn't carry responsibility. Each process's baseline is independent. Phase 2 could add process-tree context.

## Open questions

1. **Baseline contamination.** What if the machine is compromised during the learning window? Baseline absorbs the attacker as "normal." Mitigation: require a clean M8-level scan immediately before installing redforge-live. Also, the baseline is re-checkable at any time against the `prompts/learning-firewall-triage.md` IoC list.
2. **Sleep/hibernate behavior.** If the machine is asleep for hours, the 10-sec timer doesn't fire. Acceptable — most traffic goes through when awake. Post-wake, resume observation.
3. **Multi-user machines.** v0.1 assumes single operator. If multi-user, each user's baseline would be separate. Out of scope.
4. **Firewall-rule lifetime.** Block rules created by redforge-live stay until explicitly removed. Should they expire (e.g., 30 days)? Probably yes; an IoC that was bad 6 months ago might be a CDN range now. Add rule-review in Phase 2.
