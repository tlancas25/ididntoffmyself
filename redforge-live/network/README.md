# redforge-live — learning network firewall (Phase 1.5)

A PowerShell-hosted tray-icon daemon that learns your network behavior for 14 days, then alerts on anomalies and optionally auto-blocks known-bad destinations. Claude Code is the decision engine for ambiguous classifications. Windows Firewall is the enforcement mechanism.

This is the **network-only** slice of `redforge-live`. System-state watching (services, scheduled tasks, LSA auth packages, Defender state) is the sibling track — see `../watchdog/`.

## Why

Trial #1 (2026-04-20 self-scan) found a 10-month RAT that NetLimiter saw but never flagged. The gap: **no semantic review of "is this destination normal for this process?"** NetLimiter shows every connection. Defender knows about signed binaries. Neither cross-references **"signed RegAsm.exe has no business talking to port 56009 on a random IP."** This tool does exactly that cross-reference.

## What it does

- **First 14 days: learning mode.** Records every `process → destination:port` pair silently. Builds a per-process behavior graph.
- **Day 15 onward: enforcement mode.** Any new destination a process hasn't used before = anomaly. Pre-classified if obviously benign (Microsoft, known CDNs, operator-installed-app patterns). Otherwise queued for Claude triage.
- **Claude triage runs in batches** every 5 min — examines queued anomalies, classifies each as `benign | suspicious | malicious`, writes recommended firewall rules for malicious.
- **Enforcement** is operator-reviewed by default. A tray balloon fires for each malicious classification; operator clicks "Block" to apply a Windows Firewall outbound-block rule. Auto-block mode is opt-in per-alert-type.
- **Baseline evolves.** Anything classified benign joins the known-good graph. Next time the same process→destination pair appears, no alert.

## Install location

Source: this repo at `redforge-live/network/`.
Installed: `C:\redforge-live\` (PowerShell scripts + state + logs).

The install script (`install/install.ps1`) copies + registers a Scheduled Task that runs at operator logon with highest privileges. The task launches `bin/watcher.ps1` as a hidden PowerShell window with a tray icon.

## Autostart flow

```
Windows boot
  → user logon
    → Scheduled Task "RedforgeLive-Network" fires
      → powershell.exe -WindowStyle Hidden -File C:\redforge-live\bin\watcher.ps1
        → PowerShell loads System.Windows.Forms
        → Tray icon appears (shield)
        → Timer observes Get-NetTCPConnection every 10s
        → Balloon fires on first anomaly (or silent in learning mode)
```

Tray menu: **Show dashboard · Recent alerts · Pause 15 min · Mode (Learning|Enforcing) · Exit**.

## Phase 1.5 vs Phase 1 (scheduled-task watchdog)

| Aspect | Phase 1 (watchdog/) | Phase 1.5 (network/, this) |
|---|---|---|
| Focus | Full-system state diff | Network connections only |
| Trigger | Polling every 15 min via scheduled task | Persistent daemon, 10-sec observation cadence |
| UI | None (writes to alerts.md) | Tray icon + balloon notifications |
| Enforcement | None (advisory) | Windows Firewall rule creation (operator-gated) |
| Claude cost | Per-change burst | Batched every 5 min; near-zero during learning |
| Detection latency | Up to 15 min | ≤ 10 seconds |

Both run concurrently. The scheduled-task watchdog catches state changes (service install, LSA auth packages, Defender tamper); this one catches network behavior.

## Quickstart (when v0.1 is runnable)

From an **elevated** PowerShell:

```powershell
cd C:\path\to\ididntoffmyself\redforge-live\network
.\install\install.ps1

# Tray icon should appear. In Learning mode for 14 days.
# To force transition to Enforcing mode early:
Set-Content C:\redforge-live\state\mode.txt "Enforcing"

# To uninstall:
.\install\uninstall.ps1
```

## Safety

- **Read-only until explicit block.** Observes connections; creates firewall rules only on operator click OR when a destination matches a known-bad list (Trial #1 IoCs).
- **Never auto-unblocks.** Once a block rule is created, removal is operator-only.
- **Tray app runs elevated** (needed for `New-NetFirewallRule`). Document tradeoff: install is admin-once at task registration, then runs under operator's session at logon.
- **Excluded folders respected.** No file access to `Documents/Downloads/Pictures/Videos` even though the tool is network-only.
- **Off-record intel stays off-record.** The Trial #1 IoCs are baked into the triage prompt as auto-malicious triggers. Operator-identifying details (Nina, Guaranteed Grade, dr.jamespaul) are NOT committed to this directory — they stay private in `redforge-dev/MEMORY.md`.

## What's in this directory

```
network/
  README.md                       this file
  ARCHITECTURE.md                 detailed design
  bin/
    watcher.ps1                   tray-icon daemon + event loop
    firewall-manage.ps1           Windows Firewall rule add/remove helpers
    netlimiter-tail.ps1           NetLimiter log tailer (stub)
    triage-invoke.ps1             `claude -p` spawner for batched triage
  prompts/
    learning-firewall-triage.md   Claude's triage prompt + IoC list
  install/
    install.ps1                   one-time setup + scheduled-task registration
    uninstall.ps1                 teardown
  state/
    README.md                     state file schema
  docs/
    (empty, reserved)
```
