# redforge-live — continuous monitoring edition

**Status:** design + scaffold stage (branch `redforge-live`, pre-release). Lessons from Trial #1 (2026-04-20 proctoring-scam / timestomp attack on the lead developer's own machine) drove this variant. The operator had **NetLimiter** installed — it did not stop the intrusion. This tool is designed to be the **persistent-observation layer** that NetLimiter isn't: semantic analysis of every state change, triaged by Claude, with memory of "known-good" so new badness stands out.

## The gap this fills

- `rfatk` (CLI) + `claude-code-native` (Claude Code flow) are **point-in-time scanners**. You run them, they produce a report. Great for first-time discovery and audit-day assessments. They miss what happens **between** scans.
- NetLimiter, Defender, and traditional EDRs are **signature-and-heuristic based**. They missed a 10-month Russian-crimeware RMM compromise on this very machine because the attacker used legitimately-signed ConnectWise ScreenConnect, timestomped files, and added Defender exclusions — each step individually looks normal.
- **redforge-live sits between them**: a persistent agent that diffs system state against a known-good baseline, and when something changes, it wakes Claude Code to semantically classify the change (benign update vs suspicious behavior vs outright malicious).

## Design constraints (from the operator)

- **Claude-Code-only.** Not packaged CLI. Runs inside a Claude Code session with memory. This is not the shippable product variant — it's the in-house tool for the lead developer's own machines.
- **Real-time-ish.** Doesn't have to be sub-second. A 5-15 minute detection window is acceptable. The goal is "before the attacker has a week of dwell" not "intrusion-prevention."
- **Uses what's already there.** NetLimiter is installed — integrate with its log format rather than replacing it. Defender is running — query its state rather than duplicate its engine.
- **Remembers.** State from previous wake cycles persists via Claude Code's memory + a state file, so each invocation doesn't start from zero.

## Design in one sentence

**A Windows Scheduled Task wakes a small PowerShell watchdog every N minutes; the watchdog diffs the current system state against a baseline file; if anything changed, it invokes `claude -p` with the diff as input and a triage prompt; Claude classifies each change, writes alerts to `state/alerts.jsonl`, and updates the baseline for next cycle.**

See `ARCHITECTURE.md` for the full options analysis (A/B/C/D) and why we chose the scheduled-task starting point.

## Quickstart (when ready to actually run this — still in scaffold)

```powershell
# 1. Elevated PowerShell.
# 2. Install the Scheduled Task (one-time):
cd C:\path\to\ididntoffmyself\redforge-live
.\watchdog\install-task.ps1

# 3. Create the initial baseline on a KNOWN-GOOD state:
.\watchdog\watch.ps1 -BaselineOnly

# 4. Task now runs every 15 min. Alerts land at:
#    state/alerts.jsonl (structured)
#    state/alerts.md (human-readable)
```

## What it watches (initial scope)

Per each wake cycle, snapshot + diff:

1. **Services** — creation of new services, changes to service binary paths, changes to service accounts (LocalSystem ↔ NetworkService).
2. **Scheduled tasks** — creation, path changes, action changes, trigger changes.
3. **HKCU + HKLM Run keys** — additions, changes, deletions.
4. **LSA Authentication Packages** (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`) — the critical persistence mechanism the Trial #1 attacker used.
5. **Defender exclusions** (`Get-MpPreference`) — any new exclusion path or process is HIGH alert.
6. **Defender state** — MAPSReporting, CloudBlockLevel, RealTimeProtectionEnabled, TamperProtection. Any downgrade is CRITICAL alert.
7. **Listening TCP sockets** — new listeners on any interface (process attribution requires admin).
8. **Outbound established connections** — cross-reference against a "known-good destinations" allowlist built from the baseline.
9. **NetLimiter log tail** — pick up connections NetLimiter saw. Flag destinations not in allowlist.
10. **File-system canaries** — hashes of critical files (Defender binaries, Winlogon registry, HOSTS file). Any mismatch = TAMPER alert.
11. **Scheduled task history** — `Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational` for task-creation events since last check.
12. **System event log 7045** — service creation events since last check.
13. **AppX deploy events** — new UWP/AppX package installs.

## Integration with NetLimiter

NetLimiter logs per-connection data at `C:\ProgramData\Locktime Software\NetLimiter\log\` (default). If logging is enabled at the connection level, every outbound connection is recorded with process, destination, port, byte count. We **tail this log** and cross-reference new destinations against the allowlist. See `docs/netlimiter-integration.md` for log-format notes and enablement steps.

## What happens when an anomaly fires

The watchdog invokes:

```powershell
claude -p --dangerously-skip-permissions "Resume redforge-live triage. Read state/incoming-diff.json. Classify each item as benign|suspicious|malicious. Write to state/alerts.jsonl per schema. Update state/baseline.json if you accept any change as benign. See prompts/triage.md for full instructions."
```

Claude reads the diff, the baseline, `prompts/triage.md`, and optionally any recent alerts for context. It emits structured classifications. If anything is `malicious`, the triage prompt instructs Claude to write a recommended-action block (kill process, block IP, etc.) that the operator can review and execute.

The Claude session is **short-lived** per invocation — it does not stay loaded. State persists in files + Claude Code's auto-memory folder for this project.

## What this is NOT

- Not an active defense / remediation tool. Claude writes recommended actions; the operator executes them. (Future: optional `--auto-remediate` mode for high-confidence malicious events, gated on explicit operator opt-in.)
- Not a replacement for Defender, NetLimiter, or real EDR. This is a **semantic second opinion** layered on top.
- Not a public product. This is operator-use-only for BlaFrost Softwares Corp machines. Not shipping to customers.

## Contents

- `ARCHITECTURE.md` — design options analysis and chosen approach
- `watchdog/` — the PowerShell watchdog + scheduled-task installer
- `state/` — baseline file, alerts log, diff file format spec
- `prompts/` — the Claude triage prompt
- `docs/` — NetLimiter integration notes, Claude Code memory design
