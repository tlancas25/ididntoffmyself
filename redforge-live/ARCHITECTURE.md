# redforge-live — Architecture & Design Decisions

## Problem statement

Trial #1 (2026-04-20 self-scan) found a 10-month active compromise on the operator's Windows 11 laptop. The attacker used a social-engineering proctoring scam to gain initial access (2025-08-29), then operated persistently via ScreenConnect, AsyncRAT, and RegAsm.exe LOLBin channels. The operator had:

- **Windows Defender** running with default config
- **NetLimiter** installed (traffic firewall/monitor)

Neither tool caught the intrusion. **Why?**

- Defender: the attacker tampered with exclusions; legitimate ScreenConnect signature bypassed signature-based detection; T1562.001 loop defeated remediation.
- NetLimiter: the attacker's C2 traffic on port 443 (HTTPS) and port 8041 looks like any other business application. NetLimiter showed the connections, but the operator wasn't reviewing them proactively — and there was no semantic classification of "is this destination normal?"

**The gap:** no agent was diffing system state over time and asking *"is this new thing a problem?"* at the semantic layer that humans/LLMs do naturally.

## Options considered

### Option A — Pure scheduled task (polling)

Windows Scheduled Task runs a PowerShell script every N minutes (e.g., 15 min). Script snapshots state, diffs against baseline, invokes `claude -p` only if diff is non-empty.

**Pros:**
- Simple. Uses only built-in Windows + Claude Code.
- No long-running process to crash, leak memory, or miss events.
- Every run is stateless — the state lives in files. Robust against machine reboot, Claude Code updates, etc.
- Zero token cost when nothing changes (Claude only spawns on diff).

**Cons:**
- Polling gap. A 15-min window between checks means an attacker has 15 min of work before detection.
- Miss ephemeral events (a process that runs for 30 seconds and exits — gone before next poll).

### Option B — Pure event-driven

Persistent background service subscribes to Windows Event Tracing (ETW) / WMI events for process creation, service install, registry writes to sensitive keys, network connections. On event, classifies inline + invokes Claude if suspicious.

**Pros:**
- Near-real-time. Sub-second detection window for subscribed event types.
- Catches ephemeral events that polling misses.

**Cons:**
- Complex. ETW is a niche Windows API. PowerShell can subscribe to some events via WMI but it's fragile.
- The service must stay running — crashes, memory leaks, user account issues.
- Can't use `claude` CLI as the primary work engine directly — would need a queue + worker pattern.
- Noisy: every process launch fires an event. Requires substantial pre-filtering before calling Claude.

### Option C — NetLimiter-log tailer + on-demand Claude

A lightweight tail process watches NetLimiter's log file for new entries. Filters by risk patterns (unusual destinations, unsigned processes). On hit, invokes `claude -p` for triage.

**Pros:**
- Leverages existing NetLimiter installation.
- Network-focused — catches the C2-beaconing pattern (which is what actually matters for post-exploit detection).
- Simple filter logic.

**Cons:**
- Only network. Misses pure local persistence (scheduled tasks, Run keys) unless paired with another mechanism.
- Depends on NetLimiter's logging being turned on at the right level — may not be by default.

### Option D — Hybrid (scheduled + event-driven + NetLimiter)

All three layered. Scheduled task runs periodically for comprehensive diff. Event-driven watcher fires on high-priority event types (service install, Defender config change, LSA auth package change). NetLimiter-log tailer catches outbound-connection anomalies.

**Pros:**
- Best coverage.
- Each layer catches what the others miss.

**Cons:**
- Three things to maintain, debug, and keep in sync.
- Overkill for a single-operator-single-machine tool.

## Decision: Start with A, evolve toward D

**Phase 1 (v0.1, this branch's initial work):** **Option A** — pure scheduled task. Simplest possible thing that could catch a Trial #1-class attack within 15 minutes.

The 15-minute polling window is ACCEPTABLE for the threat model we're designing against. The Trial #1 attacker operated across **10 months**. A 15-min detection window reduces the dwell from months to minutes — a massive improvement without the complexity of real-time event subscription.

**Phase 2 (v0.2, later):** add **Option C** — NetLimiter-log tailer as a second channel. Outbound-connection anomalies are the highest-signal indicator of post-exploit activity, and the operator has NetLimiter already.

**Phase 3 (v0.3, later):** add a narrow **Option B** event-driven watcher for specific high-value events that polling can't reliably catch — specifically `Microsoft-Windows-Security-Auditing` Event 4697 (service install) and changes to `HKLM\SYSTEM\...\Lsa\Authentication Packages`. Not general ETW — just a small allowlist of events worth real-time subscription for.

## Memory & state architecture

Claude Code sessions invoked by the watchdog are **short-lived**. They read the state files, do their work, write alerts + update baseline, and exit. State persists in:

- **`state/baseline.json`** — full current-known-good snapshot. Updated by Claude after a change is classified benign.
- **`state/alerts.jsonl`** — every change event + Claude's classification verdict + timestamp, append-only.
- **`state/alerts.md`** — human-readable running log, Claude rewrites each invocation.
- **`state/incoming-diff.json`** — the diff written by the watchdog, consumed by Claude. Deleted after triage.
- **Claude Code auto-memory** (`~/.claude/projects/<slug>/memory/`) — high-level patterns Claude wants to remember across invocations (e.g., "this operator uses Zoom weekly — don't alert on Zoom service restarts"). Managed by Claude via its memory tool.

## Safety

- **Watchdog is read-only.** It queries system state, never modifies anything. No writes to registry, services, scheduled tasks, files outside `redforge-live/state/`.
- **Claude's triage is advisory.** Claude writes `recommended_actions[]` to alerts.jsonl but does NOT execute them. Operator reviews + executes.
- **Never ships off-record intel.** The triage prompt explicitly instructs Claude: do not publish to any repo, GitHub issue, or external service. All output stays in `state/`.
- **Excluded folders respected.** `Documents`, `Downloads`, `Pictures`, `Videos` are hard-excluded from all snapshot queries.

## Open design questions

1. **Does this need to work when the operator is NOT logged in?** If yes, the Scheduled Task must run as SYSTEM. If no, running as the operator's user is simpler and less risky.
2. **What triggers a MUST-NOTIFY-NOW alert vs a let-it-wait alert?** Initial thought: CRITICAL (Defender-off, new LSA auth package, known-C2 destination contacted) triggers a Windows toast notification; others just write to the log.
3. **How does the operator see alerts?** Options: a simple HTML dashboard rendered on each cycle, a desktop toast, a daily email digest, or they just read `alerts.md`. Start with `alerts.md` + toast for CRITICAL.
4. **Token cost.** Each Claude invocation is ~$0.01-0.05 depending on diff size + model. If the watchdog fires every 15 min with a change 2x/hour → ~$0.50/day. Acceptable. But if a noisy system fires diffs on every poll → could run to $5/day. The pre-classification in the watchdog (filtering obvious-benign changes before Claude sees them) is important for token economics.
