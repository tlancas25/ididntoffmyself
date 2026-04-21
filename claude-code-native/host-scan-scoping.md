# Host-scan trial scoping (methodology reference)

> © 2026 BlaFrost Softwares Corp. Internal reference.

This document describes the methodology, agent roster, sandbox design, and approval protocol for **host-scan trials** — REDFORGE runs targeting a running machine rather than a codebase on disk. Per-trial operator approvals, excluded folders, and scope live in each trial's `target.yaml` (NOT in this doc).

## When to use a host trial

- First-party posture audits against a machine the operator owns.
- Incident-response initial hunt ("is this machine already compromised?").
- Pre-hardening baselines before a laptop goes to a new employee.
- Continuous self-audits on a cadence (quarterly or monthly).

Out-of-scope for host-scan mode:
- Machines the operator does not own or does not have written authorization to test.
- Corporate-managed endpoints with MDM / DLP agents (those must be pre-cleared by the owning org's security team before the scan).

## Why host mode needs its own agent roster

The 16 code-trial specialists (auth-session, injection, XSS, etc.) target code on disk. A host scan is a different class of work — enumerate the *running system's* security posture, not source code. The existing file-tools (`read_file`, `glob`, `grep` inside `intake/`) don't cover the operations we need. Host mode introduces:

- A separate `HostToolContext` + PowerShell-allowlist sandbox (`rfatk-cli/src/redforge_attack/tools/host_sandbox.py`).
- 9 host-specific specialists (different surfaces, different prompts).
- A `hardening_plan` schema extension required on every host finding.
- An `alert-triage` protocol for classifying Defender/EDR noise vs real findings.

## Host specialist roster (9 specialists)

| Specialist | What it does |
|---|---|
| `host-recon` | Fingerprint OS build / patch level. Enumerate accounts, groups, logon history, installed software. Runs first. |
| `services-startup` | Audit services / drivers / scheduled tasks / startup items / run-keys. Flag anything running as SYSTEM that it shouldn't. |
| `windows-config-audit` | Baseline checks — UAC, SmartScreen, Defender state, BitLocker, SecureBoot, LSA protection, Credential Guard, PowerShell execution policy, SMB1 state, LLMNR/NBT-NS, WDigest, NTLM downgrades. |
| `network-listening` | Localhost listening ports + process owners (`netstat -ano` + process mapping). What binary owns each socket; what the firewall says about it. |
| `network-posture` | Outbound connection audit. DNS config, HOSTS file, routing table, ARP, proxy settings. Phone-home detection. |
| `firewall-audit` | Inbound + outbound firewall rules. Allow-any rules. Disabled profiles. Rules referencing stale binaries. |
| `local-subnet-sweep` | LAN sweep — what other devices are on this subnet, what ports they expose. **Requires explicit `allow_network_probe` approval** — it sends packets to other owners' hardware. |
| `credentials-exposure` | Cached credentials, saved RDP / WinRM creds, SSH keys, env-var secrets, Git config tokens, `.aws/credentials`, Docker config.json. Stays out of the excluded folders. |
| `persistence-hunt` | WMI event subscriptions, COM hijacks, DLL search-order, IFEO Debugger keys, scheduled tasks with unusual authors, Autoruns-complete enumeration. |

Plus the meta agents `recon`, `synthesizer`, and `alert-triage` (auxiliary, runs last).

See `prompts/host_specialists.md` and `prompts/host_recon.md` for the full binding briefs.

## Sandbox design (allowlist-based PowerShell execution)

The `host-scan-sandbox` (`rfatk-cli/src/redforge_attack/tools/host_sandbox.py`) is fundamentally different from the `code-scan-sandbox`:

- Reads **the live system**, not a folder tree.
- **Allowlist-gated:** every command proposed by a specialist is matched against a regex allowlist of known-read-only system queries. ~50 patterns cover Get-Service, Get-Process, netstat, reg query HKLM\..., Get-WinEvent, Defender queries, Group Policy, BitLocker, certificates, Autoruns, and more.
- **Excluded-folder enforcement:** any command referencing the per-trial excluded folders (the standard four: Documents, Downloads, Pictures, Videos) is REJECTED regardless of allowlist match.
- **Shell-composition blocked:** `;`, `|`, `&&`, `||`, `>`, `<`, backticks, `$()`, `@()`, newlines — all rejected. One read-only command per tool call.
- **Consent-gated:** admin-required commands fail without `--allow-admin`; network-probe commands fail without `--allow-network-probe`.
- **Zero state-modifying commands on the allowlist.** Reads only — no Set-*, New-*, Remove-*, Add-*, Stop-*, Start-Process, etc.

## Access / approval buckets

Each bucket is opt-in at trial start via `target.yaml` flags and CLI/operator confirmations.

### Works without elevation (standard user)

- Running services (`Get-Service`)
- Running processes + signed/unsigned (`Get-Process`, `Get-AuthenticodeSignature`)
- Scheduled tasks owned by the current user
- Listening ports (`netstat -ano` — no PID attribution for SYSTEM sockets without admin)
- Firewall rules (read-only listing)
- Installed software (via `HKLM\...\Uninstall\*` registry)
- Network config (`ipconfig`, ARP table, routing)
- Windows Defender state (`Get-MpPreference`, `Get-MpComputerStatus`)
- DNS config, HOSTS, proxy settings
- Autoruns-style HKCU run keys + user startup folder
- Git config tokens, SSH keys in `%USERPROFILE%\.ssh`
- User accounts + group memberships

### Requires admin — `allow_admin: true`

| Bucket | Commands | Why |
|---|---|---|
| SAM / SYSTEM / SOFTWARE hive reads | `reg query HKLM\SAM`, LSA protection state | Password hashing config, Credential Guard |
| Full process attribution on system sockets | `netstat -ano` with admin | Confirm which SYSTEM process owns which port |
| Security event log deep scan | `Get-WinEvent -LogName Security` | Logon failures, explicit creds, lateral-movement indicators |
| Full service DACLs | `sc sdshow <service>` | Service-hijack hunt: writable binaries by non-admins |
| Autoruns-complete | `Autorunsc.exe -accepteula -a *` | Full persistence enumeration |
| BitLocker protector state | `manage-bde -status`, `manage-bde -protectors` | Encryption posture |

### Requires network approval — `allow_network_probe: true`

| Bucket | Commands | Caveat |
|---|---|---|
| Local subnet sweep | `Test-NetConnection <neighbor>`, `arp -a` driven follow-ups | Touches other owners' devices (router, printer, phones, IoT) — their logs will show the probes. |
| Port scan of neighbors | `Test-NetConnection <ip> -Port <p>` per common port | Same — and could trip their IDS if any. |
| External reachability probes | `Resolve-DnsName google.com` etc. | Benign but leaves DNS-log fingerprints. |

**Default:** localhost-only. Subnet sweep is opt-in.

## Alert-triage protocol ("is it noise or real?")

The `alert-triage` specialist runs a baseline-and-diff to answer whether each new Defender/EDR alert during the scan is scan-induced noise or a real issue. Four steps:

### Step 1 — baseline snapshot (BEFORE any invasive specialist runs)

Captures to `evidence/alert-triage-baseline/`:

| File | Command |
|---|---|
| `defender_threats.txt` | `Get-MpThreatDetection \| Select-Object -Property ActionSuccess, DomainUser, ProcessName, ThreatId, InitialDetectionTime, LastThreatStatusChangeTime, Resources` |
| `defender_threat_list.txt` | `Get-MpThreat` |
| `defender_status.txt` | `Get-MpComputerStatus` (last-scan times) |
| `defender_preference.txt` | `Get-MpPreference` |
| `sec_log_high_water.txt` | `(Get-WinEvent -LogName Security -MaxEvents 1).RecordId` |
| `sys_log_high_water.txt` | `(Get-WinEvent -LogName System -MaxEvents 1).RecordId` |
| `app_log_high_water.txt` | `(Get-WinEvent -LogName Application -MaxEvents 1).RecordId` |
| `defender_op_high_water.txt` | Defender operational log high-water |
| `ps_op_high_water.txt` | PowerShell operational log high-water |
| `sysmon_high_water.txt` (if installed) | Sysmon log high-water |

### Step 2 — invasive specialists run

Normal parallel fan-out. `transcript.jsonl` per agent captures every tool call with timestamps — used in step 4 for correlation.

### Step 3 — post-scan delta + classify

Re-query the baseline surfaces. For each new alert:

| Classification | Criteria | Output |
|---|---|---|
| **scan-induced noise (our process)** | Alerting process == scan runner. Pattern matches what our scan did (e.g. "Suspicious WMI query" during our `Get-WmiObject`). | Logged in `evidence/alert-triage/noise.json`. INFO finding. |
| **scan-exposed pre-existing issue** | Our scan triggered it, but the issue was there before (EICAR in a forgotten folder; stale malware persistence). | **REAL finding.** Severity per §1. |
| **concurrent benign** | Unrelated to our scan. | Logged in `evidence/alert-triage/concurrent.json` for operator review. |
| **uncertain** | Can't confidently classify. | Flagged for manual adjudication. |

### Step 4 — verify noise

For each "scan-induced noise" entry:
- Confirm the triggering command is in `transcript.jsonl` at the matching timestamp.
- Confirm the alert pattern is in a pre-registered "expected scan artifact" list.
- If EITHER check fails → upgrade to "uncertain." Never silently dismiss.

### Final report section

```markdown
## Alert triage summary

During this scan, Windows Defender generated N new detections.

- X classified as scan-induced noise (verified — see evidence/alert-triage/noise.json).
  Common pattern: "Suspicious WMI query" from powershell.exe during services enumeration.

- Y scan-exposed pre-existing issues — real findings:
  1. <id> — <title> (severity)
  2. ...

- Z concurrent benign (unrelated to our scan).

- W uncertain — flagged for manual operator review.
```

## Report + hardening-plan shape

Every host finding carries a `hardening_plan` subobject alongside `remediation`:

```json
"hardening_plan": {
  "immediate": "icacls \"C:\\Program Files\\XYZ\\xyz.exe\" /remove:g Users",
  "configuration": "sc sdset XYZ <SDDL removing Users-change-config>",
  "monitoring": "Enable 'Audit object access' for Program Files; watch Event ID 4663 on xyz.exe",
  "compensating_controls": "WDAC policy to allow only signed binaries from this path",
  "estimated_effort": "minutes"
}
```

The synthesizer emits a top-of-report **Hardening Plan (prioritized)** section grouped by `estimated_effort`. This section IS the operator's work queue.

## Per-trial operator checklist (captured in target.yaml)

Before a host scan starts, operator confirms in `target.yaml → authorization.note`:

- [ ] Device is operator-owned (not managed, not corporate).
- [ ] `allow_admin` decision (true → run from elevated PowerShell; false → scope-stay).
- [ ] `allow_network_probe` decision (true → subnet-sweep capable; false → localhost-only).
- [ ] Backup anything important before the scan (we're read-only, but belt-and-suspenders).
- [ ] If `allow_network_probe: true`: confirm this is the operator's own network, not a corporate or public one.
- [ ] Excluded folders list (defaults: Documents, Downloads, Pictures, Videos).

## Roll-out of this methodology

- **Trial #2 (in flight at time of writing):** first live self-scan against the lead developer's Windows 11 laptop. Full admin elevation, local-subnet sweep, alert-triage active. Scrubbed Defender export + findings will be published separately under `docs/trials/` in this repo once the scan completes and the operator has scrubbed identifiable material.

- **Future:** Linux host-scan specialists (equivalent coverage: systemd units, auditd rules, pam configs, iptables/nftables, ssh_config, sudoers, installed kernel modules). macOS host-scan specialists (launchd, TCC, gatekeeper, XProtect, kext state). Both on the post-demo roadmap.
