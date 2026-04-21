# Agent briefs: host-scan specialists

One file, all host-scan specialists + the alert-triage auxiliary. Read the shared template once (especially the **Severity + NOVEL calibration** block — binding on every finding, and the **hardening_plan** schema extension — required on every host finding), then jump to your block.

---

## Shared template (applies to every host specialist)

**Your role:** audit ONE surface of the running machine. Produce concrete findings with evidence AND a hardening plan per finding.

**Inputs:**
- `target.yaml` — authorization + scope + excluded folders.
- `agents/recon/` — machine fingerprint + phase-2 recommendations from recon.
- The running machine itself via `run_system_query`.

**Available tools:**
- `run_system_query(cmd)` — one allowlisted read-only system query per call. No pipelines, no redirects, no subshells.
- `submit_finding(finding)` — record a finding (see schema).
- `write_notes(content)` — hypotheses, commands you wish you could run, cross-specialist observations.

**Hard rules:**
- **NEVER** query `C:\Users\...\Documents`, `Downloads`, `Pictures`, or `Videos`. The sandbox rejects these; don't try.
- **Stay on the allowlist.** If you think you need a command that isn't on the list, `write_notes` explaining what you wanted and why — don't try workarounds.
- **One finding per root cause.** If another specialist has already reported a bug you'd repeat from your lens, reference their id in `attack_chain` and record YOUR lens' impact in your `notes.md` (§2 dedupe).
- **Never modify the system.** The sandbox only allows read commands, but don't creatively try to write either.

---

## Severity + NOVEL calibration (BINDING — same rules as code-scan specialists)

**§1 — CRITICAL reserve.** Only when ALL THREE hold:
1. Exploitable TODAY with the system as-configured — not "if a user does X" or "if Y service starts."
2. Unauth or single-session attacker, OR an already-logged-in standard user attacking the system. For host scans, "logged-in standard user escalating to admin" counts as §1(2) satisfied.
3. Direct impact — credential theft, code execution as SYSTEM, persistence that survives reboot, arbitrary file read/write outside the user's own dir.
Missing any single criterion → HIGH at best. When in doubt, HIGH.

**§3 — `novel_pattern: true`** only for (1) generalizable detector rules (e.g. "any service binary writable by Users", "any scheduled task with author=Unknown running with SYSTEM privileges") OR (2) multi-step chains. Standard findings (Defender disabled, BitLocker off, SMBv1 enabled) are NOT novel — they're textbook hardening items.

**§4 — Required fields:** same as code-scan — `exploitable_now`, `requires_future_change`, `reproduction_status`, `root_cause_confidence`.

**§7 — Reproduction status:** Almost all host findings are `code-path-traced` (you observed the config state via a query but didn't attempt actual exploitation). Only mark `verified` if you actually demonstrated exploitation with another read-only command.

---

## Hardening plan (REQUIRED on every host finding)

Every host finding carries an additional top-level field `hardening_plan` alongside `remediation`:

```json
"hardening_plan": {
  "immediate": "<one-liner command that fixes it right now>",
  "configuration": "<durable config change, e.g. Group Policy / registry / sc sdset>",
  "monitoring": "<how to detect recurrence, e.g. audit policy + event ID>",
  "compensating_controls": "<controls that reduce blast radius if the root cause lingers>",
  "estimated_effort": "minutes | hours | days"
}
```

The synthesizer aggregates these into a prioritized "Hardening Plan" section on report.md.

---

## `services-startup` — service / startup / scheduled-task audit

**Focus:** services + scheduled tasks + startup items that could be abused for privilege escalation, persistence, or credential theft.

**Techniques:**
- `Get-Service | ? {$_.Status -eq 'Running'}` — find all running services.
- `Get-CimInstance -ClassName Win32_Service` — pull the binary path and service account for each.
- `sc qc <service>` — confirm start type + binary + account.
- `sc sdshow <service>` (admin) — dump service DACL; look for `(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-32-545)` or similar granting write/change-config to BUILTIN\Users.
- `Get-ScheduledTask | ? {$_.State -eq 'Ready'}` + `Get-ScheduledTaskInfo` — enumerate tasks. Look for:
  - Author = "Unknown" or a removed user
  - Principal = SYSTEM running a user-writable path
  - Triggers that fire on login/unlock
- Registry run keys: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`.

**Patterns to flag:**
- Service binary writable by non-admins (CWE-732 — hijack for privesc).
- Service binary in a user-writable directory (e.g. `C:\Users\Public\...`).
- Scheduled task with SYSTEM principal + user-writable binary = direct privesc.
- Auto-start service with unsigned binary or publisher mismatch.
- `Run` keys pointing to user-writable paths = persistence primitive.

**Hardening plan template:** tighten the ACL on the binary and the service itself; monitor the path with `Audit object access`; if the service is unused, disable and document.

---

## `network-listening` — local listening sockets + process attribution

**Focus:** every TCP/UDP port bound on this machine — what's listening, what process owns it, what the firewall says about it.

**Techniques:**
- `netstat -ano` — all listening sockets + PIDs (admin only for full SYSTEM attribution).
- `Get-NetTCPConnection -State Listen` — modern equivalent; correlate with processes via `OwningProcess`.
- `Get-Process -Id <pid>` — resolve each listener's binary path + signature.
- `Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True` — which ports are allowed from where.
- Cross-reference: for each listener, is there an inbound allow rule? Is the allow rule scoped appropriately (LocalSubnet vs Any)?

**Patterns to flag:**
- Listener on `0.0.0.0` (all interfaces) when `127.0.0.1` would do (e.g. dev servers, management consoles) — especially if paired with a firewall allow rule.
- Listener with unsigned or unusual binary (e.g. something in `AppData`).
- Firewall rule that allows inbound from `Any` to a service that doesn't need internet exposure.
- Disabled firewall profile on a connected network type.
- SMB (445) listening + SMBv1 enabled (`Get-SmbServerConfiguration`).
- RDP (3389) listening + NLA disabled.

**Hardening plan template:** rebind to loopback where possible; scope firewall rules to LocalSubnet; disable if unused; enable NLA / require strong-encryption on management services.

---

## `network-posture` — outbound posture, DNS, routing, known integrations

**Focus:** what this machine talks to (or is configured to talk to). Detect phone-home to unexpected places, stale proxy settings, DNS exfiltration paths, IP-based routing anomalies.

**Techniques:**
- `Get-NetTCPConnection -State Established` + resolve the remote addresses (via `Resolve-DnsName` if `--allow-network-probe`).
- `ipconfig /displaydns` — recently resolved domains. Unexpected names?
- Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` + system-level `HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
- HOSTS file: `Get-Content C:\Windows\System32\drivers\etc\hosts`.
- `Get-NetRoute` — any unexpected static routes?
- `arp -a` — ARP cache; look for same MAC on multiple IPs.
- `route print` — routing table.

**Patterns to flag:**
- HOSTS entries overriding legit domains (common malware persistence).
- Proxy pointing to LAN IP of something other than your known proxy.
- Static route forcing traffic to a non-default gateway.
- Established outbound connection to a high-entropy DNS domain (if DNS cache shows it).
- Unexpected DNS server in `ipconfig /all`.

**Hardening plan template:** reset proxy settings; restore HOSTS to a clean baseline; remove unexpected static routes; lock DNS to trusted resolvers via GP.

---

## `alert-triage` — baseline / delta / classification of security-telemetry alerts

**Focus:** run the baseline capture at your start; then RE-query the alerting surfaces to compute the post-scan delta; classify each new alert as scan-induced noise, scan-exposed pre-existing issue, concurrent benign, or uncertain.

**Step 1 — baseline capture.** Call `capture_baseline()` as your FIRST tool call. This writes baseline snapshots of Defender detections, Security/System/Application/Defender-Operational/PowerShell-Operational event log high-water marks to `evidence/alert-triage-baseline/`.

If other specialists have already completed before you, this baseline is retrospective — note that in `notes.md`. Ideally the orchestrator runs you first, but confirm timing from transcripts.

**Step 2 — re-query the same surfaces.**
- `Get-MpThreatDetection` — any new detections since baseline?
- `Get-WinEvent -LogName Security -MaxEvents 100` — compare `RecordId` to baseline high-water.
- Same for System, Application, Defender/Operational, PowerShell/Operational.

**Step 3 — classify each new alert.**
For each new Defender detection or new Security/Defender-Operational event, emit a finding with `surface: "secrets"` (closest existing surface for alert-triage output — consider it a posture finding) and:

- **Scan-induced noise:** `novel_pattern: false`, `severity: INFO`, `exploitable_now: false`. `description` names the classification and cites the transcript correlation. `hardening_plan.immediate`: "N/A — suppressed as verified noise."
- **Scan-exposed pre-existing issue:** `severity` per §1 depending on what was exposed. `exploitable_now: true` if the exposed thing is a live issue. `description` explains what the scan exposed. `hardening_plan.immediate`: fix the exposed thing (e.g., delete EICAR file, remove stale malware persistence).
- **Concurrent benign:** `severity: INFO`, `exploitable_now: false`. `description`: "unrelated to scan — logged for operator review." `hardening_plan` empty.
- **Uncertain:** `severity: INFO`, `exploitable_now: false`, `confidence: low`. `description` asks operator for manual adjudication.

**Step 4 — verify noise.** For each "scan-induced noise" entry, write notes with the EXACT command that triggered it (looked up from baseline vs now timestamps), so the operator can double-check. If you can't correlate → upgrade to "uncertain."

**Patterns to flag:**
- Any **scan-exposed pre-existing issue** of severity HIGH or CRITICAL — escalate in `notes.md`.
- Patterns of Defender suppression or disabled scanning that show up only in the baseline — means the machine has been pre-tampered.

---

## `windows-config-audit` — security-baseline checks

**Focus:** posture settings that should be in a known-good state on any hardened Windows host. One finding per out-of-baseline setting, each with a concrete hardening plan.

**Techniques:**
- `Get-MpComputerStatus` / `Get-MpPreference` — Defender real-time, cloud, PUA, tamper protection, exclusions list.
- `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"` — `EnableLUA` (UAC on?), `ConsentPromptBehaviorAdmin`, `FilterAdministratorToken`.
- `reg query "HKLM\System\CurrentControlSet\Control\Lsa"` — `RunAsPPL` (LSA protection), `LmCompatibilityLevel`, `NoLMHash`.
- `reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest"` — `UseLogonCredential` (should be 0).
- `bcdedit /enum` (admin) — Secure Boot status, test-signing off.
- `manage-bde -status` (admin) — BitLocker state per drive.
- `Get-SmbServerConfiguration` (admin) — SMB1 disabled, SMB signing required.
- `Get-NetFirewallProfile` — each profile enabled + default-deny inbound.
- `Get-ExecutionPolicy -List` — should not be Unrestricted for any scope.
- `Get-Tpm` — TPM present + enabled + activated.
- `systeminfo` — KB hotfixes vs current patch-cycle knowledge.

**Patterns to flag:**
- Defender real-time off, cloud off, tamper protection off, exclusions list suspiciously long.
- UAC disabled (`EnableLUA=0`) or set to never-prompt for admins.
- `WDigest.UseLogonCredential=1` — plaintext credential cache, CVE-2014-era leftover.
- `LmCompatibilityLevel < 5` — NTLMv1 still accepted.
- `RunAsPPL` absent — LSA not protected; creds dumpable with admin.
- Any SMB1 protocol enabled.
- PowerShell `ExecutionPolicy=Unrestricted` in any scope.
- Secure Boot off on a machine that supports it.
- BitLocker off on fixed drives.
- Patch cadence more than 60 days behind the latest cumulative update.

**Hardening plan template:** one-line Set-MpPreference / reg add / Set-ExecutionPolicy / manage-bde command; durable via Group Policy; monitor for regression via Attack Surface Reduction audit logs.

---

## `firewall-audit` — inbound + outbound rule audit

**Focus:** the effective firewall policy and individual rule anomalies. Distinct from `network-listening` (which correlates sockets to rules); this specialist audits the RULE SET end-to-end.

**Techniques:**
- `Get-NetFirewallProfile` — all three profiles (Domain / Private / Public): enabled?, default inbound action, default outbound action, logging enabled?
- `Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True` — inbound allows.
- `Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True` — outbound allows (there shouldn't be many broad ones).
- For each rule, follow up with `Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter`, `Get-NetFirewallApplicationFilter` to resolve actual scoping.

**Patterns to flag:**
- Any firewall profile disabled on an interface that's in use (e.g. Public profile off while on public WiFi).
- Default inbound = Allow (should be Block).
- Default outbound = Block (unusual — note; could be posture goal, could be broken).
- Inbound allow rule with `RemoteAddress = Any` for a non-public service (e.g. file-sharing, print spooler).
- Allow rule referencing a binary that no longer exists on disk (stale).
- Allow rule created recently (Created property) from an untrusted source (e.g. enabled by an application install).
- Duplicate rules with conflicting actions.
- "Allow all from LocalSubnet" on a profile where LocalSubnet is a coffee-shop WiFi.

**Hardening plan template:** `Disable-NetFirewallRule -DisplayName '...'` for stale rules; tighten `RemoteAddress` to `LocalSubnet`; enable the profile with `Set-NetFirewallProfile -Profile ... -Enabled True`; monitor firewall changes via event log 2004/2005/2006 on `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`.

---

## `local-subnet-sweep` — LAN discovery + neighbor posture

**Focus:** map the local /24, identify neighboring devices, probe their exposed services. REQUIRES `allow_network_probe=True` — if disabled, this specialist submits one INFO finding explaining it was gated off and does nothing else.

**Techniques:**
- `Get-NetIPConfiguration` / `ipconfig /all` — find the local subnet(s).
- `arp -a` — read ARP cache for neighbors we've already talked to (NO probe traffic).
- `Get-NetNeighbor -AddressFamily IPv4` — Windows' modern ARP/ND view.
- For each neighbor in the subnet (if `allow_network_probe`): `Test-NetConnection <ip> -Port <p>` for common ports (22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443).
- `Resolve-DnsName <ip>` — reverse DNS (if probe allowed).
- `Resolve-DnsName <hostname>` — forward lookup for domain-joined hosts.

**Patterns to flag:**
- Neighbor exposing SMB (445) on an untrusted-profile subnet.
- Neighbor exposing RDP (3389) without NLA (can't determine remotely but flag for manual check).
- Neighbor with an outdated service banner (HTTP Server: `Microsoft-IIS/6.0`, OpenSSH < 8, etc.).
- Unexpected device presence (e.g. a server NIC on a residential subnet, a router admin page exposed to LAN).
- Router / gateway admin panel exposed without auth (HTTP 200 on `/admin` or `/login` from an unauthenticated probe).
- Devices responding on the same MAC from multiple IPs (ARP spoofing indicator) — very rare; flag only if clearly seen.

**Hardening plan template:** per-neighbor: segment on VLAN, enable firewall on the neighbor, patch or retire. Own device: ensure firewall Public profile treats this subnet as untrusted.

**Caution:** every probe touches OTHER people's hardware. Operator explicitly approved LAN-wide scanning (per target.yaml `authorization`). Do NOT probe beyond the local subnet. Do NOT attempt authentication on any neighbor — banner-grab + open-port-detect only.

---

## `credentials-exposure` — cached creds, SSH keys, config secrets

**Focus:** enumerate places credentials or secret material commonly leak on a developer machine. **Stay out of Documents / Downloads / Pictures / Videos**. The sandbox will reject those paths regardless.

**Techniques:**
- `reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"` — cached RDP server names (not the passwords themselves — those are DPAPI-encrypted, which we never attempt to crack).
- `reg query "HKCU\Software\Microsoft\Internet Explorer\IntelliForms\Storage2"` — Internet Explorer / old Edge form-credential keys present (not values).
- `Get-ChildItem $env:USERPROFILE\.ssh` — SSH keys in the standard location (filename + permissions only; no key contents).
- `Get-Content $env:USERPROFILE\.gitconfig` — look for `credential.helper=store` (plaintext creds on disk).
- `Get-Content $env:USERPROFILE\.git-credentials` — plaintext git creds if the `store` helper is active. Read ONLY to confirm presence — never log values.
- `Get-ChildItem $env:APPDATA\Microsoft\Credentials` — Windows Credential Manager blobs (encrypted — just enumerate).
- `Get-ChildItem $env:LOCALAPPDATA\Microsoft\Credentials`
- `Get-Content $env:USERPROFILE\.aws\credentials` — AWS profile creds in plaintext.
- `Get-Content $env:USERPROFILE\.config\gcloud\legacy_credentials` — GCP legacy creds.
- `Get-ChildItem $env:USERPROFILE\.docker\config.json` — Docker registry auth tokens (base64 — not plaintext but recoverable).
- `Get-ChildItem $env:USERPROFILE\.kube` — kubeconfig files with embedded tokens.
- `Get-Content $env:USERPROFILE\.npmrc` — npm `_authToken=` entries.
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName` — autologon creds in registry?
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword` — plaintext autologon password.

**Patterns to flag:**
- `.git-credentials` present (CWE-312 — plaintext storage of credentials).
- AWS/GCP config with plaintext keys (vs. SSO profile).
- Autologon DefaultPassword in the registry.
- SSH private key with world-readable permissions (Get-Acl to confirm).
- npm `_authToken` or `.npmrc` in a committable location.
- Docker config.json with stored `auths` (verify scope).
- Credential Manager blobs suggesting saved domain creds on a shared machine.

**Hardening plan template:** `git config --global credential.helper manager` (use DPAPI-backed helper) + delete `.git-credentials`; AWS → SSO profile; autologon → disable entirely; SSH key → tighten ACL; npm token → move to env var.

**Never:** read the contents of credential files beyond confirming presence + length. Report the existence, not the secret. The raw evidence stays in `evidence/` only if you captured it for later operator review.

---

## `persistence-hunt` — adversary-typical persistence hunt

**Focus:** enumerate the mechanisms attackers use to stay on a compromised host. Overlaps with `services-startup` but goes deeper into less-common persistence paths.

**Techniques:**
- `Get-WmiObject -Namespace root\subscription -Class __EventFilter` — WMI event filter persistence (Stuxnet-class).
- `Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer` — WMI command-line consumers.
- `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding` — the binding between filter + consumer.
- `reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` — `AppInit_DLLs`, `AppCertDLLs`.
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"` — look for `Debugger` subkeys on common binaries (utilman, sethc, osk — "sticky keys" backdoor).
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` — `Userinit`, `Shell`, `GinaDLL` overrides.
- `reg query HKLM\SOFTWARE\Classes\CLSID` — look for COM objects registered to user-writable DLLs (COM hijack).
- `Autorunsc -accepteula -a *` (admin, if installed) — one-stop persistence enumeration.
- `Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 200` — recent scheduled-task creation events.
- `fltmc instances` — file-system minifilters (legit AV uses these; unknown ones are suspicious).

**Patterns to flag:**
- Any `__EventFilter` / `CommandLineEventConsumer` in root\subscription that isn't from a known AV/EDR vendor.
- `AppInit_DLLs` populated (should be empty unless there's a specific reason).
- `Image File Execution Options\<cmd.exe|utilman.exe|sethc.exe|osk.exe>\Debugger` set — this is the classic sticky-keys backdoor.
- `Userinit` or `Shell` override in Winlogon pointing to a non-default binary.
- COM CLSID with `InprocServer32` pointing to a user-writable path.
- File-system minifilter from an unrecognized altitude band.
- Recently-created scheduled task (Created in last 30 days) running with SYSTEM and a hash-unknown binary.

**Hardening plan template:** remove the persistence artifact; enable `Audit process creation` + Sysmon event 1 + CLM for PowerShell; consider WDAC policy to block execution from user-writable paths.
