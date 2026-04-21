<!--
PUBLIC REDACTED VERSION — REDFORGE Host-Scan Trial #1
Published: 2026-04-21 to docs/trials/2026-04-20-first-host-scan/

Redactions:
- Hostname            -> <hostname>
- Windows username    -> <operator>
- Personal emails     -> <redacted>@<provider>
- GCP target IPs      -> <GCP-target-IP-N>
- Docker Hub handle   -> <docker-user>

Preserved (public-interest threat intel):
- C2 IPs + domains (attacker infrastructure)
- Malware SHA256 hashes
- MITRE ATT&CK IDs (T1219, T1547.002, T1562.001, T1053.005, T1218.009, T1036.005, T1071.001)
- Defender detection names (Suweezy, Zilla, AsyncRAT, Ravartar, Heracles)
- Attribution indicators (VMProtect signer, Ekaterinburg / .ru TLD)
-->

# REDFORGE Host-Scan Report: <hostname>

**Target:** <hostname> (Windows 11 Pro, Build 26200, Lenovo)  
**Scan date:** 2026-04-20  
**Scan type:** Host self-scan (authorized, admin-elevated)  
**Specialists deployed:** 9 (persistence-hunt, credentials-exposure, windows-config-audit, network-listening, services-startup, network-posture, firewall-audit, local-subnet-sweep, alert-triage)

---

## INCIDENT RESPONSE NOTICE

**This machine is actively compromised.** Three independent command-and-control (C2) channels are operational, with an estimated dwell time of ~10 months. Immediate containment is required before any hardening work.

---

## Fix These First

These 6 CRITICAL findings represent active exploitation. Each satisfies all three CRITICAL criteria: exploitable today, attacker has remote/SYSTEM access, direct impact (credential theft + code execution + persistence).

### CRITICAL-1: ScreenConnect C2 to edgeserv.ru:8041 via LSA Authentication Package
**Finding:** `persistence-hunt-screenconnect-lsa-ru-c2` | **Chain:** `network-posture-screenconnect-c2-edgeserv`

A weaponized ConnectWise ScreenConnect client is installed under `C:\Program Files (x86)\Windows VC\` with service name "Visual C++" (mimicking Microsoft runtime). It connects to attacker relay `edgeserv.ru:8041` (IP: 95.214.234.238, Russian hosting). The `ScreenConnect.WindowsAuthenticationPackage.dll` is loaded as an LSA Authentication Package, executing as SYSTEM at every boot. A Credential Provider DLL hooks the login screen. Binaries are legitimately signed by ConnectWise (living-off-the-land RMM). Files dated 2025-06-13 = **~10 month dwell time**.

**Impact:** Full remote desktop control as SYSTEM. Pre-login access. File transfer, command execution, screen viewing. Complete machine takeover.

**Immediate action:**
```powershell
Stop-Service 'Visual C++' -Force
Set-Service 'Visual C++' -StartupType Disabled
# Remove LSA auth package from registry (requires reboot to unload from lsass.exe)
# Delete C:\Program Files (x86)\Windows VC\ entirely
# Block edgeserv.ru and 95.214.234.238 at DNS/firewall
```

### CRITICAL-2: data.exe Malware with HKCU Run Persistence
**Finding:** `persistence-hunt-data-exe-hkcu-run` | **Duplicate:** `services-startup-malware-data-exe-run-key`

Unsigned binary `data.exe` (OriginalFilename: `444.exe`, SHA256: `A875D4F7...0051`) at `C:\Users\<operator>\AppData\Local\data\data.exe`. Obfuscated version info (gibberish FileDescription, CompanyName). Created 2026-03-13, accessed today. Persists via HKCU Run key. Resides in Defender-excluded path. No Zone.Identifier ADS (non-browser download or ADS stripped).

**Impact:** Arbitrary code execution on every login. Zero AV interference due to exclusion coverage.

**Immediate action:**
```powershell
Stop-Process -Name data -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'data'
# Quarantine binary for forensic analysis, then delete
```

### CRITICAL-3: Defender Exclusion Tampering — C:\Users + LOLBins + Cloud Protection Disabled
**Finding:** `persistence-hunt-defender-exclusion-tampering` | **Duplicates:** `windows-config-audit-malicious-defender-exclusions`, `alert-triage-defender-missed-malware`, `alert-triage-no-defender-threat-alerts`

The entire `C:\Users` directory tree is excluded from Defender scanning. Additionally excluded: `powershell.exe`, 7 .NET LOLBins (MSBuild, InstallUtil, RegAsm, RegSvcs, AddInProcess, AppLaunch, aspnet_compiler), and specific malware paths. Cloud protection disabled (MAPSReporting=0, CloudBlockLevel=0). PUA protection, network protection, ASR rules, and controlled folder access all disabled. `IsSynchronized.exe` in exclusions bears a Russian VMProtect signature with HashMismatch.

**Impact:** Defender is effectively blind. Any malware under `C:\Users\` runs undetected. All confirmed malware (data.exe, IsCompleted.exe, syslog.exe) operates in the exclusion zone. On-demand scan of data.exe returned zero detections (confirmed by alert-triage).

**Immediate action:**
```powershell
# Remove malicious exclusions
Remove-MpPreference -ExclusionPath 'C:\Users'
Remove-MpPreference -ExclusionProcess 'powershell.exe'
# Remove all LOLBin and malware-specific exclusions (see full list in evidence)
# Re-enable cloud protection
Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -CloudBlockLevel High
Set-MpPreference -PUAProtection Enabled -EnableNetworkProtection Enabled
# Run full scan
Start-MpScan -ScanType FullScan
```

### CRITICAL-4: IsCompleted.exe Malware via Scheduled Task (5m44s Re-execution)
**Finding:** `persistence-hunt-sched-task-iscompleted` | **Duplicate:** `services-startup-malware-iscompleted-schtask`

Unsigned binary `IsCompleted.exe` (OriginalFilename: `Bcesuajgcga.exe`, SHA256: `41C431DC...5E4B`, 557 KB) at `C:\Users\<operator>\AppData\Local\Count\nabqt\`. Registered as scheduled task `\Microsoft\Windows\Count\IsCompleted` (masquerading under legitimate Windows path). RunLevel=Highest, repeating every 5 minutes 44 seconds (unusual interval = anti-detection). Actively running during scan. Created 2025-09-30.

**Impact:** Guaranteed re-execution every ~6 minutes even if killed. Elevated execution. Redundant persistence alongside data.exe and ScreenConnect.

**Immediate action:**
```powershell
Stop-Process -Name IsCompleted -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'IsCompleted' -TaskPath '\Microsoft\Windows\Count\' -Confirm:$false
# Quarantine binary, then delete C:\Users\<operator>\AppData\Local\Count\
```

### CRITICAL-5: syslog.exe C2 Beaconing to 64.74.162.109:443
**Finding:** `network-posture-syslog-unsigned-c2`

Unsigned executable `syslog.exe` (SHA256: `F2110725...CD8B`) running from `C:\Users\<operator>\AppData\Local\packages\syslog.exe`. Claims Company="Linker Corporation" (fabricated). Active outbound HTTPS to 64.74.162.109:443 (no reverse DNS). Local loopback socket pair suggests tunneling/proxy capability. Running since boot (2+ days).

**Impact:** Third independent C2 channel over HTTPS. Blends with legitimate traffic on port 443.

**Immediate action:**
```powershell
Stop-Process -Name syslog -Force
# Quarantine binary, block 64.74.162.109 at firewall
# Search for persistence mechanism (Run key, scheduled task, or service)
```

### CRITICAL-6: RegAsm.exe LOLBin with Dual C2 to 130.12.180.159:56009
**Finding:** `network-posture-regasm-lolbin-c2`

Microsoft-signed `RegAsm.exe` (C:\Windows\Microsoft.NET\Framework\v4.0.30319\) maintaining two concurrent TCP connections to 130.12.180.159:56009. RegAsm should never make outbound connections — this is MITRE T1218.009 (Signed Binary Proxy Execution). A malicious .NET assembly is being loaded through RegAsm to achieve code execution under a trusted Microsoft binary.

**Impact:** C2 through a Microsoft-signed binary. Evades application whitelisting and most EDR. The malicious assembly DLL needs to be located on disk.

**Immediate action:**
```powershell
Stop-Process -Id 2572 -Force
# Block 130.12.180.159 at firewall
# Investigate: Get-CimInstance Win32_Process -Filter 'ProcessId=2572' | Select CommandLine
# Find and quarantine the malicious .NET assembly
```

---

## Attack Chain Analysis

### Chain 1: Multi-Channel Persistent Compromise (PRIMARY)
```
Initial Access (unknown, ~Jun 2025)
  -> ScreenConnect RMM deployed as "Visual C++" (T1219, T1036.005)
  -> LSA Auth Package for SYSTEM persistence (T1547.002)
  -> Defender exclusions planted: C:\Users, powershell.exe, LOLBins (T1562.001)
  -> data.exe (444.exe) dropped via HKCU Run (T1547.001)
  -> IsCompleted.exe (Bcesuajgcga.exe) via scheduled task (T1053.005)
  -> Ghost tasks (EncoderFallback, IsSynchronized) as backup persistence (T1053.005)
  -> syslog.exe planted as secondary C2 (T1071.001)
  -> RegAsm.exe LOLBin as tertiary C2 (T1218.009)
```
**Dwell time:** ~10 months (Jun 2025 to Apr 2026)  
**C2 channels:** 3 independent (ScreenConnect, syslog.exe, RegAsm.exe)  
**Redundancy:** 4+ persistence mechanisms ensure reinfection if any single one is cleaned

### Chain 2: Credential Access from Compromised Host
```
Active C2 access (any channel)
  -> Browser password extraction (Edge 1MB+, Chrome, Brave) via DPAPI
  -> Windows Credential Manager (22 entries: GitHub, Docker Hub, Microsoft, OAuth)
  -> SSH key exfiltration (unencrypted id_ed25519 + google_compute_engine)
  -> PuTTY host cache reveals GCP IPs (<GCP-target-IP-1>, <GCP-target-IP-2>, <GCP-target-IP-3>)
  -> VNC auth cookie extraction from registry
  -> Tailscale node state from ProgramData
  -> WiFi passwords (20 profiles, cleartext via admin)
```

### Chain 3: Privilege Escalation via Service Binary Hijack
```
Authenticated user access (standard user sufficient)
  -> C:\GenRad, C:\DENSO, C:\i-HDS all grant Authenticated Users Modify (CWE-732)
  -> Replace TDSNetSetup.exe (LocalSystem service) or TDSReanimator.exe (HKLM Run)
  -> Next service start or admin logon = code execution as SYSTEM or admin
```

---

## Main Findings — exploitable_now = true

Findings below are exploitable with the system as-configured. Sorted by severity, then confidence.

### HIGH (22 unique after deduplication)

| # | ID | Title | Specialist | Est. Effort |
|---|-----|-------|-----------|-------------|
| 1 | persistence-hunt-ghost-tasks | Ghost scheduled tasks (EncoderFallback, IsSynchronized) — dormant reinfection | persistence-hunt | minutes |
| 2 | VNC cluster (4 findings) | Tampered vncserver.exe (SYSTEM, HashMismatch) + 0.0.0.0 binding + 4 Public ANY/ANY rules + auth cookie | network-listening, services-startup, firewall-audit, credentials-exposure | hours |
| 3 | credentials-exposure-unencrypted-ssh-private-keys | 3 SSH private keys without passphrase (ed25519 + GCP RSA + PPK) | credentials-exposure | 30 min |
| 4 | credentials-exposure-credential-manager + browser-stores | 22 Credential Manager entries + 3 browser password DBs (Edge 1MB+) | credentials-exposure | hours |
| 5 | credentials-exposure-tailscale-state | Tailscale node state in ProgramData readable by all authenticated users | credentials-exposure | 30 min |
| 6 | windows-config-audit-no-asr-rules | Zero ASR rules; cloud protection, PUA, network protection all OFF | windows-config-audit | hours |
| 7 | windows-config-audit-minimal-audit-policy | No process creation, object access, privilege use, or credential validation auditing | windows-config-audit | hours |
| 8 | windows-config-audit-ps-execution-policy-bypass | PowerShell ExecutionPolicy=Bypass (Process + CurrentUser) + Defender-excluded | windows-config-audit | minutes |
| 9 | windows-config-audit-stale-os-patches | 4+ months since last security update (KB5068861, Nov 2025) | windows-config-audit | hours |
| 10 | Firewall cluster (4 findings) | All profiles: logging OFF, DefaultInbound=NotConfigured, no egress filtering | firewall-audit, windows-config-audit, network-posture | hours |
| 11 | network-listening-netbios-all-adapters | NetBIOS TCP 139 + UDP 137/138 on all 4 adapter IPs | network-listening | 30 min |
| 12 | network-listening-smb-ipv6-no-encryption | SMB 445 on :: with EncryptData=False | network-listening | minutes |
| 13 | firewall-audit-user-writable-path-rules | 12+ inbound allow rules for binaries in AppData/TEMP/Downloads | firewall-audit | hours |
| 14 | firewall-audit-utorrent-any-any-any | uTorrent: Profile=Any, Port=Any, RemoteAddress=Any in user-writable path | firewall-audit | minutes |
| 15 | services-startup-genrad-root-dir-acl + children | C:\GenRad/DENSO/i-HDS: Authenticated Users Modify -> 4 service/Run key hijacks | services-startup | hours |
| 16 | local-subnet-sweep-gw-admin-http | Gateway 192.168.0.1 admin on HTTP (MITM risk for router creds) | local-subnet-sweep | minutes |
| 17 | alert-triage-defender-missed-malware | Defender on-demand scan returned 0 detections on confirmed C2 binary | alert-triage | hours |
| 18 | alert-triage-no-defender-threat-alerts | Zero threat alerts despite 3 active C2 channels | alert-triage | hours |

---

## Hardening Recommendations

Findings below are not directly exploitable today but represent posture weaknesses that should be addressed after incident containment.

### Hardening Plan (grouped by estimated effort)

#### Minutes
| Finding | Action |
|---------|--------|
| SMB EncryptData=False | `Set-SmbServerConfiguration -EncryptData $true -Force` |
| LmCompatibilityLevel=3 (default) | `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f` |
| EPSDNMON empty Run key | `Remove-ItemProperty HKCU:\...\Run -Name EPSDNMON` |
| SSH key ACLs (Admins FullControl) | `icacls` to remove BUILTIN\Administrators from private keys |
| Stale onvue.exe firewall rules (4) | `Remove-NetFirewallRule` for all 4 temp-path rules |
| nut.exe Downloads firewall rules | `Remove-NetFirewallRule` for both rules |
| Docker HOSTS stale IP (.116 vs .114) | Update `C:\Windows\System32\drivers\etc\hosts` |

#### Hours
| Finding | Action |
|---------|--------|
| D: drive (EASUS) unencrypted | `Enable-BitLocker -MountPoint D: -EncryptionMethod XtsAes256` |
| ScreenConnect orphaned LSA DLL | Remove from LSA Auth Packages registry if service deleted |
| Epson Event Manager on 0.0.0.0:2968 | Scope to Wi-Fi adapter or disable |
| ICS DNS resolver on 0.0.0.0:53 | Firewall block UDP/TCP 53 on Wi-Fi + Tailscale interfaces |
| RPC 135 on all interfaces | Scope firewall rules to trusted networks |
| Unsigned mDNSResponder in SysWOW64 | Update or remove Bonjour |
| Flat LAN, 15+ devices, no segmentation | Move IoT to guest network / VLAN |
| Epson printer admin unauthenticated | Set admin password on printer |
| WiFi profiles (20, cleartext recovery) | Prune unused profiles |
| Docker Hub persistent tokens | Rotate tokens, enable 2FA |
| LM Studio in user-writable AppData | Move to Program Files or remove auto-start |
| Daemon Update in writable ProgramData | Fix directory ACLs |
| HOSTS license server sinkholing | Audit software licensing |
| PuTTY SSH host cache (GCP IPs) | Migrate to OpenSSH; clear stale entries |

#### Days
| Finding | Action |
|---------|--------|
| Full CIS Windows 11 audit policy | Configure per Microsoft security baseline |
| Application whitelisting (WDAC/AppLocker) | Block unsigned binaries from user-writable paths |
| Egress firewall policy | Default-deny outbound with explicit allow-list |
| Network segmentation | IoT VLAN, management VLAN, user VLAN |

---

## Duplicate Cluster Resolution

| Cluster | Primary Finding | Duplicates Absorbed | Resolution |
|---------|----------------|-------------------|------------|
| data.exe malware | persistence-hunt-data-exe-hkcu-run | services-startup-malware-data-exe-run-key | Same binary, same Run key. persistence-hunt found first with deeper analysis. |
| IsCompleted.exe malware | persistence-hunt-sched-task-iscompleted | services-startup-malware-iscompleted-schtask | Same task, same binary. services-startup added 5m44s interval detail. |
| Defender exclusions | persistence-hunt-defender-exclusion-tampering | windows-config-audit-malicious-defender-exclusions, alert-triage-defender-missed-malware, alert-triage-no-defender-threat-alerts | Same root cause (T1562.001). Four specialists found it from different angles: exclusion list, VMProtect binary, scan bypass, zero alerts. |
| ScreenConnect C2 | persistence-hunt-screenconnect-lsa-ru-c2 | network-posture-screenconnect-c2-edgeserv, windows-config-audit-screenconnect-lsa-package | persistence-hunt: LSA persistence. network-posture: active network connection. config-audit: orphaned DLL. |
| VNC exposure | network-listening-vnc-all-interfaces | network-listening-vnc-binary-hash-mismatch, services-startup-vncserver-hash-mismatch, firewall-audit-vnc-public-any-any, credentials-exposure-vnc-auth-cookie | Five specialists flagged different aspects. Consolidated as single HIGH cluster. |
| Firewall posture | firewall-audit-profiles-not-configured | windows-config-audit-firewall-no-logging, network-posture-firewall-no-egress, firewall-audit-no-outbound-restriction | Same firewall configuration. Four findings from different scopes (profiles, logging, egress, C2 bypass). |
| Service binary hijack | services-startup-genrad-root-dir-acl | services-startup-tdsnetsetup, services-startup-dst-iagent, services-startup-iqsext, services-startup-tdsreanimator | All caused by one root cause: overpermissive ACLs on C:\ root-level directories. |

---

## Finding Counts

| Severity | Raw | After Dedup | exploitable_now |
|----------|-----|-------------|-----------------|
| CRITICAL | 10 | 6 | 6 (all) |
| HIGH | 34 | 18 | 16 |
| MEDIUM | 17 | 14 | 10 |
| LOW | 9 | 8 | 0 |
| INFO | 9 | - | - |
| **Total** | **79** | **46** | **32** |

---

## Novel Patterns

Findings flagged `novel_pattern: true` that may generalize into detection rules:

1. **ScreenConnect RMM as C2 via LSA Auth Package** — Legitimately signed ConnectWise binary pointed at attacker relay. Detection: alert on ScreenConnect service names not matching "ScreenConnect" or relay domains outside `*.screenconnect.com`.

2. **Ghost tasks with pre-placed Defender exclusions** — Scheduled tasks + matching exclusions, binaries deleted. The exclusions persist as dormant reinfection vectors. Detection: cross-reference Defender exclusion paths with non-existent files.

3. **syslog.exe masquerading in AppData\Local\packages** — Fake Windows Store package path. Detection: alert on executables in `packages\` that aren't UWP AppX packages.

4. **Firewall rules for user-writable TEMP paths** — Exam software leaves persistent firewall holes. Detection: audit rules referencing `%TEMP%` or `AppData\Local\Temp`.

5. **5m44s scheduled task interval** — Non-round-number interval likely designed to evade pattern-based detection. Detection: flag task repetition intervals that aren't standard multiples (1m, 5m, 10m, 15m, 30m, 1h).

---

## Recommended Incident Response Sequence

1. **Network isolation** — Disconnect from Wi-Fi or block C2 IPs at router (95.214.234.238, 64.74.162.109, 130.12.180.159).
2. **Kill active malware** — Stop processes: ScreenConnect, data.exe, syslog.exe, RegAsm.exe (PID 2572), IsCompleted.exe.
3. **Remove persistence** — Delete Run keys, scheduled tasks (IsCompleted, EncoderFallback, IsSynchronized), ScreenConnect service + LSA registration.
4. **Restore Defender** — Remove all malicious exclusions, re-enable cloud protection, run full scan.
5. **Credential rotation** — ALL credentials accessible from this machine are potentially compromised: GitHub tokens, Docker Hub, Microsoft accounts, SSH keys, WiFi passwords, browser-saved passwords, VNC, Tailscale. Rotate everything.
6. **Forensic preservation** — Before deleting malware binaries, copy them to an isolated location for analysis. Hash them and submit to VirusTotal.
7. **Patch** — Install all pending Windows updates.
8. **Harden** — Apply the hardening recommendations above, starting with firewall logging and egress filtering.

---

*Report generated by REDFORGE multi-agent host-scan system.*  
*9 specialist agents, 79 raw findings, 46 unique after deduplication.*  
*Scan duration: ~60 minutes active enumeration.*
