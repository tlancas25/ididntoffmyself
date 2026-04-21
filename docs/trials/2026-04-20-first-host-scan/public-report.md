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

# REDFORGE Case Study: 10-Month Compromise on a Second-Hand Windows Machine

**Published:** 2026-04-20  
**Tool:** REDFORGE Multi-Agent AI Red Team Platform  
**Target:** Personal Windows 11 Pro laptop (purchased second-hand)  
**Classification:** Real-world incident — discovered during authorized self-scan

---

## Summary

A routine REDFORGE self-scan intended to generate a preventative hardening report instead uncovered an active, multi-channel compromise with an estimated 10-month dwell time. The machine — purchased from a thrift store — had been backdoored before the current owner ever used it. Three independent command-and-control (C2) channels were operational, Windows Defender had been systematically neutralized, and at least 8 distinct malware families had been deployed over the course of the intrusion.

REDFORGE detected, verified, contained, forensically investigated, and fully remediated the compromise in a single automated session using 9 parallel specialist agents. Post-cleanup, with Defender exclusions removed, the full system scan discovered two additional hidden malware binaries (AsyncRAT and a Zilla trojan) that had been invisible for 7+ months — bringing the total to 8 distinct malware deployments.

---

## How It Was Found

REDFORGE's host-scan mode deploys 9 specialist agents in parallel, each auditing a different attack surface:

| Specialist | Focus |
|-----------|-------|
| persistence-hunt | Registry, scheduled tasks, WMI, LSA, COM hijack |
| credentials-exposure | SSH keys, credential stores, browser passwords, tokens |
| windows-config-audit | Defender, UAC, LSA, BitLocker, patches, audit policy |
| network-listening | Open ports, process attribution, firewall correlation |
| services-startup | Service binaries, DACLs, startup items, scheduled tasks |
| network-posture | Outbound connections, DNS, routing, HOSTS, proxy |
| firewall-audit | Rule set analysis, stale rules, user-writable path rules |
| local-subnet-sweep | LAN neighbor discovery, port probing, device identification |
| alert-triage | Pre/post scan Defender delta, event log classification |

The `persistence-hunt` specialist flagged the first indicators within minutes: an unsigned binary with obfuscated metadata auto-starting from a user-writable path, and a ScreenConnect remote access client disguised as "Visual C++" connecting to a Russian-hosted relay server. The `network-posture` specialist independently discovered two additional C2 channels by analyzing outbound established connections.

---

## The Compromise

### Three Independent C2 Channels

| Channel | Disguise | Destination | Method |
|---------|----------|-------------|--------|
| ScreenConnect RMM | Windows service named "Visual C++" in `Program Files (x86)\Windows VC\` | Russian relay server on port 8041 | Legitimately signed ConnectWise binaries pointed at attacker infrastructure (Living-off-the-Land RMM) |
| Custom beacon | `syslog.exe` in `AppData\Local\packages\` mimicking a Windows Store app | External IP on HTTPS (port 443) | Unsigned binary with fabricated vendor metadata and fake Windows version strings |
| .NET LOLBin proxy | `RegAsm.exe` (Microsoft-signed .NET Assembly Registration Utility) | External IP on high ephemeral port | Malicious .NET assembly loaded through legitimate Microsoft binary (MITRE T1218.009) |

### Malware Arsenal

| Binary | Threat Classification | Persistence | Deployed | Size |
|--------|----------------------|------------|----------|------|
| ScreenConnect suite | Living-off-Land RMM (ConnectWise signed) | Windows service + LSA Auth Package + Credential Provider | Jun 2025 | multiple |
| syslog.exe (Linker.exe) | Custom C2 beacon | Unknown (survived reboots) | Sep 8, 2025 | 701 KB |
| ProctorU.1.29.win.06.exe | Trojan:MSIL/Zilla.IVK!MTB | Disguised as exam software in Packages folder | Sep 8, 2025 | 12.9 MB |
| IsCompleted.exe (Bcesuajgcga.exe) | Custom trojan | Scheduled task (`\Microsoft\Windows\Count\`) repeating every 5m44s | Sep 30, 2025 | 570 KB |
| game.exe | Trojan:MSIL/AsyncRAT.SJ!MTB | Fake `MicrosoftAEFWL` folder in AppData | Jan 7, 2026 | 678 KB |
| data.exe (444.exe) | Trojan:Win32/Ravartar!rfn | HKCU Run key | Mar 13, 2026 | 1.2 MB |
| EncoderFallback.exe | VMProtect-signed stub | Scheduled task (ghost — binary zeroed, exclusions remain) | Unknown | 0 bytes |
| IsSynchronized.exe | VMProtect-signed stub (Ekaterinburg, RU) | Scheduled task (ghost — exclusions remain) | Unknown | 0 bytes |

### Defense Evasion

The attacker comprehensively neutralized Windows Defender:
- Entire `C:\Users` directory excluded from scanning
- `powershell.exe` excluded from scanning
- 7 .NET LOLBins excluded (MSBuild, InstallUtil, RegAsm, RegSvcs, AddInProcess, AppLaunch, aspnet_compiler)
- Cloud-delivered protection disabled
- PUA detection disabled
- Network protection disabled
- Attack Surface Reduction rules: zero configured
- Controlled folder access: disabled

---

## The Defender Battle: A 4-Month War the Attacker Eventually Won

The most revealing artifact was the Windows Defender operational log. It told a story of sustained conflict between the endpoint's built-in defenses and a persistent attacker — a battle Defender was winning for months until the attacker changed tactics.

### Phase 1: Repeated Deployment, Repeated Detection (Nov 2025 — Jan 2026)

Starting in November 2025, Defender began detecting and quarantining `Trojan:MSIL/Heracles.KK!MTB` — a .NET trojan. But it kept coming back:

```
Nov 20, 2025 — Heracles.KK detected (3 times in one day)
Nov 30, 2025 — Heracles.KK detected again
Dec  3, 2025 — Heracles.KK detected again
Dec 12, 2025 — Heracles.KK detected again
Dec 18, 2025 — Heracles.KK detected again
Dec 21, 2025 — Heracles.KK detected again
```

**Seven detections in one month.** Each time, Defender quarantined the trojan. Each time, the attacker re-deployed it through their ScreenConnect C2 channel — which Defender never flagged because it uses legitimately signed ConnectWise binaries.

### Phase 2: Arsenal Escalation (Jan 2026)

When Heracles kept getting caught, the attacker began cycling through different malware families:

```
Jan  3, 2026 — Heracles.KK (still trying)
Jan  5, 2026 — Trojan:MSIL/zgRAT (Remote Access Trojan — new family)
Jan  6, 2026 — HackTool:Win32/Keygen (crack tool)
Jan 10, 2026 — Program:Win32/Vigram.A (adware)
Jan 10, 2026 — HackTool:Win32/Wpakill.B (activation killer)
Jan 10, 2026 — Trojan:Win32/Tiggre (cryptominer/stealer)
Jan 30, 2026 — Heracles.KK (still persistent)
```

The attacker deployed at least 5 different malware families in January alone. Defender caught every single one.

### Phase 3: Brute Force Attempts (Feb — Mar 2026)

```
Feb  2, 2026 — Trojan:Win32/Malgent (4 copies detected in the same minute)
Feb 15, 2026 — Trojan:Win32/Kepavll (info-stealer)
Mar  1, 2026 — Trojan:Win32/Suweezy
Mar  3, 2026 — Heracles.KK (still being re-deployed after 4 months)
Mar 20, 2026 — Trojan:Win32/Ravartar (latest variant)
```

Four simultaneous copies of Malgent on Feb 2 suggests the attacker was trying to overwhelm or race Defender's real-time protection. Defender caught all four.

### Phase 4: The Attacker Wins (Late Mar 2026)

After 4 months and 8+ malware families, the attacker changed strategy. Instead of trying to evade Defender with new payloads, they **disabled Defender itself**:

- Added `C:\Users` to the exclusion path (blanket coverage for all user-writable locations)
- Added `powershell.exe` to the process exclusion list
- Added 7 .NET Living-off-the-Land binaries to exclusions
- Disabled cloud-delivered protection (MAPSReporting = 0)
- Disabled PUA detection, network protection, and controlled folder access
- Configured zero Attack Surface Reduction rules

**After March 20, 2026: zero detections.** The log goes silent.

On March 13, 2026, `data.exe` (OriginalFilename: `444.exe`) was deployed to `AppData\Local\data\` — completely undetected. Our REDFORGE scan confirmed this: an on-demand Defender scan of `data.exe` returned zero detections because it sits inside the excluded `C:\Users` path.

### Epilogue: Defender Finds What It Missed

After REDFORGE removed all malicious exclusions and triggered a full scan, Defender immediately found two additional trojans that had been hiding under the `C:\Users` exclusion:

| Time | Threat | File | Hidden Since |
|------|--------|------|-------------|
| 22:44 Apr 20 | Trojan:MSIL/Zilla.IVK!MTB | `AppData\Local\Packages\ProctorU.1.29.win.06.exe` (12.9 MB) | Sep 8, 2025 (7 months) |
| 22:48 Apr 20 | Trojan:MSIL/AsyncRAT.SJ!MTB | `AppData\Local\MicrosoftAEFWL\game.exe` (678 KB) | Jan 7, 2026 (3.5 months) |

Both filenames are deliberate camouflage: "ProctorU" mimics exam proctoring software, "MicrosoftAEFWL" mimics a Microsoft folder, and "game.exe" is generic bait. AsyncRAT is a well-known open-source RAT used extensively by cybercriminals. These discoveries confirm that the exclusion-based evasion was completely effective — Defender's detection capability was intact but its visibility was eliminated.

### What Defender Never Caught

| Threat | Why It Was Invisible |
|--------|---------------------|
| ScreenConnect C2 (entire 10-month dwell) | Legitimately signed ConnectWise binaries — not malware by signature |
| syslog.exe (Sep 2025 onward) | In `C:\Users` excluded path after Mar 2026; may have had different path before |
| IsCompleted.exe (Sep 2025 onward) | Same exclusion coverage |
| data.exe (Mar 2026) | Deployed after exclusions were added |
| RegAsm.exe LOLBin abuse | Legitimate Microsoft binary — AV cannot distinguish normal from malicious use |
| The exclusion tampering itself | Defender does not block or specially alert on its own configuration being weaponized |

### The Lesson

Defender performed admirably for 4 months — detecting and quarantining every payload the attacker threw at it. But signature-based AV has a fundamental weakness: **it protects files, not its own configuration.** The attacker pivoted from evading detection to eliminating detection entirely.

This is why defense-in-depth matters:
- Defender exclusion changes should be monitored and locked via Group Policy
- Cloud protection and ASR rules should be enforced by MDM/Intune, not left to local configuration
- A second detection layer (EDR, behavioral analysis) independent of Defender's exclusion list would have caught the post-March activity
- The ScreenConnect C2 channel — the attacker's persistent lifeline — was never detectable by file-based AV because it used legitimately signed software

---

## Root Cause: Second-Hand Hardware

The machine was purchased from a thrift store. Forensic timeline analysis revealed that the ScreenConnect installation (June 2025) predates the Windows installation (September 2025), meaning the machine was sold already compromised. The attacker's LSA Authentication Package — a DLL loaded into the Windows credential management process at every boot — survived whatever reset was performed before sale.

Within 24 hours of the new Windows setup, the attacker detected the machine coming back online through their existing ScreenConnect access and began deploying additional payloads.

**Takeaway:** Second-hand computers must be clean-installed from official Microsoft media created on a trusted device. "Factory reset" and "Reset this PC" do not reliably remove deep persistence mechanisms like LSA authentication packages, boot-sector implants, or firmware-level threats.

---

## Attribution Indicators

- ScreenConnect relay hosted on `.ru` TLD (Russian infrastructure)
- Ghost task binary (`IsSynchronized.exe`) signed by VMProtect software protection tool, registered to an individual in Ekaterinburg, Russia
- Sophisticated tradecraft: Living-off-the-Land RMM, .NET LOLBin proxy execution, .NET class name camouflage (EncoderFallback, IsSynchronized), non-standard scheduled task intervals (5m44s), fake Windows path masquerading (`\Microsoft\Windows\Count\`)

---

## REDFORGE Performance

| Metric | Value |
|--------|-------|
| Specialists deployed | 9 (parallel) |
| Raw findings | 79 |
| After deduplication | 46 |
| CRITICAL findings | 6 |
| HIGH findings | 18 |
| Novel detection patterns | 5 |
| False positives | 0 (all CRITICALs independently verified) |
| Time: scan + synthesis | ~60 minutes |
| Time: full IR (contain + forensics + removal) | ~30 minutes additional |

All 6 CRITICAL findings were verified by re-running direct system commands before any containment action was taken. Every C2 connection, malware binary, scheduled task, and Defender exclusion was confirmed live on the system.

---

## Detection Patterns Surfaced

1. **Weaponized RMM via LSA Authentication Package** — legitimate remote management tool installed as an LSA auth package for SYSTEM-level persistence. Detection: service names not matching the vendor's conventions; relay domains outside vendor infrastructure.

2. **Ghost scheduled tasks with pre-placed AV exclusions** — tasks pointing to deleted binaries, but corresponding AV exclusions persist as dormant reinfection infrastructure. Detection: cross-reference AV exclusion paths against file existence.

3. **Fake Windows Store package path** — malware in `AppData\Local\packages\` alongside legitimate UWP app directories. Detection: executables in `packages\` that aren't part of an AppX manifest.

4. **Stale firewall rules as plantable backdoors** — exam/temp software leaves persistent firewall allow rules for user-writable paths. Detection: audit rules referencing `%TEMP%` or non-existent binaries.

5. **Non-standard scheduled task repetition interval** — 5 minutes 44 seconds instead of round numbers, likely to evade pattern-based detection. Detection: flag task repetition intervals that aren't common multiples.

---

*This case study documents a real incident discovered and remediated by REDFORGE's multi-agent AI red team platform during its first host-scan trial (M8). No data was fabricated. All findings were verified against the live system.*
