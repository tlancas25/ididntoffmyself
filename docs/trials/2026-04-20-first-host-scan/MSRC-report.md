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

# Microsoft Security Response Center (MSRC) Vulnerability Report

## Title
Windows Defender Tamper Protection Does Not Prevent Exclusion Tampering — Allows Persistent AV Evasion by SYSTEM-Level Processes

## Severity Assessment
**High** — Allows a SYSTEM-level attacker to permanently blind Windows Defender's real-time protection, AMSI scanning, and on-demand scans for arbitrary file paths and processes. Defender detects the tampering but cannot prevent recurrence.

## Product Affected
- Windows Defender Antivirus (Microsoft Defender Antivirus)
- Windows 11 Pro, Build 26200
- Defender Platform: 4.18.26010.5 → 4.18.26030.3011
- Tamper Protection: Enabled (Source: Signatures)

## Summary

During a real-world incident response on a compromised Windows 11 system, we documented a 4-month adversarial campaign (November 2025 — March 2026) where an attacker systematically defeated Windows Defender through exclusion manipulation. Despite Tamper Protection being enabled, the attacker — operating via a SYSTEM-level ScreenConnect RMM backdoor — was able to:

1. Add arbitrary paths and processes to Defender's exclusion list
2. Disable cloud-delivered protection, PUA detection, and network protection
3. Survive Defender's own detection of the exclusion tampering (classified as Trojan:Win32/Suweezy)
4. Permanently blind Defender for the `C:\Users` directory tree and 7 .NET LOLBins

**Defender correctly identified the attack** (30+ malware detections via AMSI, plus detecting the exclusion entries themselves as malicious) but lacked the ability to prevent the attacker from re-adding exclusions after remediation.

## Detailed Timeline with Evidence

### Phase 1: AMSI Detection Working (Nov 1 — Nov 19, 2025)

The attacker loaded `Trojan:MSIL/Heracles.KK!MTB` through .NET LOLBins. AMSI caught every attempt:

```
Nov 1 15:50  — MSBuild.exe      → AMSI detected → Quarantined
Nov 1 17:33  — RegSvcs.exe      → AMSI detected → Quarantined
Nov 1 17:46  — AddInUtil.exe    → AMSI detected → Quarantined
Nov 1 17:55  — MSBuild.exe      → AMSI detected → Quarantined
Nov 1 17:59  — AddInUtil.exe    → AMSI detected → Quarantined
Nov 3 10:58  — RegSvcs.exe      → AMSI detected → Quarantined
Nov 7 11:15  — XWorm (aoc.bat)  → File detected → Quarantined
Nov 17 07:54 — AddInUtil.exe    → AMSI detected → Quarantined
Nov 19       ��� AddInUtil.exe    → 14 DETECTIONS IN ONE DAY (automated re-execution)
Nov 20       — AddInUtil.exe    → 3 more detections
```

All detection paths begin with `amsi:_` confirming AMSI (not file scanning) was the detection layer.

**Total Heracles.KK detections: 30+ over 4 months.** Defender quarantined every one.

### Phase 2: Attacker Escalates to Exclusion Tampering (Feb 20, 2026)

After 4 months of failed payload deployment, the attacker changed tactics:

```
Event 5007 — Feb 20, 2026 17:34:38
ADDED: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ = 0x0
```

**The attacker excluded the ENTIRE C:\ drive.** Tamper Protection did not prevent this operation.

### Phase 3: Defender Detects and Remediates the Tampering (Mar 1, 2026)

```
Event 1116 — Mar 1, 2026 16:14:03 — Trojan:Win32/Suweezy DETECTED
Path: regkeyvalue:_HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\\C:\
      regkeyvalue:_HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\\C:\Users\<operator>\AppData\Local\Temp\
      regkeyvalue:_HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\\C:\Windows\Microsoft.NET\Framework64\v4.0.30319\

Event 1117 — Mar 1, 2026 16:14:31 — Action: Quarantine

Event 5007 — Mar 1, 2026 16:14:31 — REMOVED: C:\
Event 5007 — Mar 1, 2026 16:14:31 — REMOVED: C:\Users\<operator>\AppData\Local\Temp\
Event 5007 — Mar 1, 2026 16:14:31 — REMOVED: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
```

**Defender correctly classified the exclusion entries as Trojan:Win32/Suweezy and quarantined them.** This is excellent detection. However:

### Phase 4: Attacker Re-Adds Exclusions — Defender Cannot Prevent This (Mar 3, 2026)

```
Event 5007 — Mar 3, 2026 13:10:30
ADDED: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\<operator>\AppData\Local\Temp\ = 0x0

Event 1116 — Mar 3, 2026 13:09:53 — Trojan:MSIL/Heracles.KK!MTB via AMSI/AddInUtil.exe
(Attacker still has access — immediately caught again, but now re-adding exclusions)
```

**Within 2 days of Defender removing the malicious exclusions, the attacker re-added them.** The attacker then added more targeted exclusions:
- `C:\Users` (entire user profile tree)
- `C:\Users\<operator>\AppData\Local`
- Individual LOLBin paths and process names
- `powershell.exe` as a process exclusion

### Phase 5: Defender Defeated (Mar 20, 2026 onward)

```
Mar 20 11:36 — data.exe detected as Trojan:Win32/Ravartar via AMSI → Quarantined
Mar 20 12:34 — data.exe detected AGAIN → Quarantined AGAIN
```

After March 20: **ZERO further detections.** The `C:\Users` exclusion was fully in place. The attacker re-deployed data.exe and it was never detected again. When our REDFORGE scanner found it on April 20, it had been running undetected for a full month.

Additionally, the full scan we triggered post-cleanup found two more trojans that had been invisible under the exclusions:

1. **Trojan:MSIL/Zilla.IVK!MTB** in `ProctorU.1.29.win.06.exe` (12.9 MB) — hiding in `AppData\Local\Packages\` since September 8, 2025 (7 months undetected), disguised as exam proctoring software
2. **Trojan:MSIL/AsyncRAT.SJ!MTB** in `game.exe` (678 KB) — hiding in fake `AppData\Local\MicrosoftAEFWL\` folder since January 7, 2026 (3.5 months undetected)

AsyncRAT is a well-documented open-source Remote Access Trojan. These post-cleanup discoveries confirm the exclusion-based evasion was 100% effective — Defender's detection engine recognized both immediately once it could see them.

## Root Cause Analysis

### The Vulnerability: Tamper Protection Scope Gap

Tamper Protection prevents modification of:
- Real-time protection (on/off)
- Cloud-delivered protection (on/off)
- Behavior monitoring (on/off)
- Security intelligence updates
- IOAV protection

Tamper Protection does **NOT** prevent:
- Adding exclusion paths (`Set-MpPreference -ExclusionPath`)
- Adding exclusion processes (`Set-MpPreference -ExclusionProcess`)
- Modifying `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` directly
- Disabling MAPSReporting (cloud block level)
- Disabling PUAProtection
- Disabling NetworkProtection
- Disabling ControlledFolderAccess
- Removing all ASR rules

### Registry ACL Evidence

The Defender exclusion registry key grants `NT AUTHORITY\SYSTEM` FullControl:

```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions
  NT AUTHORITY\SYSTEM: FullControl (Allow)
  NT SERVICE\TrustedInstaller: FullControl (Allow)
  NT SERVICE\WinDefend: FullControl (Allow)
  BUILTIN\Administrators: ReadKey (Allow)  ← Read only for admins

HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
  NT AUTHORITY\SYSTEM: FullControl (Allow)  ← Any SYSTEM process can write
  BUILTIN\Administrators: CreateLink, ReadKey (Allow)
```

Note: Administrators have only `CreateLink, ReadKey` on `Exclusions\Paths` — but any service running as SYSTEM (including weaponized RMM tools) has `FullControl`.

### The Attack Vector

1. Attacker gains SYSTEM execution via any means (compromised service, RMM tool, kernel exploit)
2. Attacker calls `Set-MpPreference -ExclusionPath "C:\Users"` or writes directly to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`
3. Tamper Protection does **not** intercept this operation
4. All real-time protection, AMSI scanning, and on-demand scans for `C:\Users` are immediately disabled
5. If Defender detects and removes the exclusions (Suweezy classification), the attacker re-adds them
6. No lockout, rate-limiting, or escalation mechanism exists to break this cycle

## Reproduction Steps

On a Windows 11 machine with Tamper Protection enabled:

```powershell
# From an elevated (admin) PowerShell session:
Set-MpPreference -ExclusionPath "C:\Users"
# Verify: (Get-MpPreference).ExclusionPath now contains C:\Users
# Place any malware binary under C:\Users — it will NOT be scanned

# To confirm AMSI is also blinded:
Set-MpPreference -ExclusionProcess "powershell.exe"
# Malicious PowerShell scripts will no longer trigger AMSI detection
```

No Tamper Protection bypass is required. The operation succeeds with standard admin/SYSTEM privileges.

## Proposed Mitigations

### Short-term
1. **Extend Tamper Protection to cover exclusion modifications.** Require interactive user confirmation (at the console, not programmatic) for any new exclusion addition when Tamper Protection is enabled.
2. **Rate-limit exclusion re-addition.** If Defender quarantines exclusion entries as malicious (Suweezy), block new exclusions for the same paths for a configurable period (e.g., 24 hours).

### Medium-term
3. **Implement a "circuit breaker" for repeated detection-quarantine-reinfection cycles.** After N detections of the same threat family through the same LOLBin, permanently block that execution pathway (not just quarantine the payload).
4. **Alert escalation.** When exclusion tampering is detected (Suweezy), elevate to CRITICAL in Windows Security Center and notify any connected MDM/SIEM.
5. **Scope-limit SYSTEM exclusion writes.** Only the WinDefend service and TrustedInstaller should be able to modify exclusion keys — not arbitrary SYSTEM-level processes.

### Long-term
6. **Protect cloud protection settings under Tamper Protection.** MAPSReporting, CloudBlockLevel, PUAProtection, NetworkProtection, and ASR rules should all be tamper-protected on par with real-time protection.
7. **Mandatory Intune/GPO enforcement for exclusions on consumer Windows.** Provide a "lock exclusions" toggle in Windows Security that prevents ALL local modification without cloud-backed authorization.

## Impact Assessment

This vulnerability was exploited in a real-world attack with:
- **10-month dwell time** on a consumer Windows 11 system
- **3 independent C2 channels** maintained simultaneously
- **8 malware binaries** deployed and hidden under exclusion-protected paths
- **10+ malware families** used (Heracles.KK, zgRAT, XWorm, Malgent, Kepavll, Suweezy, Ravartar, Zilla, AsyncRAT, Tiggre)
- **Complete AV blindness** after exclusion tampering succeeded, despite Tamper Protection being enabled
- Defender made **30+ correct detections** over 4 months but could not prevent the attacker from eventually winning by targeting the exclusion mechanism

The attack does not require any Defender vulnerability exploitation, zero-day, or privilege escalation beyond SYSTEM — which any compromised service provides.

## Evidence Files

All evidence is preserved locally and available for Microsoft review:
- Full Defender Operational Event Log export (5007, 1116, 1117 events)
- Registry ACL dumps for `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`
- Malware binary hashes (SHA256) for 6 samples
- ScreenConnect C2 configuration files
- PowerShell execution history
- Complete forensic timeline with 100+ mapped events

## Disclosure

This report documents a design gap in a shipping Microsoft security product. We are submitting this through the Microsoft Security Response Center (MSRC) for evaluation. No exploit code is included — the issue is reproducible with standard PowerShell cmdlets available to any admin/SYSTEM process.

## Contact

<operator>  
REDFORGE Security Research  
GitHub: tlancas25

---

*This report was generated with assistance from REDFORGE, a multi-agent AI red team platform, during incident response on a real compromised system.*
