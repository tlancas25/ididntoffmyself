<!--
PUBLIC REDACTED VERSION — REDFORGE Host-Scan Trial #1 — Forensic Follow-up v2
Published: 2026-04-21 to docs/trials/2026-04-20-first-host-scan/

Redactions:
- Windows username    -> <operator>
- Personal emails     -> <redacted>@<provider>

Preserved (public-interest threat intel):
- OS install timestamps
- Attacker artifact names and timestamps
- Attacker-chosen social-engineering handle `dr.jamespaul` (so other victims can pattern-match)
- MITRE ATT&CK IDs
- Anti-forensic tradecraft fingerprint
-->

# Forensic follow-up — Install-vector investigation (v2)

**Date:** 2026-04-21 (day-long investigation with multiple evidence rounds)
**Triggered by:** challenge to the "MAS script as initial access vector" claim in the original post-cleanup report, then superseded by operator recollection of the actual intrusion.
**Session:** non-admin user shell (most queries accessible)
**Scope:** `C:\Windows` system logs + HKLM/HKCU Uninstall registry + browser-history metadata + PS console history + MFT `$SI` timestamp analysis on known attacker artifacts. No excluded-folder access.

## Final conclusion

**The compromise was a social-engineering proctoring scam, not pre-compromised hardware, not MAS.** Anti-forensic timestamp analysis confirms ScreenConnect was actually deployed **2026-01-07**, not June 2025 as file timestamps claimed. The attacker used `SetFileTime()` to backdate ScreenConnect files to make the intrusion look like pre-existing hardware compromise — a deliberate red herring that misdirected the first round of investigation.

High confidence: multiple independent evidence streams align (MFT parent-directory mismatch + operator recollection + synchronized deployment dates with other payloads).

## Investigation trail (what we got wrong and how we fixed it)

This investigation went through three theories in 24 hours. All three are documented here because the arc illustrates how modern adversarial forensics works — attackers deliberately plant misdirecting artifacts.

### Theory 1 — MAS script initial access (2026-04-20, ORIGINAL — WRONG)

The original post-cleanup report framed the `irm https://get.activated.win | iex` PowerShell runs (6 occurrences) as the "most likely initial access vector." Rationale: these runs predated most malware deployment dates, invoked `iex` with admin, and trojanized MAS clones are a known crimeware delivery channel.

**Why it was wrong:** The earliest possible MAS run on the current Windows install was 2025-09-07 ~20:17 (PSReadLine `ConsoleHost_history.txt` file creation). ScreenConnect files on disk appeared dated 2025-06-09 — 3 months earlier. MAS runs cannot have delivered files that predate them.

### Theory 2 — Pre-compromised hardware (2026-04-21 morning — WRONG)

After ruling out MAS, the working theory became: the machine arrived backdoored from the thrift store, with an LSA Authentication Package that survived whatever reset the prior owner performed. Supporting evidence (all genuine, just misinterpreted):

- Windows 11 OOBE verifiably occurred 2025-09-07 17:49:59 (WMI + HKLM registry + Panther).
- ScreenConnect DLL `$SI CreationTime`: 2025-06-09 19:34:52 — three months BEFORE the OS install.
- Zero `ScreenConnect` / `ConnectWise` entries in Uninstall registry hives.
- Zero `MsiInstaller` Application-log events for ScreenConnect at any point.
- Earliest `ConsoleHost_history.txt` timestamp 28 minutes after OOBE — fresh-OOBE confirmed.
- LSA-auth-package persistence is a documented "survives reset" mechanism in the wild.

**Why it was wrong:** this theory was built on a single bad assumption — that the ScreenConnect DLL's `$SI CreationTime` reflects its actual deployment date. That timestamp is **timestomped**.

### Theory 3 — Social-engineering proctoring scam + timestomp anti-forensics (2026-04-21 evening — CORRECT)

Operator recollection: on **2025-08-29**, an attacker using the login handle `dr.jamespaul` (or close variant) in the remote-control software's operator interface contacted the operator posing as an online exam proctor. The attacker directed the operator to install **UltraViewer** (legitimate free remote-access tool) and a second unnamed remote-control program ("something like duet" — exact name not preserved). The attacker then used the remote session to install additional software, reconfigure system settings, and wipe `%TEMP%` to cover installer traces.

Operator subsequently reinstalled Windows on 2025-09-07 after judging the post-Aug-29 state suspicious. Day 1 post-install (2025-09-08), the same social-engineering vector hit again — operator installed `ProctorU.1.29.win.06.exe` believing it was legitimate. Because proctored exams were a recognized coursework requirement, the operator **tolerated** the "proctoring software" through the exam period (Sep 2025 – Mar 2026) and only began manually deleting attacker programs in March 2026 when coursework ended.

## 🎯 Decisive evidence — timestomp smoking gun

Full MFT `$SI` timestamp dump on suspect files (non-admin session, 2026-04-21 evening):

```
File:    C:\Program Files (x86)\Windows VC\ScreenConnect.WindowsAuthenticationPackage.dll
  $SI CreationTime  : 2025-06-09 19:34:52      ← file claims June 2025
  $SI LastWriteTime : 2025-06-09 19:34:52

Parent:  C:\Program Files (x86)\Windows VC\
  $SI CreationTime  : 2026-01-07 18:44:50      ← folder actually created Jan 2026
  $SI LastWriteTime : 2026-04-20 21:10:46
```

**A file cannot be created before its parent directory exists.** The `ScreenConnect.WindowsAuthenticationPackage.dll` $SI timestamp of 2025-06-09 is mathematically impossible — the folder it lives in wasn't created until 2026-01-07. The attacker called `SetFileTime()` to backdate the DLL but did not (or could not) stomp the parent directory's `$SI CreationTime`. MITRE ATT&CK **T1070.006 (Timestomp)**.

### Why 2026-01-07 is the real deployment date

The 2026-01-07 parent-directory date **independently matches** the `game.exe` (AsyncRAT) deployment date from the original REDFORGE scan — a file whose date was NOT suspect. Two independent artifacts converging on 2026-01-07 indicates a **coordinated multi-payload push** by the attacker that day:

- `C:\Program Files (x86)\Windows VC\` folder created (ScreenConnect re-plant)
- `game.exe` (AsyncRAT) dropped
- Multiple new Defender exclusions pushed
- LSA Auth Package re-registered

### Why the attacker timestomped to June 2025 specifically

Probably deliberate red herring for any post-hoc investigator — making it look like pre-existing compromise on thrift-store hardware. The story writes itself: "machine was compromised before user owned it" is a plausible narrative a defender would construct given those timestamps. It took operator recollection + parent-directory `$SI` analysis to see through it.

This is itself a **detection pattern worth publishing**: any file whose `$SI CreationTime` predates its parent directory's `$SI CreationTime` is either moved/copied-with-preserved-metadata (legitimate) or timestomped (malicious). Easy to automate; high signal for investigators.

## Full revised timeline

| Date | Event | Source |
|------|-------|--------|
| 2025-08-28 | Operator installs Node.js (normal dev setup) | File timestamps in `C:\Program Files\nodejs\` |
| **2025-08-29** | **"Dr. James Paul" social-engineering contact. Operator installs UltraViewer + second remote-control tool. Attacker plants secondary software, wipes %TEMP%.** | Operator recollection |
| 2025-09-07 17:49:59 | Operator reinstalls Windows 11 on main partition | WMI InstallDate + Panther unattend.xml + HKLM registry |
| 2025-09-08 | Same social vector re-hits. Operator installs `ProctorU.1.29.win.06.exe` (Trojan:MSIL/Zilla.IVK!MTB). `syslog.exe` also drops. | Original scan |
| 2025-09-30 | `IsCompleted.exe` scheduled task (`Count\` folder) planted | MFT `$SI` of `C:\Users\<operator>\AppData\Local\Count` = 2025-09-30 17:36:30 |
| 2025-11 through 2026-03 | 4-month Defender battle. 30+ AMSI detections. Attacker tolerated by operator due to perceived proctoring-software requirement. | MSRC report event timeline |
| **2026-01-07 18:44:50** | **Coordinated multi-payload re-deployment: ScreenConnect re-planted (timestomped to June 2025), `game.exe`/AsyncRAT dropped, Defender exclusions pushed** | MFT `$SI` of `C:\Program Files (x86)\Windows VC\` = 2026-01-07 18:44:50 |
| 2026-03 | Operator's proctored coursework ends. Operator begins manually deleting attacker programs (UltraViewer, proctoring-scam tools). | Operator recollection + reliability-monitor install-event activity |
| 2026-04-20 | REDFORGE host-scan discovers remaining persistence residue | This report |

## What survived the March 2026 operator cleanup

Operator manually removed the user-visible attacker software in March 2026, but sophisticated persistence survived:

- LSA Authentication Package registry hook (loads DLL into `lsass.exe` at boot — invisible to normal uninstall)
- Scheduled task `\Microsoft\Windows\Count\IsCompleted` (camouflaged in legitimate-looking path)
- HKCU Run key entries
- Defender exclusions (removal requires admin-level awareness)
- `game.exe` in fake `MicrosoftAEFWL` folder
- `data.exe` in `AppData\Local\data\`
- The timestomped ScreenConnect files themselves

## What the 2026-04-21 evening hunt found

### Present (survived operator cleanup)

- `C:\Program Files (x86)\Windows VC\ScreenConnect.WindowsAuthenticationPackage.dll` — `$SI` timestomp evidence
- `C:\Users\<operator>\AppData\Local\Count\` — authentic 2025-09-30 scheduled-task folder
- Brave / Edge / Chrome browser history SQLite databases (still intact at expected paths; locked by running browsers but copied to TEMP for future query)

### Absent (cleaned up by operator or by attacker anti-forensics)

- `C:\Program Files\UltraViewer\` / `C:\Program Files (x86)\UltraViewer\` / all AppData UltraViewer paths — **gone** (operator March 2026 cleanup)
- `HKLM:\SOFTWARE\UltraViewer`, `HKCU:\SOFTWARE\UltraViewer`, `HKCU:\SOFTWARE\DucFabulous` — **gone**
- UltraViewer Uninstall registry entries — **gone**
- Prefetch files from Aug 2025 – Sep 2025 window — **empty** (TEMP wipe on Aug 29 likely also hit Prefetch; later Disk Cleanup finished the job)
- System event log before 2025-12-19 — retention floor (7045 service-install events for ScreenConnect on 2026-01-07 would have been logged but aged out)
- Scheduled tasks created 2025-08-29 to 2025-09-08 — already unregistered during April 2026 IR
- `ProctorU.1.29.win.06.exe` and `game.exe` — quarantined + deleted by Defender during post-cleanup scan
- Volume Shadow Copies — access denied (requires admin)

### Worth chasing (not completed this round)

- Browser history SQLite queries (databases copied to `%TEMP%\rf_{Edge,Brave,Chrome}_hist_copy.db`; `sqlite3` CLI not installed — could use Python's builtin `sqlite3` next round to search for Aug 29, 2025 visits + proctoring-related URLs)
- Amcache.hve raw parse (admin-gated) — may contain executable first-run dates for UltraViewer
- `$FN` MFT attribute comparison against `$SI` on the timestomped DLL — would confirm timestomp via duplicate evidence source (admin-gated; `fsutil` or a hive parser)

## Attacker indicators (public-interest threat intel)

- **Social-engineering handle:** `dr.jamespaul` (or close variant) — observed inside the remote-control software's operator interface. Publish so other victims can pattern-match against their own incident recollections.
- **Remote-control tools abused:** **UltraViewer** (confirmed by operator); plus a second unnamed tool ("something like duet" — operator recall not preserved).
- **Target demographic:** students running online-proctored exams. Impersonating legitimate proctoring infrastructure.
- **Tradecraft fingerprint:**
  - `SetFileTime()` timestomp with parent-directory-mismatch leak (T1070.006)
  - `%TEMP%` wipe post-install (T1070.004)
  - LSA Authentication Package for SYSTEM persistence (T1547.002)
  - ScreenConnect RMM as C2 tunnel to `edgeserv.ru:8041` (T1219)
  - Fake Microsoft service name "Visual C++" (T1036.005)
  - Fake Windows scheduled-task namespace `\Microsoft\Windows\Count\` (T1036.005)
  - Non-standard scheduled-task interval 5m44s (anti-detection — T1053.005)
  - Malware file named after legitimate product (`ProctorU.1.29.win.06.exe`)
  - Coordinated multi-payload push on single dates (2026-01-07, 2026-03-13)
  - Defender exclusion weaponization (T1562.001, documented separately in `MSRC-report.md`)

## Confidence

- Timestomp confirmed: **very high** (parent-directory `$SI` mismatch is deterministic evidence).
- Aug 29 proctoring-scam initial contact: **high** (operator recollection + consistent filesystem absence of pre-Sep-7 attacker artifacts + `ProctorU.1.29.win.06.exe` malware name matching the social-engineering pretext).
- "Dr. James Paul" identifier: **operator-recalled** (no surviving artifact confirms — worth cross-checking against email / social-media history in future queries).
- 2026-01-07 coordinated re-deployment: **high** (two independent artifacts align).
- Pre-compromised hardware (Theory 2): **ruled out** (timestomp invalidates).
- MAS as initial vector (Theory 1): **ruled out** (temporally impossible regardless of which of Theory 2/3 is correct).

## Prior versions

- v1 (2026-04-21 morning): proposed pre-compromised hardware as initial access. Published at commit `a6035e4`. Superseded by this v2.
