<!--
PUBLIC REDACTED VERSION — REDFORGE Host-Scan Trial #1 — Forensic Follow-up
Published: 2026-04-21 to docs/trials/2026-04-20-first-host-scan/

Redactions:
- Windows username    -> <operator>
- Personal emails     -> <redacted>@<provider>

Preserved (public-interest threat intel):
- OS install timestamps
- Evidence-source paths in the Windows namespace
- Attacker artifact names and timestamps
-->

# Forensic follow-up — Install-vector investigation

**Date:** 2026-04-21 (post-reboot)
**Triggered by:** challenge to the "MAS script as initial access vector" claim in the post-cleanup report
**Session:** non-admin user shell
**Scope:** `C:\Windows` system logs + HKLM/HKCU Uninstall registry + browser-history metadata + PS console history. No excluded-folder access.

## Conclusion

**Pre-compromised hardware theory is CONFIRMED. MAS script is ruled out as the initial access vector for ScreenConnect.** High confidence (multiple independent signals align).

## Evidence

### Windows install date — authoritative

| Source | Value |
|---|---|
| `Win32_OperatingSystem.InstallDate` | 2025-09-07 17:49:59 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.InstallDate` | 1757292599 (unix) = 2025-09-07 17:49:59 |
| `HKLM\SYSTEM\Setup.CloneTag` | `{Sun Sep 07 17:31:30 2025}` — OOBE phase start |
| `C:\Windows\Panther\unattend.xml` CreationTime | 2025-09-07 17:25:22 |
| Earliest browser history DB (Edge) CreationTime | 2025-09-07 20:13:45 |
| PowerShell `ConsoleHost_history.txt` CreationTime | 2025-09-07 20:17:50 |

All sources agree: **Windows 11 was installed on this machine on 2025-09-07 17:49:59**.

### ScreenConnect files predate the install

From the prior forensic file timeline (original scan):

- `ScreenConnect.WindowsAuthenticationPackage.dll` → 2025-06-09 (LSA Auth Package DLL)
- `C:\Program Files (x86)\Windows VC\` install → 2025-06-13
- **Windows installed on this hardware** → 2025-09-07 (3 months LATER)

### What the Uninstall registry does NOT contain

- ZERO products with `InstallDate < 20250907`.
- ZERO ScreenConnect entries in any Uninstall hive (HKLM, HKLM-Wow6432, HKCU).
- NO `ConnectWise` publisher entries at all.

Interpretation: ScreenConnect was **not installed via Windows Installer** on the current Windows install. It exists as files + registry services only. This is consistent with "files carried from prior Windows install; LSA auth package hook re-registered at first boot."

### What the Application event log does NOT contain

- 50 most recent `MsiInstaller` events are all legitimate user installs (Office C2R, Pandoc via WinGet, etc.). **No ScreenConnect MSI transactions ever.**
- The only ScreenConnect entries in Application log are ProviderName=ScreenConnect error events all dated **2026-04-20** — the scan day, when the client failed to reach the blocked C2. These are `ClientService` runtime events, not install events.

### What the System event log does NOT contain

- **Retention floor: 2025-12-19** (oldest surviving event). The June 2025 ScreenConnect service-install 7045 event has aged out.
- 7045 events that DO exist for RMM: all are for **TeamViewer** (a user-installed legit RMM), events dated 2026-01-28 onward. No 7045 for "Visual C++" or any ScreenConnect-related service name.

### PS console history — MAS runs

`ConsoleHost_history.txt` was created **2025-09-07 20:17:50** — i.e. ~28 minutes after the Windows install completed. First line (`irm https://get.activated.win | iex`) was the first command run in PowerShell on this install. Six total MAS runs at lines 1, 695, 1184, 1191, 1211, 1296. PSReadLine does not record timestamps per line, so per-run dating isn't possible from history alone.

**Critical point:** The EARLIEST possible MAS execution is 2025-09-07 ~20:17. ScreenConnect files are dated 2025-06-09 / 2025-06-13. MAS is temporally incapable of being responsible for the original foothold.

### Amcache.hve

Not found at `C:\Windows\appcompat\Programs\Amcache.hve` from this non-admin session. Either the file requires `SeBackupPrivilege` (possible — elevated session could confirm) OR the attacker cleaned the hive. Worth a deeper admin-session check, but the rest of the evidence is already decisive.

### Registered owner

`HKLM\...\CurrentVersion.RegisteredOwner` = `<redacted>@hotmail.com` — confirms the current operator's Microsoft account was used at OOBE on 2025-09-07. This rules out "a prior owner's current Windows install that the operator inherited" and confirms a fresh OOBE. The backdoor therefore truly survived ACROSS Windows reinstalls.

### Incidental find — TeamViewer

The operator has TeamViewer installed legitimately. Multiple 7045 reinstall events from Jan 2026 onward. Not the attacker's ScreenConnect channel, but worth noting for posture: having two RMMs on one machine is a large attack surface. Recommend removing TeamViewer if not actively in use.

## Implications for the public narrative

The earlier post-cleanup-report claim:

> "The first execution predates all malware deployment dates, making this the most likely initial access vector."

was **factually wrong**. The MAS runs cannot predate the ScreenConnect files by 3 months because the OS install itself doesn't predate them. The corrected statement is now in `scan-post-cleanup-report.md` and `public-report.md` (see the "Initial Access Vector — CORRECTED 2026-04-21" section).

## Follow-on queries that need an elevated session

Not required for the conclusion — the evidence is decisive — but these would add forensic-grade depth for an MSRC-level disclosure:

- Amcache.hve raw parse (needs `SeBackupPrivilege`) — would list every executable first-run timestamp going back further than the System log retention floor. Decisive if ScreenConnect binaries show first-run dates before 2025-09-07.
- ShimCache (`AppCompatCache` registry value in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`) — similar. Requires reg load with elevated privs.
- `C:\Windows\Panther\setupact.log` full read — ACLed; would show exact OOBE step-by-step. Non-admin got only directory listing.
- Driver-install history via `Microsoft-Windows-UserModePowerService/DiagnosticInfo` — could reveal hardware-first-seen dates (CPU, TPM, HDD) pre-dating this Windows install.

## Confidence

- **Pre-compromised hardware**: very high (multiple independent signals: timestamps + missing installer traces + fresh-OOBE confirmation + LSA persistence mechanism).
- **MAS as initial vector**: ruled out (temporal impossibility).
- **MAS as later-stage vector for data.exe or similar**: plausible but unproven.
