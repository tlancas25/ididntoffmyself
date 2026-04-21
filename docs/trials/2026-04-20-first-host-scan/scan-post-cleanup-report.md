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

# Post-Cleanup Report: <hostname>

**Date:** 2026-04-20  
**Operator:** <operator>  
**System:** <hostname>, Windows 11 Pro Build 26200

---

## Executive Summary

An active multi-channel compromise was discovered, contained, investigated, and cleaned in a single session. The machine had been under attacker control for approximately **10 months** (June 2025 to April 2026) via 3 independent command-and-control channels. All malware processes have been killed, all persistence mechanisms removed, all Defender exclusions cleaned, and all C2 IPs blocked. A full Defender scan is running in background. **A reboot is required** to release 2 locked files from system memory.

---

## What Was Found

### Threat Summary

| Component | Type | Deployed | C2 Destination | Status |
|-----------|------|----------|----------------|--------|
| ScreenConnect ("Visual C++") | RMM backdoor + LSA auth package | 2025-06-13 | edgeserv.ru:8041 (95.214.234.238) | **REMOVED** |
| syslog.exe ("Linker Manager") | Standalone C2 beacon | 2025-09-08 | 64.74.162.109:443 | **REMOVED** |
| ProctorU.1.29.win.06.exe | Trojan:MSIL/Zilla.IVK!MTB | 2025-09-08 | Unknown | **DEFENDER QUARANTINING** |
| IsCompleted.exe (Bcesuajgcga.exe) | Scheduled persistence malware | 2025-09-30 | Unknown | **REMOVED** (dir locked, reboot needed) |
| game.exe (in fake MicrosoftAEFWL) | Trojan:MSIL/AsyncRAT.SJ!MTB | 2026-01-07 | Unknown | **DEFENDER QUARANTINING** |
| data.exe (444.exe) | Trojan:Win32/Ravartar!rfn | 2026-03-13 | Unknown | **REMOVED** |
| RegAsm.exe LOLBin | .NET assembly proxy execution | Unknown | 130.12.180.159:56009 | **KILLED** (binary is legitimate MS tool) |
| EncoderFallback / IsSynchronized | Ghost tasks (dormant reinfection) | Unknown | N/A (binaries zeroed) | **REMOVED** |
| Defender exclusion tampering | Defense evasion | Unknown | N/A | **RESTORED** |

**Note:** ProctorU and AsyncRAT binaries were discovered by Defender's full scan AFTER we removed the malicious exclusions — confirming the exclusion-based evasion was completely effective.

### Attribution Indicators

- **Russian infrastructure:** ScreenConnect relay at `edgeserv.ru` (.ru TLD), hosted at 95.214.234.238 (vsys.host, Russia)
- **Russian tooling:** IsSynchronized.exe signed by VMProtect (`info@vmpsoft.com`, Permyakov Ivan Yurievich, Ekaterinburg, Russia)
- **Sophistication:** Living-off-the-land (weaponized legitimate ConnectWise ScreenConnect + RegAsm.exe LOLBin), .NET class name camouflage (EncoderFallback, IsSynchronized), fake Windows paths (`\Microsoft\Windows\Count\`), non-standard scheduled task interval (5m44s for anti-detection)

---

## Initial Access Vector — CORRECTED 2026-04-21 (v2)

**Social-engineering proctoring scam + anti-forensic timestomp.** A deeper forensic follow-up on the evening of 2026-04-21, informed by operator recollection of the actual intrusion, overturned both the original "MAS script" claim AND the first correction's "pre-compromised hardware" theory. The actual attack sequence:

1. **2025-08-29** — Operator received social-engineering contact posing as an online exam proctor. The attacker's login handle inside the remote-control operator interface was `dr.jamespaul` (or a close variant). Under the pretext of "setting up" a proctored exam, the attacker instructed the operator to install **UltraViewer** (a legitimate free remote-access tool) and a second remote-control program (operator recalled "something like duet" — exact name not preserved). The attacker used the remote session to install additional software, reconfigure system settings, and **wipe `%TEMP%`** to cover installer traces.
2. **2025-09-07 17:49:59** — Operator reinstalled Windows 11 on the main partition after judging the post-Aug 29 system state suspicious.
3. **2025-09-08** (Day 1 post-install) — The same social-engineering vector hit again. Operator installed `ProctorU.1.29.win.06.exe` (12.9 MB) believing it was legitimate proctoring software. Defender later classified it as `Trojan:MSIL/Zilla.IVK!MTB`.
4. **2025-09-30** — `IsCompleted.exe` scheduled task deployed (`Count\` folder — authentic creation timestamp).
5. **2025-11 through 2026-03** — Operator actively used the machine for proctored courses, tolerating the "proctoring software" they believed was required for coursework. Defender detected attacker activity 30+ times via AMSI across this window. Attacker eventually escalated to the Defender-exclusion tampering (separately documented in `MSRC-report.md`).
6. **2026-01-07** — **Coordinated multi-payload re-deployment.** `C:\Program Files (x86)\Windows VC\` folder created (ScreenConnect re-planted), `game.exe`/AsyncRAT dropped, new Defender exclusions pushed. Attacker timestomped the ScreenConnect DLL to `2025-06-09` via `SetFileTime()` as anti-forensics — a deliberate red herring suggesting pre-existing compromise.
7. **2026-03** — Operator's proctored courses ended. Operator began manually deleting attacker programs (UltraViewer and siblings).
8. **2026-04-20** — REDFORGE scan found the surviving persistence residue (LSA Auth Package DLL, scheduled tasks, registry Run keys, ScreenConnect service) that manual cleanup did not fully remove.

### 🎯 Timestomp — smoking gun

The ScreenConnect DLL on disk appears dated 2025-06-09, but:

```
File:    C:\Program Files (x86)\Windows VC\ScreenConnect.WindowsAuthenticationPackage.dll
  $SI CreationTime : 2025-06-09 19:34:52     ← impossible (see below)

Parent directory: C:\Program Files (x86)\Windows VC\
  $SI CreationTime : 2026-01-07 18:44:50     ← actual deployment date
```

**A file cannot be created before its parent directory exists.** The 2025-06-09 date on the DLL is mathematically impossible — the folder it lives in wasn't created until 2026-01-07. The attacker called `SetFileTime()` to backdate the DLL but did not stomp the parent directory's `$SI` timestamp, leaving a forensically-detectable discrepancy. MITRE ATT&CK **T1070.006 (Timestomp)**.

The 2026-01-07 date matches the independently-verified `game.exe` / AsyncRAT drop date from the original scan — strongly suggesting a coordinated multi-payload push by the attacker on that day.

### Attacker indicators (public-interest threat intel)

- **Social-engineering handle** observed in remote-control operator UI: `dr.jamespaul` (or similar variant). Public so other victims / investigators can pattern-match.
- **Remote-control tools abused**: **UltraViewer** (confirmed), plus a second unidentified tool.
- **ScreenConnect C2 relay**: `edgeserv.ru:8041` (95.214.234.238 — vsys.host, Russia) — unchanged from original scan.
- **MITRE techniques**: T1566 (Phishing) → T1219 (Remote Access Software) → T1070.006 (Timestomp) → T1547.002 (LSA Auth Package) → T1562.001 (Disable/Modify Tools — Defender).

### Separate risk-behavior observation (unchanged)

The MAS PowerShell runs (`irm https://get.activated.win | iex` × 6) remain a separate piracy-risk observation — not the initial access vector. They were temporally incapable of delivering the original foothold, which occurred via the Aug 29 proctoring scam. **HOSTS file sinkholing** of license servers for Noregon JPRO and CCleaner confirms an elevated piracy-risk behavior pattern but not a foothold source.

### Secondary observation — TeamViewer (second RMM)

Uninstall registry + System-log 7045 events show **TeamViewer** installed and reinstalled multiple times between Jan–Apr 2026. Legitimate user-installed RMM, separate from the attacker's ScreenConnect channel. Recommend removing TeamViewer if not actively in use — two RMMs on one machine materially expands remote-access attack surface.

---

## Forensic Timeline

| Date | Event |
|------|-------|
| 2024-11-15 | syslog.exe binary compiled (OriginalFilename: Linker.exe) |
| 2025-06-09 | ScreenConnect LSA auth package DLL created |
| 2025-06-13 | ScreenConnect full installation deployed (17 files, "Visual C++" service) |
| 2025-09-07 | Windows 11 installed on this machine |
| 2025-09-08 | syslog.exe deployed to AppData\Local\packages\ |
| 2025-09-30 | IsCompleted.exe (Bcesuajgcga.exe) deployed with scheduled task |
| 2026-03-13 | data.exe (444.exe) deployed to AppData\Local\data\ |
| 2026-04-20 | REDFORGE scan discovers compromise; containment + cleanup executed |

**Note:** ScreenConnect was installed June 2025 but Windows was installed September 2025. This means either: (a) ScreenConnect was on a prior Windows installation and survived the reinstall, or (b) the machine was compromised very shortly after the Windows install using saved credentials/profiles that carried over.

---

## What the Attacker Could Have Accessed

With ~10 months of SYSTEM-level remote access, the attacker had potential access to:

### Credentials (ASSUME COMPROMISED)
- **Browser passwords:** Edge (1MB+ Login Data = likely hundreds of saved passwords), Chrome, Brave
- **Windows Credential Manager:** 22 entries including GitHub (tlancas25), Docker Hub (<docker-user>), Microsoft accounts (<redacted>@outlook.com, <redacted>@hotmail.com), OAuth tokens
- **SSH keys:** Unencrypted id_ed25519 + google_compute_engine (RSA + PPK) with known GCP target IPs (<GCP-target-IP-1>, <GCP-target-IP-2>, <GCP-target-IP-3>)
- **VNC auth cookie:** RealVNC device registration
- **Tailscale node state:** Mesh VPN identity
- **WiFi passwords:** 20 stored profiles recoverable in cleartext
- **DPAPI master keys:** 3 keys enabling offline credential extraction

### Accounts That Need Rotation
| Account | Service | Priority |
|---------|---------|----------|
| All browser-saved passwords | Every website in Edge/Chrome/Brave | **IMMEDIATE** |
| tlancas25 | GitHub | **IMMEDIATE** |
| <docker-user> | Docker Hub | **IMMEDIATE** |
| <redacted>@outlook.com | Microsoft account | **IMMEDIATE** |
| <redacted>@hotmail.com | Microsoft/Hotmail | **IMMEDIATE** |
| <redacted>@gmail.com | Google (Git identity) | **IMMEDIATE** |
| id_ed25519 | SSH (all servers in known_hosts) | **IMMEDIATE** |
| google_compute_engine | GCP SSH (3 known instances) | **IMMEDIATE** |
| Tailscale node key | Tailscale mesh | HIGH |
| VNC auth cookie | RealVNC Connect | HIGH |
| Router admin password | 192.168.0.1 | HIGH |
| All WiFi passwords | 20 networks | MEDIUM |
| Windows account password | <hostname>\<operator> | **IMMEDIATE** |

### Cloud Services to Audit
- **GitHub:** Check audit log for tlancas25 — unauthorized repo access, commits, or SSH key additions
- **Docker Hub:** Check <docker-user> for unauthorized image pushes (supply chain risk)
- **GCP:** Check Cloud Audit Logs for SSH access from this machine's IPs to the 3 known compute instances
- **Tailscale:** Check admin console for unauthorized device joins or ACL changes
- **Microsoft 365:** Check sign-in logs for <redacted>@outlook.com

---

## Actions Taken

### Phase A: Containment
| Action | Result |
|--------|--------|
| Firewall block: 95.214.234.238, 64.74.162.109, 130.12.180.159 (outbound + inbound) | 4 rules created |
| DNS sinkhole: edgeserv.ru -> 127.0.0.1 | HOSTS entry added |
| Stop "Visual C++" service + set Disabled | Service stopped |
| Kill processes: ScreenConnect (2 PIDs), syslog.exe, RegAsm.exe | All killed |
| Disable scheduled tasks: IsCompleted, EncoderFallback, IsSynchronized | All disabled |
| **Verified: zero C2 connections remaining** | CLEAN |

### Phase B: Forensic Investigation
| Artifact | Finding |
|----------|---------|
| Prefetch | ScreenConnect and RegAsm execution confirmed |
| PowerShell history | `irm https://get.activated.win \| iex` run 6x — probable initial access |
| ScreenConnect config | Hardcoded `edgeserv.ru:8041` relay with session GUID and RSA key |
| HOSTS file | License server sinkholing (pirated Noregon JPRO + CCleaner) |
| Malware file timeline | Jun 2025 -> Sep 2025 -> Sep 2025 -> Mar 2026 deployment wave |
| Zone.Identifier | NONE on any malware — C2-delivered payloads, not browser downloads |
| Service creation log | ScreenConnect install too old for event retention (rolled over) |
| Defender Event 5007 | 30+ config change events (exclusion tampering timeline) |
| syslog.exe metadata | Fake "Linker Corporation" vendor, fake Windows version string |

### Phase C: Removal
| Action | Result |
|--------|--------|
| Quarantine hashes saved for 3 binaries | SHA256 in evidence/quarantine/ |
| Delete: data.exe, syslog.exe, ghost task dirs | **DELETED** |
| Delete: IsCompleted.exe (Count dir) | **LOCKED** (reboot needed) |
| Delete: ScreenConnect dir | **1 file locked** (LSA DLL in lsass.exe, reboot needed) |
| Delete ScreenConnect service | `sc delete` SUCCESS |
| Clean LSA auth packages | Only msv1_0 remains |
| Remove HKCU Run: data, EPSDNMON | REMOVED |
| Unregister tasks: IsCompleted, EncoderFallback, IsSynchronized | ALL REMOVED |
| Remove 16 Defender path exclusions | REMOVED (1 legitimate IE exclusion kept) |
| Remove 14 Defender process exclusions | ALL REMOVED |
| Restore MAPS, cloud block, PUA, network protection | ALL ENABLED |
| Set ExecutionPolicy to RemoteSigned | SET (effective after session) |
| Start full Defender scan | RUNNING in background |

---

## Post-Cleanup System State

| Check | Status |
|-------|--------|
| Active C2 connections | **ZERO** |
| Malware processes running | **ZERO** |
| Malicious scheduled tasks | **ZERO** (all 3 unregistered) |
| Malicious Run key entries | **ZERO** (data + EPSDNMON removed) |
| LSA auth packages | **CLEAN** (msv1_0 only) |
| ScreenConnect service | **DELETED** |
| Defender exclusions | **CLEAN** (only IE path remains) |
| Defender cloud protection | **ENABLED** (Advanced MAPS + High cloud block) |
| Defender PUA protection | **ENABLED** |
| Network protection | **ENABLED** |
| C2 firewall blocks | **ACTIVE** (3 outbound + 1 inbound rule) |
| DNS sinkhole | **ACTIVE** (edgeserv.ru in HOSTS) |

### Requires Reboot
- `C:\Users\<operator>\AppData\Local\Count\` — IsCompleted.exe locked by task scheduler
- `C:\Program Files (x86)\Windows VC\` — 1 LSA DLL locked by lsass.exe

After reboot, manually verify these directories are deletable and remove them.

---

## Remaining Hardening Recommendations

These are NOT part of the malware cleanup but were identified during the scan:

1. **Install Windows updates immediately** — 4+ months of patches missing
2. **Investigate VNC HashMismatch** — vncserver.exe signature invalid; reinstall or remove RealVNC
3. **Fix C:\GenRad, C:\DENSO, C:\i-HDS ACLs** — Authenticated Users have Modify (privesc risk)
4. **Enable firewall logging** on all profiles
5. **Disable NetBIOS** on Wi-Fi and Tailscale adapters
6. **Remove stale firewall rules** (onvue.exe, nut.exe, uTorrent ANY/ANY)
7. **Enable audit policy** for process creation, credential validation, privilege use
8. **Encrypt D: drive** with BitLocker
9. **Segment IoT devices** to guest network/VLAN
10. **Stop using piracy activation scripts** — this was the probable infection vector

---

## Malware Hashes (for VirusTotal / Threat Intel)

```
SHA256: A875D4F7DEE6271EDB043090BFA977F03351CCC8BC527CF7DA5A392D818A0051  data.exe (444.exe)
SHA256: 41C431DC6129D57E0DF76F13655B4211698A3E1457785E84E85DDD2C1A345E4B  IsCompleted.exe (Bcesuajgcga.exe)
SHA256: F2110725AE6D45908008091D34203277360BE9958E67C7FF5DBEB1FB3F3ACD8B  syslog.exe (Linker.exe)
```

## C2 Infrastructure (for blocking / reporting)

```
95.214.234.238:8041   — ScreenConnect relay (edgeserv.ru), vsys.host Russia
64.74.162.109:443     — syslog.exe beacon, no rDNS
130.12.180.159:56009  — RegAsm LOLBin C2, no rDNS
```

---

*Report generated by REDFORGE incident response module.*  
*Scan + containment + forensics + cleanup completed in a single session.*
