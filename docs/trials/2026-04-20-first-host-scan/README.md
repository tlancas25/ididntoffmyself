# Trial 1 — First REDFORGE Host-Scan (2026-04-20)

**Target:** lead developer's second-hand Windows 11 laptop (thrift-store purchase)
**Operator:** BlaFrost Softwares Corp — Terrell A. Lancaster, lead developer
**Engine:** Claude Code running Opus 4.7 (native, pre-CLI)
**Duration:** ~60 minutes active enumeration + ~90 minutes IR
**Outcome:** Active 10-month compromise detected, contained, remediated in-session

---

## Executive summary

The first REDFORGE host-scan trial was intended to generate a preventative hardening baseline on the lead developer's personal machine. Within minutes, the `persistence-hunt` specialist surfaced indicators of an active, multi-channel compromise. The scan pivoted to a full incident response and discovered:

- **8 malware binaries** deployed over ~10 months (Jun 2025 – Mar 2026)
- **3 independent C2 channels** (ScreenConnect RMM to a Russian relay, a custom HTTPS beacon, and a Microsoft-signed LOLBin proxy)
- **Comprehensive Defender neutralization** via exclusion tampering, cloud-protection disablement, and ASR-rule wipe
- **Russian threat actor** attribution (VMProtect-signed binary with Ekaterinburg registration; `.ru` relay infrastructure)

The compromise predated the current Windows install — the thrift machine arrived already backdoored via an LSA Authentication Package that survived the pre-sale reset.

---

## Correction — 2026-04-21

The original `post-cleanup-report` (now `scan-post-cleanup-report.md`) framed the Microsoft Activation Scripts (MAS) runs found in PowerShell history as the "most likely initial access vector." **That framing was wrong.**

A forensic follow-up on 2026-04-21 (see `FINDINGS.md`) confirmed the initial access vector was **pre-compromised hardware at resale**, not MAS:

- Windows 11 OOBE on this machine: **2025-09-07 17:49:59** (confirmed by WMI, registry, and Panther logs — four independent sources agree).
- ScreenConnect LSA Authentication Package DLL timestamp: **2025-06-09** — three months BEFORE the current Windows install.
- Earliest possible MAS run: ~28 minutes after OOBE completed on 2025-09-07 — temporally incompatible with the June 2025 ScreenConnect files.
- Zero `ScreenConnect` / `ConnectWise` entries in any Uninstall registry hive, and zero MSI install events in the Application log — confirming ScreenConnect was not installed via Windows Installer on this OS.

`scan-post-cleanup-report.md` § "Initial Access Vector" has been rewritten. The MAS runs are now documented as a separate piracy-risk observation, not the foothold. Also added: secondary observation on a legitimately-installed **TeamViewer** (second RMM on the machine, separate from the attacker's channel).

Public-narrative impact: this is an even stronger story for "second-hand hardware carries persistent malware" — the headline lesson for consumer buyers. Lesson: **factory reset is not clean install.**

---

## What's in this directory

| File | Purpose |
|------|---------|
| [`public-report.md`](public-report.md) | Case-study narrative. Suitable for public consumption. The 4-month adversarial timeline, what Defender did / didn't catch, detection patterns surfaced. |
| [`MSRC-report.md`](MSRC-report.md) | Formal Microsoft Security Response Center disclosure draft. Documents the **Tamper Protection scope gap** — a real Windows Defender vulnerability where exclusion manipulation, cloud protection, PUA, network protection, and ASR rules are all **outside** Tamper Protection's scope. Includes reproduction steps (2-line PowerShell) and proposed mitigations. |
| [`scan-report.md`](scan-report.md) | Full REDFORGE raw-bundle output — 79 raw → 46 unique findings across 9 specialists, dedupe clusters, cross-agent attack chains, novel-patterns flagged for detection-rule promotion. |
| [`scan-post-cleanup-report.md`](scan-post-cleanup-report.md) | IR actions log. Containment / forensics / removal / Defender restoration phases. Credential rotation priorities. Post-cleanup system state verification. **§ "Initial Access Vector" was rewritten 2026-04-21** — see the Correction section above. |
| [`FINDINGS.md`](FINDINGS.md) | **2026-04-21 forensic follow-up** on the install-vector question. Multi-source timeline reconstruction (WMI / Panther / registry / MsiInstaller event log / Uninstall hives / PS console history) that definitively confirms pre-compromised hardware and rules out the MAS script as the initial foothold. Also flags TeamViewer as a legitimate second RMM on the machine. |

All files are scrubbed per the redaction policy at the top of each file. Operator identifiers are anonymized; threat intel (C2 IPs, malware hashes, MITRE IDs, attribution indicators, Defender detection names) is preserved.

---

## Why this case study matters

Three reasons we're publishing:

1. **The Tamper Protection scope gap is a real Windows vulnerability worth disclosing.** A SYSTEM-privileged attacker can blanket-exclude `C:\Users` and `powershell.exe` without tripping Tamper Protection. Defender will detect the exclusion entries themselves as malicious (Trojan:Win32/Suweezy), but cannot prevent the attacker from re-adding them after remediation. The MSRC report documents the attack chain with event-log evidence and proposes specific mitigations.

2. **Second-hand hardware is a vector most people underestimate.** "Factory reset" and "Reset this PC" do not remove LSA authentication packages, boot-sector implants, or firmware-level threats. The ONLY reliable cleanup of a used PC is: download Windows ISO on a trusted device → verify hash → clean-install from that media → reset UEFI to factory → verify firmware. This trial demonstrates why.

3. **REDFORGE surfaced in ~60 minutes what Defender missed for 10 months.** Parallel specialist agents auditing different attack surfaces (persistence, network posture, credentials, config baseline, etc.) and cross-correlating their findings catch compromise patterns that pattern-based EDR cannot. This is the product thesis — multi-agent AI red-team methodology applied to preventative security.

---

## MITRE ATT&CK coverage observed

| Technique | Observed as |
|-----------|------------|
| T1219 (Remote Access Software) | Weaponized ConnectWise ScreenConnect |
| T1547.002 (LSA Authentication Package) | `ScreenConnect.WindowsAuthenticationPackage.dll` in lsass.exe |
| T1036.005 (Match Legitimate Name/Location) | Service named "Visual C++"; `\Microsoft\Windows\Count\` path |
| T1562.001 (Disable/Modify Tools — Defender) | Exclusion tampering, cloud protection off, ASR wipe |
| T1053.005 (Scheduled Task) | `IsCompleted` task with 5m44s non-standard interval |
| T1547.001 (Registry Run Keys) | HKCU Run: `data.exe` |
| T1071.001 (Application Layer Protocol — Web) | syslog.exe HTTPS beacon to 64.74.162.109 |
| T1218.009 (Signed Binary Proxy — RegAsm) | Malicious .NET assembly loaded through RegAsm.exe |

---

## C2 infrastructure (for defenders — block these at your perimeter)

```
95.214.234.238:8041    — ScreenConnect relay (edgeserv.ru)   — vsys.host, Russia
64.74.162.109:443      — syslog.exe beacon                    — no rDNS
130.12.180.159:56009   — RegAsm LOLBin C2                     — no rDNS
edgeserv.ru            — DNS name for C2 relay                — block at resolver
```

## Malware hashes (for threat intel / VirusTotal correlation)

```
SHA256: A875D4F7DEE6271EDB043090BFA977F03351CCC8BC527CF7DA5A392D818A0051  data.exe (444.exe)           — Trojan:Win32/Ravartar!rfn
SHA256: 41C431DC6129D57E0DF76F13655B4211698A3E1457785E84E85DDD2C1A345E4B  IsCompleted.exe (Bcesuajgcga) — Custom trojan
SHA256: F2110725AE6D45908008091D34203277360BE9958E67C7FF5DBEB1FB3F3ACD8B  syslog.exe (Linker.exe)       — Custom C2 beacon
```

Additional binaries discovered by post-cleanup Defender scan: `ProctorU.1.29.win.06.exe` (Trojan:MSIL/Zilla.IVK!MTB), `game.exe` (Trojan:MSIL/AsyncRAT.SJ!MTB).

---

## Disclosure status

- **MSRC submission:** draft ready in `MSRC-report.md`. Pending operator review before formal submission to Microsoft.
- **Public disclosure:** this repo. Published 2026-04-21.
- **VirusTotal:** hashes not yet submitted. Decision deferred to operator (attribution vs intel-value tradeoff).
- **Law enforcement:** not pursued at this time. Machine is out of service; compromise is contained.

---

## Credits

REDFORGE methodology, host-scan sandbox, specialist roster, severity calibration, and synthesis pipeline © 2026 BlaFrost Softwares Corp. Lead developer: Terrell A. Lancaster. Engine: Claude Code (Anthropic) running Claude Opus 4.7.

Not affiliated with Anthropic, ConnectWise, Microsoft, or any other vendor referenced in this report.
