# Trial 1 — First REDFORGE Host-Scan (2026-04-20)

**Target:** lead developer's second-hand Windows 11 laptop (thrift-store purchase)
**Operator:** BlaFrost Softwares Corp — Terrell A. Lancaster, lead developer
**Engine:** Claude Code running Opus 4.7 (native, pre-CLI)
**Duration:** ~60 minutes active enumeration + ~90 minutes IR
**Outcome:** Active 10-month compromise detected, contained, remediated in-session

---

## Executive summary

The first REDFORGE host-scan trial was intended to generate a preventative hardening baseline on the lead developer's personal machine. Within minutes, the `persistence-hunt` specialist surfaced indicators of an active, multi-channel compromise. The scan pivoted to a full incident response and discovered:

- **8 malware binaries** deployed over ~7 months (Aug 2025 – Mar 2026)
- **3 independent C2 channels** (ScreenConnect RMM to a Russian relay, a custom HTTPS beacon, and a Microsoft-signed LOLBin proxy)
- **Comprehensive Defender neutralization** via exclusion tampering, cloud-protection disablement, and ASR-rule wipe
- **Russian threat actor** attribution (VMProtect-signed binary with Ekaterinburg registration; `.ru` relay infrastructure)

The compromise originated in a **social-engineering proctoring scam** on 2025-08-29 (attacker handle `dr.jamespaul` in the remote-control operator interface) with same-vector re-victimization on 2025-09-08 via `ProctorU.1.29.win.06.exe`. The attacker used `SetFileTime()` to **timestomp** ScreenConnect files back to June 2025 as anti-forensics — a deliberate red herring that initially misled investigation toward a pre-compromised-hardware theory. See Correction below + `FINDINGS.md` for the decisive timestomp evidence.

---

## Correction — 2026-04-21 (v2 — supersedes v1)

This trial's initial-access narrative has been revised twice as evidence emerged. The trail is documented in full so readers see the investigative arc, not just the final answer:

1. **Original claim (2026-04-20):** MAS PowerShell runs (`irm https://get.activated.win | iex`) were the likely initial access vector.
2. **First correction (2026-04-21 morning):** Ruled MAS out as temporally impossible. Attributed initial access to **pre-compromised hardware at resale** (ScreenConnect files appeared dated before the Windows install date).
3. **Second correction (2026-04-21 evening — this one):** Operator recollection + deeper `$SI` timestamp forensics invalidated *both* prior theories. Actual vector was a **social-engineering proctoring scam** on **2025-08-29** in which the attacker, using the login handle `dr.jamespaul` (or variant) inside the remote-control operator UI, instructed the operator to install **UltraViewer** plus a second remote-control tool under the pretext of exam-proctor setup. The ScreenConnect files appearing to be from 2025-06-09 were **timestomped** (`SetFileTime()`) as anti-forensics — the containing folder's `$SI CreationTime` is 2026-01-07, and a file cannot predate its parent directory, proving backdating. Actual ScreenConnect deployment date: **2026-01-07**, matching the independently-verified `game.exe`/AsyncRAT drop.

Revised public narrative: **student-targeted proctoring-scam re-victimization with sophisticated anti-forensics (`SetFileTime()` timestomp, `%TEMP%` wipe, Defender-exclusion tampering).** Active attacker dwell was ~7 months (Aug 2025 – Mar 2026). The operator did not experience a passive "unwitting 10-month compromise" — they *tolerated* the "proctoring software" during their proctored-exam coursework because they believed it was required, and manually began deleting it in March 2026 once courses ended. REDFORGE was run April 2026 and surfaced the residual persistence that manual cleanup missed.

**Headline lesson shifts** from "check second-hand hardware" to **"verify any proctor or instructor who asks you to install remote-access software before an exam — call your institution's IT help desk and get written confirmation before complying."** Second-hand hardware *is* a real vector worth worrying about; it just wasn't the vector here.

See `FINDINGS.md` for the decisive timestomp evidence and the full revised timeline.

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
