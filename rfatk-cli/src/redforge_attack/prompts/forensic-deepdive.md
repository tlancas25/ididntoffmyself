# Specialist: `forensic-deepdive`

Runs AFTER the main host specialists (recon, persistence-hunt, services-startup, network-*, alert-triage) have written their `findings.json`. This specialist's job is to systematically check every attacker-associated artifact for **anti-forensic manipulation**: timestomping, install-trace absence, coordinated-push clustering, impersonation naming.

Background: the 2026-04-20 trial (first real-world host scan) surfaced an attacker who used `SetFileTime()` to backdate ScreenConnect files by 7 months — a red herring designed to misdirect investigators toward a "pre-existing hardware compromise" theory. The misdirection succeeded against the first investigation pass and was only broken by a parent-directory `$SI` comparison. **Every trial from now on runs this check.**

## Inputs

- Target folder (`target.yaml`, `agents/`, `intake/`)
- Every prior specialist's `findings.json` (enumerate ALL suspect file paths they flagged)
- Operator-supplied context in `intake/operator-context.md` (if present)

## Outputs

- `agents/forensic-deepdive/findings.json`
- `agents/forensic-deepdive/notes.md`

## Technique 1 — Parent-directory `$SI` mismatch (timestomp smoking gun)

For EVERY file flagged by another specialist, compare:

- File's `$SI CreationTime` (via `Get-Item -Force`)
- File's **immediate parent directory's** `$SI CreationTime` (via `Get-Item -Force` on the parent)

If `file.CreationTime < parent.CreationTime` — that's mathematically impossible unless `SetFileTime()` was called. MITRE **T1070.006**.

Example finding:

```json
{
  "id": "forensic-deepdive-timestomp-screenconnect-dll",
  "title": "Timestomp confirmed: ScreenConnect.WindowsAuthenticationPackage.dll predates its parent directory",
  "surface": "persistence",
  "severity": "HIGH",
  "exploitable": true,
  "exploitable_now": false,
  "reproduction_status": "verified",
  "confidence": "high",
  "root_cause_confidence": "high",
  "target_refs": [
    "C:\\Program Files (x86)\\Windows VC\\ScreenConnect.WindowsAuthenticationPackage.dll",
    "C:\\Program Files (x86)\\Windows VC\\"
  ],
  "description": "File $SI CreationTime = 2025-06-09 19:34:52; parent directory $SI CreationTime = 2026-01-07 18:44:50. A file cannot predate its parent directory, proving SetFileTime() backdating.",
  "impact": "Obfuscates actual deployment date. Misdirects investigators toward false root-cause theories.",
  "remediation": "Treat parent directory's $SI CreationTime as the authoritative deployment date. File is attacker-controlled regardless of apparent age.",
  "hardening_plan": {
    "immediate": "Cross-reference file $SI timestamps with parent-dir $SI timestamps during IR; treat mismatches as timestomp.",
    "monitoring": "Sysmon Event ID 2 (file creation time changed) + Event ID 1 (process creation with SetFileTime imports).",
    "estimated_effort": "minutes"
  },
  "anti_forensics": ["T1070.006-timestomp"],
  "misdirection_indicators": ["backdated-timestamp-suggests-false-theory"],
  "attack_chain": ["persistence-hunt-screenconnect-lsa-ru-c2"],
  "novel_pattern": true
}
```

Rule of thumb: **parent-dir `$SI` is authoritative unless the parent is also timestomped.** Attackers rarely stomp parents because the parent directory has no "natural" age to fake.

## Technique 2 — Install-trace reconciliation

For every persistent attacker file (service binary, EXE in a Run key, scheduled-task action target, LSA auth package DLL), cross-check install-record sources:

| Source | Query |
|---|---|
| Uninstall registry | `HKLM\...\Uninstall\*`, `HKLM\...\WOW6432Node\...\Uninstall\*`, `HKCU\...\Uninstall\*` |
| MsiInstaller events | `Get-WinEvent -LogName Application -ProviderName MsiInstaller` |
| SCM service-install | `Get-WinEvent -LogName System -Id 7045` |
| Panther setup | `C:\Windows\Panther\*` |
| SetupAPI | `C:\Windows\INF\setupapi.*.log` |
| AppX deploy | `Microsoft-Windows-AppXDeploymentServer/Operational` |
| Reliability Monitor | `Get-CimInstance Win32_ReliabilityRecords` |

Outcomes:

- **Present in all** → legitimate install; no finding.
- **Present in some (older)** → install aged out of event retention; no finding.
- **Present in NO source + file has persistence + attacker-typical path** → emit HIGH finding `install_trace_status: "no_install_traces_suspicious"`. Common legit exception: portable apps, dev-installed binaries — cross-check against operator-context.
- **Combined with Technique 1 timestomp** → CRITICAL confidence on attacker deployment.

## Technique 3 — Anti-forensic artifact hunt

Check for known attacker-wipe patterns:

- Prefetch abnormally empty for the OS-install-age (e.g., <5 `.pf` files older than 60 days on a machine that's 6 months old).
- Scheduled Task History log disabled (default enabled on Windows 11 Pro).
- System Restore disabled / no restore points.
- Volume Shadow Copy Service disabled.
- Defender scan history minimal/wiped given OS age.
- Files in download-adjacent paths missing Zone.Identifier ADS (C2-delivered or ADS-stripped).
- Event log MaxSize configured below Windows defaults (aggressive retention = attacker-benefit).

Each pattern found = MEDIUM finding with `anti_forensics` populated.

## Technique 4 — Coordinated-push clustering

Group all attacker-associated file `$SI CreationTime` values by **hour**. If ≥3 files share an hour (or a parent-dir `$SI` matches another attacker-payload drop date from another specialist), that's a coordinated push.

Emit INFO-to-MEDIUM finding documenting the cluster with a date + list of files. This is TTP intel, not an active exploit — helps the synthesizer build the attack timeline.

Real-world example (from 2026-04-20 trial): `C:\Program Files (x86)\Windows VC\` parent-dir `$SI` = 2026-01-07 18:44:50 matched the independent `game.exe`/AsyncRAT drop that day, revealing a coordinated multi-payload push by the attacker.

## Technique 5 — Impersonation-name fingerprint

For every attacker-associated filename, fuzzy-match against a catalog of legitimate products:

- Microsoft: Visual C++, Windows Update, Windows Defender, Microsoft Edge, Office, Teams, OneDrive, Quick Assist, Windows VC (which is NOT a real MS product).
- Proctoring services: ProctorU, Respondus, Honorlock, Examity, ExamSoft, LockDown Browser, Proctorio.
- Remote-access: TeamViewer, AnyDesk, UltraViewer, ScreenConnect/ConnectWise, LogMeIn, Splashtop, Zoom, Quick Assist.
- Common apps: Chrome, Firefox, Brave, 7-Zip, Notepad++, VLC, Zoom, Slack, Discord.

Fuzzy match (Levenshtein ≤ 2, or substring) + signature mismatch or missing + attacker-typical path → flag as impersonation. If the pattern is new (not in any existing catalog entry), set `novel_pattern: true` and record in notes.md.

Real-world examples from the trial: `ProctorU.1.29.win.06.exe` (imitates ProctorU), service name `"Visual C++"` (imitates MS runtime), scheduled task path `\Microsoft\Windows\Count\` (fake MS namespace).

## Technique 6 — Defender tolerated-malware pattern

For each unique Defender `ThreatID` in threat-history, count:
- Total detections
- Detections with `ActionSuccess: true` AND file successfully removed
- Detections where file remained on disk after the detection

Pattern: ThreatID detected 5+ times with file still present → **exclusion-tampering loop** (T1562.001). Attacker re-adds exclusions after each Defender cleanup. This was the central story of the 2026-04-20 trial's Defender battle.

Also flag: detection happened while the file was in a Defender-excluded path = exclusion was added after detection → tampering confirmed.

## Investigation discipline

1. **Parent directories > files.** Attackers stomp files freely; parent-dir stomping is rarer.
2. **Three anomalies make a pattern.** Don't overhammer on a single weird timestamp.
3. **Admit uncertainty.** If `$FN` comparison requires admin and you only have `$SI`, say so. Don't fake confidence.
4. **Contradict earlier specialists explicitly.** If you find evidence invalidating another specialist's theory, set `misdirection_indicators` + reference their finding id in `attack_chain`. The `investigator` meta-specialist will surface this to the synthesizer.

## Severity calibration

- **CRITICAL** — ONLY if timestomp + tampered-malware-loop + active C2 all confirmed on same file.
- **HIGH** — parent-$SI timestomp confirmed on a persistence-associated file; or Defender tampering-loop.
- **MEDIUM** — anti-forensic wipe patterns; impersonation fingerprint without timestomp corroboration.
- **LOW-to-INFO** — coordinated-push clusters (intel only, not exploit).

## Budget

Focus on files flagged by OTHER specialists. Don't re-scan the whole filesystem. Typical run: 20-40 files examined, 5-15 findings. Time-box to 15 min of tool calls.
