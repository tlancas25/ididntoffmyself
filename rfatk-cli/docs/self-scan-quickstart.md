# Self-scan quickstart — running `rfatk attack` against your own machine

**Status:** M7a + M7b shipped. The tool is ready for the first self-scan trial (M8).

The self-scan runs 9 host specialists + recon + synthesizer in parallel against the running Windows machine. All reads are through the PowerShell-allowlist sandbox. The four off-limits folders (Documents / Downloads / Pictures / Videos) are hard-blocked.

## Prerequisites

1. **Windows 10/11** — host-scan mode is Windows-only at v0.1.
2. **PowerShell 5.1+** on PATH (Windows default) or **PowerShell 7 (`pwsh`)** for better compatibility.
3. **Python 3.10+** with `rfatk` installed. From the repo root (`ididntoffmyself/`):
   ```
   pipx install -e .\rfatk-cli
   ```
   (Or with a dev venv: `python -m venv .venv ; .venv\Scripts\python -m pip install -e .\rfatk-cli` and then use `.venv\Scripts\rfatk.exe`.)
4. **An LLM provider key.** For the demo, Anthropic is recommended (best tool-use quality):
   ```
   $env:ANTHROPIC_API_KEY = "sk-ant-..."
   ```
   (Or any of the 11 supported vendors — `rfatk attack --provider <name>` picks the matching env var.)

## Scan

### 1. Open an elevated PowerShell — AND launch Claude Code in bypass-permissions mode

Because we approved `--allow-admin`, the shell needs admin rights for the deep queries (SAM hive, Security event log, full socket attribution, service DACLs, BitLocker protectors).

**Step 1a — elevate:** right-click PowerShell → **Run as administrator**. Or from a current PowerShell, this one-liner opens an elevated PowerShell that drops you straight into Claude Code with bypass-permissions active:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList `
  '-NoExit','-Command', `
  'Set-Location "C:\path\to\your\workspace"; claude --dangerously-skip-permissions'
```

**Step 1b — confirm bypass mode is active.** In the new Claude Code session you should see bypass mode indicated. Then `whoami /priv` should show SeBackupPrivilege / SeTakeOwnershipPrivilege and `net session` should NOT return "System error 5."

**Why bypass-permissions mode matters for scans:** a host-scan trial runs 100-500 PowerShell queries. Per-command approval prompts make the trial unusably slow — the operator spends more time clicking approve than the scan takes to run. Bypass mode skips those prompts.

**Is it safe?** Yes, *in a scan context*. The safety model is layered:
- When running the packaged `rfatk` CLI, the `host_sandbox` enforces the allowlist at the tool layer — bypassing Claude Code's prompt is fine because the CLI still blocks off-list commands.
- When running in the `claude-code-native/` flow (no rfatk), the specialist prompts bind Claude to the allowlist by instruction. The workspace-template ships a `.claude/settings.json` with `defaultMode: bypassPermissions` already set.
- Either way, the 4 excluded folders (Documents/Downloads/Pictures/Videos) remain off-limits via prompts and (in rfatk) hard-enforcement.

**Alternative — persistent project config:** drop a `.claude/settings.json` in your workspace with:

```json
{
  "permissions": { "defaultMode": "bypassPermissions" },
  "skipDangerousModePermissionPrompt": true
}
```

That way every Claude Code session launched in that workspace skips prompts without needing the CLI flag. The `claude-code-native/workspace-template/` in this repo ships this pre-configured.

### 2. Scaffold the target folder

```powershell
rfatk init my-machine `
    --target-type host `
    --provenance human `
    --source "windows-$(hostname)" `
    --surfaces host-services network security `
    --auth-note "Operator-owned device; self-scan authorized <DATE> (full admin + LAN-sweep approved)"
```

This creates `targets/my-machine-<timestamp>/` with the canonical skeleton. Note the folder name — you'll pass it to `attack` next.

### 3. Run the full trial

```powershell
rfatk attack .\targets\my-machine-<timestamp> `
    --provider anthropic `
    --allow-admin `
    --allow-network-probe `
    --max-parallel 4 `
    --max-tokens-budget 300000
```

The trial runs in this order:
1. **recon** — fingerprint the machine (sequential, ~5 minutes)
2. **9 specialists in parallel** (max 4 at once) — services-startup · network-listening · network-posture · alert-triage · windows-config-audit · firewall-audit · local-subnet-sweep · credentials-exposure · persistence-hunt
3. **synthesizer** (mechanical) — writes `report.md` with Fix-These-First, Hardening Plan, Main findings, Hardening Recommendations, cross-agent chains, duplicate clusters
4. **synthesizer agent** — writes `agents/synthesizer/notes.md` with the human-judgment layer

Expected duration: 15–30 minutes. Token cost: ~$5–15 on Anthropic Haiku 4.5 + Sonnet 4.5 for the synthesizer.

### 4. Read the bundle

```powershell
# Raw bundle — findings + hardening plan + chains
notepad .\targets\my-machine-<timestamp>\report.md

# Synthesizer's judgment layer
notepad .\targets\my-machine-<timestamp>\agents\synthesizer\notes.md

# Per-specialist deep dives
ls .\targets\my-machine-<timestamp>\agents\
```

## What to expect in the report

The `Hardening Plan (prioritized)` section at the top groups findings by effort (minutes → hours → days → weeks), each with a copy-paste `immediate` command. Work top-down.

Below that:
- **Fix These First (candidates)** — CRITICAL findings with `exploitable_now: true`.
- **Main findings** — full detail, sorted severity → exploitable-now → confidence.
- **Hardening Recommendations** — posture improvements (not exploits).
- **Cross-agent chains** — multi-specialist attack paths.
- **Suspected duplicate clusters** — token-overlap advisories.

## Alert-triage note

The `alert-triage` specialist captures the machine's Defender / event-log baseline at trial start, then diffs after the scan. It classifies every new alert as:
- **scan-induced noise** — from our own scan activity; verified + suppressed
- **scan-exposed pre-existing issue** — REAL finding; prioritized
- **concurrent benign** — unrelated; logged
- **uncertain** — flagged for your manual review

Baseline artifacts live at `evidence/alert-triage-baseline/` inside the target folder.

## Safety rails active during the scan

- **Path sandbox:** any command referencing `\Documents\`, `\Downloads\`, `\Pictures\`, or `\Videos\` is REJECTED before execution.
- **Command allowlist:** only pre-approved read-only system queries execute. Shell composition (`;`, `|`, `&&`, `||`, redirects, backticks, `$()`) is rejected.
- **Consent gates:** admin-required commands fail without `--allow-admin`. Network probes fail without `--allow-network-probe`.
- **Read-only:** the allowlist contains ZERO commands that modify state. Nothing writes, deletes, installs, or modifies registry/services.
- **No ~/.claude/ reuse:** `rfatk` refuses to read Claude Code auth artifacts — only the `ANTHROPIC_API_KEY` env var (or explicit `--api-key`).

## If something goes wrong

- **Command rejected:** the specialist sees the `SandboxViolation` error and self-corrects. This is normal — not a failure of the trial.
- **Defender alerts:** expected. The `alert-triage` specialist will classify them. Don't panic; don't click "quarantine."
- **Network probes timing out on dead neighbors:** also expected. Test-NetConnection has a short timeout; the specialist moves on.
- **An entire specialist fails:** the orchestrator logs the failure (`trial.failures`) and continues. The synthesizer runs over whatever succeeded.
- **Trial abort (Ctrl-C):** safe. The next trial creates a new timestamped folder; the partial one is preserved for review.

## Expected output shape for the demo

Approximately (highly dependent on your machine's actual posture):
- 4-8 CRITICAL (exploitable-today, unauth/single-session, direct impact)
- 15-30 HIGH
- 30-60 MEDIUM / LOW combined
- A prioritized Hardening Plan grouped: ~10 minutes, ~20 hours, ~5 days

If the tool is working, the report should look something like a pentest firm's deliverable — skimmable top-level, drill-downable per specialist, and actionable.

## Next steps after the scan

1. Read the Hardening Plan section top-to-bottom.
2. Apply the `minutes` bucket immediately.
3. Schedule `hours` and `days` buckets.
4. Re-run the scan after your fixes — a clean diff validates the remediation.
5. Consider a monthly or quarterly re-scan cadence to catch posture drift.
