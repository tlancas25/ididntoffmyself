# Invokes Claude Code to triage batched anomalies.
# Called by watcher.ps1 every 5 minutes when triage-queue.jsonl is non-empty.
#
# Claude's output goes to alerts.jsonl + alerts.md; baseline.json may be
# updated for benign classifications.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$QueueFile,
    [Parameter(Mandatory)][string]$BaselineFile,
    [Parameter(Mandatory)][string]$AlertsFile,
    [Parameter(Mandatory)][string]$PromptFile
)

if (-not (Test-Path $QueueFile)) {
    Write-Host "No queue file -- nothing to triage."
    exit 0
}
if ((Get-Item $QueueFile).Length -eq 0) {
    Write-Host "Queue empty -- nothing to triage."
    exit 0
}

# Prompt Claude Code with a one-shot instruction.
$prompt = @"
You are the batch triage agent for redforge-live's network firewall.

INPUT FILES:
- Anomaly queue: $QueueFile  (JSONL -- one anomaly per line)
- Current baseline: $BaselineFile  (process-to-destinations map)
- Your instructions + IoC list: $PromptFile

OUTPUT FILES:
- Append classifications to: $AlertsFile  (JSONL)
- Append human-readable summary to: $(Join-Path (Split-Path $AlertsFile -Parent) 'alerts.md')
- Update baseline.json if you classify any anomaly as benign (add the
  (process, destination) pair to baseline.Baseline[process]).

CLASSIFY each anomaly as benign|suspicious|malicious per your instructions.
For malicious: include a recommended_actions array with PowerShell one-liners
the operator can review and execute via the tray menu.

Do NOT modify firewall rules yourself. Do NOT kill processes yourself. Only
write classifications and recommended actions.

NEVER publish anything from this session to any repo or external service.
Output stays local in $(Split-Path $AlertsFile -Parent).
"@

Write-Host "Invoking: claude --dangerously-skip-permissions -p <prompt>"
& claude --dangerously-skip-permissions -p "$prompt"

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Claude invocation exited non-zero ($LASTEXITCODE). Queue NOT drained -- will retry next cycle."
    exit $LASTEXITCODE
}

Write-Host "Triage complete."
