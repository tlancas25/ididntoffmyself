# redforge-live -- install script (run from ELEVATED PowerShell, once).
#
# Copies bin/ + prompts/ to C:\redforge-live\, seeds state/ config,
# registers scheduled task "RedforgeLive-Network" to run at operator
# logon with highest privileges.

[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\redforge-live',
    [string]$TaskName = 'RedforgeLive-Network'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this installer from an elevated PowerShell."
    exit 1
}

$SourceRoot = Split-Path $PSScriptRoot -Parent  # .../network/

Write-Host "=== redforge-live network installer ==="
Write-Host "Source:  $SourceRoot"
Write-Host "Install: $InstallRoot"
Write-Host ""

# 1. Create install-root structure
foreach ($sub in 'bin','prompts','state','logs','quarantine','web','.claude') {
    $p = Join-Path $InstallRoot $sub
    if (-not (Test-Path $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        Write-Host "  mkdir $p"
    }
}

# 2. Copy files
Write-Host ""
Write-Host "Copying source files..."
Copy-Item -Path (Join-Path $SourceRoot 'bin\*')     -Destination (Join-Path $InstallRoot 'bin')     -Recurse -Force
Copy-Item -Path (Join-Path $SourceRoot 'prompts\*') -Destination (Join-Path $InstallRoot 'prompts') -Recurse -Force
Copy-Item -Path (Join-Path $SourceRoot 'web\*')     -Destination (Join-Path $InstallRoot 'web')     -Recurse -Force

# Seed CLAUDE.md at install root (chat context for dashboard sessions)
$ClaudeMdSrc = Join-Path $SourceRoot 'CLAUDE.md'
$ClaudeMdDst = Join-Path $InstallRoot 'CLAUDE.md'
if (Test-Path $ClaudeMdSrc) {
    Copy-Item -Path $ClaudeMdSrc -Destination $ClaudeMdDst -Force
    Write-Host "  seeded CLAUDE.md at install root"
}

# Seed .claude/settings.json (bypass-permissions + deny-list for chat sessions)
$ClaudeSettingsSrc = Join-Path $SourceRoot 'claude-settings-template.json'
$ClaudeSettingsDst = Join-Path $InstallRoot '.claude\settings.json'
if ((Test-Path $ClaudeSettingsSrc) -and (-not (Test-Path $ClaudeSettingsDst))) {
    Copy-Item -Path $ClaudeSettingsSrc -Destination $ClaudeSettingsDst -Force
    Write-Host "  seeded .claude/settings.json"
}

# 3. Seed initial config if missing
$ConfigFile = Join-Path $InstallRoot 'state\config.json'
if (-not (Test-Path $ConfigFile)) {
    $cfg = @{
        LearningDurationDays = 14
        ObservationIntervalSec = 10
        TriageIntervalMin = 5
        AutoBlockOnIoCMatch = $true
        AutoKillOnIoCMatch = $true
        KillSwitchDestinations = @(
            '95.214.234.238','64.74.162.109','130.12.180.159'
        )
    }
    $cfg | ConvertTo-Json -Depth 5 | Set-Content $ConfigFile -Encoding UTF8
    Write-Host "  seeded config.json"
}

# 4. Seed mode = Learning
$ModeFile = Join-Path $InstallRoot 'state\mode.txt'
if (-not (Test-Path $ModeFile)) {
    Set-Content -Path $ModeFile -Value 'Learning'
    Write-Host "  mode.txt = Learning"
}

# 5. Seed empty baseline
$BaselineFile = Join-Path $InstallRoot 'state\baseline.json'
if (-not (Test-Path $BaselineFile)) {
    '{}' | Set-Content $BaselineFile -Encoding UTF8
    Write-Host "  seeded empty baseline.json"
}

# 6. Register scheduled task
Write-Host ""
Write-Host "Registering scheduled task '$TaskName'..."

$watchScript = Join-Path $InstallRoot 'bin\watcher.ps1'

$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$watchScript`""

$trigger = New-ScheduledTaskTrigger `
    -AtLogOn `
    -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -MultipleInstances IgnoreNew

# Highest privileges so firewall rule creation works
$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "redforge-live network watcher -- learning firewall + tray UI." `
    -Force | Out-Null

Write-Host "Task registered."
Write-Host ""
Write-Host "=== Install complete ==="
Write-Host ""
Write-Host "To start NOW (without logoff/logon): "
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host ""
Write-Host "Or manually:"
Write-Host "  powershell.exe -ExecutionPolicy Bypass -File '$watchScript' -ShowConsole"
Write-Host ""
Write-Host "Dashboard: http://127.0.0.1:47474/  (opens after watcher starts; tray -> Open dashboard)"
Write-Host ""
Write-Host "Learning mode is active for 14 days. During this period, all"
Write-Host "observed (process -> destination) pairs are silently learned."
Write-Host "After 14 days, watcher will transition to Enforcing mode and"
Write-Host "anomalies will be triaged via Claude Code."
Write-Host ""
Write-Host "Force transition early:"
Write-Host "  Set-Content '$ModeFile' 'Enforcing'"
Write-Host ""
Write-Host "Uninstall: .\uninstall.ps1"
