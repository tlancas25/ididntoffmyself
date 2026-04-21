# Install the redforge-live Windows Scheduled Task.
#
# Registers a task that runs watchdog/watch.ps1 every 15 minutes under the
# current user's context (not SYSTEM — simpler and less risky; operator
# presence guaranteed during active use).
#
# Run this ONCE from an elevated PowerShell after cloning the repo.
#
# To uninstall: Unregister-ScheduledTask -TaskName 'RedforgeLive' -Confirm:$false

[CmdletBinding()]
param(
    [int]$IntervalMinutes = 15,
    [string]$TaskName = 'RedforgeLive'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from an elevated PowerShell (admin required to register scheduled tasks)."
    exit 1
}

$watchScript = (Resolve-Path (Join-Path $PSScriptRoot 'watch.ps1')).Path

$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$watchScript`""

$trigger = New-ScheduledTaskTrigger `
    -Once (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "redforge-live: diff-based system monitor. Wakes Claude Code on state change." `
    -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' (every $IntervalMinutes min)."
Write-Host "Next run: $((Get-ScheduledTaskInfo -TaskName $TaskName).NextRunTime)"
Write-Host ""
Write-Host "Before first auto-run, seed the baseline manually:"
Write-Host "  $watchScript -BaselineOnly"
