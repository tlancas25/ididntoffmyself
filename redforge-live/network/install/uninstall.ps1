# redforge-live -- uninstall script.
#
# Unregisters the scheduled task and (optionally) removes C:\redforge-live\
# + all Windows Firewall rules created by the tool.

[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\redforge-live',
    [string]$TaskName = 'RedforgeLive-Network',
    [switch]$RemoveStateAndLogs,
    [switch]$RemoveFirewallRules
)

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from elevated PowerShell."
    exit 1
}

Write-Host "=== redforge-live uninstaller ==="

# 1. Unregister task
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "  task '$TaskName' unregistered"
} catch {
    Write-Warning "  could not unregister task: $_"
}

# 2. Kill any running watcher + dashboard processes
Get-Process -Name 'powershell' -ErrorAction SilentlyContinue | Where-Object {
    try {
        $_.CommandLine -match 'redforge-live.*(watcher|dashboard)\.ps1'
    } catch { $false }
} | ForEach-Object {
    $which = if ($_.CommandLine -match 'dashboard\.ps1') { 'dashboard' } else { 'watcher' }
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  killed $which PID $($_.Id)"
}

# 3. Optionally remove firewall rules
if ($RemoveFirewallRules) {
    $rules = Get-NetFirewallRule -Group 'RedforgeLive' -ErrorAction SilentlyContinue
    if ($rules) {
        Write-Host "  removing $($rules.Count) firewall rules (Group='RedforgeLive')..."
        Remove-NetFirewallRule -Group 'RedforgeLive' -Confirm:$false
    } else {
        Write-Host "  no firewall rules to remove"
    }
} else {
    Write-Host "  (firewall rules preserved; use -RemoveFirewallRules to also remove)"
}

# 4. Optionally remove state + logs
if ($RemoveStateAndLogs) {
    if (Test-Path $InstallRoot) {
        Remove-Item -Path $InstallRoot -Recurse -Force
        Write-Host "  removed $InstallRoot"
    }
} else {
    Write-Host "  (state + logs preserved at $InstallRoot; use -RemoveStateAndLogs to delete)"
}

Write-Host ""
Write-Host "Uninstall complete."
