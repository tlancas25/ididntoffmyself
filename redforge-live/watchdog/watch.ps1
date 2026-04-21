# redforge-live watchdog — Phase 1 (Option A: scheduled-task polling)
#
# Runs from a Windows Scheduled Task every N minutes. Snapshots current
# system state, diffs against state/baseline.json, and if the diff is
# non-empty, invokes `claude -p` with state/incoming-diff.json as input
# and prompts/triage.md as the instruction.
#
# Read-only by design. Never modifies system state. All output in state/.
#
# Usage:
#   .\watch.ps1                      # normal run: snapshot, diff, triage-if-changed
#   .\watch.ps1 -BaselineOnly        # create initial baseline without triage
#   .\watch.ps1 -DryRun              # snapshot + diff, print to stdout, no Claude call
#   .\watch.ps1 -Verbose             # more logging

[CmdletBinding()]
param(
    [switch]$BaselineOnly,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- paths ---
$RepoRoot    = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$StateDir    = Join-Path $RepoRoot 'state'
$Baseline    = Join-Path $StateDir 'baseline.json'
$Incoming    = Join-Path $StateDir 'incoming-diff.json'
$AlertsLog   = Join-Path $StateDir 'alerts.jsonl'
$LastRun     = Join-Path $StateDir 'last-run.txt'

if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }

# --- excluded folders (hard guard) ---
$EXCLUDED = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Videos"
)

# --- snapshot functions (all read-only) ---

function Get-Snapshot {
    Write-Verbose "Snapshotting system state..."
    $s = [ordered]@{}

    # Services — name + BinaryPathName + StartName + StartMode
    $s.services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, PathName, StartName, StartMode, State, Description)

    # Scheduled tasks (user + system), author + action target
    $s.scheduledTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            TaskPath = $_.TaskPath
            TaskName = $_.TaskName
            State    = $_.State.ToString()
            Author   = $_.Author
            Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
            Principal = $_.Principal.UserId
            RunLevel = $_.Principal.RunLevel.ToString()
        }
    })

    # HKLM Run + HKCU Run + Winlogon Userinit/Shell
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $s.runKeys = @()
    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        $s.runKeys += [PSCustomObject]@{
                            Hive = $rk
                            Name = $_.Name
                            Value = $_.Value
                        }
                    }
            }
        }
    }

    # LSA Authentication Packages (the Trial #1 persistence)
    $s.lsaAuthPackages = @()
    try {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
        if ($lsa.'Authentication Packages') { $s.lsaAuthPackages += $lsa.'Authentication Packages' }
        if ($lsa.'Notification Packages')   { $s.lsaNotificationPackages = $lsa.'Notification Packages' }
        if ($lsa.'Security Packages')        { $s.lsaSecurityPackages = $lsa.'Security Packages' }
    } catch {
        $s.lsaAuthPackages = @('ERROR: ' + $_.Exception.Message)
    }

    # Defender state
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $s.defender = [ordered]@{
            RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
            AntivirusEnabled          = $mp.AntivirusEnabled
            IsTamperProtected         = $mp.IsTamperProtected
            MAPSReporting             = $pref.MAPSReporting
            CloudBlockLevel           = $pref.CloudBlockLevel
            SubmitSamplesConsent      = $pref.SubmitSamplesConsent
            EnableNetworkProtection   = $pref.EnableNetworkProtection
            PUAProtection             = $pref.PUAProtection
            ExclusionPath             = $pref.ExclusionPath
            ExclusionProcess          = $pref.ExclusionProcess
            ExclusionExtension        = $pref.ExclusionExtension
            AttackSurfaceReductionRules_Ids = $pref.AttackSurfaceReductionRules_Ids
            AttackSurfaceReductionRules_Actions = $pref.AttackSurfaceReductionRules_Actions
        }
    } catch {
        $s.defender = @{ error = $_.Exception.Message }
    }

    # Listening TCP sockets (port + LocalAddress + process)
    try {
        $s.listeningTcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object LocalAddress, LocalPort, OwningProcess,
                @{n='ProcessName';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}})
    } catch {
        $s.listeningTcp = @()
    }

    # Established outbound connections (destination IPs the machine is currently talking to)
    try {
        $s.establishedOut = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|169\.254\.)' } |
            Select-Object RemoteAddress, RemotePort, OwningProcess,
                @{n='ProcessName';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}})
    } catch {
        $s.establishedOut = @()
    }

    # Canary file hashes (critical config)
    $canaries = @(
        "$env:SystemRoot\System32\drivers\etc\hosts",
        "$env:SystemRoot\System32\winlogon.exe",
        "$env:SystemRoot\System32\svchost.exe",
        "$env:SystemRoot\System32\lsass.exe"
    )
    $s.fileCanaries = @()
    foreach ($f in $canaries) {
        if (Test-Path $f) {
            try {
                $s.fileCanaries += [PSCustomObject]@{
                    Path = $f
                    SHA256 = (Get-FileHash $f -Algorithm SHA256).Hash
                    LastWriteTime = (Get-Item $f).LastWriteTime.ToString('o')
                }
            } catch {}
        }
    }

    # Recent service-install events since last check
    $sinceMarker = if (Test-Path $LastRun) { Get-Date (Get-Content $LastRun -Raw) } else { (Get-Date).AddMinutes(-30) }
    try {
        $s.recentServiceInstall = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$sinceMarker} -ErrorAction Stop |
            Select-Object TimeCreated, @{n='Message';e={ ($_.Message -split "`n")[0..3] -join ' ' }})
    } catch {
        $s.recentServiceInstall = @()
    }

    $s.snapshotTime = (Get-Date).ToString('o')
    return $s
}

function Diff-Snapshots {
    param($Before, $After)
    # Simple JSON-based diff: compare serialized representations key by key.
    $changes = @{}
    foreach ($key in $After.Keys) {
        $a = $Before.$key | ConvertTo-Json -Depth 10 -Compress -ErrorAction SilentlyContinue
        $b = $After[$key] | ConvertTo-Json -Depth 10 -Compress -ErrorAction SilentlyContinue
        if ($a -ne $b) {
            $changes[$key] = @{
                before = $Before.$key
                after  = $After[$key]
            }
        }
    }
    return $changes
}

function Invoke-Triage {
    param($DiffPath)
    # Spawn Claude Code with the triage prompt.
    # The triage prompt is at prompts/triage.md in the repo.
    $prompt = @"
Resume redforge-live triage. Read:
  1. $DiffPath (the incoming diff you must triage)
  2. $Baseline (current known-good baseline)
  3. $RepoRoot\prompts\triage.md (your instructions)

Classify each diff item as benign|suspicious|malicious and write entries
to $AlertsLog per the schema in prompts/triage.md. If you classify any
item as benign, update $Baseline to incorporate it. If anything is
malicious, write recommended_actions in the alert entry.

DO NOT publish to any repo or external service. All output stays in
$StateDir.
"@
    Write-Verbose "Invoking Claude Code for triage..."
    & claude --dangerously-skip-permissions -p "$prompt"
}

# --- main flow ---

if ($BaselineOnly) {
    Write-Host "Capturing initial baseline..."
    $snap = Get-Snapshot
    $snap | ConvertTo-Json -Depth 10 | Set-Content $Baseline -Encoding UTF8
    (Get-Date).ToString('o') | Set-Content $LastRun -Encoding UTF8
    Write-Host "Baseline saved: $Baseline"
    exit 0
}

if (-not (Test-Path $Baseline)) {
    Write-Warning "No baseline found at $Baseline. Run with -BaselineOnly first."
    exit 2
}

$before = Get-Content $Baseline -Raw | ConvertFrom-Json -AsHashtable
$after  = Get-Snapshot
$diff   = Diff-Snapshots -Before $before -After $after

if ($diff.Count -eq 0) {
    Write-Verbose "No changes since last baseline."
    (Get-Date).ToString('o') | Set-Content $LastRun -Encoding UTF8
    exit 0
}

Write-Host "Detected $($diff.Count) changed state keys. Writing incoming-diff.json."
$diff | ConvertTo-Json -Depth 10 | Set-Content $Incoming -Encoding UTF8

if ($DryRun) {
    Write-Host "DryRun mode. Diff written to $Incoming. Exiting without Claude invocation."
    exit 0
}

Invoke-Triage -DiffPath $Incoming

# After triage, Claude should have updated baseline.json.
(Get-Date).ToString('o') | Set-Content $LastRun -Encoding UTF8
Write-Host "Triage complete. Alerts at $AlertsLog"
