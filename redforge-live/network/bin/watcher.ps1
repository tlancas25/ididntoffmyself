# redforge-live -- learning network firewall (Phase 1.5)
# Tray-icon PowerShell daemon. Launched at logon by scheduled task.
# Observes connections, learns baseline, triages anomalies via Claude,
# offers Windows Firewall block on malicious classifications.
#
# Usage (normally invoked by scheduled task):
#   powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File watcher.ps1
#
# For manual testing / dev:
#   powershell.exe -ExecutionPolicy Bypass -File watcher.ps1 -ShowConsole

[CmdletBinding()]
param(
    [switch]$ShowConsole,
    [string]$InstallRoot = 'C:\redforge-live'
)

# --- Require admin (for New-NetFirewallRule later) ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Can still run without admin -- just won't enforce. Log warning.
    Write-Warning "Not running elevated. Enforcement (firewall rules) will be disabled."
}

# --- Load WinForms for tray icon ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Hide console window unless -ShowConsole ---
if (-not $ShowConsole) {
    $sig = @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
    Add-Type -MemberDefinition $sig -Namespace Win32 -Name NativeMethods
    $null = [Win32.NativeMethods]::ShowWindow([Win32.NativeMethods]::GetConsoleWindow(), 0)
}

# --- State ---
$Global:RFL = @{
    InstallRoot      = $InstallRoot
    StateDir         = Join-Path $InstallRoot 'state'
    BinDir           = Join-Path $InstallRoot 'bin'
    PromptsDir       = Join-Path $InstallRoot 'prompts'
    LogFile          = Join-Path $InstallRoot 'logs\watcher.log'
    BaselineFile     = Join-Path $InstallRoot 'state\baseline.json'
    TriageQueue      = Join-Path $InstallRoot 'state\triage-queue.jsonl'
    AlertsFile       = Join-Path $InstallRoot 'state\alerts.jsonl'
    AlertsMdFile     = Join-Path $InstallRoot 'state\alerts.md'
    ModeFile         = Join-Path $InstallRoot 'state\mode.txt'
    ConfigFile       = Join-Path $InstallRoot 'state\config.json'
    FirewallRulesLog = Join-Path $InstallRoot 'state\firewall-rules.jsonl'
    Mode             = 'Learning'
    Baseline         = @{}
    AlertCount       = 0
    Paused           = $false
    LastTriageTime   = [DateTime]::MinValue
    TriageIntervalMin = 5
}

# --- Ensure directories exist ---
foreach ($d in @($Global:RFL.StateDir, (Split-Path $Global:RFL.LogFile -Parent))) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

function Write-RFLLog {
    param([string]$Level, [string]$Msg)
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'o'), $Level, $Msg
    Add-Content -Path $Global:RFL.LogFile -Value $line -ErrorAction SilentlyContinue
    if ($ShowConsole) { Write-Host $line }
}

Write-RFLLog INFO "redforge-live watcher starting. InstallRoot=$InstallRoot"

# --- Load mode ---
if (Test-Path $Global:RFL.ModeFile) {
    $Global:RFL.Mode = (Get-Content $Global:RFL.ModeFile -Raw).Trim()
} else {
    Set-Content -Path $Global:RFL.ModeFile -Value 'Learning'
}
Write-RFLLog INFO "Mode=$($Global:RFL.Mode)"

# --- Load baseline ---
if (Test-Path $Global:RFL.BaselineFile) {
    try {
        $Global:RFL.Baseline = Get-Content $Global:RFL.BaselineFile -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    } catch {
        Write-RFLLog WARN "Could not load baseline; starting fresh. $_"
        $Global:RFL.Baseline = @{}
    }
} else {
    $Global:RFL.Baseline = @{}
}

# --- Known-good CIDR ranges (pre-classify short-circuit) ---
$Global:RFL.KnownGoodRanges = @(
    # Microsoft AS-8075 approximations
    '13.64.','13.65.','13.66.','13.67.','13.68.','13.69.','13.70.',
    '20.','40.','52.',
    '131.253.',
    # Google AS-15169
    '8.8.8.8','8.8.4.4',
    '64.233.','142.250.','172.217.','216.58.','209.85.',
    # Cloudflare AS-13335
    '1.1.1.1','1.0.0.1','104.16.','104.17.','104.18.','104.19.','172.64.',
    # GitHub AS-36459
    '140.82.112.','140.82.113.','140.82.114.','140.82.115.',
    # Local ranges
    '127.','10.','192.168.','172.16.','172.17.','172.18.','172.19.',
    '172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.',
    '172.27.','172.28.','172.29.','172.30.','172.31.',
    # Link-local
    '169.254.',
    # Tailscale CGNAT
    '100.64.','100.65.','100.66.','100.67.','100.68.','100.69.','100.70.',
    '100.71.','100.72.','100.73.','100.74.','100.75.','100.76.','100.77.',
    '100.78.','100.79.','100.80.','100.81.','100.82.','100.83.','100.84.',
    '100.85.','100.86.','100.87.','100.88.','100.89.','100.90.','100.91.',
    '100.92.','100.93.','100.94.','100.95.','100.96.','100.97.','100.98.',
    '100.99.','100.100.','100.101.','100.102.','100.103.','100.104.',
    '100.105.','100.106.','100.107.','100.108.','100.109.','100.110.',
    '100.111.','100.112.','100.113.','100.114.','100.115.','100.116.',
    '100.117.','100.118.','100.119.','100.120.','100.121.','100.122.',
    '100.123.','100.124.','100.125.','100.126.','100.127.'
)

# --- Known-MALICIOUS IoCs (Trial #1 -- auto-block) ---
$Global:RFL.KnownBadIPs = @(
    '95.214.234.238',  # edgeserv.ru ScreenConnect relay (Russia)
    '64.74.162.109',   # syslog.exe beacon
    '130.12.180.159'   # RegAsm LOLBin C2
)
$Global:RFL.KnownBadDomains = @(
    'edgeserv.ru'
)

function Is-KnownGood {
    param([string]$Addr)
    foreach ($r in $Global:RFL.KnownGoodRanges) {
        if ($Addr.StartsWith($r)) { return $true }
    }
    return $false
}

function Is-KnownBad {
    param([string]$Addr)
    if ($Global:RFL.KnownBadIPs -contains $Addr) { return $true }
    return $false
}

# --- Observe-Connections (10-sec timer tick) ---
function Observe-Connections {
    if ($Global:RFL.Paused) { return }

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                 Where-Object { $_.RemoteAddress -notmatch '^(::|fe80)' }  # skip IPv6 link-local
    } catch {
        Write-RFLLog WARN "Get-NetTCPConnection failed: $_"
        return
    }

    foreach ($c in $conns) {
        $procName = try {
            (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        } catch { 'unknown' }
        if (-not $procName) { $procName = "pid-$($c.OwningProcess)" }

        $destKey = "$($c.RemoteAddress):$($c.RemotePort)"

        # Auto-block on IoC match (any mode, always enforce)
        if (Is-KnownBad $c.RemoteAddress) {
            Handle-KnownBad -Process $procName -Address $c.RemoteAddress -Port $c.RemotePort -OwningPID $c.OwningProcess
            continue
        }

        # Check baseline
        $knownForProc = $Global:RFL.Baseline[$procName]
        $alreadyKnown = $false
        if ($knownForProc) {
            if ($knownForProc -contains $destKey) {
                $alreadyKnown = $true
            } else {
                # Allow /24 aggregation for public non-CDN addresses
                $octets = $c.RemoteAddress.Split('.')
                if ($octets.Count -eq 4) {
                    $slash24 = "$($octets[0]).$($octets[1]).$($octets[2])."
                    foreach ($k in $knownForProc) {
                        if ($k.StartsWith($slash24)) { $alreadyKnown = $true; break }
                    }
                }
            }
        }
        if ($alreadyKnown) { continue }

        # Pre-classify known-good
        if (Is-KnownGood $c.RemoteAddress) {
            Add-ToBaseline -Process $procName -Dest $destKey
            continue
        }

        # Unknown -- handle per mode
        if ($Global:RFL.Mode -eq 'Learning') {
            Add-ToBaseline -Process $procName -Dest $destKey
        } else {
            Queue-Anomaly -Process $procName -Address $c.RemoteAddress -Port $c.RemotePort -OwningPID $c.OwningProcess
        }
    }
}

function Add-ToBaseline {
    param([string]$Process, [string]$Dest)
    if (-not $Global:RFL.Baseline.ContainsKey($Process)) {
        $Global:RFL.Baseline[$Process] = @()
    }
    if ($Global:RFL.Baseline[$Process] -notcontains $Dest) {
        $Global:RFL.Baseline[$Process] = $Global:RFL.Baseline[$Process] + $Dest
        # Persist (could batch, but simple is fine for v0.1)
        $Global:RFL.Baseline | ConvertTo-Json -Depth 5 | Set-Content $Global:RFL.BaselineFile -Encoding UTF8
    }
}

function Queue-Anomaly {
    param([string]$Process, [string]$Address, [int]$Port, [int]$OwningPID)
    $obj = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        process   = $Process
        address   = $Address
        port      = $Port
        pid       = $OwningPID
    }
    $json = $obj | ConvertTo-Json -Compress
    Add-Content -Path $Global:RFL.TriageQueue -Value $json -Encoding UTF8
    Write-RFLLog INFO "Anomaly queued: $Process -> ${Address}:${Port}"
}

function Handle-KnownBad {
    param([string]$Process, [string]$Address, [int]$Port, [int]$OwningPID)
    Write-RFLLog CRIT "KNOWN-BAD connection: $Process -> ${Address}:${Port} (PID $OwningPID)"

    # Fire tray balloon CRITICAL
    $Global:RFL.Icon.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Error
    $Global:RFL.Icon.BalloonTipTitle = "CRITICAL: Trial#1 IoC contacted"
    $Global:RFL.Icon.BalloonTipText  = "$Process -> ${Address}:${Port}"
    $Global:RFL.Icon.ShowBalloonTip(10000)

    # Immediately create outbound-block firewall rule
    $ruleDate = Get-Date -Format 'yyyyMMdd'
    $ruleName = "RedforgeLive-Block-$Address-$ruleDate"
    try {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                                -Direction Outbound `
                                -Action Block `
                                -RemoteAddress $Address `
                                -Enabled True `
                                -Group 'RedforgeLive' `
                                -Description "Auto-created by redforge-live on known-bad IoC hit" | Out-Null
            Write-RFLLog INFO "Firewall rule created: $ruleName"
            Add-Content $Global:RFL.FirewallRulesLog -Value (@{timestamp=(Get-Date).ToString('o');rule=$ruleName;address=$Address;reason='IoC-auto-block'} | ConvertTo-Json -Compress)
        }
    } catch {
        Write-RFLLog WARN "Could not create firewall rule (not admin?): $_"
    }

    # Also try to kill the offending process (best-effort)
    try {
        Stop-Process -Id $OwningPID -Force -ErrorAction Stop
        Write-RFLLog INFO "Killed offending PID $OwningPID ($Process)"
    } catch {
        Write-RFLLog WARN "Could not kill PID ${OwningPID}: $_"
    }

    # Write to alerts log
    $alert = [ordered]@{
        timestamp   = (Get-Date).ToString('o')
        severity    = 'CRITICAL'
        source      = 'watcher-ioc-match'
        process     = $Process
        address     = $Address
        port        = $Port
        pid         = $OwningPID
        action_taken = @("firewall-rule-created:$ruleName", "process-kill-attempted:$OwningPID")
    }
    Add-Content -Path $Global:RFL.AlertsFile -Value ($alert | ConvertTo-Json -Compress) -Encoding UTF8
}

# --- Batch triage (5-min timer tick) ---
function Run-BatchTriage {
    if ($Global:RFL.Paused) { return }
    if (-not (Test-Path $Global:RFL.TriageQueue)) { return }
    if ((Get-Item $Global:RFL.TriageQueue).Length -eq 0) { return }

    $now = Get-Date
    if (($now - $Global:RFL.LastTriageTime).TotalMinutes -lt $Global:RFL.TriageIntervalMin) { return }

    Write-RFLLog INFO "Invoking Claude triage..."
    $triageScript = Join-Path $Global:RFL.BinDir 'triage-invoke.ps1'
    if (Test-Path $triageScript) {
        try {
            & $triageScript -QueueFile $Global:RFL.TriageQueue -BaselineFile $Global:RFL.BaselineFile -AlertsFile $Global:RFL.AlertsFile -PromptFile (Join-Path $Global:RFL.PromptsDir 'learning-firewall-triage.md')
            # Truncate queue after successful run
            Clear-Content $Global:RFL.TriageQueue
            $Global:RFL.LastTriageTime = $now
        } catch {
            Write-RFLLog WARN "triage-invoke failed: $_"
        }
    } else {
        Write-RFLLog WARN "triage-invoke.ps1 not found at $triageScript"
    }
}

# --- Dashboard child process ---
$dashboardScript = Join-Path (Split-Path $PSCommandPath -Parent) 'dashboard.ps1'
$Global:RFL.DashboardProc = $null
if (Test-Path $dashboardScript) {
    try {
        $dpsi = New-Object System.Diagnostics.ProcessStartInfo
        $dpsi.FileName        = 'powershell.exe'
        $dpsi.Arguments       = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dashboardScript`""
        $dpsi.UseShellExecute  = $false
        $dpsi.CreateNoWindow   = $true
        $Global:RFL.DashboardProc = [System.Diagnostics.Process]::Start($dpsi)
        Write-RFLLog INFO "Spawned dashboard.ps1 (PID $($Global:RFL.DashboardProc.Id)) -> http://127.0.0.1:47474/"
    } catch {
        Write-RFLLog WARN "Could not spawn dashboard.ps1: $_"
    }
} else {
    Write-RFLLog WARN "dashboard.ps1 not found at ${dashboardScript}; dashboard disabled"
}

# --- Tray icon ---
$Global:RFL.Icon = New-Object System.Windows.Forms.NotifyIcon
$Global:RFL.Icon.Icon    = [System.Drawing.SystemIcons]::Shield
$Global:RFL.Icon.Visible = $true
$Global:RFL.Icon.Text    = "redforge-live (Mode=$($Global:RFL.Mode))"

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.Items.Add("Show dashboard (alerts.md)").add_Click({ Start-Process notepad.exe $Global:RFL.AlertsMdFile })
$menu.Items.Add("Open alerts.jsonl").add_Click({ Start-Process notepad.exe $Global:RFL.AlertsFile })
$menu.Items.Add("Open baseline.json").add_Click({ Start-Process notepad.exe $Global:RFL.BaselineFile })
$menu.Items.Add("Open dashboard (browser)").add_Click({ Start-Process 'http://127.0.0.1:47474/' })
$menu.Items.Add("Open dashboard log").add_Click({
    $dlog = Join-Path (Split-Path $Global:RFL.LogFile -Parent) 'dashboard.log'
    if (Test-Path $dlog) { Start-Process notepad.exe $dlog }
})
$menu.Items.Add("-")
$miPause = $menu.Items.Add("Pause 15 min")
$miPause.add_Click({
    $Global:RFL.Paused = $true
    $Global:RFL.Icon.Text = "redforge-live (PAUSED)"
    Start-Sleep -Seconds 900
    $Global:RFL.Paused = $false
    $Global:RFL.Icon.Text = "redforge-live (Mode=$($Global:RFL.Mode))"
})
$menu.Items.Add("Force triage now").add_Click({ $Global:RFL.LastTriageTime = [DateTime]::MinValue; Run-BatchTriage })
$menu.Items.Add("-")
$menu.Items.Add("Switch to Enforcing mode").add_Click({
    $Global:RFL.Mode = 'Enforcing'
    Set-Content $Global:RFL.ModeFile -Value 'Enforcing'
    $Global:RFL.Icon.Text = "redforge-live (Mode=Enforcing)"
    $Global:RFL.Icon.ShowBalloonTip(3000, 'redforge-live', 'Switched to Enforcing mode. New destinations will trigger alerts.', 'Info')
})
$menu.Items.Add("Switch to Learning mode").add_Click({
    $Global:RFL.Mode = 'Learning'
    Set-Content $Global:RFL.ModeFile -Value 'Learning'
    $Global:RFL.Icon.Text = "redforge-live (Mode=Learning)"
})
$menu.Items.Add("-")
$menu.Items.Add("Exit").add_Click({
    $Global:RFL.Icon.Visible = $false
    if ($Global:RFL.DashboardProc -and -not $Global:RFL.DashboardProc.HasExited) {
        try { $Global:RFL.DashboardProc.Kill() } catch { }
    }
    [System.Windows.Forms.Application]::Exit()
})
$Global:RFL.Icon.ContextMenuStrip = $menu

# --- Startup balloon ---
$baselineSize = ($Global:RFL.Baseline.Keys | Measure-Object).Count
$Global:RFL.Icon.ShowBalloonTip(5000, "redforge-live",
    "Started. Mode=$($Global:RFL.Mode). Known processes in baseline: $baselineSize.",
    [System.Windows.Forms.ToolTipIcon]::Info)

# --- Timers ---
$observationTimer = New-Object System.Windows.Forms.Timer
$observationTimer.Interval = 10000  # 10s
$observationTimer.add_Tick({ Observe-Connections })
$observationTimer.Start()

$triageTimer = New-Object System.Windows.Forms.Timer
$triageTimer.Interval = 60000  # 1-min tick; inside, we check 5-min elapsed
$triageTimer.add_Tick({ Run-BatchTriage })
$triageTimer.Start()

# --- Main message loop ---
try {
    [System.Windows.Forms.Application]::Run()
} finally {
    Write-RFLLog INFO "redforge-live watcher exiting"
    if ($Global:RFL.DashboardProc -and -not $Global:RFL.DashboardProc.HasExited) {
        try { $Global:RFL.DashboardProc.Kill() } catch { }
    }
    $Global:RFL.Icon.Visible = $false
    $Global:RFL.Icon.Dispose()
}
