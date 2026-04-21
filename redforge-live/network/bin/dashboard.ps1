# redforge-live -- localhost SIEM dashboard + Claude chat relay
#
# Runs as sibling to watcher.ps1. Binds 127.0.0.1:47474 only. Serves
# web/index.html + JSON APIs that read state files. Chat endpoint
# spawns `claude --dangerously-skip-permissions` with CWD at install
# root so Claude has read/write over state/, config/, prompts/, logs/.
#
# Never exposes beyond 127.0.0.1. Never reads outside $InstallRoot.

[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\redforge-live',
    [int]$Port = 47474
)

$ErrorActionPreference = 'Continue'

# --- paths ---
$StateDir     = Join-Path $InstallRoot 'state'
$LogsDir      = Join-Path $InstallRoot 'logs'
$WebDir       = Join-Path $InstallRoot 'web'
$BaselineFile = Join-Path $StateDir 'baseline.json'
$AlertsFile   = Join-Path $StateDir 'alerts.jsonl'
$ModeFile     = Join-Path $StateDir 'mode.txt'
$ConfigFile   = Join-Path $StateDir 'config.json'
$TriageQueue  = Join-Path $StateDir 'triage-queue.jsonl'
$DashLog      = Join-Path $LogsDir 'dashboard.log'
$ChatLog      = Join-Path $LogsDir 'chat.jsonl'

foreach ($d in @($LogsDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

function Write-DLog {
    param([string]$Level, [string]$Msg)
    $line = "[{0}] {1} {2}" -f (Get-Date).ToString('o'), $Level, $Msg
    Add-Content -Path $DashLog -Value $line -ErrorAction SilentlyContinue
}

# --- probe for claude CLI ---
$claudeOnPath = $null
try { $claudeOnPath = (Get-Command claude -ErrorAction Stop).Source } catch { }
if (-not $claudeOnPath) {
    Write-DLog WARN "claude CLI not on PATH -- chat endpoint will return 503"
} else {
    Write-DLog INFO "claude CLI: $claudeOnPath"
}

# --- HttpListener bound to loopback only ---
$listener = New-Object System.Net.HttpListener
$prefix   = "http://127.0.0.1:$Port/"
$listener.Prefixes.Add($prefix)
try {
    $listener.Start()
    Write-DLog INFO "Dashboard listening at $prefix"
} catch {
    Write-DLog ERROR "Could not bind ${prefix}: $_"
    exit 1
}

$MimeMap = @{
    '.html' = 'text/html; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.ico'  = 'image/x-icon'
}

function Send-Text {
    param($Ctx, [string]$Text, [string]$Mime = 'text/plain; charset=utf-8', [int]$Status = 200)
    try {
        $Ctx.Response.StatusCode  = $Status
        $Ctx.Response.ContentType = $Mime
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $Ctx.Response.ContentLength64 = $bytes.Length
        $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Ctx.Response.OutputStream.Close()
    } catch { }
}

function Send-Json {
    param($Ctx, $Obj, [int]$Status = 200)
    $json = $Obj | ConvertTo-Json -Depth 10 -Compress
    Send-Text -Ctx $Ctx -Text $json -Mime 'application/json; charset=utf-8' -Status $Status
}

function Send-File {
    param($Ctx, [string]$Path)
    if (-not (Test-Path $Path)) { Send-Text -Ctx $Ctx -Text "Not found" -Status 404; return }
    $ext  = [IO.Path]::GetExtension($Path).ToLower()
    $mime = if ($MimeMap.ContainsKey($ext)) { $MimeMap[$ext] } else { 'application/octet-stream' }
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $Ctx.Response.StatusCode = 200
        $Ctx.Response.ContentType = $mime
        $Ctx.Response.ContentLength64 = $bytes.Length
        $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Ctx.Response.OutputStream.Close()
    } catch { Write-DLog WARN "send-file error: $_" }
}

function Read-JsonBody {
    param($Ctx)
    $reader = New-Object System.IO.StreamReader $Ctx.Request.InputStream
    $body = $reader.ReadToEnd()
    $reader.Close()
    try { return $body | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
}

# --- handlers ---
function Handle-State {
    param($Ctx)
    $mode = if (Test-Path $ModeFile) { (Get-Content $ModeFile -Raw).Trim() } else { 'Learning' }
    $config = if (Test-Path $ConfigFile) { Get-Content $ConfigFile -Raw | ConvertFrom-Json } else { $null }
    $baseline = @{}
    if (Test-Path $BaselineFile) {
        try { $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json -AsHashtable } catch { $baseline = @{} }
    }
    $procCount = ($baseline.Keys | Measure-Object).Count
    $destCount = 0
    foreach ($k in $baseline.Keys) { $destCount += @($baseline[$k]).Count }
    $alertsTotal = if (Test-Path $AlertsFile) { (Get-Content $AlertsFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines } else { 0 }
    $queueDepth  = if (Test-Path $TriageQueue) { (Get-Content $TriageQueue -ErrorAction SilentlyContinue | Measure-Object -Line).Lines } else { 0 }
    $fwRuleCount = (Get-NetFirewallRule -Group 'RedforgeLive' -ErrorAction SilentlyContinue | Measure-Object).Count

    Send-Json -Ctx $Ctx -Obj ([ordered]@{
        mode                       = $mode
        config                     = $config
        baseline_process_count     = $procCount
        baseline_destination_count = $destCount
        alerts_total               = $alertsTotal
        triage_queue_depth         = $queueDepth
        firewall_rule_count        = $fwRuleCount
        claude_available           = [bool]$claudeOnPath
        ts                         = (Get-Date).ToString('o')
    })
}

function Handle-Connections {
    param($Ctx)
    $baseline = @{}
    if (Test-Path $BaselineFile) {
        try { $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json -AsHashtable } catch { }
    }
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') }
    $result = @()
    foreach ($c in $conns) {
        $proc = 'unknown'
        try { $proc = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).Name } catch { }
        $dest = "$($c.RemoteAddress):$($c.RemotePort)"
        $known = $baseline.ContainsKey($proc) -and (@($baseline[$proc]) -contains $dest)
        $result += [ordered]@{
            process        = $proc
            pid            = $c.OwningProcess
            local_port     = $c.LocalPort
            remote_address = $c.RemoteAddress
            remote_port    = $c.RemotePort
            classification = if ($known) { 'known' } else { 'new' }
        }
    }
    Send-Json -Ctx $Ctx -Obj @{ connections = $result; ts = (Get-Date).ToString('o') }
}

function Handle-Alerts {
    param($Ctx)
    $limit = 50
    $qsLimit = $Ctx.Request.QueryString['limit']
    if ($qsLimit) { $limit = [int]$qsLimit }
    $alerts = @()
    if (Test-Path $AlertsFile) {
        $alerts = Get-Content $AlertsFile -Tail $limit -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $null }
        } | Where-Object { $_ -ne $null }
    }
    Send-Json -Ctx $Ctx -Obj @{ alerts = @($alerts); ts = (Get-Date).ToString('o') }
}

function Handle-Firewall {
    param($Ctx)
    $rules = @()
    Get-NetFirewallRule -Group 'RedforgeLive' -ErrorAction SilentlyContinue | ForEach-Object {
        $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $rules += [ordered]@{
            name           = $_.Name
            display_name   = $_.DisplayName
            enabled        = [string]$_.Enabled
            action         = [string]$_.Action
            direction      = [string]$_.Direction
            remote_address = $af.RemoteAddress -join ','
        }
    }
    Send-Json -Ctx $Ctx -Obj @{ rules = $rules; ts = (Get-Date).ToString('o') }
}

function Handle-Mode {
    param($Ctx)
    if ($Ctx.Request.HttpMethod -ne 'POST') { Send-Text -Ctx $Ctx -Text 'POST only' -Status 405; return }
    $body = Read-JsonBody $Ctx
    if ($body.mode -in 'Learning','Enforcing') {
        Set-Content -Path $ModeFile -Value $body.mode
        Write-DLog INFO "Mode changed to $($body.mode) via dashboard"
        Send-Json -Ctx $Ctx -Obj @{ ok = $true; mode = $body.mode }
    } else {
        Send-Text -Ctx $Ctx -Text 'Invalid mode' -Status 400
    }
}

# --- chat relay ---
# Spawns `claude` with CWD=$InstallRoot, --session-id for continuity,
# stream-json output. Each line of claude stdout becomes one SSE event.
function Handle-Chat {
    param($Ctx)
    if ($Ctx.Request.HttpMethod -ne 'POST') { Send-Text -Ctx $Ctx -Text 'POST only' -Status 405; return }
    if (-not $claudeOnPath) { Send-Json -Ctx $Ctx -Obj @{ error = 'claude CLI not on PATH' } -Status 503; return }

    $body = Read-JsonBody $Ctx
    if (-not $body.message) { Send-Text -Ctx $Ctx -Text 'Missing message' -Status 400; return }

    # Session handling:
    #   First turn : no session_id from browser -> generate new guid, pass --session-id (creates session)
    #   Subsequent : browser echoes session_id from first 'event: session' frame -> pass --resume (continues)
    $hasExisting = $false
    $sid = $body.session_id
    if ($sid -and $sid -is [string] -and $sid.Length -ge 32 -and $sid -ne 'null') {
        $hasExisting = $true
        $sessionId = $sid
    } else {
        $sessionId = [guid]::NewGuid().ToString()
    }
    $sessionFlag = if ($hasExisting) { "--resume $sessionId" } else { "--session-id $sessionId" }

    Add-Content -Path $ChatLog -Value ((@{ ts=(Get-Date).ToString('o'); role='user'; session_id=$sessionId; message=$body.message } | ConvertTo-Json -Compress))

    # SSE response headers
    $Ctx.Response.StatusCode  = 200
    $Ctx.Response.ContentType = 'text/event-stream'
    $Ctx.Response.Headers.Add('Cache-Control', 'no-cache')
    $Ctx.Response.Headers.Add('X-Accel-Buffering', 'no')
    $Ctx.Response.SendChunked = $true

    $writer = New-Object System.IO.StreamWriter($Ctx.Response.OutputStream, [System.Text.Encoding]::UTF8)
    $writer.AutoFlush = $true
    $writer.NewLine   = "`n"   # SSE delimiter is LFLF; force LF so browser parser matches

    # First event: session id
    $writer.WriteLine("event: session")
    $writer.WriteLine("data: {`"session_id`":`"$sessionId`"}")
    $writer.WriteLine("")

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $claudeOnPath
        $psi.WorkingDirectory       = $InstallRoot
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        # escape double-quotes in the user message
        $safeMsg = $body.message.Replace('"','\"')
        $psi.Arguments = "--dangerously-skip-permissions $sessionFlag --output-format stream-json --verbose -p `"$safeMsg`""

        Write-DLog INFO "Chat spawn flag=$sessionFlag msg_len=$($body.message.Length)"

        $proc = [System.Diagnostics.Process]::Start($psi)

        while (-not $proc.StandardOutput.EndOfStream) {
            $line = $proc.StandardOutput.ReadLine()
            if ($null -ne $line -and $line.Length -gt 0) {
                $writer.WriteLine("event: claude")
                $writer.WriteLine("data: $line")
                $writer.WriteLine("")
            }
        }
        $proc.WaitForExit()
        $stderr = $proc.StandardError.ReadToEnd()
        if ($stderr) {
            $esc = ($stderr -replace '"','\"') -replace "`r?`n",' '
            $writer.WriteLine("event: stderr")
            $writer.WriteLine("data: {`"text`":`"$esc`"}")
            $writer.WriteLine("")
        }
        $writer.WriteLine("event: done")
        $writer.WriteLine("data: {`"exit_code`":$($proc.ExitCode),`"session_id`":`"$sessionId`"}")
        $writer.WriteLine("")

        Add-Content -Path $ChatLog -Value ((@{ ts=(Get-Date).ToString('o'); role='session-done'; session_id=$sessionId; exit_code=$proc.ExitCode } | ConvertTo-Json -Compress))
    } catch {
        $err = ($_.Exception.Message -replace '"','\"') -replace "`r?`n",' '
        $writer.WriteLine("event: error")
        $writer.WriteLine("data: {`"error`":`"$err`"}")
        $writer.WriteLine("")
        Write-DLog ERROR "Chat relay failed: $_"
    } finally {
        try { $writer.Close() } catch { }
        try { $Ctx.Response.OutputStream.Close() } catch { }
    }
}

# --- main loop ---
Write-DLog INFO "Dashboard ready. Open http://127.0.0.1:$Port/ in browser."

while ($listener.IsListening) {
    try {
        $ctx = $listener.GetContext()
    } catch {
        Write-DLog WARN "GetContext exception (listener stopped?): $_"
        break
    }

    # localhost-only enforcement
    $remoteIp = $ctx.Request.RemoteEndPoint.Address.ToString()
    if ($remoteIp -notin @('127.0.0.1','::1')) {
        Send-Text -Ctx $ctx -Text 'Forbidden' -Status 403
        Write-DLog WARN "Rejected non-localhost: $remoteIp"
        continue
    }

    $path = $ctx.Request.Url.AbsolutePath
    try {
        switch -regex ($path) {
            '^/$'                { Send-File -Ctx $ctx -Path (Join-Path $WebDir 'index.html') }
            '^/favicon\.ico$'    { Send-Text -Ctx $ctx -Text '' -Mime 'image/x-icon' -Status 204 }
            '^/web/.+'           {
                $rel = $path.TrimStart('/').Replace('/','\')
                $full = [IO.Path]::GetFullPath((Join-Path $InstallRoot $rel))
                if (-not $full.StartsWith($WebDir, [StringComparison]::OrdinalIgnoreCase)) {
                    Send-Text -Ctx $ctx -Text 'Forbidden' -Status 403
                } else {
                    Send-File -Ctx $ctx -Path $full
                }
            }
            '^/api/state$'       { Handle-State $ctx }
            '^/api/connections$' { Handle-Connections $ctx }
            '^/api/alerts$'      { Handle-Alerts $ctx }
            '^/api/firewall$'    { Handle-Firewall $ctx }
            '^/api/mode$'        { Handle-Mode $ctx }
            '^/api/chat$'        { Handle-Chat $ctx }
            default              { Send-Text -Ctx $ctx -Text 'Not found' -Status 404 }
        }
    } catch {
        Write-DLog ERROR "Handler exception on ${path}: $_"
        try { Send-Text -Ctx $ctx -Text 'Internal error' -Status 500 } catch { }
    }
}

Write-DLog INFO "Dashboard shutting down."
try { $listener.Stop() } catch { }
