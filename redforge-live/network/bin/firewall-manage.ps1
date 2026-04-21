# redforge-live firewall-rule management helpers.
# All rules created by redforge-live are tagged with Group = "RedforgeLive"
# for easy audit + bulk removal.
#
# This file is dot-sourced by the watcher; also usable standalone from an
# elevated PowerShell for manual operator review.

function New-RedforgeLiveBlock {
    <#
    .SYNOPSIS
    Create an outbound-block Windows Firewall rule tagged for redforge-live.

    .EXAMPLE
    New-RedforgeLiveBlock -Address '95.214.234.238' -Reason 'Trial#1 IoC'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Address,
        [int]$Port = 0,
        [string]$Reason = 'manual'
    )
    $date = Get-Date -Format 'yyyyMMdd'
    $portSuffix = if ($Port -gt 0) { "-p${Port}" } else { '' }
    $ruleName = "RedforgeLive-Block-${Address}${portSuffix}-${date}"

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warning "Rule already exists: $ruleName"
        return $existing
    }

    $ruleParams = @{
        DisplayName   = $ruleName
        Direction     = 'Outbound'
        Action        = 'Block'
        RemoteAddress = $Address
        Enabled       = 'True'
        Group         = 'RedforgeLive'
        Description   = "redforge-live auto-block. Reason: $Reason. Created $date."
    }
    if ($Port -gt 0) { $ruleParams.RemotePort = $Port; $ruleParams.Protocol = 'TCP' }

    New-NetFirewallRule @ruleParams
}

function Get-RedforgeLiveRules {
    <#
    .SYNOPSIS
    List all Windows Firewall rules created by redforge-live.
    #>
    Get-NetFirewallRule -Group 'RedforgeLive' |
        Select-Object DisplayName, Direction, Action, Enabled, Description
}

function Remove-RedforgeLiveRule {
    <#
    .SYNOPSIS
    Remove a specific redforge-live firewall rule by DisplayName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayName
    )
    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if (-not $rule) {
        Write-Warning "Rule not found: $DisplayName"
        return
    }
    if ($rule.Group -ne 'RedforgeLive') {
        Write-Warning "Refusing to remove rule not tagged 'RedforgeLive': $DisplayName"
        return
    }
    Remove-NetFirewallRule -DisplayName $DisplayName
    Write-Host "Removed: $DisplayName"
}

function Remove-AllRedforgeLiveRules {
    <#
    .SYNOPSIS
    Nuclear option -- removes every firewall rule tagged 'RedforgeLive'.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()
    $rules = Get-NetFirewallRule -Group 'RedforgeLive'
    if (-not $rules) {
        Write-Host "No redforge-live rules to remove."
        return
    }
    if ($PSCmdlet.ShouldProcess("$($rules.Count) redforge-live firewall rules", "Remove")) {
        Remove-NetFirewallRule -Group 'RedforgeLive'
        Write-Host "Removed $($rules.Count) rule(s)."
    }
}

# If dot-sourced, functions are available in caller's scope.
# If run directly, show usage.
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "redforge-live firewall-manage module"
    Write-Host "Commands:"
    Write-Host "  New-RedforgeLiveBlock -Address <IP> [-Port <N>] [-Reason <text>]"
    Write-Host "  Get-RedforgeLiveRules"
    Write-Host "  Remove-RedforgeLiveRule -DisplayName <name>"
    Write-Host "  Remove-AllRedforgeLiveRules"
    Write-Host ""
    Write-Host "To use: . .\firewall-manage.ps1"
}
