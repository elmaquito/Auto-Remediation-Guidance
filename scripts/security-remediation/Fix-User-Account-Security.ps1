# Fix-User-Account-Security.ps1
# Remediation script for user account security: check for unused/privileged accounts, disable/remove as needed

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\User-Account-Security-Remediation.log"
)

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-UserAccountSecurity {
    $issues = @()
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $users) {
        if ($user.LastLogon -and $user.LastLogon -lt (Get-Date).AddMonths(-6)) {
            $issues += @{ User = $user.Name; LastLogon = $user.LastLogon; Recommendation = 'Disable unused account' }
        }
        if ($user.Name -eq 'Administrator' -and $user.Enabled) {
            $issues += @{ User = $user.Name; LastLogon = $user.LastLogon; Recommendation = 'Consider disabling built-in Administrator' }
        }
    }
    return $issues
}

function Repair-UserAccountSecurity {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        if ($issue.Recommendation -like '*Disable*' -and -not $WhatIf) {
            try {
                Disable-LocalUser -Name $issue.User
                $changes += "Disabled user $($issue.User)"
            } catch {
                Write-Log "Failed to disable $($issue.User): $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting user account security remediation"
    $issues = Test-UserAccountSecurity
    $remediationStatus = 'No issues found'
    $changes = @()
    if ($issues.Count -eq 0) {
        Write-Log "No unused or risky accounts found"
        $output = @{ Success = $true; Message = 'No unused or risky accounts found'; ChangesNeeded = $false }
        $remediationStatus = 'No issues found'
    } else {
        Write-Log "User account security issues found: $($issues.Count)"
        foreach ($i in $issues) {
            Write-Log ("Issue: " + ($i | Out-String))
        }
        $changes = Repair-UserAccountSecurity -Issues $issues -WhatIf:$WhatIf
        $output = @{ Success = $true; Message = 'User account security remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
        $remediationStatus = if ($changes.Count -gt 0) { 'Remediated' } else { 'Issues detected, no changes applied' }
    }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"

    # Export summary to Excel in output folder
    $excelPath = Join-Path -Path (Join-Path $PSScriptRoot '..\..\output') 'User-Account-Security-Remediation.xlsx'
    $excelDir = Split-Path $excelPath -Parent
    if (-not (Test-Path $excelDir)) { New-Item -Path $excelDir -ItemType Directory -Force | Out-Null }

    $summary = @()
    if ($issues.Count -eq 0) {
        $summary += [PSCustomObject]@{
            User = ''
            LastLogon = ''
            Recommendation = ''
            RemediationStatus = $remediationStatus
        }
    } else {
        foreach ($i in $issues) {
            $summary += [PSCustomObject]@{
                User = $i.User
                LastLogon = $i.LastLogon
                Recommendation = $i.Recommendation
                RemediationStatus = $remediationStatus
            }
        }
    }

    try {
        # Export to Excel (requires ImportExcel module)
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Install-Module -Name ImportExcel -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        }
        Import-Module ImportExcel -ErrorAction SilentlyContinue
        $summary | Export-Excel -Path $excelPath -WorksheetName 'Remediation' -AutoSize -TableName 'UserAccountRemediation' -Force
        Write-Log "Remediation summary exported to $excelPath"
    } catch {
        Write-Log "Failed to export remediation summary to Excel: $($_.Exception.Message)" 'ERROR'
    }

    exit 0
}
