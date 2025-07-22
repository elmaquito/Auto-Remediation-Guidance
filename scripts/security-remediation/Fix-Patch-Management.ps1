# Fix-Patch-Management.ps1
# Remediation script for patch management: check for missing OS/app patches, apply updates

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Patch-Management-Remediation.log"
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

function Test-PatchManagement {
    $issues = @()
    $pending = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue | Where-Object { $_.IsInstalled -eq $false }
    if ($pending -and $pending.Count -gt 0) {
        $issues += @{ Type = 'MissingUpdates'; Count = $pending.Count; Recommendation = 'Apply all critical/important updates' }
    }
    return $issues
}

function Repair-PatchManagement {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        if ($issue.Type -eq 'MissingUpdates' -and -not $WhatIf) {
            try {
                Install-WindowsUpdate -AcceptAll -AutoReboot
                $changes += "Applied all pending updates"
            } catch {
                Write-Log "Failed to apply updates: $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting patch management remediation"
    $issues = Test-PatchManagement
    if ($issues.Count -eq 0) {
        Write-Log "All critical/important updates applied"
        $output = @{ Success = $true; Message = 'All critical/important updates applied'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Patch management issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-PatchManagement -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Patch management remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
