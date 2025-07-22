# Fix-Driver-Updates.ps1
# Remediation script for driver updates: check for outdated/missing drivers, update via Device Manager

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Driver-Updates-Remediation.log"
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

function Test-DriverUpdates {
    $issues = @()
    $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverVersion -and $_.DeviceName }
    foreach ($drv in $drivers) {
        if ($drv.DriverDate -lt (Get-Date).AddYears(-2)) {
            $issues += @{ Device = $drv.DeviceName; Version = $drv.DriverVersion; Date = $drv.DriverDate; Recommendation = 'Update driver' }
        }
    }
    return $issues
}

function Repair-DriverUpdates {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        if (-not $WhatIf) {
            try {
                # Attempt to update driver automatically
                Update-PnpDevice -InstanceId (Get-PnpDevice | Where-Object { $_.FriendlyName -eq $issue.Device }).InstanceId -Verbose:$false -ErrorAction Stop
                $changes += "Attempted update for $($issue.Device)"
            } catch {
                Write-Log "Failed to update $($issue.Device): $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting driver updates remediation"
    $issues = Test-DriverUpdates
    if ($issues.Count -eq 0) {
        Write-Log "All drivers up to date"
        $output = @{ Success = $true; Message = 'All drivers up to date'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Driver update issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-DriverUpdates -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Driver updates remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
