# Fix-Battery-Health.ps1
# Remediation script for battery health: check wear, calibration, power plans

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Battery-Health-Remediation.log"
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

function Test-BatteryHealth {
    $issues = @()
    $batt = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue
    if ($batt) {
        if ($batt.DesignCapacity -and $batt.FullChargeCapacity -and $batt.FullChargeCapacity -lt ($batt.DesignCapacity * 0.7)) {
            $issues += @{ Type = 'Wear'; Status = "High wear ($([math]::Round(100 * $batt.FullChargeCapacity / $batt.DesignCapacity,1))%)"; Recommendation = 'Consider battery replacement or calibration' }
        }
    }
    $activePlan = powercfg /GetActiveScheme
    if ($activePlan -notmatch 'Balanced|Power saver') {
        $issues += @{ Type = 'PowerPlan'; Status = $activePlan; Recommendation = 'Switch to Balanced or Power saver plan' }
    }
    return $issues
}

function Repair-BatteryHealth {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        switch ($issue.Type) {
            'Wear' {
                Write-Log "Battery wear detected: $($issue.Status)" 'WARNING'
                # No auto remediation for battery replacement
            }
            'PowerPlan' {
                if (-not $WhatIf) {
                    try {
                        powercfg /S SCHEME_BALANCED
                        $changes += "Set power plan to Balanced"
                    } catch {
                        Write-Log "Failed to set power plan: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting battery health remediation"
    $issues = Test-BatteryHealth
    if ($issues.Count -eq 0) {
        Write-Log "Battery healthy"
        $output = @{ Success = $true; Message = 'Battery healthy'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Battery health issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-BatteryHealth -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Battery health remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
