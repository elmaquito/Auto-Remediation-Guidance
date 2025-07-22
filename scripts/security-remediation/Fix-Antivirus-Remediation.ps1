# Fix-Antivirus-Remediation.ps1
# Remediation script for Antivirus/Antimalware: check real-time protection, update definitions, run scan

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Antivirus-Remediation.log"
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

function Test-Antivirus {
    $issues = @()
    $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $av) {
        $issues += @{ Type = 'Antivirus'; Status = 'Not detected'; Recommendation = 'Install antivirus' }
        return $issues
    }
    if (-not $av.AntivirusEnabled) {
        $issues += @{ Type = 'Antivirus'; Status = 'Disabled'; Recommendation = 'Enable antivirus' }
    }
    if (-not $av.RealTimeProtectionEnabled) {
        $issues += @{ Type = 'RealTimeProtection'; Status = 'Disabled'; Recommendation = 'Enable real-time protection' }
    }
    if ($av.AntivirusSignatureAge -gt 3) {
        $issues += @{ Type = 'Signatures'; Status = "Outdated ($($av.AntivirusSignatureAge) days)"; Recommendation = 'Update definitions' }
    }
    return $issues
}

function Repair-Antivirus {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        switch ($issue.Type) {
            'Antivirus' {
                Write-Log "Antivirus not detected or disabled" 'ERROR'
                # No auto remediation for missing AV
            }
            'RealTimeProtection' {
                if (-not $WhatIf) {
                    try {
                        Set-MpPreference -DisableRealtimeMonitoring $false
                        $changes += "Enabled real-time protection"
                    } catch {
                        Write-Log "Failed to enable real-time protection: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
            'Signatures' {
                if (-not $WhatIf) {
                    try {
                        Update-MpSignature
                        $changes += "Updated antivirus definitions"
                    } catch {
                        Write-Log "Failed to update definitions: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
        }
    }
    # Optionally run a quick scan
    if (-not $WhatIf) {
        try {
            Start-MpScan -ScanType QuickScan
            $changes += "Started quick antivirus scan"
        } catch {
            Write-Log "Failed to start antivirus scan: $($_.Exception.Message)" 'ERROR'
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting antivirus remediation"
    $issues = Test-Antivirus
    if ($issues.Count -eq 0) {
        Write-Log "Antivirus healthy"
        $output = @{ Success = $true; Message = 'Antivirus healthy'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Antivirus issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-Antivirus -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Antivirus remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
