# Fix-Network-Adapter-Settings.ps1
# Remediation script for network adapter settings: check for unused adapters, rogue Wi-Fi profiles

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Network-Adapter-Remediation.log"
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

function Test-NetworkAdapterSettings {
    $issues = @()
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Disconnected' -and $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback' }
    foreach ($adapter in $adapters) {
        $issues += @{ Adapter = $adapter.Name; Status = $adapter.Status; Recommendation = 'Disable unused adapter' }
    }
    $profiles = netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() }
    foreach ($profile in $profiles) {
        if ($profile -notmatch 'TrustedSSID1|TrustedSSID2') {
            $issues += @{ WiFiProfile = $profile; Recommendation = 'Remove rogue Wi-Fi profile' }
        }
    }
    return $issues
}

function Repair-NetworkAdapterSettings {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        if ($issue.Adapter -and -not $WhatIf) {
            try {
                Disable-NetAdapter -Name $issue.Adapter -Confirm:$false
                $changes += "Disabled adapter $($issue.Adapter)"
            } catch {
                Write-Log "Failed to disable adapter $($issue.Adapter): $($_.Exception.Message)" 'ERROR'
            }
        }
        if ($issue.WiFiProfile -and -not $WhatIf) {
            try {
                netsh wlan delete profile name="$($issue.WiFiProfile)"
                $changes += "Removed Wi-Fi profile $($issue.WiFiProfile)"
            } catch {
                Write-Log "Failed to remove Wi-Fi profile $($issue.WiFiProfile): $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting network adapter settings remediation"
    $issues = Test-NetworkAdapterSettings
    if ($issues.Count -eq 0) {
        Write-Log "No unused adapters or rogue Wi-Fi profiles found"
        $output = @{ Success = $true; Message = 'No unused adapters or rogue Wi-Fi profiles found'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Network adapter issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-NetworkAdapterSettings -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Network adapter settings remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
