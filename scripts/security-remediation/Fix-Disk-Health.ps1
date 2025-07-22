# Fix-Disk-Health.ps1
# Remediation script for disk health: SMART status, defragmentation, disk errors

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Disk-Health-Remediation.log"
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

function Test-DiskHealth {
    $issues = @()
    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($disk in $disks) {
        if ($disk.OperationalStatus -ne 'OK') {
            $issues += @{ Type = 'SMART'; Disk = $disk.FriendlyName; Status = $disk.OperationalStatus; Recommendation = 'Replace or check disk' }
        }
    }
    $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
    foreach ($vol in $volumes) {
        if ($vol.HealthStatus -ne 'Healthy') {
            $issues += @{ Type = 'Volume'; Volume = $vol.DriveLetter; Status = $vol.HealthStatus; Recommendation = 'Run chkdsk' }
        }
        # Check fragmentation
        $frag = (Optimize-Volume -DriveLetter $vol.DriveLetter -Analyze -Verbose:$false -ErrorAction SilentlyContinue)
        if ($frag -and $frag.FragmentationPercentage -gt 10) {
            $issues += @{ Type = 'Fragmentation'; Volume = $vol.DriveLetter; Fragmentation = $frag.FragmentationPercentage; Recommendation = 'Defragment volume' }
        }
    }
    return $issues
}

function Repair-DiskHealth {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        switch ($issue.Type) {
            'SMART' {
                Write-Log "SMART issue on $($issue.Disk): $($issue.Status)" 'ERROR'
                # No automatic remediation for failing disk
            }
            'Volume' {
                Write-Log "Volume $($issue.Volume) health: $($issue.Status)" 'WARNING'
                if (-not $WhatIf) {
                    try {
                        chkdsk $($issue.Volume): /F | Out-Null
                        $changes += "Ran chkdsk on $($issue.Volume):"
                    } catch {
                        Write-Log "Failed to run chkdsk on $($issue.Volume): $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
            'Fragmentation' {
                Write-Log "Volume $($issue.Volume) fragmentation: $($issue.Fragmentation)%" 'WARNING'
                if (-not $WhatIf) {
                    try {
                        Optimize-Volume -DriveLetter $issue.Volume -Defrag -Verbose:$false
                        $changes += "Defragmented $($issue.Volume):"
                    } catch {
                        Write-Log "Failed to defragment $($issue.Volume): $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting disk health remediation"
    $issues = Test-DiskHealth
    if ($issues.Count -eq 0) {
        Write-Log "All disks and volumes healthy"
        $output = @{ Success = $true; Message = 'All disks and volumes healthy'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Disk health issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-DiskHealth -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Disk health remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
