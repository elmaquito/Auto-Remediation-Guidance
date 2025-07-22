# Fix-Startup-Programs.ps1
# Remediation script for startup programs: audit and disable unnecessary startup items

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Startup-Programs-Remediation.log"
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

function Get-StartupPrograms {
    $startupItems = @()
    # Registry: Current User
    $startupItems += Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSDrive' -and $_.Name -ne 'PSProvider' } | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Command = $_.Value; Location = 'HKCU' } } }
    # Registry: Local Machine
    $startupItems += Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSDrive' -and $_.Name -ne 'PSProvider' } | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Command = $_.Value; Location = 'HKLM' } } }
    # Startup folder (Current User)
    $startupFolderCU = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupFolderCU) {
        Get-ChildItem $startupFolderCU -File | ForEach-Object {
            $startupItems += [PSCustomObject]@{ Name = $_.Name; Command = $_.FullName; Location = 'StartupFolderCU' }
        }
    }
    # Startup folder (All Users)
    $startupFolderAll = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupFolderAll) {
        Get-ChildItem $startupFolderAll -File | ForEach-Object {
            $startupItems += [PSCustomObject]@{ Name = $_.Name; Command = $_.FullName; Location = 'StartupFolderAll' }
        }
    }
    return $startupItems
}

function Test-StartupPrograms {
    $issues = @()
    $startupItems = Get-StartupPrograms
    # Example: flag all non-Microsoft items as potentially unnecessary
    foreach ($item in $startupItems) {
        if ($item.Command -notmatch 'Microsoft|Windows Defender|OneDrive') {
            $issues += @{ Name = $item.Name; Command = $item.Command; Location = $item.Location; Recommendation = 'Review and disable if unnecessary' }
        }
    }
    return $issues
}

function Repair-StartupPrograms {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        switch ($issue.Location) {
            'HKCU' {
                if (-not $WhatIf) {
                    try {
                        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $issue.Name -ErrorAction Stop
                        $changes += "Disabled startup item $($issue.Name) from HKCU"
                    } catch {
                        Write-Log "Failed to disable $($issue.Name) from HKCU: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
            'HKLM' {
                if (-not $WhatIf) {
                    try {
                        Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $issue.Name -ErrorAction Stop
                        $changes += "Disabled startup item $($issue.Name) from HKLM"
                    } catch {
                        Write-Log "Failed to disable $($issue.Name) from HKLM: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
            'StartupFolderCU' {
                if (-not $WhatIf) {
                    try {
                        Remove-Item -Path $issue.Command -Force -ErrorAction Stop
                        $changes += "Removed $($issue.Name) from StartupFolderCU"
                    } catch {
                        Write-Log "Failed to remove $($issue.Name) from StartupFolderCU: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
            'StartupFolderAll' {
                if (-not $WhatIf) {
                    try {
                        Remove-Item -Path $issue.Command -Force -ErrorAction Stop
                        $changes += "Removed $($issue.Name) from StartupFolderAll"
                    } catch {
                        Write-Log "Failed to remove $($issue.Name) from StartupFolderAll: $($_.Exception.Message)" 'ERROR'
                    }
                }
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting startup programs remediation"
    $issues = Test-StartupPrograms
    if ($issues.Count -eq 0) {
        Write-Log "No unnecessary startup programs found"
        $output = @{ Success = $true; Message = 'No unnecessary startup programs found'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Startup program issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-StartupPrograms -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Startup programs remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
