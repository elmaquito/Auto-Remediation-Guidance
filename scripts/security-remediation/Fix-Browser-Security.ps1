# Fix-Browser-Security.ps1
# Remediation script for browser security: check for risky extensions, clear cache/history

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\Browser-Security-Remediation.log"
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

function Test-BrowserSecurity {
    $issues = @()
    # Only basic checks for Edge/IE (PowerShell cannot easily enumerate Chrome/Firefox extensions)
    $edgeExt = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgeExt) {
        $extCount = (Get-ChildItem $edgeExt -Directory | Measure-Object).Count
        if ($extCount -gt 5) {
            $issues += @{ Browser = 'Edge'; Extensions = $extCount; Recommendation = 'Review installed extensions' }
        }
    }
    $ieBars = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Toolbar\WebBrowser' -ErrorAction SilentlyContinue
    if ($ieBars) {
        $issues += @{ Browser = 'IE'; Toolbars = ($ieBars.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' }).Count; Recommendation = 'Review IE toolbars' }
    }
    return $issues
}

function Repair-BrowserSecurity {
    param($Issues, [switch]$WhatIf)
    $changes = @()
    foreach ($issue in $Issues) {
        if ($issue.Browser -eq 'Edge' -and -not $WhatIf) {
            try {
                Remove-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
                $changes += "Cleared Edge cache"
            } catch {
                Write-Log "Failed to clear Edge cache: $($_.Exception.Message)" 'ERROR'
            }
        }
        if ($issue.Browser -eq 'IE' -and -not $WhatIf) {
            try {
                RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
                $changes += "Cleared IE cache/history"
            } catch {
                Write-Log "Failed to clear IE cache/history: $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $changes
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log "Starting browser security remediation"
    $issues = Test-BrowserSecurity
    if ($issues.Count -eq 0) {
        Write-Log "No risky browser extensions or toolbars found"
        $output = @{ Success = $true; Message = 'No risky browser extensions or toolbars found'; ChangesNeeded = $false }
        Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
        exit 0
    }
    Write-Log "Browser security issues found: $($issues.Count)"
    foreach ($i in $issues) {
        Write-Log ("Issue: " + ($i | Out-String))
    }
    $changes = Repair-BrowserSecurity -Issues $issues -WhatIf:$WhatIf
    $output = @{ Success = $true; Message = 'Browser security remediation completed'; Issues = $issues; ChangesApplied = $changes; ChangesNeeded = $true }
    Write-Host "NEXTHINK_OUTPUT: $($output | ConvertTo-Json -Compress)"
    exit 0
}
