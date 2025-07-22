# Fix-Windows-Updates.ps1
# Auto-remediation script to configure Windows Update settings
# Addresses: Automatic Updates Not Configured

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [ValidateSet("Automatic", "DownloadOnly", "NotifyOnly", "Disabled")]
    [string]$UpdateMode = "Automatic",
    [ValidateRange(1,23)]
    [int]$AutoInstallHour = 3,
    [string]$LogPath = "$env:TEMP\WindowsUpdate-Remediation.log"
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

function Get-WindowsUpdateConfiguration {
    try {
        $config = @{}
        
        # Check Windows Update service status
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        $config.ServiceStatus = $wuService.Status
        $config.ServiceStartType = $wuService.StartType
        
        # Check registry settings
        $auOptionsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        
        if (Test-Path $auOptionsPath) {
            try {
                $auOptions = Get-ItemProperty -Path $auOptionsPath -Name "AUOptions" -ErrorAction SilentlyContinue
                $config.AUOptions = $auOptions.AUOptions
            }
            catch {
                $config.AUOptions = $null
            }
            
            try {
                $scheduledInstallDay = Get-ItemProperty -Path $auOptionsPath -Name "ScheduledInstallDay" -ErrorAction SilentlyContinue
                $config.ScheduledInstallDay = $scheduledInstallDay.ScheduledInstallDay
            }
            catch {
                $config.ScheduledInstallDay = $null
            }
            
            try {
                $scheduledInstallTime = Get-ItemProperty -Path $auOptionsPath -Name "ScheduledInstallTime" -ErrorAction SilentlyContinue
                $config.ScheduledInstallTime = $scheduledInstallTime.ScheduledInstallTime
            }
            catch {
                $config.ScheduledInstallTime = $null
            }
        }
        
        # Check if Windows Update is disabled by policy
        if (Test-Path $wuPath) {
            try {
                $noAutoUpdate = Get-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
                $config.NoAutoUpdate = $noAutoUpdate.NoAutoUpdate
            }
            catch {
                $config.NoAutoUpdate = $null
            }
        }
        
        # Get Windows Update settings via WMI/PowerShell if available
        try {
            $updateSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
            if ($updateSettings) {
                $config.AutoUpdateEnabled = $updateSettings.EnableAutomaticUpdates
            }
        }
        catch {
            $config.AutoUpdateEnabled = $null
        }
        
        return $config
    }
    catch {
        Write-Log "Error reading Windows Update configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-WindowsUpdateSecurity {
    param($Config)
    
    $issues = @()
    
    # Check if Windows Update service is running
    if ($Config.ServiceStatus -ne "Running") {
        $issues += @{
            Issue = "Windows Update Service Not Running"
            Severity = "High"
            CurrentValue = $Config.ServiceStatus
            Recommendation = "Start Windows Update service"
        }
    }
    
    # Check if Windows Update service is set to automatic
    if ($Config.ServiceStartType -ne "Automatic") {
        $issues += @{
            Issue = "Windows Update Service Not Set to Automatic"
            Severity = "Medium"
            CurrentValue = $Config.ServiceStartType
            Recommendation = "Set Windows Update service to Automatic startup"
        }
    }
    
    # Check if automatic updates are disabled by policy
    if ($Config.NoAutoUpdate -eq 1) {
        $issues += @{
            Issue = "Automatic Updates Disabled by Policy"
            Severity = "High"
            CurrentValue = "Disabled"
            Recommendation = "Enable automatic updates"
        }
    }
    
    # Check AUOptions setting (4 = Download and install automatically)
    if ($Config.AUOptions -and $Config.AUOptions -ne 4) {
        $auOptionsText = switch ($Config.AUOptions) {
            1 { "Keep my computer up to date is disabled" }
            2 { "Notify before download" }
            3 { "Automatic download and notify of installation" }
            4 { "Automatic download and scheduled installation" }
            5 { "Automatic Updates is required, but end users can configure it" }
            default { "Unknown setting: $($Config.AUOptions)" }
        }
        
        $issues += @{
            Issue = "Suboptimal Automatic Update Configuration"
            Severity = "Medium"
            CurrentValue = "$($Config.AUOptions) ($auOptionsText)"
            Recommendation = "Set AUOptions to 4 for automatic download and installation"
        }
    }
    
    # Check if AutoUpdate is disabled
    if ($Config.AutoUpdateEnabled -eq 0) {
        $issues += @{
            Issue = "Automatic Updates Disabled"
            Severity = "High"
            CurrentValue = "Disabled"
            Recommendation = "Enable automatic updates"
        }
    }
    
    return $issues
}

function Set-WindowsUpdateSecureConfiguration {
    param(
        [switch]$WhatIf
    )
    
    $currentConfig = Get-WindowsUpdateConfiguration
    if (-not $currentConfig) {
        return @{ Success = $false; Message = "Failed to read current Windows Update configuration" }
    }
    
    Write-Log "Current Windows Update Configuration:"
    Write-Log "  Service Status: $($currentConfig.ServiceStatus)"
    Write-Log "  Service StartType: $($currentConfig.ServiceStartType)"
    Write-Log "  AUOptions: $($currentConfig.AUOptions)"
    Write-Log "  NoAutoUpdate: $($currentConfig.NoAutoUpdate)"
    Write-Log "  AutoUpdateEnabled: $($currentConfig.AutoUpdateEnabled)"
    Write-Log "  ScheduledInstallTime: $($currentConfig.ScheduledInstallTime)"
    
    $issues = Test-WindowsUpdateSecurity -Config $currentConfig
    
    if ($issues.Count -eq 0) {
        Write-Log "Windows Update is already securely configured"
        return @{ 
            Success = $true
            Message = "Windows Update already securely configured"
            ChangesNeeded = $false
        }
    }
    
    Write-Log "Security issues found:"
    foreach ($issue in $issues) {
        Write-Log "  [$($issue.Severity)] $($issue.Issue)"
        Write-Log "    Current: $($issue.CurrentValue)"
        Write-Log "    Recommendation: $($issue.Recommendation)"
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would apply Windows Update security configuration changes"
        return @{
            Success = $true
            Message = "WhatIf operation completed"
            ChangesNeeded = $true
            Issues = $issues
        }
    }
    
    try {
        $changesApplied = @()
        
        # Create registry paths if they don't exist
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        if (-not (Test-Path $auPath)) {
            New-Item -Path $auPath -Force | Out-Null
        }
        
        foreach ($issue in $issues) {
            switch ($issue.Issue) {
                "Windows Update Service Not Running" {
                    Write-Log "Starting Windows Update service..."
                    Start-Service -Name "wuauserv" -ErrorAction Stop
                    $changesApplied += "Started Windows Update service"
                }
                
                "Windows Update Service Not Set to Automatic" {
                    Write-Log "Setting Windows Update service to Automatic..."
                    Set-Service -Name "wuauserv" -StartupType Automatic
                    $changesApplied += "Set Windows Update service to Automatic startup"
                }
                
                "Automatic Updates Disabled by Policy" {
                    Write-Log "Enabling automatic updates..."
                    Remove-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
                    $changesApplied += "Enabled automatic updates (removed NoAutoUpdate policy)"
                }
                
                "Suboptimal Automatic Update Configuration" {
                    Write-Log "Configuring automatic updates for download and install..."
                    Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
                    Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value $AutoInstallHour -Type DWord
                    Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord  # 0 = Every day
                    $changesApplied += "Set AUOptions to 4 (automatic download and install)"
                    $changesApplied += "Set scheduled install time to ${AutoInstallHour}:00"
                }
                
                "Automatic Updates Disabled" {
                    Write-Log "Enabling automatic updates in registry..."
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "EnableAutomaticUpdates" -Value 1 -Type DWord
                    $changesApplied += "Enabled automatic updates in registry"
                }
            }
        }
        
        # Restart Windows Update service to apply changes
        Write-Log "Restarting Windows Update service to apply changes..."
        Restart-Service -Name "wuauserv" -Force
        Start-Sleep -Seconds 3
        
        # Verify changes
        $verifyConfig = Get-WindowsUpdateConfiguration
        $remainingIssues = Test-WindowsUpdateSecurity -Config $verifyConfig
        
        Write-Log "Windows Update configuration updated successfully"
        Write-Log "Applied changes:"
        foreach ($change in $changesApplied) {
            Write-Log "  - $change"
        }
        
        if ($remainingIssues.Count -gt 0) {
            Write-Log "Some issues remain after remediation:" "WARNING"
            foreach ($issue in $remainingIssues) {
                Write-Log "  - $($issue.Issue)" "WARNING"
            }
        }
        
        return @{
            Success = $true
            Message = "Windows Update configuration updated successfully"
            ChangesApplied = $changesApplied
            RemainingIssues = $remainingIssues
        }
    }
    catch {
        Write-Log "Error applying Windows Update configuration: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin -and -not $WhatIf) {
        Write-Log "Administrator privileges required for Windows Update remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting Windows Update security remediation"
    Write-Log "Update Mode: $UpdateMode"
    Write-Log "Auto Install Hour: $AutoInstallHour"
    
    try {
        $result = Set-WindowsUpdateSecureConfiguration -WhatIf:$WhatIf
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            Message = $result.Message
            UpdateMode = $UpdateMode
            AutoInstallHour = $AutoInstallHour
            ChangesNeeded = $result.ChangesNeeded
            WhatIf = $WhatIf.IsPresent
            LogPath = $LogPath
        }
        
        if ($result.Issues) {
            $output.Issues = $result.Issues
        }
        
        if ($result.ChangesApplied) {
            $output.ChangesApplied = $result.ChangesApplied
        }
        
        if ($result.RemainingIssues) {
            $output.RemainingIssues = $result.RemainingIssues
        }
        
        $jsonOutput = $output | ConvertTo-Json -Compress
        Write-Host "NEXTHINK_OUTPUT: $jsonOutput"
        
        if ($result.Success) {
            exit 0
        } else {
            exit 1
        }
    }
    catch {
        $errorOutput = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Error = $_.Exception.Message
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $errorOutput"
        exit 1
    }
}
