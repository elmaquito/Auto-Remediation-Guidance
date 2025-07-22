# Fix-Firewall-Settings.ps1
# Auto-remediation script to configure Windows Firewall security settings
# Addresses: Firewall default inbound rules set to allow

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [ValidateSet("Domain", "Private", "Public", "All")]
    [string]$Profile = "All",
    [string]$LogPath = "$env:TEMP\Firewall-Remediation.log"
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

function Get-FirewallProfileConfiguration {
    try {
        $profiles = @()
        
        if ($Profile -eq "All") {
            $profiles = @("Domain", "Private", "Public")
        } else {
            $profiles = @($Profile)
        }
        
        $config = @{}
        
        foreach ($prof in $profiles) {
            $firewallProfile = Get-NetFirewallProfile -Profile $prof -ErrorAction Stop
            $config[$prof] = @{
                Enabled = $firewallProfile.Enabled
                DefaultInboundAction = $firewallProfile.DefaultInboundAction
                DefaultOutboundAction = $firewallProfile.DefaultOutboundAction
                AllowInboundRules = $firewallProfile.AllowInboundRules
                AllowLocalFirewallRules = $firewallProfile.AllowLocalFirewallRules
                NotifyOnListen = $firewallProfile.NotifyOnListen
            }
        }
        
        return $config
    }
    catch {
        Write-Log "Error reading firewall configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-FirewallSecurity {
    param($Config)
    
    $issues = @()
    
    foreach ($profileName in $Config.Keys) {
        $profileConfig = $Config[$profileName]
        
        # Check if firewall is enabled
        if (-not $profileConfig.Enabled) {
            $issues += @{
                Profile = $profileName
                Issue = "Firewall Disabled"
                Severity = "Critical"
                Recommendation = "Enable Windows Firewall"
            }
        }
        
        # Check default inbound action
        if ($profileConfig.DefaultInboundAction -ne "Block") {
            $issues += @{
                Profile = $profileName
                Issue = "Default Inbound Action Not Block"
                Severity = "High"
                Recommendation = "Set default inbound action to Block"
                CurrentValue = $profileConfig.DefaultInboundAction
            }
        }
        
        # Check if local firewall rules are allowed (potential security risk)
        if ($profileConfig.AllowLocalFirewallRules -eq $true -and $profileName -eq "Public") {
            $issues += @{
                Profile = $profileName
                Issue = "Local Firewall Rules Allowed on Public Profile"
                Severity = "Medium"
                Recommendation = "Disable local firewall rules on Public profile"
            }
        }
        
        # Check notification settings
        if (-not $profileConfig.NotifyOnListen -and $profileName -eq "Public") {
            $issues += @{
                Profile = $profileName
                Issue = "No Notification on Listen"
                Severity = "Low"
                Recommendation = "Enable notifications when programs listen for connections"
            }
        }
    }
    
    return $issues
}

function Set-FirewallSecureConfiguration {
    param(
        [switch]$WhatIf
    )
    
    $currentConfig = Get-FirewallProfileConfiguration
    if (-not $currentConfig) {
        return @{ Success = $false; Message = "Failed to read current firewall configuration" }
    }
    
    Write-Log "Current Firewall Configuration:"
    foreach ($profileName in $currentConfig.Keys) {
        $config = $currentConfig[$profileName]
        Write-Log "  $profileName Profile:"
        Write-Log "    Enabled: $($config.Enabled)"
        Write-Log "    DefaultInboundAction: $($config.DefaultInboundAction)"
        Write-Log "    DefaultOutboundAction: $($config.DefaultOutboundAction)"
        Write-Log "    AllowLocalFirewallRules: $($config.AllowLocalFirewallRules)"
        Write-Log "    NotifyOnListen: $($config.NotifyOnListen)"
    }
    
    $issues = Test-FirewallSecurity -Config $currentConfig
    
    if ($issues.Count -eq 0) {
        Write-Log "Firewall is already securely configured"
        return @{ 
            Success = $true
            Message = "Firewall already securely configured"
            ChangesNeeded = $false
        }
    }
    
    Write-Log "Security issues found:"
    foreach ($issue in $issues) {
        Write-Log "  [$($issue.Severity)] $($issue.Profile): $($issue.Issue)"
        Write-Log "    Recommendation: $($issue.Recommendation)"
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would apply firewall security configuration changes"
        return @{
            Success = $true
            Message = "WhatIf operation completed"
            ChangesNeeded = $true
            Issues = $issues
        }
    }
    
    try {
        $changesApplied = @()
        
        foreach ($issue in $issues) {
            $profileName = $issue.Profile
            
            switch ($issue.Issue) {
                "Firewall Disabled" {
                    Write-Log "Enabling firewall for $profileName profile..."
                    Set-NetFirewallProfile -Profile $profileName -Enabled True
                    $changesApplied += "Enabled firewall for $profileName profile"
                }
                
                "Default Inbound Action Not Block" {
                    Write-Log "Setting default inbound action to Block for $profileName profile..."
                    Set-NetFirewallProfile -Profile $profileName -DefaultInboundAction Block
                    $changesApplied += "Set default inbound action to Block for $profileName profile"
                }
                
                "Local Firewall Rules Allowed on Public Profile" {
                    Write-Log "Disabling local firewall rules for $profileName profile..."
                    Set-NetFirewallProfile -Profile $profileName -AllowLocalFirewallRules False
                    $changesApplied += "Disabled local firewall rules for $profileName profile"
                }
                
                "No Notification on Listen" {
                    Write-Log "Enabling notifications on listen for $profileName profile..."
                    Set-NetFirewallProfile -Profile $profileName -NotifyOnListen True
                    $changesApplied += "Enabled notifications on listen for $profileName profile"
                }
            }
        }
        
        # Verify changes
        Start-Sleep -Seconds 2
        $verifyConfig = Get-FirewallProfileConfiguration
        $remainingIssues = Test-FirewallSecurity -Config $verifyConfig
        
        Write-Log "Firewall configuration updated successfully"
        Write-Log "Applied changes:"
        foreach ($change in $changesApplied) {
            Write-Log "  - $change"
        }
        
        if ($remainingIssues.Count -gt 0) {
            Write-Log "Some issues remain after remediation:" "WARNING"
            foreach ($issue in $remainingIssues) {
                Write-Log "  - $($issue.Profile): $($issue.Issue)" "WARNING"
            }
        }
        
        return @{
            Success = $true
            Message = "Firewall configuration updated successfully"
            ChangesApplied = $changesApplied
            RemainingIssues = $remainingIssues
        }
    }
    catch {
        Write-Log "Error applying firewall configuration: $($_.Exception.Message)" "ERROR"
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
        Write-Log "Administrator privileges required for firewall remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting Windows Firewall security remediation"
    Write-Log "Target Profile(s): $Profile"
    
    try {
        $result = Set-FirewallSecureConfiguration -WhatIf:$WhatIf
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            Message = $result.Message
            Profile = $Profile
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
