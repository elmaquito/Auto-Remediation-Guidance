# Fix-UAC-Settings.ps1
# Auto-remediation script to configure User Account Control (UAC) settings
# Addresses: UAC Admin Approval Mode Disabled

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\UAC-Remediation.log"
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

function Test-UACConfiguration {
    try {
        $enableLUA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop
        $consentPromptBehaviorAdmin = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction Stop
        $promptOnSecureDesktop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ErrorAction Stop
        
        return @{
            EnableLUA = $enableLUA.EnableLUA
            ConsentPromptBehaviorAdmin = $consentPromptBehaviorAdmin.ConsentPromptBehaviorAdmin
            PromptOnSecureDesktop = $promptOnSecureDesktop.PromptOnSecureDesktop
        }
    }
    catch {
        Write-Log "Error reading UAC configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Set-UACConfiguration {
    param(
        [switch]$WhatIf
    )
    
    $currentConfig = Test-UACConfiguration
    if (-not $currentConfig) {
        return @{ Success = $false; Message = "Failed to read current UAC configuration" }
    }
    
    Write-Log "Current UAC Configuration:"
    Write-Log "  EnableLUA: $($currentConfig.EnableLUA)"
    Write-Log "  ConsentPromptBehaviorAdmin: $($currentConfig.ConsentPromptBehaviorAdmin)"
    Write-Log "  PromptOnSecureDesktop: $($currentConfig.PromptOnSecureDesktop)"
    
    $changes = @()
    $needsReboot = $false
    
    # Check if EnableLUA needs to be enabled (Admin Approval Mode)
    if ($currentConfig.EnableLUA -ne 1) {
        $changes += "Enable Admin Approval Mode (EnableLUA=1)"
        $needsReboot = $true
    }
    
    # Check if ConsentPromptBehaviorAdmin needs adjustment
    if ($currentConfig.ConsentPromptBehaviorAdmin -eq 0) {
        $changes += "Enable UAC prompts for administrators (ConsentPromptBehaviorAdmin=5)"
    }
    
    # Check if PromptOnSecureDesktop should be enabled
    if ($currentConfig.PromptOnSecureDesktop -ne 1) {
        $changes += "Enable secure desktop for UAC prompts (PromptOnSecureDesktop=1)"
    }
    
    if ($changes.Count -eq 0) {
        Write-Log "UAC is already properly configured"
        return @{ 
            Success = $true
            Message = "UAC already properly configured"
            ChangesNeeded = $false
            RebootRequired = $false
        }
    }
    
    Write-Log "Changes needed:"
    foreach ($change in $changes) {
        Write-Log "  - $change"
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would apply UAC security configuration changes"
        return @{
            Success = $true
            Message = "WhatIf operation completed"
            ChangesNeeded = $true
            Changes = $changes
            RebootRequired = $needsReboot
        }
    }
    
    try {
        # Apply UAC settings
        if ($currentConfig.EnableLUA -ne 1) {
            Write-Log "Enabling UAC Admin Approval Mode..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
        }
        
        if ($currentConfig.ConsentPromptBehaviorAdmin -eq 0) {
            Write-Log "Configuring UAC prompt behavior for administrators..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord
        }
        
        if ($currentConfig.PromptOnSecureDesktop -ne 1) {
            Write-Log "Enabling secure desktop for UAC prompts..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        }
        
        Write-Log "UAC configuration updated successfully"
        
        if ($needsReboot) {
            Write-Log "IMPORTANT: System reboot required for UAC changes to take effect" "WARNING"
        }
        
        return @{
            Success = $true
            Message = "UAC configuration updated successfully"
            ChangesApplied = $changes
            RebootRequired = $needsReboot
        }
    }
    catch {
        Write-Log "Error applying UAC configuration: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Message = $_.Exception.Message
            RebootRequired = $false
        }
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin -and -not $WhatIf) {
        Write-Log "Administrator privileges required for UAC remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting UAC security remediation"
    
    try {
        $result = Set-UACConfiguration -WhatIf:$WhatIf
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            Message = $result.Message
            ChangesNeeded = $result.ChangesNeeded
            RebootRequired = $result.RebootRequired
            WhatIf = $WhatIf.IsPresent
            LogPath = $LogPath
        }
        
        if ($result.Changes) {
            $output.Changes = $result.Changes
        }
        
        if ($result.ChangesApplied) {
            $output.ChangesApplied = $result.ChangesApplied
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
