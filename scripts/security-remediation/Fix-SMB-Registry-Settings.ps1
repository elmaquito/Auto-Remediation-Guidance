# Fix-SMB-Registry-Settings.ps1
# Auto-remediation script to configure SMB security registry settings
# Addresses: SMB signing not required, insecure registry settings

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\SMB-Registry-Remediation.log"
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

function Get-SMBSecurityConfiguration {
    try {
        $config = @{}
        
        # SMB Server settings
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        if (Test-Path $serverPath) {
            try {
                $requireSecuritySignature = Get-ItemProperty -Path $serverPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                $config.ServerRequireSecuritySignature = if ($requireSecuritySignature) { $requireSecuritySignature.RequireSecuritySignature } else { $null }
                
                $enableSecuritySignature = Get-ItemProperty -Path $serverPath -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
                $config.ServerEnableSecuritySignature = if ($enableSecuritySignature) { $enableSecuritySignature.EnableSecuritySignature } else { $null }
            }
            catch {
                Write-Log "Error reading SMB server settings: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # SMB Client settings
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        if (Test-Path $clientPath) {
            try {
                $requireSecuritySignature = Get-ItemProperty -Path $clientPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                $config.ClientRequireSecuritySignature = if ($requireSecuritySignature) { $requireSecuritySignature.RequireSecuritySignature } else { $null }
                
                $enableSecuritySignature = Get-ItemProperty -Path $clientPath -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
                $config.ClientEnableSecuritySignature = if ($enableSecuritySignature) { $enableSecuritySignature.EnableSecuritySignature } else { $null }
            }
            catch {
                Write-Log "Error reading SMB client settings: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Additional security settings
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        if (Test-Path $lsaPath) {
            try {
                $restrictAnonymous = Get-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
                $config.RestrictAnonymous = if ($restrictAnonymous) { $restrictAnonymous.RestrictAnonymous } else { $null }
                
                $restrictAnonymousSAM = Get-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
                $config.RestrictAnonymousSAM = if ($restrictAnonymousSAM) { $restrictAnonymousSAM.RestrictAnonymousSAM } else { $null }
            }
            catch {
                Write-Log "Error reading LSA security settings: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Network security settings
        $networkPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        if (Test-Path $networkPath) {
            try {
                $ntlmMinClientSec = Get-ItemProperty -Path $networkPath -Name "NtlmMinClientSec" -ErrorAction SilentlyContinue
                $config.NtlmMinClientSec = if ($ntlmMinClientSec) { $ntlmMinClientSec.NtlmMinClientSec } else { $null }
                
                $ntlmMinServerSec = Get-ItemProperty -Path $networkPath -Name "NtlmMinServerSec" -ErrorAction SilentlyContinue
                $config.NtlmMinServerSec = if ($ntlmMinServerSec) { $ntlmMinServerSec.NtlmMinServerSec } else { $null }
            }
            catch {
                Write-Log "Error reading NTLM security settings: $($_.Exception.Message)" "WARNING"
            }
        }
        
        return $config
    }
    catch {
        Write-Log "Error reading SMB security configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-SMBSecurity {
    param($Config)
    
    $issues = @()
    
    # Check SMB Server security signature requirements
    if ($Config.ServerRequireSecuritySignature -ne 1) {
        $issues += @{
            Issue = "SMB Server Security Signature Not Required"
            Severity = "High"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature"
            CurrentValue = $Config.ServerRequireSecuritySignature
            RecommendedValue = 1
            Recommendation = "Require SMB server security signatures"
        }
    }
    
    if ($Config.ServerEnableSecuritySignature -ne 1) {
        $issues += @{
            Issue = "SMB Server Security Signature Not Enabled"
            Severity = "Medium"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature"
            CurrentValue = $Config.ServerEnableSecuritySignature
            RecommendedValue = 1
            Recommendation = "Enable SMB server security signatures"
        }
    }
    
    # Check SMB Client security signature requirements
    if ($Config.ClientRequireSecuritySignature -ne 1) {
        $issues += @{
            Issue = "SMB Client Security Signature Not Required"
            Severity = "High"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature"
            CurrentValue = $Config.ClientRequireSecuritySignature
            RecommendedValue = 1
            Recommendation = "Require SMB client security signatures"
        }
    }
    
    if ($Config.ClientEnableSecuritySignature -ne 1) {
        $issues += @{
            Issue = "SMB Client Security Signature Not Enabled"
            Severity = "Medium"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature"
            CurrentValue = $Config.ClientEnableSecuritySignature
            RecommendedValue = 1
            Recommendation = "Enable SMB client security signatures"
        }
    }
    
    # Check anonymous access restrictions
    if ($Config.RestrictAnonymous -ne 1) {
        $issues += @{
            Issue = "Anonymous Access Not Restricted"
            Severity = "Medium"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous"
            CurrentValue = $Config.RestrictAnonymous
            RecommendedValue = 1
            Recommendation = "Restrict anonymous access to shares and pipes"
        }
    }
    
    if ($Config.RestrictAnonymousSAM -ne 1) {
        $issues += @{
            Issue = "Anonymous SAM Access Not Restricted"
            Severity = "High"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"
            CurrentValue = $Config.RestrictAnonymousSAM
            RecommendedValue = 1
            Recommendation = "Restrict anonymous access to SAM accounts and shares"
        }
    }
    
    # Check NTLM security settings (basic check for 128-bit encryption)
    # 0x20080000 = Require NTLMv2 session security and 128-bit encryption
    if ($Config.NtlmMinClientSec -ne 0x20080000) {
        $issues += @{
            Issue = "NTLM Client Security Level Too Low"
            Severity = "Medium"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec"
            CurrentValue = if ($Config.NtlmMinClientSec) { "0x$($Config.NtlmMinClientSec.ToString('X8'))" } else { "Not Set" }
            RecommendedValue = "0x20080000"
            Recommendation = "Require NTLMv2 session security and 128-bit encryption for client"
        }
    }
    
    if ($Config.NtlmMinServerSec -ne 0x20080000) {
        $issues += @{
            Issue = "NTLM Server Security Level Too Low"
            Severity = "Medium"
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec"
            CurrentValue = if ($Config.NtlmMinServerSec) { "0x$($Config.NtlmMinServerSec.ToString('X8'))" } else { "Not Set" }
            RecommendedValue = "0x20080000"
            Recommendation = "Require NTLMv2 session security and 128-bit encryption for server"
        }
    }
    
    return $issues
}

function Set-SMBSecureConfiguration {
    param(
        [switch]$WhatIf
    )
    
    $currentConfig = Get-SMBSecurityConfiguration
    if (-not $currentConfig) {
        return @{ Success = $false; Message = "Failed to read current SMB security configuration" }
    }
    
    Write-Log "Current SMB Security Configuration:"
    Write-Log "  Server RequireSecuritySignature: $($currentConfig.ServerRequireSecuritySignature)"
    Write-Log "  Server EnableSecuritySignature: $($currentConfig.ServerEnableSecuritySignature)"
    Write-Log "  Client RequireSecuritySignature: $($currentConfig.ClientRequireSecuritySignature)"
    Write-Log "  Client EnableSecuritySignature: $($currentConfig.ClientEnableSecuritySignature)"
    Write-Log "  RestrictAnonymous: $($currentConfig.RestrictAnonymous)"
    Write-Log "  RestrictAnonymousSAM: $($currentConfig.RestrictAnonymousSAM)"
    Write-Log "  NtlmMinClientSec: $($currentConfig.NtlmMinClientSec)"
    Write-Log "  NtlmMinServerSec: $($currentConfig.NtlmMinServerSec)"
    
    $issues = Test-SMBSecurity -Config $currentConfig
    
    if ($issues.Count -eq 0) {
        Write-Log "SMB security is already properly configured"
        return @{ 
            Success = $true
            Message = "SMB security already properly configured"
            ChangesNeeded = $false
        }
    }
    
    Write-Log "Security issues found:"
    foreach ($issue in $issues) {
        Write-Log "  [$($issue.Severity)] $($issue.Issue)"
        Write-Log "    Path: $($issue.RegistryPath)"
        Write-Log "    Current: $($issue.CurrentValue)"
        Write-Log "    Recommended: $($issue.RecommendedValue)"
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would apply SMB security configuration changes"
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
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $networkPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        # Ensure paths exist
        @($serverPath, $clientPath, $lsaPath, $networkPath) | ForEach-Object {
            if (-not (Test-Path $_)) {
                New-Item -Path $_ -Force | Out-Null
            }
        }
        
        foreach ($issue in $issues) {
            $registryPath = Split-Path $issue.RegistryPath -Parent
            $registryName = Split-Path $issue.RegistryPath -Leaf
            $value = $issue.RecommendedValue
            
            Write-Log "Setting $($issue.RegistryPath) to $value..."
            
            switch ($issue.Issue) {
                { $_ -match "SMB.*Security Signature" } {
                    Set-ItemProperty -Path $registryPath -Name $registryName -Value $value -Type DWord
                    $changesApplied += "Set $registryName to $value in $registryPath"
                }
                
                { $_ -match "Anonymous.*Access" } {
                    Set-ItemProperty -Path $registryPath -Name $registryName -Value $value -Type DWord
                    $changesApplied += "Set $registryName to $value in $registryPath"
                }
                
                { $_ -match "NTLM.*Security Level" } {
                    # Convert hex string back to int
                    $hexValue = [Convert]::ToInt32($value.Replace("0x", ""), 16)
                    Set-ItemProperty -Path $registryPath -Name $registryName -Value $hexValue -Type DWord
                    $changesApplied += "Set $registryName to $value in $registryPath"
                }
            }
        }
        
        Write-Log "SMB security configuration updated successfully"
        Write-Log "Applied changes:"
        foreach ($change in $changesApplied) {
            Write-Log "  - $change"
        }
        
        Write-Log "NOTE: Some changes may require a system restart to take effect" "WARNING"
        
        # Verify changes
        Start-Sleep -Seconds 2
        $verifyConfig = Get-SMBSecurityConfiguration
        $remainingIssues = Test-SMBSecurity -Config $verifyConfig
        
        if ($remainingIssues.Count -gt 0) {
            Write-Log "Some issues remain after remediation:" "WARNING"
            foreach ($issue in $remainingIssues) {
                Write-Log "  - $($issue.Issue)" "WARNING"
            }
        }
        
        return @{
            Success = $true
            Message = "SMB security configuration updated successfully"
            ChangesApplied = $changesApplied
            RemainingIssues = $remainingIssues
            RebootRecommended = $true
        }
    }
    catch {
        Write-Log "Error applying SMB security configuration: $($_.Exception.Message)" "ERROR"
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
        Write-Log "Administrator privileges required for SMB security remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting SMB security remediation"
    
    try {
        $result = Set-SMBSecureConfiguration -WhatIf:$WhatIf
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            Message = $result.Message
            ChangesNeeded = $result.ChangesNeeded
            RebootRecommended = $result.RebootRecommended
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
