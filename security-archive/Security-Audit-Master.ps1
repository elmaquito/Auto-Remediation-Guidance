# Security-Audit-Master.ps1
# Advanced Security Audit and Remediation Script for Windows 11
# This script performs comprehensive security checks and automated remediation

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Remediate,
    [switch]$DetailedReport,
    [string]$ReportPath = "$env:TEMP\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$LogPath = "$env:TEMP\SecurityAudit.log",
    [ValidateSet("Critical", "High", "Medium", "Low", "All")]
    [string]$SeverityLevel = "High"
)

# Initialize logging
function Write-SecurityLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "GENERAL"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Category] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

# Security audit results storage
$script:SecurityFindings = @()
$script:RemediationActions = @()

function Add-SecurityFinding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity,
        [string]$Description,
        [string]$Recommendation,
        [bool]$CanAutoRemediate = $false,
        [scriptblock]$RemediationAction = $null
    )
    
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date
        Category = $Category
        Finding = $Finding
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        CanAutoRemediate = $CanAutoRemediate
        RemediationAction = $RemediationAction
    }
    
    $script:SecurityFindings += $finding
    Write-SecurityLog "Finding: [$Severity] $Category - $Finding" $Severity $Category
}

# Windows Defender and Antivirus Checks
function Test-AntivirusStatus {
    Write-SecurityLog "Checking Windows Defender and Antivirus status" "INFO" "ANTIVIRUS"
    
    try {
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if (-not $defenderStatus) {
            Add-SecurityFinding -Category "ANTIVIRUS" -Finding "Windows Defender Not Available" -Severity "Critical" `
                -Description "Windows Defender is not available or accessible" `
                -Recommendation "Enable Windows Defender or install alternative antivirus"
            return
        }
        
        # Real-time protection
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            Add-SecurityFinding -Category "ANTIVIRUS" -Finding "Real-time Protection Disabled" -Severity "Critical" `
                -Description "Windows Defender real-time protection is disabled" `
                -Recommendation "Enable real-time protection" `
                -CanAutoRemediate $true `
                -RemediationAction { Set-MpPreference -DisableRealtimeMonitoring $false }
        }
        
        # Behavior monitoring
        if (-not $defenderStatus.BehaviorMonitorEnabled) {
            Add-SecurityFinding -Category "ANTIVIRUS" -Finding "Behavior Monitoring Disabled" -Severity "High" `
                -Description "Windows Defender behavior monitoring is disabled" `
                -Recommendation "Enable behavior monitoring" `
                -CanAutoRemediate $true `
                -RemediationAction { Set-MpPreference -DisableBehaviorMonitoring $false }
        }
        
        # Definition updates
        $lastUpdate = $defenderStatus.AntivirusSignatureLastUpdated
        if ($lastUpdate -lt (Get-Date).AddDays(-3)) {
            Add-SecurityFinding -Category "ANTIVIRUS" -Finding "Outdated Virus Definitions" -Severity "High" `
                -Description "Virus definitions are more than 3 days old" `
                -Recommendation "Update virus definitions" `
                -CanAutoRemediate $true `
                -RemediationAction { Update-MpSignature }
        }
        
        # Cloud protection
        if ($defenderStatus.AMServiceEnabled -eq $false) {
            Add-SecurityFinding -Category "ANTIVIRUS" -Finding "Cloud Protection Disabled" -Severity "Medium" `
                -Description "Windows Defender cloud protection is disabled" `
                -Recommendation "Enable cloud-delivered protection"
        }
        
        Write-SecurityLog "Windows Defender status check completed" "SUCCESS" "ANTIVIRUS"
    }
    catch {
        Write-SecurityLog "Error checking antivirus status: $($_.Exception.Message)" "ERROR" "ANTIVIRUS"
    }
}

# Windows Update Security Checks
function Test-WindowsUpdateSecurity {
    Write-SecurityLog "Checking Windows Update security settings" "INFO" "UPDATES"
    
    try {
        # Check Windows Update service
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService.Status -ne "Running") {
            Add-SecurityFinding -Category "UPDATES" -Finding "Windows Update Service Not Running" -Severity "High" `
                -Description "Windows Update service is not running" `
                -Recommendation "Start Windows Update service" `
                -CanAutoRemediate $true `
                -RemediationAction { Start-Service -Name "wuauserv" }
        }
        
        # Check for pending updates
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate -Force
            $pendingUpdates = Get-WUList -MicrosoftUpdate
            
            if ($pendingUpdates) {
                $criticalUpdates = $pendingUpdates | Where-Object { $_.MsrcSeverity -eq "Critical" }
                if ($criticalUpdates) {
                    Add-SecurityFinding -Category "UPDATES" -Finding "Critical Security Updates Pending" -Severity "Critical" `
                        -Description "Critical security updates are available but not installed" `
                        -Recommendation "Install critical security updates immediately" `
                        -CanAutoRemediate $true `
                        -RemediationAction { Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot }
                }
            }
        }
        
        # Check automatic update settings
        $auSettings = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue).AUOptions
        if ($auSettings -ne 4) {
            Add-SecurityFinding -Category "UPDATES" -Finding "Automatic Updates Not Configured" -Severity "Medium" `
                -Description "Automatic updates are not properly configured" `
                -Recommendation "Configure automatic updates to download and install automatically"
        }
        
        Write-SecurityLog "Windows Update security check completed" "SUCCESS" "UPDATES"
    }
    catch {
        Write-SecurityLog "Error checking Windows Update security: $($_.Exception.Message)" "ERROR" "UPDATES"
    }
}

# User Account Control (UAC) Checks
function Test-UACConfiguration {
    Write-SecurityLog "Checking User Account Control configuration" "INFO" "UAC"
    
    try {
        $uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        
        # UAC enabled check
        if ($uacSettings.EnableLUA -ne 1) {
            Add-SecurityFinding -Category "UAC" -Finding "UAC Disabled" -Severity "Critical" `
                -Description "User Account Control is disabled" `
                -Recommendation "Enable UAC for better security" `
                -CanAutoRemediate $true `
                -RemediationAction { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 }
        }
        
        # Admin approval mode
        if ($uacSettings.FilterAdministratorToken -ne 1) {
            Add-SecurityFinding -Category "UAC" -Finding "Admin Approval Mode Disabled" -Severity "High" `
                -Description "Administrator approval mode is disabled" `
                -Recommendation "Enable administrator approval mode"
        }
        
        # Prompt level
        if ($uacSettings.ConsentPromptBehaviorAdmin -lt 2) {
            Add-SecurityFinding -Category "UAC" -Finding "Weak UAC Prompt Level" -Severity "Medium" `
                -Description "UAC prompt level is set too low" `
                -Recommendation "Increase UAC prompt level for better security"
        }
        
        Write-SecurityLog "UAC configuration check completed" "SUCCESS" "UAC"
    }
    catch {
        Write-SecurityLog "Error checking UAC configuration: $($_.Exception.Message)" "ERROR" "UAC"
    }
}

# Firewall Security Checks
function Test-FirewallSecurity {
    Write-SecurityLog "Checking Windows Firewall security" "INFO" "FIREWALL"
    
    try {
        $firewallProfiles = Get-NetFirewallProfile
        
        foreach ($profile in $firewallProfiles) {
            if (-not $profile.Enabled) {
                Add-SecurityFinding -Category "FIREWALL" -Finding "$($profile.Name) Firewall Disabled" -Severity "Critical" `
                    -Description "Windows Firewall is disabled for $($profile.Name) profile" `
                    -Recommendation "Enable Windows Firewall for all profiles" `
                    -CanAutoRemediate $true `
                    -RemediationAction { Set-NetFirewallProfile -Profile $profile.Name -Enabled True }
            }
            
            if ($profile.DefaultInboundAction -ne "Block") {
                Add-SecurityFinding -Category "FIREWALL" -Finding "$($profile.Name) Inbound Default Allow" -Severity "High" `
                    -Description "Default inbound action is not set to block for $($profile.Name) profile" `
                    -Recommendation "Set default inbound action to block"
            }
        }
        
        # Check for risky firewall rules
        $riskyRules = Get-NetFirewallRule | Where-Object { 
            $_.Enabled -eq $true -and 
            $_.Direction -eq "Inbound" -and 
            $_.Action -eq "Allow" -and
            ($_.RemoteAddress -eq "Any" -or $_.RemoteAddress -eq "0.0.0.0/0")
        }
        
        if ($riskyRules.Count -gt 10) {
            Add-SecurityFinding -Category "FIREWALL" -Finding "Too Many Permissive Inbound Rules" -Severity "Medium" `
                -Description "Large number of permissive inbound firewall rules detected" `
                -Recommendation "Review and minimize inbound firewall rules"
        }
        
        Write-SecurityLog "Firewall security check completed" "SUCCESS" "FIREWALL"
    }
    catch {
        Write-SecurityLog "Error checking firewall security: $($_.Exception.Message)" "ERROR" "FIREWALL"
    }
}

# Password Policy Checks
function Test-PasswordPolicy {
    Write-SecurityLog "Checking password policy settings" "INFO" "PASSWORD"
    
    try {
        # Get local security policy
        $tempFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tempFile | Out-Null
        $secPolicy = Get-Content $tempFile
        Remove-Item $tempFile
        
        # Parse password policy settings
        $minPwdLength = ($secPolicy | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
        $pwdComplexity = ($secPolicy | Select-String "PasswordComplexity").ToString().Split("=")[1].Trim()
        $maxPwdAge = ($secPolicy | Select-String "MaximumPasswordAge").ToString().Split("=")[1].Trim()
        
        if ([int]$minPwdLength -lt 8) {
            Add-SecurityFinding -Category "PASSWORD" -Finding "Weak Minimum Password Length" -Severity "High" `
                -Description "Minimum password length is less than 8 characters" `
                -Recommendation "Set minimum password length to at least 8 characters"
        }
        
        if ($pwdComplexity -eq "0") {
            Add-SecurityFinding -Category "PASSWORD" -Finding "Password Complexity Disabled" -Severity "High" `
                -Description "Password complexity requirements are disabled" `
                -Recommendation "Enable password complexity requirements"
        }
        
        if ([int]$maxPwdAge -eq -1 -or [int]$maxPwdAge -gt 90) {
            Add-SecurityFinding -Category "PASSWORD" -Finding "Password Never Expires" -Severity "Medium" `
                -Description "Passwords are set to never expire or expire after more than 90 days" `
                -Recommendation "Set password expiration to 60-90 days"
        }
        
        Write-SecurityLog "Password policy check completed" "SUCCESS" "PASSWORD"
    }
    catch {
        Write-SecurityLog "Error checking password policy: $($_.Exception.Message)" "ERROR" "PASSWORD"
    }
}

# Network Security Checks
function Test-NetworkSecurity {
    Write-SecurityLog "Checking network security configuration" "INFO" "NETWORK"
    
    try {
        # Check for open ports
        $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -eq "0.0.0.0" }
        
        $riskyPorts = @(21, 23, 135, 139, 445, 1433, 3389, 5985, 5986)
        foreach ($port in $openPorts) {
            if ($riskyPorts -contains $port.LocalPort) {
                Add-SecurityFinding -Category "NETWORK" -Finding "Risky Port Open" -Severity "High" `
                    -Description "Potentially risky port $($port.LocalPort) is listening on all interfaces" `
                    -Recommendation "Review if port $($port.LocalPort) needs to be publicly accessible"
            }
        }
        
        # Check SMB configuration
        $smbConfig = Get-SmbServerConfiguration
        if ($smbConfig.EnableSMB1Protocol) {
            Add-SecurityFinding -Category "NETWORK" -Finding "SMBv1 Enabled" -Severity "Critical" `
                -Description "SMBv1 protocol is enabled (vulnerable to WannaCry and similar attacks)" `
                -Recommendation "Disable SMBv1 protocol" `
                -CanAutoRemediate $true `
                -RemediationAction { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
        }
        
        # Check network adapter security
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $networkAdapters) {
            $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_server"
            if ($binding.Enabled -and $adapter.InterfaceDescription -like "*Wireless*") {
                Add-SecurityFinding -Category "NETWORK" -Finding "File Sharing on Wireless" -Severity "Medium" `
                    -Description "File and printer sharing is enabled on wireless adapter" `
                    -Recommendation "Disable file sharing on wireless connections"
            }
        }
        
        Write-SecurityLog "Network security check completed" "SUCCESS" "NETWORK"
    }
    catch {
        Write-SecurityLog "Error checking network security: $($_.Exception.Message)" "ERROR" "NETWORK"
    }
}

# Registry Security Checks
function Test-RegistrySecurity {
    Write-SecurityLog "Checking registry security settings" "INFO" "REGISTRY"
    
    try {
        # Check for dangerous registry settings
        $dangerousSettings = @(
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                Name = "LmCompatibilityLevel"
                DangerousValue = 0, 1, 2
                Severity = "High"
                Description = "Weak NTLM authentication level"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                Name = "RequireSecuritySignature" 
                DangerousValue = 0
                Severity = "High"
                Description = "SMB signing not required"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "LocalAccountTokenFilterPolicy"
                DangerousValue = 1
                Severity = "Medium"
                Description = "Remote UAC restrictions disabled for local accounts"
            }
        )
        
        foreach ($setting in $dangerousSettings) {
            $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
            if ($value -and $setting.DangerousValue -contains $value.$($setting.Name)) {
                Add-SecurityFinding -Category "REGISTRY" -Finding "Insecure Registry Setting" -Severity $setting.Severity `
                    -Description $setting.Description `
                    -Recommendation "Review and secure registry setting: $($setting.Path)\$($setting.Name)"
            }
        }
        
        Write-SecurityLog "Registry security check completed" "SUCCESS" "REGISTRY"
    }
    catch {
        Write-SecurityLog "Error checking registry security: $($_.Exception.Message)" "ERROR" "REGISTRY"
    }
}

# Service Security Checks
function Test-ServiceSecurity {
    Write-SecurityLog "Checking service security configuration" "INFO" "SERVICES"
    
    try {
        # Check for unnecessary services
        $riskyServices = @(
            "Telnet", "SNMP", "RemoteRegistry", "RemoteAccess", 
            "TermService", "Browser", "Messenger"
        )
        
        foreach ($serviceName in $riskyServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Add-SecurityFinding -Category "SERVICES" -Finding "Risky Service Running" -Severity "Medium" `
                    -Description "$serviceName service is running and may pose security risks" `
                    -Recommendation "Disable $serviceName service if not needed" `
                    -CanAutoRemediate $true `
                    -RemediationAction { Stop-Service -Name $serviceName; Set-Service -Name $serviceName -StartupType Disabled }
            }
        }
        
        # Check service permissions
        $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -like "*%*" }
        foreach ($service in $services) {
            Add-SecurityFinding -Category "SERVICES" -Finding "Service with Environment Variables" -Severity "Low" `
                -Description "Service $($service.Name) uses environment variables in path" `
                -Recommendation "Review service path for potential DLL hijacking"
        }
        
        Write-SecurityLog "Service security check completed" "SUCCESS" "SERVICES"
    }
    catch {
        Write-SecurityLog "Error checking service security: $($_.Exception.Message)" "ERROR" "SERVICES"
    }
}

# Execute Remediation Actions
function Invoke-SecurityRemediation {
    if (-not $Remediate) {
        Write-SecurityLog "Remediation mode not enabled. Use -Remediate switch to auto-fix issues" "WARNING" "REMEDIATION"
        return
    }
    
    Write-SecurityLog "Starting automated security remediation" "INFO" "REMEDIATION"
    
    $remediatedCount = 0
    foreach ($finding in $script:SecurityFindings) {
        if ($finding.CanAutoRemediate -and $finding.RemediationAction) {
            try {
                if ($WhatIf) {
                    Write-SecurityLog "WhatIf: Would remediate $($finding.Finding)" "INFO" "REMEDIATION"
                } else {
                    Write-SecurityLog "Remediating: $($finding.Finding)" "INFO" "REMEDIATION"
                    & $finding.RemediationAction
                    $remediatedCount++
                }
                
                $script:RemediationActions += [PSCustomObject]@{
                    Finding = $finding.Finding
                    Category = $finding.Category
                    Status = if ($WhatIf) { "WhatIf" } else { "Success" }
                    Timestamp = Get-Date
                }
            }
            catch {
                Write-SecurityLog "Failed to remediate $($finding.Finding): $($_.Exception.Message)" "ERROR" "REMEDIATION"
                $script:RemediationActions += [PSCustomObject]@{
                    Finding = $finding.Finding
                    Category = $finding.Category
                    Status = "Failed"
                    Error = $_.Exception.Message
                    Timestamp = Get-Date
                }
            }
        }
    }
    
    Write-SecurityLog "Remediation completed. $remediatedCount issues $(if ($WhatIf) {'would be'} else {'were'}) fixed" "SUCCESS" "REMEDIATION"
}

# Generate Security Report
function Generate-SecurityReport {
    Write-SecurityLog "Generating security audit report" "INFO" "REPORT"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows 11 Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .findings { margin: 20px 0; }
        .finding { margin: 10px 0; padding: 15px; border-left: 4px solid #bdc3c7; background-color: #f8f9fa; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #27ae60; }
        .category { font-weight: bold; color: #2c3e50; }
        .severity { font-weight: bold; padding: 2px 8px; border-radius: 3px; color: white; }
        .severity.critical { background-color: #e74c3c; }
        .severity.high { background-color: #f39c12; }
        .severity.medium { background-color: #f1c40f; }
        .severity.low { background-color: #27ae60; }
        .remediation { margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows 11 Security Audit Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Computer: $env:COMPUTERNAME | User: $env:USERNAME</p>
    </div>
    
    <div class="summary">
        <h2>Security Summary</h2>
        <p><strong>Total Findings:</strong> $($script:SecurityFindings.Count)</p>
        <p><strong>Critical:</strong> $(($script:SecurityFindings | Where-Object Severity -eq "Critical").Count)</p>
        <p><strong>High:</strong> $(($script:SecurityFindings | Where-Object Severity -eq "High").Count)</p>
        <p><strong>Medium:</strong> $(($script:SecurityFindings | Where-Object Severity -eq "Medium").Count)</p>
        <p><strong>Low:</strong> $(($script:SecurityFindings | Where-Object Severity -eq "Low").Count)</p>
        <p><strong>Auto-Remediable:</strong> $(($script:SecurityFindings | Where-Object CanAutoRemediate -eq $true).Count)</p>
    </div>
    
    <div class="findings">
        <h2>Security Findings</h2>
"@
    
    foreach ($finding in ($script:SecurityFindings | Sort-Object Severity, Category)) {
        $severityClass = $finding.Severity.ToLower()
        $html += @"
        <div class="finding $severityClass">
            <div class="category">[$($finding.Category)] $($finding.Finding)</div>
            <span class="severity $severityClass">$($finding.Severity)</span>
            <p><strong>Description:</strong> $($finding.Description)</p>
            <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
            $(if ($finding.CanAutoRemediate) { "<p><strong>Auto-Remediation:</strong> Available</p>" })
        </div>
"@
    }
    
    if ($script:RemediationActions.Count -gt 0) {
        $html += @"
    </div>
    
    <div class="remediation">
        <h2>Remediation Actions</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Finding</th>
                <th>Status</th>
                <th>Timestamp</th>
            </tr>
"@
        
        foreach ($action in $script:RemediationActions) {
            $html += @"
            <tr>
                <td>$($action.Category)</td>
                <td>$($action.Finding)</td>
                <td>$($action.Status)</td>
                <td>$($action.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
            </tr>
"@
        }
        
        $html += @"
        </table>
    </div>
"@
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-SecurityLog "Security report generated: $ReportPath" "SUCCESS" "REPORT"
}

# Main execution
function Start-SecurityAudit {
    Write-SecurityLog "Starting Windows 11 Security Audit" "INFO" "AUDIT"
    Write-SecurityLog "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "INFO" "AUDIT"
    Write-SecurityLog "Severity Level: $SeverityLevel | WhatIf: $($WhatIf.IsPresent) | Remediate: $($Remediate.IsPresent)" "INFO" "AUDIT"
    
    # Execute security checks
    Test-AntivirusStatus
    Test-WindowsUpdateSecurity
    Test-UACConfiguration
    Test-FirewallSecurity
    Test-PasswordPolicy
    Test-NetworkSecurity
    Test-RegistrySecurity
    Test-ServiceSecurity
    
    # Filter findings by severity level
    if ($SeverityLevel -ne "All") {
        $severityOrder = @{ "Critical" = 4; "High" = 3; "Medium" = 2; "Low" = 1 }
        $minSeverity = $severityOrder[$SeverityLevel]
        $script:SecurityFindings = $script:SecurityFindings | Where-Object { 
            $severityOrder[$_.Severity] -ge $minSeverity 
        }
    }
    
    # Execute remediation if requested
    if ($Remediate -or $WhatIf) {
        Invoke-SecurityRemediation
    }
    
    # Generate report
    Generate-SecurityReport
    
    # Summary
    Write-SecurityLog "Security audit completed" "SUCCESS" "AUDIT"
    Write-SecurityLog "Total findings: $($script:SecurityFindings.Count)" "INFO" "AUDIT"
    Write-SecurityLog "Report saved to: $ReportPath" "INFO" "AUDIT"
    
    # Return results for Nexthink
    $output = @{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        Success = $true
        TotalFindings = $script:SecurityFindings.Count
        CriticalFindings = ($script:SecurityFindings | Where-Object Severity -eq "Critical").Count
        HighFindings = ($script:SecurityFindings | Where-Object Severity -eq "High").Count
        MediumFindings = ($script:SecurityFindings | Where-Object Severity -eq "Medium").Count
        LowFindings = ($script:SecurityFindings | Where-Object Severity -eq "Low").Count
        RemediationActions = $script:RemediationActions.Count
        ReportPath = $ReportPath
        LogPath = $LogPath
    } | ConvertTo-Json -Compress
    
    Write-Host "NEXTHINK_OUTPUT: $output"
    
    # Exit code based on critical findings
    $criticalCount = ($script:SecurityFindings | Where-Object Severity -eq "Critical").Count
    if ($criticalCount -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-SecurityAudit
    }
    catch {
        Write-SecurityLog "Critical error during security audit: $($_.Exception.Message)" "ERROR" "AUDIT"
        
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
