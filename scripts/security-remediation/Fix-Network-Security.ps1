# Fix-Network-Security.ps1
# Auto-remediation script to address network security issues
# Addresses: Risky ports open, wireless file sharing enabled

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string[]]$AllowedPorts = @(),
    [string]$LogPath = "$env:TEMP\Network-Security-Remediation.log"
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

function Get-RiskyOpenPorts {
    try {
        # List of commonly risky ports that shouldn't be publicly accessible
        $riskyPorts = @{
            135 = "RPC Endpoint Mapper"
            139 = "NetBIOS Session Service"
            445 = "SMB/CIFS"
            1433 = "SQL Server"
            1521 = "Oracle Database"
            2049 = "NFS"
            3389 = "Remote Desktop"
            5985 = "WinRM HTTP"
            5986 = "WinRM HTTPS"
            5432 = "PostgreSQL"
            3306 = "MySQL"
        }
        
        $openPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } |
                    Select-Object LocalPort, LocalAddress -Unique |
                    Sort-Object LocalPort
        
        $riskyOpenPorts = @()
        foreach ($connection in $openPorts) {
            $port = $connection.LocalPort
            if ($riskyPorts.ContainsKey($port) -and $port -notin $AllowedPorts) {
                $riskyOpenPorts += @{
                    Port = $port
                    Service = $riskyPorts[$port]
                    LocalAddress = $connection.LocalAddress
                    Risk = "High"
                }
            }
        }
        
        return $riskyOpenPorts
    }
    catch {
        Write-Log "Error checking open ports: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-NetworkSharing {
    try {
        $sharingConfig = @{}
        
        # Check network adapters and their sharing settings
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        foreach ($adapter in $adapters) {
            try {
                $profile = Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($profile) {
                    $isWireless = $adapter.PhysicalMediaType -match "802.11|Native 802.11|Wireless"
                    
                    # Check if file and printer sharing is enabled
                    $firewallRules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -ErrorAction SilentlyContinue |
                                   Where-Object { $_.Profile -match $profile.NetworkCategory }
                    
                    $sharingConfig[$adapter.Name] = @{
                        InterfaceIndex = $adapter.InterfaceIndex
                        NetworkCategory = $profile.NetworkCategory
                        IsWireless = $isWireless
                        FileSharingEnabled = $firewallRules.Count -gt 0
                        AdapterType = $adapter.PhysicalMediaType
                    }
                }
            }
            catch {
                Write-Log "Error checking adapter $($adapter.Name): $($_.Exception.Message)" "WARNING"
            }
        }
        
        return $sharingConfig
    }
    catch {
        Write-Log "Error checking network sharing configuration: $($_.Exception.Message)" "ERROR"
        return @{}
    }
}

function Get-WindowsServices {
    try {
        # Check for unnecessary/risky services that might be running
        $riskyServices = @{
            "Telnet" = "Insecure remote access"
            "FTP Publishing Service" = "Unencrypted file transfer"
            "Simple TCP/IP Services" = "Legacy network services"
            "Print Spooler" = "PrintNightmare vulnerability vector"
            "Remote Registry" = "Remote registry access"
            "Routing and Remote Access" = "VPN/routing service"
        }
        
        $runningRiskyServices = @()
        foreach ($serviceName in $riskyServices.Keys) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                $runningRiskyServices += @{
                    Name = $serviceName
                    DisplayName = $service.DisplayName
                    Risk = $riskyServices[$serviceName]
                    Status = $service.Status
                }
            }
        }
        
        return $runningRiskyServices
    }
    catch {
        Write-Log "Error checking Windows services: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Test-NetworkSecurity {
    Write-Log "Analyzing network security configuration..."
    
    $issues = @()
    
    # Check for risky open ports
    $riskyPorts = Get-RiskyOpenPorts
    foreach ($portInfo in $riskyPorts) {
        $issues += @{
            Category = "Network Ports"
            Issue = "Risky Port Open"
            Severity = "High"
            Description = "Port $($portInfo.Port) ($($portInfo.Service)) is listening on all interfaces"
            Port = $portInfo.Port
            Service = $portInfo.Service
            Recommendation = "Review if port $($portInfo.Port) needs to be publicly accessible"
        }
    }
    
    # Check network sharing on wireless connections
    $networkSharing = Get-NetworkSharing
    foreach ($adapterName in $networkSharing.Keys) {
        $config = $networkSharing[$adapterName]
        if ($config.IsWireless -and $config.FileSharingEnabled) {
            $issues += @{
                Category = "Network Sharing"
                Issue = "File Sharing on Wireless"
                Severity = "Medium"
                Description = "File and printer sharing is enabled on wireless adapter '$adapterName'"
                Adapter = $adapterName
                NetworkCategory = $config.NetworkCategory
                Recommendation = "Disable file sharing on wireless connections"
            }
        }
    }
    
    # Check for risky running services
    $riskyServices = Get-WindowsServices
    foreach ($service in $riskyServices) {
        $issues += @{
            Category = "Windows Services"
            Issue = "Risky Service Running"
            Severity = "Medium"
            Description = "Potentially risky service '$($service.DisplayName)' is running"
            ServiceName = $service.Name
            Risk = $service.Risk
            Recommendation = "Review if service '$($service.DisplayName)' is necessary"
        }
    }
    
    return $issues
}

function Set-NetworkSecureConfiguration {
    param(
        [switch]$WhatIf
    )
    
    Write-Log "Starting network security analysis..."
    
    $issues = Test-NetworkSecurity
    
    if ($issues.Count -eq 0) {
        Write-Log "Network security is already properly configured"
        return @{ 
            Success = $true
            Message = "Network security already properly configured"
            ChangesNeeded = $false
        }
    }
    
    Write-Log "Network security issues found:"
    foreach ($issue in $issues) {
        Write-Log "  [$($issue.Severity)] $($issue.Category) - $($issue.Issue)"
        Write-Log "    Description: $($issue.Description)"
        Write-Log "    Recommendation: $($issue.Recommendation)"
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would apply network security configuration changes"
        return @{
            Success = $true
            Message = "WhatIf operation completed"
            ChangesNeeded = $true
            Issues = $issues
        }
    }
    
    try {
        $changesApplied = @()
        $skippedChanges = @()
        
        foreach ($issue in $issues) {
            switch ($issue.Category) {
                "Network Ports" {
                    # For risky ports, we'll create firewall rules to block external access
                    # but allow local network access if needed
                    if (-not $Force) {
                        Write-Log "Skipping port $($issue.Port) remediation - use -Force to apply firewall rules" "WARNING"
                        $skippedChanges += "Port $($issue.Port) firewall rule creation (requires -Force)"
                    } else {
                        try {
                            $ruleName = "Block-Port-$($issue.Port)-External"
                            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                            
                            if (-not $existingRule) {
                                Write-Log "Creating firewall rule to block external access to port $($issue.Port)..."
                                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $issue.Port -Action Block -RemoteAddress "Internet" -Profile Public
                                $changesApplied += "Created firewall rule to block external access to port $($issue.Port)"
                            } else {
                                Write-Log "Firewall rule for port $($issue.Port) already exists"
                            }
                        }
                        catch {
                            Write-Log "Error creating firewall rule for port $($issue.Port): $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
                
                "Network Sharing" {
                    # Disable file sharing on wireless networks
                    try {
                        $adapterName = $issue.Adapter
                        Write-Log "Disabling file sharing on wireless adapter '$adapterName'..."
                        
                        # Disable File and Printer Sharing rules for this network category
                        $rules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Where-Object { $_.Profile -match $issue.NetworkCategory }
                        foreach ($rule in $rules) {
                            if ($rule.Enabled -eq $true) {
                                Disable-NetFirewallRule -DisplayName $rule.DisplayName
                            }
                        }
                        
                        $changesApplied += "Disabled file sharing on wireless adapter '$adapterName'"
                    }
                    catch {
                        Write-Log "Error disabling file sharing on adapter '$($issue.Adapter)': $($_.Exception.Message)" "ERROR"
                    }
                }
                
                "Windows Services" {
                    # Stop and disable risky services
                    if (-not $Force) {
                        Write-Log "Skipping service '$($issue.ServiceName)' remediation - use -Force to stop services" "WARNING"
                        $skippedChanges += "Stop service '$($issue.ServiceName)' (requires -Force)"
                    } else {
                        try {
                            $serviceName = $issue.ServiceName
                            Write-Log "Stopping and disabling risky service '$serviceName'..."
                            
                            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                            if ($service -and $service.Status -eq "Running") {
                                Stop-Service -Name $serviceName -Force
                                Set-Service -Name $serviceName -StartupType Disabled
                                $changesApplied += "Stopped and disabled service '$serviceName'"
                            }
                        }
                        catch {
                            Write-Log "Error stopping service '$($issue.ServiceName)': $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
            }
        }
        
        Write-Log "Network security remediation completed"
        
        if ($changesApplied.Count -gt 0) {
            Write-Log "Applied changes:"
            foreach ($change in $changesApplied) {
                Write-Log "  - $change"
            }
        }
        
        if ($skippedChanges.Count -gt 0) {
            Write-Log "Skipped changes (use -Force to apply):"
            foreach ($change in $skippedChanges) {
                Write-Log "  - $change"
            }
        }
        
        # Re-check for remaining issues
        $remainingIssues = Test-NetworkSecurity
        $resolvedCount = $issues.Count - $remainingIssues.Count
        
        return @{
            Success = $true
            Message = "Network security remediation completed ($resolvedCount/$($issues.Count) issues resolved)"
            ChangesApplied = $changesApplied
            SkippedChanges = $skippedChanges
            RemainingIssues = $remainingIssues
            ResolvedCount = $resolvedCount
            TotalIssues = $issues.Count
        }
    }
    catch {
        Write-Log "Error during network security remediation: $($_.Exception.Message)" "ERROR"
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
        Write-Log "Administrator privileges required for network security remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting network security remediation"
    if ($AllowedPorts.Count -gt 0) {
        Write-Log "Allowed ports: $($AllowedPorts -join ', ')"
    }
    
    try {
        $result = Set-NetworkSecureConfiguration -WhatIf:$WhatIf
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            Message = $result.Message
            ChangesNeeded = $result.ChangesNeeded
            AllowedPorts = $AllowedPorts
            Force = $Force.IsPresent
            WhatIf = $WhatIf.IsPresent
            LogPath = $LogPath
        }
        
        if ($result.Issues) {
            $output.Issues = $result.Issues
        }
        
        if ($result.ChangesApplied) {
            $output.ChangesApplied = $result.ChangesApplied
        }
        
        if ($result.SkippedChanges) {
            $output.SkippedChanges = $result.SkippedChanges
        }
        
        if ($result.RemainingIssues) {
            $output.RemainingIssues = $result.RemainingIssues
        }
        
        if ($result.ResolvedCount -and $result.TotalIssues) {
            $output.ResolvedCount = $result.ResolvedCount
            $output.TotalIssues = $result.TotalIssues
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
