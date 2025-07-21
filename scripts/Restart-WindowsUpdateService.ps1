# Restart-WindowsUpdateService.ps1
# Sample remediation script to restart Windows Update service
# This script demonstrates auto-remediation concepts for Nexthink v6

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [string]$LogPath = "$env:TEMP\WindowsUpdateRemediation.log"
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

function Test-ServiceExists {
    param([string]$ServiceName)
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-ServiceStatus {
    param([string]$ServiceName)
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return $service.Status
    }
    catch {
        return "NotFound"
    }
}

function Restart-WindowsUpdateService {
    [CmdletBinding()]
    param(
        [switch]$WhatIf,
        [switch]$Force
    )
    
    $serviceName = "wuauserv"
    $dependentServices = @("BITS", "CryptSvc")
    
    Write-Log "Starting Windows Update service remediation"
    
    # Check if service exists
    if (-not (Test-ServiceExists -ServiceName $serviceName)) {
        Write-Log "Windows Update service not found" "ERROR"
        return @{
            Success = $false
            Message = "Service not found"
            ServiceStatus = "NotFound"
        }
    }
    
    $initialStatus = Get-ServiceStatus -ServiceName $serviceName
    Write-Log "Initial service status: $initialStatus"
    
    # If service is already running and not forced, return success
    if ($initialStatus -eq "Running" -and -not $Force) {
        Write-Log "Service is already running"
        return @{
            Success = $true
            Message = "Service already running"
            ServiceStatus = $initialStatus
        }
    }
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would restart Windows Update service" "INFO"
        return @{
            Success = $true
            Message = "WhatIf operation completed"
            ServiceStatus = $initialStatus
        }
    }
    
    try {
        # Stop dependent services first if needed
        foreach ($depService in $dependentServices) {
            if (Test-ServiceExists -ServiceName $depService) {
                $depStatus = Get-ServiceStatus -ServiceName $depService
                if ($depStatus -eq "Running") {
                    Write-Log "Stopping dependent service: $depService"
                    Stop-Service -Name $depService -Force -ErrorAction Stop
                }
            }
        }
        
        # Stop and start the main service
        Write-Log "Stopping Windows Update service"
        Stop-Service -Name $serviceName -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        Write-Log "Starting Windows Update service"
        Start-Service -Name $serviceName -ErrorAction Stop
        
        # Restart dependent services
        foreach ($depService in $dependentServices) {
            if (Test-ServiceExists -ServiceName $depService) {
                Write-Log "Starting dependent service: $depService"
                Start-Service -Name $depService -ErrorAction SilentlyContinue
            }
        }
        
        # Verify service is running
        Start-Sleep -Seconds 3
        $finalStatus = Get-ServiceStatus -ServiceName $serviceName
        
        if ($finalStatus -eq "Running") {
            Write-Log "Windows Update service restarted successfully"
            return @{
                Success = $true
                Message = "Service restarted successfully"
                ServiceStatus = $finalStatus
            }
        } else {
            Write-Log "Service restart failed - final status: $finalStatus" "ERROR"
            return @{
                Success = $false
                Message = "Service restart failed"
                ServiceStatus = $finalStatus
            }
        }
    }
    catch {
        Write-Log "Error during service restart: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Message = $_.Exception.Message
            ServiceStatus = (Get-ServiceStatus -ServiceName $serviceName)
        }
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    $result = Restart-WindowsUpdateService -WhatIf:$WhatIf -Force:$Force
    
    # Output for Nexthink (JSON format)
    $output = @{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        Success = $result.Success
        Message = $result.Message
        ServiceStatus = $result.ServiceStatus
        LogPath = $LogPath
    } | ConvertTo-Json -Compress
    
    Write-Host "NEXTHINK_OUTPUT: $output"
    
    if ($result.Success) {
        exit 0
    } else {
        exit 1
    }
}
