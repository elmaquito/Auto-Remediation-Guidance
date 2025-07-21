#Requires -Version 5.1

<#
.SYNOPSIS
    Restart Windows Update service for auto-remediation.

.DESCRIPTION
    This script attempts to restart the Windows Update service (wuauserv) when it's detected as stopped.
    Designed for use with Nexthink v6 Remote Actions for auto-remediation scenarios.

.PARAMETER Force
    Force restart the service even if it's already running.

.PARAMETER WaitTime
    Time in seconds to wait after stopping before starting the service (default: 5).

.EXAMPLE
    .\sample-remediation-script.ps1
    Restart Windows Update service if stopped.

.EXAMPLE
    .\sample-remediation-script.ps1 -Force
    Force restart Windows Update service regardless of current state.

.NOTES
    Author: Auto-Remediation Team
    Version: 1.0
    PowerShell Version: 5.1+
    
    Exit Codes:
    0 = Success
    1 = General error
    2 = Service not found
    3 = Insufficient privileges
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,60)]
    [int]$WaitTime = 5
)

# Initialize variables
$serviceName = "wuauserv"
$serviceDisplayName = "Windows Update"
$exitCode = 0

# Function to write structured output for Nexthink
function Write-RemediationOutput {
    param(
        [string]$Level,  # SUCCESS, ERROR, WARNING, INFO
        [string]$Message
    )
    Write-Output "[$Level] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-RemediationOutput -Level "ERROR" -Message "Script requires administrator privileges"
    exit 3
}

try {
    Write-RemediationOutput -Level "INFO" -Message "Starting Windows Update service remediation"
    
    # Get the service
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    Write-RemediationOutput -Level "INFO" -Message "Found service: $($service.DisplayName) - Current status: $($service.Status)"
    
    # Check current service status
    if ($service.Status -eq "Running" -and -not $Force) {
        Write-RemediationOutput -Level "SUCCESS" -Message "Windows Update service is already running. No action needed."
        exit 0
    }
    
    # Stop service if running (for forced restart or if in error state)
    if ($service.Status -eq "Running" -and $Force) {
        Write-RemediationOutput -Level "INFO" -Message "Force restart requested. Stopping service first..."
        Stop-Service -Name $serviceName -Force -ErrorAction Stop
        Write-RemediationOutput -Level "INFO" -Message "Service stopped. Waiting $WaitTime seconds..."
        Start-Sleep -Seconds $WaitTime
    }
    
    # Handle other states (Stopped, StartPending, StopPending, etc.)
    if ($service.Status -eq "StartPending") {
        Write-RemediationOutput -Level "INFO" -Message "Service is starting. Waiting for completion..."
        $service.WaitForStatus("Running", "00:01:00")
        Write-RemediationOutput -Level "SUCCESS" -Message "Windows Update service started successfully"
        exit 0
    }
    
    if ($service.Status -eq "StopPending") {
        Write-RemediationOutput -Level "INFO" -Message "Service is stopping. Waiting for completion..."
        $service.WaitForStatus("Stopped", "00:01:00")
    }
    
    # Start the service
    if ($service.Status -eq "Stopped") {
        Write-RemediationOutput -Level "INFO" -Message "Starting Windows Update service..."
        Start-Service -Name $serviceName -ErrorAction Stop
        
        # Verify service started
        $service.Refresh()
        if ($service.Status -eq "Running") {
            Write-RemediationOutput -Level "SUCCESS" -Message "Windows Update service started successfully"
            
            # Additional verification - check if service is responsive
            Start-Sleep -Seconds 2
            $service.Refresh()
            if ($service.Status -eq "Running") {
                Write-RemediationOutput -Level "SUCCESS" -Message "Service verification completed - Windows Update is healthy"
                exit 0
            } else {
                Write-RemediationOutput -Level "WARNING" -Message "Service started but may not be stable. Status: $($service.Status)"
                exit 1
            }
        } else {
            Write-RemediationOutput -Level "ERROR" -Message "Failed to start Windows Update service. Current status: $($service.Status)"
            exit 1
        }
    }
    
    # Handle unexpected states
    Write-RemediationOutput -Level "WARNING" -Message "Service in unexpected state: $($service.Status). Attempting to start anyway..."
    Start-Service -Name $serviceName -ErrorAction Stop
    Write-RemediationOutput -Level "SUCCESS" -Message "Windows Update service remediation completed"
    
} catch [System.ServiceProcess.ServiceNotFoundException] {
    Write-RemediationOutput -Level "ERROR" -Message "Windows Update service not found on this system"
    exit 2
} catch [System.TimeoutException] {
    Write-RemediationOutput -Level "ERROR" -Message "Timeout waiting for service to change state"
    exit 1
} catch [System.UnauthorizedAccessException] {
    Write-RemediationOutput -Level "ERROR" -Message "Access denied. Ensure script is running with administrator privileges"
    exit 3
} catch {
    Write-RemediationOutput -Level "ERROR" -Message "Unexpected error: $($_.Exception.Message)"
    Write-RemediationOutput -Level "ERROR" -Message "Error details: $($_.Exception.GetType().FullName)"
    exit 1
} finally {
    Write-RemediationOutput -Level "INFO" -Message "Remediation script completed with exit code: $exitCode"
}