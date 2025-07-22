
# Auto-Remediation-Master.ps1
# Master script to orchestrate all security remediations
# Addresses all identified security issues in coordinated manner

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,
    [ValidateSet("UAC", "Firewall", "WindowsUpdate", "SMB", "Network", "All")]
    [string[]]$Categories,
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$MinimumSeverity,
    [string]$LogPath,
    [string]$ReportPath,
    [switch]$GenerateReport
)

# Set default values for parameters if not provided
if (-not $Categories) { $Categories = @("All") }
if (-not $MinimumSeverity) { $MinimumSeverity = "Medium" }
if (-not $LogPath) { $LogPath = "$env:TEMP\Auto-Remediation-Master.log" }
if (-not $ReportPath) { $ReportPath = "$env:TEMP\Security-Remediation-Report.html" }

# Import required functions
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Gather system performance and service info for audit/remediation
function Get-SystemPerformanceAndServiceInfo {
    $info = @{}
    # Basic system info
    $info.ComputerName = $env:COMPUTERNAME
    $info.UserName = $env:USERNAME
    $info.OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
    $info.CPU = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)
    $info.TotalRAMGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $info.FreeRAMGB = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
    $info.CPUUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
    $info.DiskFreeGB = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Measure-Object -Property FreeSpace -Sum).Sum / 1GB
    $info.DiskTotalGB = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Measure-Object -Property Size -Sum).Sum / 1GB
    # Critical services to audit (example: can be customized)
    $criticalServices = @('wuauserv','WinDefend','BITS','LanmanServer','LanmanWorkstation','TermService','Spooler')
    $info.Services = Get-Service | Where-Object { $_.Name -in $criticalServices } | Select-Object Name,DisplayName,Status,StartType
    # Add thresholds for anomaly detection
    $info.Thresholds = @{
        CPUUsage = 85
        FreeRAMGB = 1
        DiskFreeGB = 5
        ServiceStatus = 'Running'
        ServiceStartType = 'Automatic'
    }
    return $info
}

# Detect anomalies in system performance and services
function Test-SystemAnomalies {
    param($SystemInfo)
    $anomalies = @()
    # CPU usage anomaly
    if ($SystemInfo.CPUUsage -gt $SystemInfo.Thresholds.CPUUsage) {
        $anomalies += "High CPU usage detected: $($SystemInfo.CPUUsage)%"
    }
    # Free RAM anomaly
    if ($SystemInfo.FreeRAMGB -lt $SystemInfo.Thresholds.FreeRAMGB) {
        $anomalies += "Low free RAM: $($SystemInfo.FreeRAMGB) GB"
    }
    # Disk space anomaly
    if ($SystemInfo.DiskFreeGB -lt $SystemInfo.Thresholds.DiskFreeGB) {
        $anomalies += "Low disk space: $([math]::Round($SystemInfo.DiskFreeGB,2)) GB free"
    }
    # Service anomalies
    foreach ($svc in $SystemInfo.Services) {
        if ($svc.Status -ne $SystemInfo.Thresholds.ServiceStatus -or $svc.StartType -ne $SystemInfo.Thresholds.ServiceStartType) {
            $anomalies += "Service anomaly: $($svc.Name) is $($svc.Status)/$($svc.StartType) (expected: $($SystemInfo.Thresholds.ServiceStatus)/$($SystemInfo.Thresholds.ServiceStartType))"
        }
    }
    return $anomalies
}

# Try to remediate detected anomalies
function Repair-SystemAnomalies {
    param($SystemInfo, $Anomalies)
    $remediationResults = @()
    foreach ($anomaly in $Anomalies) {
        if ($anomaly -like "High CPU usage*") {
            # Try to find top CPU process and log it
            $topProc = Get-Process | Sort-Object CPU -Descending | Select-Object -First 1
            $remediationResults += "High CPU: Top process is $($topProc.ProcessName) ($([math]::Round($topProc.CPU,1)) CPU sec)"
        } elseif ($anomaly -like "Low free RAM*") {
            # Try to clear standby memory (Windows 10/11)
            $remediationResults += "Low RAM: Recommend closing unused applications. Manual remediation required."
        } elseif ($anomaly -like "Low disk space*") {
            # Try to clean temp files
            $temp = $env:TEMP
            try {
                Remove-Item "$temp\*" -Recurse -Force -ErrorAction SilentlyContinue
                $remediationResults += "Disk cleanup: Temp files deleted from $temp."
            } catch {
                $remediationResults += "Disk cleanup: Failed to delete temp files."
            }
        } elseif ($anomaly -like "Service anomaly:*") {
            $svcName = ($anomaly -split ": ")[1] -split " " | Select-Object -First 1
            try {
                Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $svcName -ErrorAction SilentlyContinue
                $remediationResults += "Service $svcName set to Automatic and started."
            } catch {
                $remediationResults += "Service $svcName remediation failed."
            }
        } else {
            $remediationResults += "No remediation available for: $anomaly"
        }
    }
    return $remediationResults
}

# Advanced debug logging function
function Write-DebugLog {
    param(
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[DEBUG] [$timestamp] $Message"
    Write-Host $logEntry -ForegroundColor DarkGray
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [MASTER] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-SeverityWeight {
    param([string]$Severity)
    
    switch ($Severity.ToLower()) {
        "low" { return 1 }
        "medium" { return 2 }
        "high" { return 3 }
        "critical" { return 4 }
        default { return 2 }
    }
}

function Test-SeverityThreshold {
    param(
        [string]$IssueSeverity,
        [string]$MinimumSeverity
    )
    
    $issueWeight = Get-SeverityWeight -Severity $IssueSeverity
    $minimumWeight = Get-SeverityWeight -Severity $MinimumSeverity
    
    return $issueWeight -ge $minimumWeight
}

function Invoke-RemediationScript {
    param(
        [string]$ScriptPath,
        [string]$Category,
        [hashtable]$Parameters = @{},
        [switch]$WhatIf
    )
    
    $result = @{
        Category = $Category
        ScriptPath = $ScriptPath
        Success = $false
        Message = ""
        Issues = @()
        ChangesApplied = @()
        ExecutionTime = 0
        Error = $null
    }
    
    if (-not (Test-Path $ScriptPath)) {
        $result.Error = "Script not found: $ScriptPath"
        $result.Message = "Script file not found"
        return $result
    }
    
    try {
        Write-Log "Executing $Category remediation script..."
        Write-DebugLog "ScriptPath: $ScriptPath"
        Write-DebugLog "Parameters: $($Parameters | Out-String)"
        Write-DebugLog "WhatIf: $WhatIf"
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Build parameter string
        $paramString = ""
        foreach ($key in $Parameters.Keys) {
            $value = $Parameters[$key]
            if ($value -is [switch] -and $value) {
                $paramString += " -$key"
            } elseif ($value -is [array]) {
                $paramString += " -$key @('$($value -join "','")')"
            } else {
                $paramString += " -$key '$value'"
            }
        }

        if ($WhatIf) {
            $paramString += " -WhatIf"
        }

        Write-DebugLog "Full command: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'call $ScriptPath $paramString'"

        # Execute the script
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$ScriptPath' $paramString"
        Write-DebugLog "Script output: $($output | Out-String)"
        Write-DebugLog "LASTEXITCODE: $LASTEXITCODE"

        $stopwatch.Stop()
        $result.ExecutionTime = $stopwatch.ElapsedMilliseconds

        # Parse Nexthink output
        $nexthinkOutput = $output | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
        if ($nexthinkOutput) {
            $jsonData = ($nexthinkOutput -split "NEXTHINK_OUTPUT: ")[1]
            $parsedResult = $jsonData | ConvertFrom-Json

            $result.Success = $parsedResult.Success
            $result.Message = $parsedResult.Message

            if ($parsedResult.Issues) {
                $result.Issues = $parsedResult.Issues
            }

            if ($parsedResult.ChangesApplied) {
                $result.ChangesApplied = $parsedResult.ChangesApplied
            }
        } else {
            # Fallback: check exit code
            if ($LASTEXITCODE -eq 0) {
                $result.Success = $true
                $result.Message = "Script executed successfully"
            } else {
                $result.Success = $false
                $result.Message = "Script execution failed"
            }
        }

        Write-Log "$Category remediation completed in $($result.ExecutionTime)ms - Success: $($result.Success)"
        Write-DebugLog "Remediation result: $($result | Out-String)"

    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Message = "Script execution failed with error"
        Write-Log "$Category remediation failed: $($_.Exception.Message)" "ERROR"
        Write-DebugLog "Exception: $($_.Exception | Out-String)"
    }

    return $result
# Test case function for validation
function Test-AutoRemediationMaster {
    Write-Host "Running test case: Test-AutoRemediationMaster" -ForegroundColor Cyan
    $testCategories = @("UAC")
    $testResult = $null
    try {
        $testResult = Start-SecurityRemediation -Categories $testCategories -MinimumSeverity "Medium" -WhatIf
        if ($testResult.OverallSuccess) {
            Write-Host "Test case PASSED: UAC remediation in WhatIf mode succeeded." -ForegroundColor Green
        } else {
            Write-Host "Test case FAILED: UAC remediation in WhatIf mode did not succeed." -ForegroundColor Red
        }
        Write-Host ("Test result: " + ($testResult | Out-String)) -ForegroundColor Gray
    } catch {
        Write-Host "Test case ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    return $testResult
}
}

function Start-SecurityRemediation {
    param(
        [string[]]$Categories,
        [string]$MinimumSeverity,
        [switch]$WhatIf
    )
    
    $remediationResults = @()
    $overallSuccess = $true
    
    # Define remediation scripts and their configurations
    $remediationScripts = @{
        "UAC" = @{
            Script = Join-Path $scriptDir "Fix-UAC-Settings.ps1"
            Description = "User Account Control Configuration"
            Parameters = @{}
            Priority = 1
        }
        "Firewall" = @{
            Script = Join-Path $scriptDir "Fix-Firewall-Settings.ps1"
            Description = "Windows Firewall Security"
            Parameters = @{ Profile = "All" }
            Priority = 2
        }
        "WindowsUpdate" = @{
            Script = Join-Path $scriptDir "Fix-Windows-Updates.ps1"
            Description = "Windows Update Configuration"
            Parameters = @{ UpdateMode = "Automatic"; AutoInstallHour = 3 }
            Priority = 3
        }
        "SMB" = @{
            Script = Join-Path $scriptDir "Fix-SMB-Registry-Settings.ps1"
            Description = "SMB Security Registry Settings"
            Parameters = @{}
            Priority = 4
        }
        "Network" = @{
            Script = Join-Path $scriptDir "Fix-Network-Security.ps1"
            Description = "Network Security Configuration"
            Parameters = @{ AllowedPorts = @() }
            Priority = 5
        }
    }
    
    # Determine which categories to run
    $categoriesToRun = if ($Categories -contains "All") {
        $remediationScripts.Keys
    } else {
        $Categories | Where-Object { $remediationScripts.ContainsKey($_) }
    }
    
    Write-Log "Starting security remediation for categories: $($categoriesToRun -join ', ')"
    Write-Log "Minimum severity: $MinimumSeverity"
    Write-Log "WhatIf mode: $($WhatIf.IsPresent)"
    
    # Sort by priority and execute
    $sortedCategories = $categoriesToRun | Sort-Object { $remediationScripts[$_].Priority }
    
    foreach ($category in $sortedCategories) {
        $config = $remediationScripts[$category]
        Write-Log "Processing $category - $($config.Description)"
        
        $result = Invoke-RemediationScript -ScriptPath $config.Script -Category $category -Parameters $config.Parameters -WhatIf:$WhatIf
        $remediationResults += $result
        
        if (-not $result.Success) {
            $overallSuccess = $false
            Write-Log "$category remediation failed: $($result.Message)" "ERROR"
            if ($result.Error) {
                Write-Log "Error details: $($result.Error)" "ERROR"
            }
        } else {
            Write-Log "$category remediation successful: $($result.Message)"
            if ($result.ChangesApplied -and $result.ChangesApplied.Count -gt 0) {
            Write-Log "Changes applied in ${category}:"
                foreach ($change in $result.ChangesApplied) {
                    Write-Log "  - $change"
                }
            }
        }
    }
    
    # Only include objects with ExecutionTime property for total time calculation
    $timedResults = $remediationResults | Where-Object { $_.PSObject.Properties["ExecutionTime"] -and ($_.ExecutionTime -is [int]) }
    return @{
        OverallSuccess = $overallSuccess
        Results = $remediationResults
        CategoriesProcessed = $sortedCategories
        TotalExecutionTime = ($timedResults | Measure-Object ExecutionTime -Sum).Sum
    }
}

function New-RemediationReport {
    param(
        [object]$RemediationResults,
        [string]$ReportPath
    )
    
    try {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Remediation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .success { color: #27ae60; font-weight: bold; }
        .error { color: #e74c3c; font-weight: bold; }
        .category { margin: 20px 0; padding: 15px; border: 1px solid #bdc3c7; border-radius: 5px; }
        .changes { background-color: #d5dbdb; padding: 10px; margin: 10px 0; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Remediation Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Computer: $env:COMPUTERNAME | User: $env:USERNAME</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Overall Status:</strong> <span class="$(if ($RemediationResults.OverallSuccess) { 'success' } else { 'error' })">$(if ($RemediationResults.OverallSuccess) { 'SUCCESS' } else { 'FAILED' })</span></p>
        <p><strong>Categories Processed:</strong> $($RemediationResults.CategoriesProcessed.Count)</p>
        <p><strong>Total Execution Time:</strong> $($RemediationResults.TotalExecutionTime) ms</p>
        <p><strong>WhatIf Mode:</strong> $($WhatIf.IsPresent)</p>
    </div>
    
    <h2>Remediation Details</h2>
"@
        
        foreach ($result in $RemediationResults.Results) {
            $statusClass = if ($result.Success) { "success" } else { "error" }
            $statusText = if ($result.Success) { "SUCCESS" } else { "FAILED" }
            
            $html += @"
    <div class="category">
        <h3>$($result.Category) - $(Split-Path $result.ScriptPath -Leaf)</h3>
        <p><strong>Status:</strong> <span class="$statusClass">$statusText</span></p>
        <p><strong>Message:</strong> $($result.Message)</p>
        <p><strong>Execution Time:</strong> $($result.ExecutionTime) ms</p>
        
"@
            
            if ($result.Error) {
                $html += "<p><strong>Error:</strong> <span class='error'>$($result.Error)</span></p>`n"
            }
            
            if ($result.ChangesApplied -and $result.ChangesApplied.Count -gt 0) {
                $html += "<div class='changes'><strong>Changes Applied:</strong><ul>`n"
                foreach ($change in $result.ChangesApplied) {
                    $html += "<li>$change</li>`n"
                }
                $html += "</ul></div>`n"
            }
            
            if ($result.Issues -and $result.Issues.Count -gt 0) {
                $html += "<h4>Issues Found:</h4><table><tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr>`n"
                foreach ($issue in $result.Issues) {
                    $html += "<tr><td>$($issue.Severity)</td><td>$($issue.Issue)</td><td>$($issue.Recommendation)</td></tr>`n"
                }
                $html += "</table>`n"
            }
            
            $html += "</div>`n"
        }
        
        $html += @"
    
    <div class="summary">
        <h2>Recommendations</h2>
        <ul>
            <li>Review all applied changes before restarting the system</li>
            <li>Test applications after remediation to ensure compatibility</li>
            <li>Schedule regular security audits to maintain compliance</li>
            <li>Keep this report for audit and compliance purposes</li>
        </ul>
    </div>
</body>
</html>
"@
        
        $html | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Log "Security remediation report generated: $ReportPath"
        
        return $true
    }
    catch {
        Write-Log "Error generating report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin -and -not $WhatIf) {
        Write-Log "Administrator privileges required for security remediation" "ERROR"
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Message = "Administrator privileges required"
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 1
    }
    
    Write-Log "Starting Auto-Remediation Master Process"
    Write-Log "Categories: $($Categories -join ', ')"
    Write-Log "Minimum Severity: $MinimumSeverity"
    Write-Log "WhatIf Mode: $($WhatIf.IsPresent)"
    Write-Log "Force Mode: $($Force.IsPresent)"
    
    try {
        $masterResult = Start-SecurityRemediation -Categories $Categories -MinimumSeverity $MinimumSeverity -WhatIf:$WhatIf

        # Gather and log system/service context for audit/remediation
        $systemInfo = Get-SystemPerformanceAndServiceInfo
        Write-Log "System Context: Computer=$($systemInfo.ComputerName), User=$($systemInfo.UserName), OS=$($systemInfo.OSVersion), CPU=$($systemInfo.CPU), RAM=$($systemInfo.TotalRAMGB)GB, FreeRAM=$($systemInfo.FreeRAMGB)GB, CPU%=$([math]::Round($systemInfo.CPUUsage,1)), DiskFree=$([math]::Round($systemInfo.DiskFreeGB,1))GB/$([math]::Round($systemInfo.DiskTotalGB,1))GB"
        Write-Log "Critical Services State: $(($systemInfo.Services | ForEach-Object { "$($_.Name)=$($_.Status)/$($_.StartType)" }) -join ', ')"

        # Detect anomalies
        $anomalies = Test-SystemAnomalies $systemInfo
        if ($anomalies.Count -gt 0) {
            Write-Log "Anomalies detected: $($anomalies -join '; ')" "ERROR"
            # Try remediation
            $remediationActions = Repair-SystemAnomalies $systemInfo $anomalies
            Write-Log "Remediation actions: $($remediationActions -join '; ')"
        } else {
            Write-Log "No system/service anomalies detected."
        }
        
        # Generate report if requested
        $reportGenerated = $false
        if ($GenerateReport) {
            $reportGenerated = New-RemediationReport -RemediationResults $masterResult -ReportPath $ReportPath
        }
        
        # Summary
        $successCount = ($masterResult.Results | Where-Object { $_.Success }).Count
        $totalCount = $masterResult.Results.Count
        $totalChanges = ($masterResult.Results | ForEach-Object { $_.ChangesApplied } | Measure-Object).Count
        
        Write-Log "Auto-Remediation Master Process completed"
        Write-Log "Results: $successCount/$totalCount categories successful"
        Write-Log "Total changes applied: $totalChanges"
        Write-Log "Total execution time: $($masterResult.TotalExecutionTime) ms"
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $masterResult.OverallSuccess
            Message = "Auto-remediation completed: $successCount/$totalCount categories successful"
            Categories = $Categories
            MinimumSeverity = $MinimumSeverity
            SuccessCount = $successCount
            TotalCount = $totalCount
            TotalChanges = $totalChanges
            TotalExecutionTime = $masterResult.TotalExecutionTime
            ReportGenerated = $reportGenerated
            ReportPath = if ($reportGenerated) { $ReportPath } else { $null }
            WhatIf = $WhatIf.IsPresent
            LogPath = $LogPath
            Results = $masterResult.Results | ForEach-Object {
                @{
                    Category = $_.Category
                    Success = $_.Success
                    Message = $_.Message
                    ExecutionTime = $_.ExecutionTime
                    ChangesCount = if ($_.ChangesApplied) { $_.ChangesApplied.Count } else { 0 }
                }
            }
        }
        
        $jsonOutput = $output | ConvertTo-Json -Compress
        Write-Host "NEXTHINK_OUTPUT: $jsonOutput"
        
        # Print a simple summary table to the console
        Write-Host "\nSystem/Performance Context:" -ForegroundColor Yellow
        $sysTable = [PSCustomObject]@{
            Computer = $systemInfo.ComputerName
            User = $systemInfo.UserName
            OS = $systemInfo.OSVersion
            CPU = $systemInfo.CPU
            TotalRAMGB = $systemInfo.TotalRAMGB
            FreeRAMGB = $systemInfo.FreeRAMGB
            CPUUsage = [math]::Round($systemInfo.CPUUsage,1)
            DiskFreeGB = [math]::Round($systemInfo.DiskFreeGB,1)
            DiskTotalGB = [math]::Round($systemInfo.DiskTotalGB,1)
        }
        $sysTable | Format-List | Out-String | Write-Host

        Write-Host "\nCritical Services State:" -ForegroundColor Yellow
        $systemInfo.Services | Format-Table Name,DisplayName,Status,StartType -AutoSize | Out-String | Write-Host

        # Show anomalies and remediation actions
        if ($anomalies.Count -gt 0) {
            Write-Host "\nDetected Anomalies:" -ForegroundColor Red
            $anomalies | ForEach-Object { Write-Host $_ -ForegroundColor Red }
            Write-Host "\nRemediation Actions Taken:" -ForegroundColor Green
            $remediationActions | ForEach-Object { Write-Host $_ -ForegroundColor Green }
        } else {
            Write-Host "\nNo system/service anomalies detected." -ForegroundColor Green
        }
        Write-Host "\nRemediation Summary Table:" -ForegroundColor Cyan
        $table = @()
        foreach ($r in $masterResult.Results) {
            $table += [PSCustomObject]@{
                Category = $r.Category
                Success = $r.Success
                Message = $r.Message
                ExecutionTimeMs = $r.ExecutionTime
            }
        }
        $table | Format-Table -AutoSize | Out-String | Write-Host

        if ($masterResult.OverallSuccess) {
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
        Write-Log "Critical error in Auto-Remediation Master: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}
