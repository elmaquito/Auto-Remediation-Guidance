# Security-Test-Runner.ps1
# Comprehensive test runner for all security scripts
# Runs coordinated security assessments and generates consolidated reports

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$AutoRemediate,
    [switch]$FullScan,
    [switch]$QuickScan,
    [string]$OutputPath = "$env:TEMP\SecurityAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$LogPath = "$env:TEMP\SecurityTestRunner.log",
    [ValidateSet("Critical", "High", "Medium", "Low", "All")]
    [string]$MinimumSeverity = "Medium"
)

# Initialize logging
function Write-SecurityTestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "RUNNER"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] [$Category] $Message"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "CRITICAL" { "Magenta" }
        default { "Cyan" }
    }
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

# Test results storage
$script:TestResults = @()
$script:ConsolidatedFindings = @()

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [int]$ExitCode,
        [string]$OutputPath = "",
        [timespan]$Duration,
        [hashtable]$Metrics = @{},
        [string]$ErrorMessage = ""
    )
    
    $result = [PSCustomObject]@{
        TestName = $TestName
        Status = $Status
        ExitCode = $ExitCode
        OutputPath = $OutputPath
        Duration = $Duration
        Metrics = $Metrics
        ErrorMessage = $ErrorMessage
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    Write-SecurityTestLog "Test completed: $TestName - Status: $Status" $Status "TEST"
}

# Run Security Audit Master
function Invoke-SecurityAuditTest {
    Write-SecurityTestLog "Starting Security Audit Master test" "INFO" "AUDIT"
    
    $startTime = Get-Date
    try {
        $scriptPath = Join-Path $PSScriptRoot "Security-Audit-Master.ps1"
        if (-not (Test-Path $scriptPath)) {
            throw "Security-Audit-Master.ps1 not found"
        }
        
        $auditOutputPath = Join-Path $OutputPath "SecurityAudit"
        New-Item -Path $auditOutputPath -ItemType Directory -Force | Out-Null
        
        $params = @{
            SeverityLevel = $MinimumSeverity
            ReportPath = Join-Path $auditOutputPath "SecurityAudit_Report.html"
            LogPath = Join-Path $auditOutputPath "SecurityAudit.log"
        }
        
        if ($WhatIf) { $params.WhatIf = $true }
        if ($AutoRemediate) { $params.Remediate = $true }
        
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath
        ) + ($params.GetEnumerator() | ForEach-Object { "-$($_.Key)", $_.Value }) -Wait -PassThru -NoNewWindow
        
        $duration = (Get-Date) - $startTime
        
        Add-TestResult -TestName "Security Audit" -Status $(if ($process.ExitCode -eq 0) { "SUCCESS" } else { "WARNING" }) `
            -ExitCode $process.ExitCode -OutputPath $auditOutputPath -Duration $duration
        
    }
    catch {
        $duration = (Get-Date) - $startTime
        Add-TestResult -TestName "Security Audit" -Status "ERROR" -ExitCode -1 -Duration $duration -ErrorMessage $_.Exception.Message
        Write-SecurityTestLog "Security Audit test failed: $($_.Exception.Message)" "ERROR" "AUDIT"
    }
}

# Run Advanced Malware Scanner
function Invoke-MalwareScanTest {
    Write-SecurityTestLog "Starting Advanced Malware Scanner test" "INFO" "MALWARE"
    
    $startTime = Get-Date
    try {
        $scriptPath = Join-Path $PSScriptRoot "Advanced-Malware-Scanner.ps1"
        if (-not (Test-Path $scriptPath)) {
            throw "Advanced-Malware-Scanner.ps1 not found"
        }
        
        $scanOutputPath = Join-Path $OutputPath "MalwareScan"
        New-Item -Path $scanOutputPath -ItemType Directory -Force | Out-Null
        
        $scanPath = if ($QuickScan) { "$env:USERPROFILE" } else { "C:\" }
        
        $params = @{
            ScanPath = $scanPath
            LogPath = Join-Path $scanOutputPath "MalwareScan.log"
        }
        
        if ($WhatIf) { $params.WhatIf = $true }
        if ($FullScan) { $params.DeepScan = $true }
        if ($AutoRemediate) { $params.QuarantineMode = $true }
        
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath
        ) + ($params.GetEnumerator() | ForEach-Object { "-$($_.Key)", $_.Value }) -Wait -PassThru -NoNewWindow
        
        $duration = (Get-Date) - $startTime
        $status = switch ($process.ExitCode) {
            0 { "SUCCESS" }
            1 { "WARNING" }
            2 { "CRITICAL" }
            default { "ERROR" }
        }
        
        Add-TestResult -TestName "Malware Scan" -Status $status -ExitCode $process.ExitCode `
            -OutputPath $scanOutputPath -Duration $duration
        
    }
    catch {
        $duration = (Get-Date) - $startTime
        Add-TestResult -TestName "Malware Scan" -Status "ERROR" -ExitCode -1 -Duration $duration -ErrorMessage $_.Exception.Message
        Write-SecurityTestLog "Malware scan test failed: $($_.Exception.Message)" "ERROR" "MALWARE"
    }
}

# Run Vulnerability Assessment
function Invoke-VulnerabilityAssessmentTest {
    Write-SecurityTestLog "Starting Vulnerability Assessment test" "INFO" "VULN"
    
    $startTime = Get-Date
    try {
        $scriptPath = Join-Path $PSScriptRoot "Vulnerability-Assessment.ps1"
        if (-not (Test-Path $scriptPath)) {
            throw "Vulnerability-Assessment.ps1 not found"
        }
        
        $vulnOutputPath = Join-Path $OutputPath "VulnerabilityAssessment"
        New-Item -Path $vulnOutputPath -ItemType Directory -Force | Out-Null
        
        $params = @{
            MinimumSeverity = $MinimumSeverity
            ReportPath = Join-Path $vulnOutputPath "Vulnerability_Report.html"
            LogPath = Join-Path $vulnOutputPath "VulnerabilityAssessment.log"
        }
        
        if ($WhatIf) { $params.WhatIf = $true }
        if ($AutoRemediate) { $params.AutoRemediate = $true }
        if ($FullScan) { $params.DetailedScan = $true }
        
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath
        ) + ($params.GetEnumerator() | ForEach-Object { "-$($_.Key)", $_.Value }) -Wait -PassThru -NoNewWindow
        
        $duration = (Get-Date) - $startTime
        $status = switch ($process.ExitCode) {
            0 { "SUCCESS" }
            1 { "WARNING" }
            2 { "CRITICAL" }
            default { "ERROR" }
        }
        
        Add-TestResult -TestName "Vulnerability Assessment" -Status $status -ExitCode $process.ExitCode `
            -OutputPath $vulnOutputPath -Duration $duration
        
    }
    catch {
        $duration = (Get-Date) - $startTime
        Add-TestResult -TestName "Vulnerability Assessment" -Status "ERROR" -ExitCode -1 -Duration $duration -ErrorMessage $_.Exception.Message
        Write-SecurityTestLog "Vulnerability assessment test failed: $($_.Exception.Message)" "ERROR" "VULN"
    }
}

# Run Ransomware Protection
function Invoke-RansomwareProtectionTest {
    Write-SecurityTestLog "Starting Ransomware Protection test" "INFO" "RANSOMWARE"
    
    $startTime = Get-Date
    try {
        $scriptPath = Join-Path $PSScriptRoot "Ransomware-Protection.ps1"
        if (-not (Test-Path $scriptPath)) {
            throw "Ransomware-Protection.ps1 not found"
        }
        
        $ransomwareOutputPath = Join-Path $OutputPath "RansomwareProtection"
        New-Item -Path $ransomwareOutputPath -ItemType Directory -Force | Out-Null
        
        $params = @{
            LogPath = Join-Path $ransomwareOutputPath "RansomwareProtection.log"
        }
        
        if ($WhatIf) { $params.WhatIf = $true }
        if ($AutoRemediate) { $params.EnableProtection = $true }
        
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath
        ) + ($params.GetEnumerator() | ForEach-Object { "-$($_.Key)", $_.Value }) -Wait -PassThru -NoNewWindow
        
        $duration = (Get-Date) - $startTime
        $status = switch ($process.ExitCode) {
            0 { "SUCCESS" }
            1 { "WARNING" }
            2 { "CRITICAL" }
            default { "ERROR" }
        }
        
        Add-TestResult -TestName "Ransomware Protection" -Status $status -ExitCode $process.ExitCode `
            -OutputPath $ransomwareOutputPath -Duration $duration
        
    }
    catch {
        $duration = (Get-Date) - $startTime
        Add-TestResult -TestName "Ransomware Protection" -Status "ERROR" -ExitCode -1 -Duration $duration -ErrorMessage $_.Exception.Message
        Write-SecurityTestLog "Ransomware protection test failed: $($_.Exception.Message)" "ERROR" "RANSOMWARE"
    }
}

# Generate consolidated security report
function Generate-ConsolidatedSecurityReport {
    Write-SecurityTestLog "Generating consolidated security report" "INFO" "REPORT"
    
    $reportPath = Join-Path $OutputPath "Consolidated_Security_Report.html"
    
    $totalDuration = ($script:TestResults | Measure-Object -Property Duration -Sum).Sum
    $successfulTests = ($script:TestResults | Where-Object Status -eq "SUCCESS").Count
    $totalTests = $script:TestResults.Count
    
    $overallStatus = if ($script:TestResults | Where-Object Status -eq "CRITICAL") { "CRITICAL" }
                    elseif ($script:TestResults | Where-Object Status -eq "ERROR") { "ERROR" }
                    elseif ($script:TestResults | Where-Object Status -eq "WARNING") { "WARNING" }
                    else { "SUCCESS" }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Consolidated Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 10px 40px rgba(0,0,0,0.3); min-height: 100vh; }
        .header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 40px; text-align: center; }
        .header h1 { margin: 0; font-size: 3em; }
        .header p { font-size: 1.2em; opacity: 0.9; margin: 10px 0; }
        .status-bar { height: 10px; background: $(switch ($overallStatus) {
            "SUCCESS" { "#27ae60" }
            "WARNING" { "#f39c12" }
            "ERROR" { "#e74c3c" }
            "CRITICAL" { "#8e44ad" }
            default { "#95a5a6" }
        }); }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .metric-card { background: white; padding: 30px; border-radius: 15px; text-align: center; box-shadow: 0 5px 20px rgba(0,0,0,0.1); transition: transform 0.3s ease; }
        .metric-card:hover { transform: translateY(-5px); }
        .metric-number { font-size: 3em; font-weight: bold; margin-bottom: 15px; }
        .metric-label { color: #666; font-weight: 500; font-size: 1.1em; }
        .success-metric { color: #27ae60; }
        .warning-metric { color: #f39c12; }
        .error-metric { color: #e74c3c; }
        .critical-metric { color: #8e44ad; }
        .test-results { padding: 30px; }
        .test-card { background: white; margin: 20px 0; padding: 25px; border-radius: 15px; box-shadow: 0 3px 15px rgba(0,0,0,0.1); border-left: 5px solid; }
        .test-success { border-left-color: #27ae60; }
        .test-warning { border-left-color: #f39c12; }
        .test-error { border-left-color: #e74c3c; }
        .test-critical { border-left-color: #8e44ad; }
        .test-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .test-name { font-size: 1.3em; font-weight: bold; color: #2c3e50; }
        .status-badge { padding: 8px 16px; border-radius: 25px; color: white; font-weight: bold; font-size: 0.9em; }
        .status-success { background: #27ae60; }
        .status-warning { background: #f39c12; }
        .status-error { background: #e74c3c; }
        .status-critical { background: #8e44ad; }
        .test-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .detail-item { background: #f8f9fa; padding: 15px; border-radius: 8px; }
        .detail-label { font-weight: bold; color: #495057; margin-bottom: 5px; }
        .detail-value { color: #6c757d; }
        .recommendations { background: linear-gradient(135deg, #74b9ff, #0984e3); color: white; padding: 30px; margin: 30px; border-radius: 15px; }
        .footer { background: #2c3e50; color: white; padding: 30px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Consolidated Security Assessment</h1>
            <p>Comprehensive Windows 11 Security Analysis & Protection Report</p>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Computer: $env:COMPUTERNAME | User: $env:USERNAME</p>
            <p>Assessment Duration: $($totalDuration.ToString('hh\:mm\:ss')) | Overall Status: <strong>$overallStatus</strong></p>
        </div>
        
        <div class="status-bar"></div>
        
        <div class="dashboard">
            <div class="metric-card">
                <div class="metric-number success-metric">$successfulTests/$totalTests</div>
                <div class="metric-label">Tests Completed</div>
            </div>
            <div class="metric-card">
                <div class="metric-number $(switch ($overallStatus) {
                    "SUCCESS" { "success-metric" }
                    "WARNING" { "warning-metric" }
                    "ERROR" { "error-metric" }
                    "CRITICAL" { "critical-metric" }
                    default { "success-metric" }
                })">$overallStatus</div>
                <div class="metric-label">Overall Status</div>
            </div>
            <div class="metric-card">
                <div class="metric-number" style="color: #3498db;">$(($script:TestResults | Where-Object Status -eq "SUCCESS").Count)</div>
                <div class="metric-label">Successful</div>
            </div>
            <div class="metric-card">
                <div class="metric-number warning-metric">$(($script:TestResults | Where-Object Status -eq "WARNING").Count)</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card">
                <div class="metric-number error-metric">$(($script:TestResults | Where-Object Status -eq "ERROR").Count)</div>
                <div class="metric-label">Errors</div>
            </div>
            <div class="metric-card">
                <div class="metric-number critical-metric">$(($script:TestResults | Where-Object Status -eq "CRITICAL").Count)</div>
                <div class="metric-label">Critical</div>
            </div>
        </div>
        
        <div class="test-results">
            <h2>🧪 Security Test Results</h2>
"@
    
    foreach ($test in $script:TestResults) {
        $statusClass = "test-" + $test.Status.ToLower()
        $badgeClass = "status-" + $test.Status.ToLower()
        
        $html += @"
            <div class="test-card $statusClass">
                <div class="test-header">
                    <div class="test-name">$($test.TestName)</div>
                    <div class="status-badge $badgeClass">$($test.Status)</div>
                </div>
                <div class="test-details">
                    <div class="detail-item">
                        <div class="detail-label">Duration</div>
                        <div class="detail-value">$($test.Duration.ToString('hh\:mm\:ss'))</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Exit Code</div>
                        <div class="detail-value">$($test.ExitCode)</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Timestamp</div>
                        <div class="detail-value">$($test.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</div>
                    </div>
                    $(if ($test.OutputPath) {
                        "<div class='detail-item'>
                            <div class='detail-label'>Output Path</div>
                            <div class='detail-value'>$($test.OutputPath)</div>
                        </div>"
                    })
                    $(if ($test.ErrorMessage) {
                        "<div class='detail-item'>
                            <div class='detail-label'>Error</div>
                            <div class='detail-value' style='color: #e74c3c;'>$($test.ErrorMessage)</div>
                        </div>"
                    })
                </div>
            </div>
"@
    }
    
    # Add recommendations based on results
    $recommendations = @()
    if ($script:TestResults | Where-Object Status -eq "CRITICAL") {
        $recommendations += "🚨 IMMEDIATE ACTION REQUIRED: Critical security issues detected. Isolate system and contact security team."
    }
    if ($script:TestResults | Where-Object Status -eq "ERROR") {
        $recommendations += "⚠️ Some security tests failed to complete. Investigate error conditions and retry."
    }
    if ($script:TestResults | Where-Object Status -eq "WARNING") {
        $recommendations += "📋 Security issues detected that require attention. Review detailed reports and remediate."
    }
    if ($script:TestResults | Where-Object Status -eq "SUCCESS" | Measure-Object | Select-Object -ExpandProperty Count -eq $totalTests) {
        $recommendations += "✅ All security tests passed successfully. Continue regular monitoring."
    }
    
    if ($recommendations.Count -gt 0) {
        $html += @"
        </div>
        
        <div class="recommendations">
            <h3>📋 Security Recommendations</h3>
            <ul>
"@
        foreach ($rec in $recommendations) {
            $html += "<li>$rec</li>"
        }
        $html += "</ul></div>"
    } else {
        $html += "</div>"
    }
    
    $html += @"
        
        <div class="footer">
            <h3>🛡️ Security Assessment Complete</h3>
            <p>This comprehensive security assessment covered multiple attack vectors and protection mechanisms.</p>
            <p>For detailed findings, review the individual test reports in their respective output directories.</p>
            <p><strong>Next Assessment Recommended:</strong> $($(Get-Date).AddDays(7).ToString('yyyy-MM-dd'))</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-SecurityTestLog "Consolidated security report generated: $reportPath" "SUCCESS" "REPORT"
    return $reportPath
}

# Main execution function
function Start-SecurityTestRunner {
    $script:RunnerStartTime = Get-Date
    
    Write-SecurityTestLog "Starting Comprehensive Security Test Runner" "INFO" "MAIN"
    Write-SecurityTestLog "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "INFO" "MAIN"
    Write-SecurityTestLog "Parameters: WhatIf=$($WhatIf.IsPresent), AutoRemediate=$($AutoRemediate.IsPresent), FullScan=$($FullScan.IsPresent), QuickScan=$($QuickScan.IsPresent)" "INFO" "MAIN"
    
    try {
        # Create output directory
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-SecurityTestLog "Output directory created: $OutputPath" "INFO" "MAIN"
        
        # Run all security tests
        Invoke-SecurityAuditTest
        Invoke-MalwareScanTest
        Invoke-VulnerabilityAssessmentTest
        Invoke-RansomwareProtectionTest
        
        # Generate consolidated report
        $reportPath = Generate-ConsolidatedSecurityReport
        
        # Summary
        $totalDuration = (Get-Date) - $script:RunnerStartTime
        $successCount = ($script:TestResults | Where-Object Status -eq "SUCCESS").Count
        $totalCount = $script:TestResults.Count
        
        Write-SecurityTestLog "Security test runner completed in $($totalDuration.ToString('hh\:mm\:ss'))" "SUCCESS" "MAIN"
        Write-SecurityTestLog "Tests completed: $successCount/$totalCount successful" "INFO" "MAIN"
        Write-SecurityTestLog "Consolidated report: $reportPath" "INFO" "MAIN"
        
        # Return results for Nexthink
        $overallStatus = if ($script:TestResults | Where-Object Status -eq "CRITICAL") { "CRITICAL" }
                        elseif ($script:TestResults | Where-Object Status -eq "ERROR") { "ERROR" }
                        elseif ($script:TestResults | Where-Object Status -eq "WARNING") { "WARNING" }
                        else { "SUCCESS" }
        
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $successCount -eq $totalCount
            OverallStatus = $overallStatus
            TestsCompleted = $totalCount
            TestsSuccessful = $successCount
            TestsWithWarnings = ($script:TestResults | Where-Object Status -eq "WARNING").Count
            TestsWithErrors = ($script:TestResults | Where-Object Status -eq "ERROR").Count
            CriticalIssues = ($script:TestResults | Where-Object Status -eq "CRITICAL").Count
            TotalDuration = $totalDuration.TotalMinutes
            OutputPath = $OutputPath
            ConsolidatedReport = $reportPath
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        
        # Exit code based on overall status
        $exitCode = switch ($overallStatus) {
            "SUCCESS" { 0 }
            "WARNING" { 1 }
            "ERROR" { 2 }
            "CRITICAL" { 3 }
            default { 0 }
        }
        
        exit $exitCode
    }
    catch {
        Write-SecurityTestLog "Critical error during security test runner: $($_.Exception.Message)" "ERROR" "MAIN"
        
        $errorOutput = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Error = $_.Exception.Message
            OutputPath = $OutputPath
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $errorOutput"
        exit 1
    }
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Start-SecurityTestRunner
}
