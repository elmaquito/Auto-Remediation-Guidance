# Test-Runner.ps1
# Main test runner script for the auto-remediation project

[CmdletBinding()]
param(
    [string]$TestPath = ".\tests",
    [switch]$Coverage,
    [switch]$CodeAnalysis,
    [string]$OutputFormat = "NUnitXml",
    [string]$OutputPath = ".\TestResults",
    [switch]$PassThru
)

# Ensure required modules are available
$requiredModules = @('Pester', 'PSScriptAnalyzer')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Error "Required module '$module' is not installed. Run Install-TestDependencies.ps1 first."
        exit 1
    }
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "🧪 Running Auto-Remediation Tests..." -ForegroundColor Green
Write-Host "Test Path: $TestPath" -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan

# Configure Pester
$pesterConfig = @{
    Run = @{
        Path = $TestPath
        PassThru = $PassThru.IsPresent
    }
    TestResult = @{
        Enabled = $true
        OutputFormat = $OutputFormat
        OutputPath = Join-Path $OutputPath "TestResults.xml"
    }
    Output = @{
        Verbosity = 'Detailed'
    }
}

if ($Coverage) {
    $pesterConfig.CodeCoverage = @{
        Enabled = $true
        Path = ".\scripts\*.ps1"
        OutputFormat = 'JaCoCo'
        OutputPath = Join-Path $OutputPath "Coverage.xml"
    }
    Write-Host "Code coverage enabled" -ForegroundColor Yellow
}

# Run Pester tests
$testResults = Invoke-Pester -Configuration $pesterConfig

# Run PSScriptAnalyzer if requested
if ($CodeAnalysis) {
    Write-Host "`n🔍 Running Code Analysis..." -ForegroundColor Green
    
    $analysisPath = ".\scripts"
    if (Test-Path $analysisPath) {
        $analysisResults = Invoke-ScriptAnalyzer -Path $analysisPath -Recurse -ReportSummary
        
        if ($analysisResults) {
            Write-Host "Code Analysis Issues Found:" -ForegroundColor Red
            $analysisResults | Format-Table -AutoSize
            
            # Export analysis results
            $analysisResults | Export-Csv -Path (Join-Path $OutputPath "CodeAnalysis.csv") -NoTypeInformation
        } else {
            Write-Host "✅ No code analysis issues found!" -ForegroundColor Green
        }
    }
}

# Summary
Write-Host "`n📊 Test Summary:" -ForegroundColor Green
Write-Host "  Total: $($testResults.TotalCount)" -ForegroundColor White
Write-Host "  Passed: $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "  Failed: $($testResults.FailedCount)" -ForegroundColor Red
Write-Host "  Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow

if ($Coverage -and $testResults.CodeCoverage) {
    $coveragePercent = [math]::Round($testResults.CodeCoverage.CoveragePercent, 2)
    Write-Host "  Coverage: $coveragePercent%" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($testResults.FailedCount -gt 0) {
    Write-Host "`n❌ Some tests failed!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n✅ All tests passed!" -ForegroundColor Green
    exit 0
}
