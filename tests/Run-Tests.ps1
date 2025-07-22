# Run-Tests.ps1
# Convenience script to run all tests with different configurations

[CmdletBinding()]
param(
    [ValidateSet('Unit', 'Integration', 'All')]
    [string]$TestType = 'All',
    
    [switch]$Coverage,
    [switch]$CI,
    [string]$OutputPath = ".\TestResults"
)

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "Auto-Remediation Test Runner" -ForegroundColor Green
Write-Host "Test Type: $TestType" -ForegroundColor Cyan
Write-Host "Coverage: $($Coverage.IsPresent)" -ForegroundColor Cyan

# Check if Pester is available and get version
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $pesterModule) {
    Write-Error "Pester is not installed. Please run Install-TestDependencies.ps1 first."
    exit 1
}

$pesterVersion = $pesterModule.Version
Write-Host "Using Pester Version: $pesterVersion" -ForegroundColor Cyan

# Import required modules
Import-Module Pester -Force

# Determine test path based on test type
$testPath = switch ($TestType) {
    'Unit' { @('.\tests\*.Tests.ps1') }
    'Integration' { @('.\tests\Integration.Tests.ps1') }
    'All' { @('.\tests\*.Tests.ps1') }
}

# Exclude Integration tests for Unit tests
$excludePath = if ($TestType -eq 'Unit') { @('.\tests\Integration.Tests.ps1') } else { @() }

Write-Host "Running $TestType tests..." -ForegroundColor Cyan

# Check Pester version and use appropriate syntax
if ($pesterVersion -ge [Version]"5.0.0") {
    # Pester 5.x configuration
    $config = New-PesterConfiguration
    $config.Run.Path = $testPath
    if ($excludePath) { $config.Run.ExcludePath = $excludePath }
    $config.Run.PassThru = $true
    $config.Output.Verbosity = if ($CI) { 'Normal' } else { 'Detailed' }
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $OutputPath "TestResults-$TestType.xml"
    
    # Code coverage configuration
    if ($Coverage -and $TestType -ne 'Integration') {
        $config.CodeCoverage.Enabled = $true
        $config.CodeCoverage.Path = @('.\scripts\*.ps1')
        $config.CodeCoverage.OutputFormat = 'JaCoCo'
        $config.CodeCoverage.OutputPath = Join-Path $OutputPath "Coverage-$TestType.xml"
    }
    
    $result = Invoke-Pester -Configuration $config
} else {
    # Pester 3.x/4.x configuration
    $pesterArgs = @{
        Script = $testPath
        PassThru = $true
        OutputFormat = 'NUnitXml'
        OutputFile = Join-Path $OutputPath "TestResults-$TestType.xml"
    }
    
    # Add code coverage for older Pester versions
    if ($Coverage -and $TestType -ne 'Integration') {
        $pesterArgs.CodeCoverage = @('.\scripts\*.ps1')
        $pesterArgs.CodeCoverageOutputFile = Join-Path $OutputPath "Coverage-$TestType.xml"
        $pesterArgs.CodeCoverageOutputFileFormat = 'JaCoCo'
    }
    
    $result = Invoke-Pester @pesterArgs
}

# Display results
Write-Host "`nTest Results:" -ForegroundColor Green
Write-Host "  Total: $($result.TotalCount)" -ForegroundColor White
Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor Green
Write-Host "  Failed: $($result.FailedCount)" -ForegroundColor Red
Write-Host "  Skipped: $($result.SkippedCount)" -ForegroundColor Yellow

if ($result.Time) {
    Write-Host "  Duration: $($result.Time)" -ForegroundColor Cyan
} elseif ($result.Duration) {
    Write-Host "  Duration: $($result.Duration)" -ForegroundColor Cyan
}

# Display code coverage if available
if ($Coverage -and $result.CodeCoverage) {
    if ($result.CodeCoverage.CoveragePercent) {
        # Pester 5.x
        $coveragePercent = [math]::Round($result.CodeCoverage.CoveragePercent, 2)
    } else {
        # Pester 3.x/4.x
        $totalCommands = $result.CodeCoverage.NumberOfCommandsAnalyzed
        $missedCommands = $result.CodeCoverage.NumberOfCommandsMissed
        $coveragePercent = if ($totalCommands -gt 0) { 
            [math]::Round((($totalCommands - $missedCommands) / $totalCommands) * 100, 2) 
        } else { 0 }
    }
    
    Write-Host "  Coverage: $coveragePercent%" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($result.FailedCount -gt 0) {
    Write-Host "`nSome tests failed!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
}
