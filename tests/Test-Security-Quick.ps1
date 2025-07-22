# Test-Security-Quick.ps1
# Quick security testing script - runs the most important tests

[CmdletBinding()]
param(
    [switch]$SkipDependencies,
    [switch]$WhatIf,
    [ValidateSet("Basic", "Full", "Security", "All")]
    [string]$TestType = "Basic"
)

$ErrorActionPreference = "Stop"

Write-Host "🛡️ Security Testing Quick Start" -ForegroundColor Green
Write-Host "Test Type: $TestType" -ForegroundColor Cyan
Write-Host "WhatIf Mode: $($WhatIf.IsPresent)" -ForegroundColor Cyan

# Check if running as Administrator for security tests
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($TestType -in @("Security", "Full") -and -not $isAdmin) {
    Write-Warning "Administrator privileges required for security tests. Run as Administrator or use -TestType 'Basic'"
    Write-Host "Starting elevated PowerShell session..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-File `"$PSCommandPath`" -TestType $TestType" -Verb RunAs
    exit
}

# Install dependencies if not skipped
if (-not $SkipDependencies) {
    Write-Host "`n📦 Installing/Checking Dependencies..." -ForegroundColor Yellow
    if (Test-Path ".\Install-TestDependencies.ps1") {
        & ".\Install-TestDependencies.ps1"
    } else {
        Write-Warning "Install-TestDependencies.ps1 not found. Skipping dependency check."
    }
}

# Create TestResults directory
$testResultsPath = ".\TestResults"
if (-not (Test-Path $testResultsPath)) {
    New-Item -Path $testResultsPath -ItemType Directory -Force | Out-Null
}

$testsPassed = 0
$testsFailed = 0
$testsSkipped = 0

function Invoke-TestScript {
    param(
        [string]$ScriptPath,
        [string]$Description
    )
    
    if (Test-Path $ScriptPath) {
        Write-Host "`n🧪 $Description" -ForegroundColor Blue
        try {
            & $ScriptPath | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ $Description - PASSED" -ForegroundColor Green
                $script:testsPassed++
            } else {
                Write-Host "❌ $Description - FAILED (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
                $script:testsFailed++
            }
        } catch {
            Write-Host "❌ $Description - ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $script:testsFailed++
        }
    } else {
        Write-Host "⚠️ $Description - SKIPPED (Script not found: $ScriptPath)" -ForegroundColor Yellow
        $script:testsSkipped++
    }
}

# Basic Tests - Always run these
Write-Host "`n📋 Running Basic Tests..." -ForegroundColor Cyan

# Test 1: Check if scripts exist
Write-Host "`n🔍 Testing Script Existence" -ForegroundColor Blue
$scriptPaths = @(
    ".\scripts\Restart-WindowsUpdateService.ps1",
    ".\scripts\Clear-TempFiles.ps1"
)

foreach ($scriptPath in $scriptPaths) {
    if (Test-Path $scriptPath) {
        Write-Host "✅ Found: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "❌ Missing: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Red
        $testsFailed++
    }
}

# Test 2: Check security scripts exist
if ($TestType -in @("Security", "Full", "All")) {
    Write-Host "`n🛡️ Testing Security Scripts" -ForegroundColor Blue
    $securityScripts = @(
        ".\security\Invoke-SecurityAudit.ps1",
        ".\security\Test-SecurityBaseline.ps1",
        ".\security\Remediate-SecurityIssues.ps1"
    )
    
    foreach ($scriptPath in $securityScripts) {
        if (Test-Path $scriptPath) {
            Write-Host "✅ Found: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Green
            $testsPassed++
        } else {
            Write-Host "❌ Missing: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Test 3: Run basic script validation
Write-Host "`n📝 Testing Script Syntax" -ForegroundColor Blue
foreach ($scriptPath in $scriptPaths) {
    if (Test-Path $scriptPath) {
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$null)
            Write-Host "✅ Syntax OK: $(Split-Path $scriptPath -Leaf)" -ForegroundColor Green
            $testsPassed++
        } catch {
            Write-Host "❌ Syntax Error: $(Split-Path $scriptPath -Leaf) - $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Test 4: Run actual script tests if available
if ($TestType -in @("Basic", "Full", "All")) {
    Write-Host "`n🔬 Running Script Tests" -ForegroundColor Blue
    
    # Test Windows Update script in WhatIf mode
    if (Test-Path ".\scripts\Restart-WindowsUpdateService.ps1") {
        try {
            Write-Host "Testing Windows Update Service script..." -ForegroundColor Cyan
            $output = & ".\scripts\Restart-WindowsUpdateService.ps1" -WhatIf
            if ($output -match "NEXTHINK_OUTPUT:") {
                Write-Host "✅ Windows Update Script - Output format correct" -ForegroundColor Green
                $testsPassed++
            } else {
                Write-Host "❌ Windows Update Script - Invalid output format" -ForegroundColor Red
                $testsFailed++
            }
        } catch {
            Write-Host "❌ Windows Update Script - Error: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
    
    # Test Temp Files script in WhatIf mode
    if (Test-Path ".\scripts\Clear-TempFiles.ps1") {
        try {
            Write-Host "Testing Clear Temp Files script..." -ForegroundColor Cyan
            $output = & ".\scripts\Clear-TempFiles.ps1" -WhatIf -MaxSizeMB 1 -OlderThanDays 30
            if ($output -match "NEXTHINK_OUTPUT:") {
                Write-Host "✅ Clear Temp Files Script - Output format correct" -ForegroundColor Green
                $testsPassed++
            } else {
                Write-Host "❌ Clear Temp Files Script - Invalid output format" -ForegroundColor Red
                $testsFailed++
            }
        } catch {
            Write-Host "❌ Clear Temp Files Script - Error: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Security Tests - Only if requested and running as admin
if ($TestType -in @("Security", "Full", "All") -and $isAdmin) {
    Write-Host "`n🛡️ Running Security Tests..." -ForegroundColor Cyan
    
    # Test security audit in WhatIf mode
    if (Test-Path ".\security\Invoke-SecurityAudit.ps1") {
        try {
            Write-Host "Testing Security Audit script..." -ForegroundColor Cyan
            $output = & ".\security\Invoke-SecurityAudit.ps1" -WhatIf -Verbose
            Write-Host "✅ Security Audit - Executed successfully" -ForegroundColor Green
            $testsPassed++
        } catch {
            Write-Host "❌ Security Audit - Error: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
    
    # Test security baseline
    if (Test-Path ".\security\Test-SecurityBaseline.ps1") {
        try {
            Write-Host "Testing Security Baseline..." -ForegroundColor Cyan
            $output = & ".\security\Test-SecurityBaseline.ps1"
            Write-Host "✅ Security Baseline - Executed successfully" -ForegroundColor Green
            $testsPassed++
        } catch {
            Write-Host "❌ Security Baseline - Error: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Run Pester tests if available
if ($TestType -in @("Full", "All") -and (Get-Module -Name Pester -ListAvailable)) {
    Write-Host "`n🧪 Running Pester Tests..." -ForegroundColor Cyan
    
    if (Test-Path ".\tests") {
        try {
            Import-Module Pester -Force
            $pesterResult = Invoke-Pester -Path ".\tests" -PassThru
            $testsPassed += $pesterResult.PassedCount
            $testsFailed += $pesterResult.FailedCount
            $testsSkipped += $pesterResult.SkippedCount
            
            Write-Host "✅ Pester Tests - Completed" -ForegroundColor Green
        } catch {
            Write-Host "❌ Pester Tests - Error: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Final Summary
Write-Host "`n📊 Test Summary" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green
Write-Host "✅ Tests Passed:  $testsPassed" -ForegroundColor Green
Write-Host "❌ Tests Failed:  $testsFailed" -ForegroundColor Red
Write-Host "⚠️  Tests Skipped: $testsSkipped" -ForegroundColor Yellow
Write-Host "📋 Total Tests:   $($testsPassed + $testsFailed + $testsSkipped)" -ForegroundColor Cyan

# Save results
$testResults = @{
    TestType = $TestType
    Timestamp = Get-Date
    Passed = $testsPassed
    Failed = $testsFailed
    Skipped = $testsSkipped
    Total = $testsPassed + $testsFailed + $testsSkipped
    IsAdmin = $isAdmin
    WhatIfMode = $WhatIf.IsPresent
}

$testResults | ConvertTo-Json | Out-File -FilePath "$testResultsPath\QuickTestResults.json"

# Exit with appropriate code
if ($testsFailed -eq 0) {
    Write-Host "`n🎉 All tests completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️ Some tests failed. Check the output above for details." -ForegroundColor Yellow
    exit 1
}
