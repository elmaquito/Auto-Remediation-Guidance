# Run-Tests-Simple.ps1
# Simple test runner for security and remediation scripts

param(
    [switch]$SecurityOnly,
    [switch]$WhatIf
)

Write-Host "🛡️ Auto-Remediation Testing Suite" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

$testsPassed = 0
$testsFailed = 0

function Test-ScriptExistence {
    param([string]$Path, [string]$Name)
    
    if (Test-Path $Path) {
        Write-Host "✅ $Name exists" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ $Name missing" -ForegroundColor Red
        return $false
    }
}

function Test-ScriptExecution {
    param([string]$Path, [string]$Name, [string[]]$Arguments = @())
    
    try {
        Write-Host "🧪 Testing $Name..." -ForegroundColor Yellow
        if ($Arguments.Count -gt 0) {
            & $Path @Arguments | Out-Null
        } else {
            & $Path | Out-Null
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $Name executed successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ $Name failed with exit code $LASTEXITCODE" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ $Name error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Test 1: Check script files exist
Write-Host "`n📁 Testing File Existence..." -ForegroundColor Cyan

$scripts = @(
    @{Path=".\scripts\Restart-WindowsUpdateService.ps1"; Name="Windows Update Service Script"},
    @{Path=".\scripts\Clear-TempFiles.ps1"; Name="Clear Temp Files Script"}
)

if (-not $SecurityOnly) {
    foreach ($script in $scripts) {
        if (Test-ScriptExistence -Path $script.Path -Name $script.Name) {
            $testsPassed++
        } else {
            $testsFailed++
        }
    }
}

# Test 2: Security scripts
Write-Host "`n🛡️ Testing Security Scripts..." -ForegroundColor Cyan

$securityScripts = @(
    @{Path=".\security\Invoke-SecurityAudit.ps1"; Name="Security Audit Script"},
    @{Path=".\security\Test-SecurityBaseline.ps1"; Name="Security Baseline Script"},
    @{Path=".\security\Remediate-SecurityIssues.ps1"; Name="Security Remediation Script"}
)

foreach ($script in $securityScripts) {
    if (Test-ScriptExistence -Path $script.Path -Name $script.Name) {
        $testsPassed++
    } else {
        $testsFailed++
    }
}

# Test 3: Execute scripts in safe mode
Write-Host "`n⚡ Testing Script Execution..." -ForegroundColor Cyan

if (-not $SecurityOnly -and (Test-Path ".\scripts\Restart-WindowsUpdateService.ps1")) {
    if (Test-ScriptExecution -Path ".\scripts\Restart-WindowsUpdateService.ps1" -Name "Windows Update Service" -Arguments @("-WhatIf")) {
        $testsPassed++
    } else {
        $testsFailed++
    }
}

if (-not $SecurityOnly -and (Test-Path ".\scripts\Clear-TempFiles.ps1")) {
    if (Test-ScriptExecution -Path ".\scripts\Clear-TempFiles.ps1" -Name "Clear Temp Files" -Arguments @("-WhatIf", "-MaxSizeMB", "100", "-OlderThanDays", "30")) {
        $testsPassed++
    } else {
        $testsFailed++
    }
}

# Test 4: Security baseline check
if (Test-Path ".\security\Test-SecurityBaseline.ps1") {
    if (Test-ScriptExecution -Path ".\security\Test-SecurityBaseline.ps1" -Name "Security Baseline Check") {
        $testsPassed++
    } else {
        $testsFailed++
    }
}

# Summary
Write-Host "`n📊 Test Results:" -ForegroundColor Green
Write-Host "================" -ForegroundColor Green
Write-Host "✅ Passed: $testsPassed" -ForegroundColor Green
Write-Host "❌ Failed: $testsFailed" -ForegroundColor Red
Write-Host "📋 Total:  $($testsPassed + $testsFailed)" -ForegroundColor Cyan

if ($testsFailed -eq 0) {
    Write-Host "`n🎉 All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️ Some tests failed!" -ForegroundColor Yellow
    exit 1
}
