# Test-Basic.ps1
# Basic test script without special characters

Write-Host "Auto-Remediation Testing" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green

$passed = 0
$failed = 0

Write-Host "Testing file existence..." -ForegroundColor Cyan

# Test 1: Check if main scripts exist
$mainScripts = @(
    ".\scripts\Restart-WindowsUpdateService.ps1",
    ".\scripts\Clear-TempFiles.ps1"
)

foreach ($script in $mainScripts) {
    if (Test-Path $script) {
        Write-Host "PASS: $(Split-Path $script -Leaf) exists" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "FAIL: $(Split-Path $script -Leaf) missing" -ForegroundColor Red
        $failed++
    }
}

# Test 2: Check security scripts
Write-Host "`nTesting security scripts..." -ForegroundColor Cyan

$securityScripts = @(
    ".\security\Security-Audit-Master.ps1",
    ".\security\Advanced-Malware-Scanner.ps1", 
    ".\security\Vulnerability-Assessment.ps1",
    ".\security\Ransomware-Protection.ps1"
)

foreach ($script in $securityScripts) {
    if (Test-Path $script) {
        Write-Host "PASS: $(Split-Path $script -Leaf) exists" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "FAIL: $(Split-Path $script -Leaf) missing" -ForegroundColor Red
        $failed++
    }
}

# Test 3: Try executing one script in safe mode
Write-Host "`nTesting script execution..." -ForegroundColor Cyan

if (Test-Path ".\scripts\Restart-WindowsUpdateService.ps1") {
    try {
        Write-Host "Testing Windows Update script in WhatIf mode..."
        & ".\scripts\Restart-WindowsUpdateService.ps1" -WhatIf | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PASS: Windows Update script executed" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "FAIL: Windows Update script failed" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "FAIL: Windows Update script error - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

# Test 4: Test security audit if available
if (Test-Path ".\security\Security-Audit-Master.ps1") {
    try {
        Write-Host "Testing Security Audit Master..."
        & ".\security\Security-Audit-Master.ps1" -WhatIf | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PASS: Security Audit Master executed" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "FAIL: Security Audit Master failed" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "FAIL: Security Audit Master error - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

# Summary
Write-Host "`nTest Summary:" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host "Total:  $($passed + $failed)" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Yellow
    exit 1
}
