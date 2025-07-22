# Simple-Test-Security.ps1
# Simple test for security remediation scripts

Write-Host "Security Remediation Scripts Test" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

$passed = 0
$failed = 0

Write-Host "`nTesting file existence..." -ForegroundColor Cyan

$scripts = @(
    ".\scripts\security-remediation\Fix-UAC-Settings.ps1",
    ".\scripts\security-remediation\Fix-Firewall-Settings.ps1",
    ".\scripts\security-remediation\Fix-Windows-Updates.ps1",
    ".\scripts\security-remediation\Fix-SMB-Registry-Settings.ps1",
    ".\scripts\security-remediation\Fix-Network-Security.ps1",
    ".\scripts\security-remediation\Auto-Remediation-Master.ps1"
)

foreach ($script in $scripts) {
    if (Test-Path $script) {
        Write-Host "PASS: $(Split-Path $script -Leaf) exists" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "FAIL: $(Split-Path $script -Leaf) missing" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nTesting UAC fix script..." -ForegroundColor Cyan
if (Test-Path ".\scripts\security-remediation\Fix-UAC-Settings.ps1") {
    try {
        & ".\scripts\security-remediation\Fix-UAC-Settings.ps1" -WhatIf | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PASS: UAC Settings script executed" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "FAIL: UAC Settings script failed" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "FAIL: UAC Settings script error" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nTesting Master script..." -ForegroundColor Cyan
if (Test-Path ".\scripts\security-remediation\Auto-Remediation-Master.ps1") {
    try {
        & ".\scripts\security-remediation\Auto-Remediation-Master.ps1" -WhatIf -Categories UAC | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PASS: Master script executed" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "FAIL: Master script failed" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "FAIL: Master script error" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nResults:" -ForegroundColor Green
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red

if ($failed -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Yellow
    exit 1
}
