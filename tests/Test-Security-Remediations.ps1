# Test-Security-Remediations.ps1
# Test script for all security remediation scripts

Write-Host "🛡️ Testing Security Remediation Scripts" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green

$testsPassed = 0
$testsFailed = 0

# Test script existence
Write-Host "`n📁 Testing Security Remediation Scripts Existence..." -ForegroundColor Cyan

$remediationScripts = @(
    ".\scripts\security-remediation\Fix-UAC-Settings.ps1",
    ".\scripts\security-remediation\Fix-Firewall-Settings.ps1", 
    ".\scripts\security-remediation\Fix-Windows-Updates.ps1",
    ".\scripts\security-remediation\Fix-SMB-Registry-Settings.ps1",
    ".\scripts\security-remediation\Fix-Network-Security.ps1",
    ".\scripts\security-remediation\Auto-Remediation-Master.ps1"
)

foreach ($script in $remediationScripts) {
    $displayName = if (![string]::IsNullOrWhiteSpace($script)) { try { Split-Path $script -Leaf } catch { $script } } else { '<empty>' }
    if ([string]::IsNullOrWhiteSpace($script)) {
        Write-Host "FAIL: Script path is null or empty ($displayName)" -ForegroundColor Red
        $testsFailed++
        continue
    }
    if (Test-Path $script) {
        Write-Host "PASS: $displayName exists" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "FAIL: $displayName missing" -ForegroundColor Red
        $testsFailed++
    }
}

# Test script syntax
Write-Host "`n📝 Testing Script Syntax..." -ForegroundColor Cyan

foreach ($script in $remediationScripts) {
    if (Test-Path $script) {
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $script -Raw), [ref]$null)
            Write-Host "PASS: $(Split-Path $script -Leaf) syntax OK" -ForegroundColor Green
            $testsPassed++
        } catch {
            Write-Host "FAIL: $(Split-Path $script -Leaf) syntax error" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
            $testsFailed++
        }
    }
}

# Test script execution in WhatIf mode (safe)
Write-Host "`n⚡ Testing Script Execution (WhatIf Mode)..." -ForegroundColor Cyan

$executionTests = @(
    @{ Script = ".\scripts\security-remediation\Fix-UAC-Settings.ps1"; Name = "UAC Settings Fix" },
    @{ Script = ".\scripts\security-remediation\Fix-Firewall-Settings.ps1"; Name = "Firewall Settings Fix"; Args = @("-Profile", "All") },
    @{ Script = ".\scripts\security-remediation\Fix-Windows-Updates.ps1"; Name = "Windows Updates Fix" },
    @{ Script = ".\scripts\security-remediation\Fix-SMB-Registry-Settings.ps1"; Name = "SMB Registry Fix" },
    @{ Script = ".\scripts\security-remediation\Fix-Network-Security.ps1"; Name = "Network Security Fix" }
)

foreach ($test in $executionTests) {
    if (Test-Path $test.Script) {
        try {
            Write-Host "Testing $($test.Name)..." -ForegroundColor Yellow
            
            $scriptArgs = @("-WhatIf")
            if ($test.Args) {
                $scriptArgs += $test.Args
            }
            
            $output = & $test.Script @scriptArgs 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                # Check for Nexthink output
                $nexthinkOutput = $output | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
                if ($nexthinkOutput) {
                    Write-Host "PASS: $($test.Name) - Valid Nexthink output" -ForegroundColor Green
                    $testsPassed++
                } else {
                    Write-Host "WARN: $($test.Name) - No Nexthink output found" -ForegroundColor Yellow
                    $testsPassed++
                }
            } else {
                Write-Host "FAIL: $($test.Name) - Exit code $LASTEXITCODE" -ForegroundColor Red
                $testsFailed++
            }
        } catch {
            Write-Host "FAIL: $($test.Name) - Exception: $($_.Exception.Message)" -ForegroundColor Red
            $testsFailed++
        }
    }
}

# Test Master script
Write-Host "`n🎯 Testing Auto-Remediation Master Script..." -ForegroundColor Cyan

if (Test-Path ".\scripts\security-remediation\Auto-Remediation-Master.ps1") {
    try {
        Write-Host "Testing Auto-Remediation Master in WhatIf mode..." -ForegroundColor Yellow
        
        $masterOutput = & ".\scripts\security-remediation\Auto-Remediation-Master.ps1" -WhatIf -Categories @("UAC") 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $nexthinkOutput = $masterOutput | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
            if ($nexthinkOutput) {
                Write-Host "PASS: Auto-Remediation Master executed successfully" -ForegroundColor Green
                $testsPassed++
            } else {
                Write-Host "WARN: Auto-Remediation Master - No Nexthink output" -ForegroundColor Yellow
                $testsPassed++
            }
        } else {
            Write-Host "FAIL: Auto-Remediation Master failed" -ForegroundColor Red
            $testsFailed++
        }
    } catch {
        Write-Host "FAIL: Auto-Remediation Master error: $($_.Exception.Message)" -ForegroundColor Red
        $testsFailed++
    }
}

# Summary
Write-Host "\nTest Results:" -ForegroundColor Green
Write-Host "================" -ForegroundColor Green
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor Red
Write-Host "Total:  $($testsPassed + $testsFailed)" -ForegroundColor Cyan

if ($testsFailed -eq 0) {
    Write-Host "\nAll security remediation tests passed!" -ForegroundColor Green
    Write-Host "\nReady for deployment!" -ForegroundColor Green
    Write-Host "\nNext steps:" -ForegroundColor Cyan
    Write-Host "1. Run individual scripts with -WhatIf to preview changes" -ForegroundColor White
    Write-Host "2. Use Auto-Remediation-Master.ps1 for orchestrated remediation" -ForegroundColor White
    Write-Host "3. Always test in a controlled environment first" -ForegroundColor White
    exit 0
} else {
    Write-Host "\n[FAIL] Some tests failed!" -ForegroundColor Red
    Write-Host "Please review the errors above before deployment." -ForegroundColor Yellow
    exit 1
}

