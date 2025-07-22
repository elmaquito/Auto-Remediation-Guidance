# Execute Security Suite Test

Write-Host "Starting comprehensive security audit..." -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Yellow

# Test the Security Test Runner
try {
    $result = & ".\security\Security-Test-Runner.ps1" -QuickScan -WhatIf -Verbose
    
    if ($result) {
        Write-Host "✅ Security audit completed successfully!" -ForegroundColor Green
        Write-Host "Check the generated HTML report for detailed findings." -ForegroundColor Cyan
    }
} catch {
    Write-Host "❌ Error during security audit: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nTo run individual security modules:" -ForegroundColor Yellow
Write-Host "  .\security\Security-Audit-Master.ps1 -WhatIf" -ForegroundColor White
Write-Host "  .\security\Advanced-Malware-Scanner.ps1 -QuickScan" -ForegroundColor White  
Write-Host "  .\security\Vulnerability-Assessment.ps1 -WhatIf" -ForegroundColor White
Write-Host "  .\security\Ransomware-Protection.ps1 -WhatIf" -ForegroundColor White

Write-Host "`nFor full automated remediation:" -ForegroundColor Yellow
Write-Host "  .\security\Security-Test-Runner.ps1 -FullScan -AutoRemediate" -ForegroundColor White
