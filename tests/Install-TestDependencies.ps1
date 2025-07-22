# Install-TestDependencies.ps1
# Script to install testing dependencies for the auto-remediation project

[CmdletBinding()]
param(
    [switch]$Force
)

Write-Host "Installing testing dependencies..." -ForegroundColor Green

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Running without Administrator privileges. Some installations might fail."
}

# Install Pester if not present or if Force is specified
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($Force -or -not $pesterModule -or $pesterModule.Version -lt [Version]"5.0.0") {
    Write-Host "Installing/Updating Pester module..." -ForegroundColor Yellow
    try {
        if ($Force) {
            Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser
        } else {
            Install-Module -Name Pester -SkipPublisherCheck -Scope CurrentUser -AllowClobber
        }
        Write-Host "✅ Pester installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Pester: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "✅ Pester is already installed (Version: $($pesterModule.Version))" -ForegroundColor Green
}

# Install PSScriptAnalyzer for code quality checks
$psaModule = Get-Module -Name PSScriptAnalyzer -ListAvailable

if ($Force -or -not $psaModule) {
    Write-Host "Installing PSScriptAnalyzer module..." -ForegroundColor Yellow
    try {
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force:$Force
        Write-Host "✅ PSScriptAnalyzer installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install PSScriptAnalyzer: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "✅ PSScriptAnalyzer is already installed (Version: $($psaModule.Version))" -ForegroundColor Green
}

Write-Host "`n🎉 All testing dependencies installed successfully!" -ForegroundColor Green
Write-Host "You can now run tests using: Invoke-Pester" -ForegroundColor Cyan
