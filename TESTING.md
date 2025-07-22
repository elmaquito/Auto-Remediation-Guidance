# Security Testing Guide

This guide explains how to test the security audit and remediation system for Windows 11.

## Quick Start

### 1. Install Dependencies
First, install the required testing modules:
```powershell
.\Install-TestDependencies.ps1
```

### 2. Run Basic Tests
Run the basic security tests:
```powershell
.\Test-Security-Basic.ps1
```

### 3. Run Full Security Audit (Administrator Required)
For a complete security audit:
```powershell
# Run as Administrator
.\security\Invoke-SecurityAudit.ps1 -WhatIf
```

## Detailed Testing Instructions

### Prerequisites
- Windows 11
- PowerShell 5.1 or later
- Administrator privileges (for full security tests)
- Internet connection (for module downloads)

### Step-by-Step Testing

#### 1. Environment Setup
```powershell
# Navigate to the project directory
cd "C:\Users\elmaq\OneDrive\Documents\apprentissage\Perso\Soft_Workplace\Auto-Remediation-Guidance"

# Install testing dependencies
.\Install-TestDependencies.ps1 -Force

# Verify installation
Get-Module -Name Pester -ListAvailable
Get-Module -Name PSScriptAnalyzer -ListAvailable
```

#### 2. Unit Tests
Test individual security functions:
```powershell
# Run unit tests for security scripts
Invoke-Pester .\tests\Security-*.Tests.ps1 -Verbose

# Run specific test file
Invoke-Pester .\tests\Security-WindowsDefender.Tests.ps1 -Verbose
```

#### 3. Integration Tests
Test complete security workflows:
```powershell
# Run integration tests (requires Admin)
Invoke-Pester .\tests\Security-Integration.Tests.ps1 -Verbose

# Run in WhatIf mode (safe testing)
.\security\Invoke-SecurityAudit.ps1 -WhatIf -Verbose
```

#### 4. Security Audit Tests
Test the main security audit functionality:
```powershell
# Basic security check (no Admin required)
.\security\Test-SecurityBaseline.ps1

# Full security audit (requires Admin)
.\security\Invoke-SecurityAudit.ps1 -Categories @("Firewall", "WindowsDefender", "Updates") -WhatIf

# Generate security report
.\security\Generate-SecurityReport.ps1 -OutputPath ".\TestResults\SecurityReport.html"
```

### Test Categories

#### 1. **Security Baseline Tests**
- Windows Defender status
- Firewall configuration
- Windows Update settings
- User Account Control (UAC)
- BitLocker encryption status

#### 2. **Vulnerability Assessment Tests**
- Missing security updates
- Weak password policies
- Unencrypted drives
- Open network shares
- Unnecessary services

#### 3. **Compliance Tests**
- CIS Benchmarks
- Security policies
- Registry security settings
- File system permissions

#### 4. **Remediation Tests**
- Automatic fix validation
- Rollback functionality
- Configuration restoration
- Error handling

### Running Tests in Different Modes

#### Safe Mode (WhatIf)
```powershell
# Test what would be changed without making actual changes
.\security\Invoke-SecurityAudit.ps1 -WhatIf -Verbose
```

#### Selective Testing
```powershell
# Test specific security categories
.\security\Invoke-SecurityAudit.ps1 -Categories @("WindowsDefender", "Firewall") -WhatIf

# Test specific severity levels
.\security\Invoke-SecurityAudit.ps1 -Severity "High" -WhatIf
```

#### Full Audit Mode
```powershell
# Complete security assessment and remediation
.\security\Invoke-SecurityAudit.ps1 -AutoRemediate -GenerateReport
```

### Automated Testing with GitHub Actions

The project includes automated testing via GitHub Actions. Tests run on:
- Push to main branch
- Pull requests
- Scheduled weekly runs

View test results in the GitHub repository under the "Actions" tab.

### Test Output and Reports

#### Test Results Location
- **Unit Test Results**: `.\TestResults\UnitTests.xml`
- **Integration Test Results**: `.\TestResults\IntegrationTests.xml`
- **Security Report**: `.\TestResults\SecurityReport.html`
- **Logs**: `.\TestResults\Logs\`

#### Reading Test Results
```powershell
# View latest test results
Get-Content .\TestResults\SecurityReport.html | Out-String

# View test logs
Get-ChildItem .\TestResults\Logs\ | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
```

### Troubleshooting

#### Common Issues

**1. Module Installation Fails**
```powershell
# Solution: Run as Administrator or use -Force
.\Install-TestDependencies.ps1 -Force
```

**2. Access Denied Errors**
```powershell
# Solution: Run PowerShell as Administrator
Start-Process powershell -Verb RunAs
```

**3. Execution Policy Errors**
```powershell
# Solution: Set execution policy temporarily
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**4. Tests Fail Due to Missing Dependencies**
```powershell
# Solution: Verify all modules are installed
.\Install-TestDependencies.ps1 -Force
Import-Module Pester -Force
Import-Module PSScriptAnalyzer -Force
```

### Performance Testing

#### Benchmark Security Operations
```powershell
# Measure audit performance
Measure-Command { .\security\Invoke-SecurityAudit.ps1 -WhatIf }

# Profile memory usage
[System.GC]::Collect()
$before = [System.GC]::GetTotalMemory($false)
.\security\Invoke-SecurityAudit.ps1 -WhatIf
$after = [System.GC]::GetTotalMemory($false)
Write-Host "Memory used: $($after - $before) bytes"
```

### Continuous Testing

#### Set Up Scheduled Testing
```powershell
# Create scheduled task for weekly security audits
.\security\Install-ScheduledSecurityAudit.ps1 -Frequency Weekly -WhatIf
```

#### Monitoring Test Results
```powershell
# Check last test execution
Get-ScheduledTask -TaskName "SecurityAudit" | Get-ScheduledTaskInfo
```

## Best Practices for Testing

1. **Always test in WhatIf mode first**
2. **Run tests in a controlled environment**
3. **Review test results before applying changes**
4. **Keep test logs for audit trails**
5. **Test rollback procedures**
6. **Validate fixes with subsequent tests**

## Support

For issues with testing:
1. Check the troubleshooting section
2. Review test logs in `.\TestResults\Logs\`
3. Run tests with `-Verbose` for detailed output
4. Create an issue in the GitHub repository
