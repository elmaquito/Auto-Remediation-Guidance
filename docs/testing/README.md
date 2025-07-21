# Automatic Testing for Auto-Remediation Scripts

This document explains how to implement and run automatic tests for your PowerShell auto-remediation scripts in the Nexthink v6 environment.

## 🎯 Overview

Automatic testing ensures that your remediation scripts work reliably before deploying them to production environments. Our testing framework provides:

- **Unit Tests**: Test individual functions and components
- **Integration Tests**: Test complete script execution
- **Security Analysis**: Check for security vulnerabilities
- **Code Coverage**: Ensure comprehensive test coverage
- **CI/CD Integration**: Automatic testing in GitHub Actions

## 🛠️ Test Framework Components

### 1. Testing Tools

- **Pester**: PowerShell testing framework for unit and integration tests
- **PSScriptAnalyzer**: Code quality and security analysis
- **GitHub Actions**: Continuous integration and automated testing

### 2. Test Types

#### Unit Tests
Test individual functions in isolation:
```powershell
Describe "Test-ServiceExists" {
    It "Should return true for existing service" {
        Mock Get-Service { return @{ Name = "TestService" } }
        Test-ServiceExists -ServiceName "TestService" | Should -Be $true
    }
}
```

#### Integration Tests
Test complete script execution:
```powershell
It "Should execute without errors in WhatIf mode" {
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath, "-WhatIf"
    ) -Wait -PassThru -NoNewWindow
    
    $process.ExitCode | Should -Be 0
}
```

#### Security Tests
Check for security vulnerabilities:
```powershell
It "Should not contain hardcoded credentials" {
    $scriptContent | Should -Not -Match 'password\s*=\s*["\x27][^"\x27]+["\x27]'
}
```

## 🚀 Getting Started

### 1. Install Dependencies

Run the dependency installation script:
```powershell
.\Install-TestDependencies.ps1
```

This installs:
- Pester 5.x (PowerShell testing framework)
- PSScriptAnalyzer (Code analysis tool)

### 2. Run Tests

#### Quick Test Run
```powershell
.\Run-Tests.ps1
```

#### Specific Test Types
```powershell
# Unit tests only
.\Run-Tests.ps1 -TestType Unit

# Integration tests only
.\Run-Tests.ps1 -TestType Integration

# With code coverage
.\Run-Tests.ps1 -Coverage
```

#### Watch Mode (Development)
```powershell
.\Run-Tests.ps1 -Watch
```

### 3. Advanced Testing

#### Using Test Runner with Options
```powershell
.\Test-Runner.ps1 -TestPath ".\tests" -Coverage -CodeAnalysis -OutputFormat "NUnitXml"
```

#### Direct Pester Configuration
```powershell
$config = New-PesterConfiguration
$config.Run.Path = ".\tests"
$config.CodeCoverage.Enabled = $true
Invoke-Pester -Configuration $config
```

## 📁 Test Structure

```
Auto-Remediation-Guidance/
├── scripts/                          # Remediation scripts
│   ├── Restart-WindowsUpdateService.ps1
│   └── Clear-TempFiles.ps1
├── tests/                            # Test files
│   ├── Restart-WindowsUpdateService.Tests.ps1
│   ├── Clear-TempFiles.Tests.ps1
│   └── Integration.Tests.ps1
├── Install-TestDependencies.ps1      # Dependency installer
├── Run-Tests.ps1                     # Main test runner
├── Test-Runner.ps1                   # Advanced test runner
└── PesterConfiguration.psd1          # Test configuration
```

## ✅ Test Standards

### 1. Test Naming Conventions

- Test files: `ScriptName.Tests.ps1`
- Test descriptions: Use clear, descriptive names
- Context blocks: Group related tests

```powershell
Describe "ScriptName Tests" {
    Context "Function Tests" {
        Describe "Specific-Function" {
            It "Should perform expected behavior" {
                # Test implementation
            }
        }
    }
}
```

### 2. Mock Usage

Use mocks to isolate tests from external dependencies:

```powershell
BeforeAll {
    Mock Get-Service { return @{ Status = "Running" } }
    Mock Write-Host {}
    Mock Add-Content {}
}
```

### 3. Test Coverage Goals

- **Minimum**: 70% code coverage
- **Target**: 80% code coverage
- **Excellent**: 90%+ code coverage

### 4. Required Test Categories

Every remediation script should have tests for:

1. **Parameter validation**
2. **WhatIf mode behavior**
3. **Error handling**
4. **Success scenarios**
5. **Edge cases**
6. **Security requirements**

## 🔒 Security Testing

### Automated Security Checks

The test framework automatically checks for:

- Hardcoded passwords/API keys
- Unsafe PowerShell practices
- Execution policy bypasses
- Potentially dangerous functions

### Custom Security Tests

Add specific security tests for your scripts:

```powershell
Context "Security Tests" {
    It "Should not use Invoke-Expression" {
        $scriptContent | Should -Not -Match 'Invoke-Expression|iex\s'
    }
    
    It "Should validate all input parameters" {
        $scriptContent | Should -Match '\[CmdletBinding\(\)\]'
    }
}
```

## 📊 Code Coverage

### Enabling Coverage

```powershell
# In configuration
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = @('.\scripts\*.ps1')
$config.CodeCoverage.OutputFormat = 'JaCoCo'

# Using Run-Tests script
.\Run-Tests.ps1 -Coverage
```

### Coverage Reports

Coverage reports are generated in JaCoCo XML format, compatible with:
- GitHub Actions
- Azure DevOps
- Jenkins
- SonarQube

## 🔄 Continuous Integration

### GitHub Actions Integration

The included `.github/workflows/test.yml` provides:

- Automatic testing on push/PR
- Multi-version PowerShell testing
- Code coverage reporting
- Security scanning
- Test result publishing

### Local CI Simulation

```powershell
# Simulate CI environment
.\Run-Tests.ps1 -CI -Coverage -TestType All
```

## 🐛 Debugging Tests

### Verbose Test Output

```powershell
$config = New-PesterConfiguration
$config.Output.Verbosity = 'Detailed'
$config.Debug.ShowFullErrors = $true
Invoke-Pester -Configuration $config
```

### Individual Test Execution

```powershell
# Run specific test file
Invoke-Pester -Path ".\tests\Restart-WindowsUpdateService.Tests.ps1"

# Run specific test
Invoke-Pester -Path ".\tests\*.Tests.ps1" -FullNameFilter "*Should restart service*"
```

## 📈 Best Practices

### 1. Test Organization

- One test file per script
- Group related tests in `Context` blocks
- Use descriptive test names

### 2. Test Data

- Use realistic test data
- Create test fixtures for complex scenarios
- Clean up test data in `AfterEach`/`AfterAll`

### 3. Performance

- Keep tests fast (< 1 second per test)
- Use mocks instead of real external calls
- Parallelize where possible

### 4. Maintainability

- Keep tests simple and focused
- Avoid testing implementation details
- Test behavior, not internal structure

## 🚨 Common Issues

### Issue: Module Import Errors
**Solution**: Ensure all required modules are installed:
```powershell
.\Install-TestDependencies.ps1 -Force
```

### Issue: Test Timeout
**Solution**: Add timeout configuration:
```powershell
$config.Run.Timeout = '00:05:00'  # 5 minutes
```

### Issue: Mock Not Working
**Solution**: Ensure mocks are defined in `BeforeAll`:
```powershell
BeforeAll {
    Mock Function-Name { return "expected-value" }
}
```

## 📚 Additional Resources

- [Pester Documentation](https://pester.dev/)
- [PSScriptAnalyzer Rules](https://github.com/PowerShell/PSScriptAnalyzer)
- [PowerShell Testing Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/writing-portable-modules)

## 🤝 Contributing

When adding new remediation scripts:

1. Create corresponding test file
2. Ensure minimum 70% code coverage
3. Include security tests
4. Verify CI/CD pipeline passes
5. Update documentation

---

*Last updated: July 2025*
