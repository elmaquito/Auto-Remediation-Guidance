# Test Writing Guide

This guide provides detailed instructions for writing effective tests for PowerShell auto-remediation scripts.

## 🎯 Test Structure

### Basic Test Template

```powershell
# ScriptName.Tests.ps1
BeforeAll {
    # Import the script being tested
    $scriptPath = Join-Path $PSScriptRoot "..\scripts\ScriptName.ps1"
    . $scriptPath
    
    # Mock external dependencies
    Mock Write-Host {}
    Mock Add-Content {}
}

Describe "ScriptName Tests" {
    Context "Helper Functions" {
        Describe "Function-Name" {
            It "Should perform expected behavior" {
                # Arrange
                Mock External-Command { return "expected-result" }
                
                # Act
                $result = Function-Name -Parameter "value"
                
                # Assert
                $result | Should -Be "expected-result"
            }
        }
    }
    
    Context "Main Function Tests" {
        Describe "Main-Function" {
            It "Should handle normal cases" {
                # Test implementation
            }
            
            It "Should handle error cases" {
                # Test implementation
            }
        }
    }
    
    Context "Integration Tests" {
        # End-to-end tests
    }
}
```

## 🔧 Writing Effective Unit Tests

### 1. Test Individual Functions

Focus on testing one function at a time:

```powershell
Describe "Test-ServiceExists" {
    It "Should return true for existing service" {
        # Arrange
        Mock Get-Service { return @{ Name = "TestService" } }
        
        # Act
        $result = Test-ServiceExists -ServiceName "TestService"
        
        # Assert
        $result | Should -Be $true
        Should -Invoke Get-Service -Times 1 -ParameterFilter { $Name -eq "TestService" }
    }
    
    It "Should return false for non-existing service" {
        # Arrange
        Mock Get-Service { throw "Service not found" }
        
        # Act
        $result = Test-ServiceExists -ServiceName "NonExistentService"
        
        # Assert
        $result | Should -Be $false
    }
}
```

### 2. Test Parameter Validation

Verify that functions handle parameters correctly:

```powershell
Describe "Parameter Validation" {
    It "Should accept valid parameters" {
        { Function-Name -ValidParameter "ValidValue" } | Should -Not -Throw
    }
    
    It "Should reject invalid parameters" {
        { Function-Name -InvalidParameter "Value" } | Should -Throw
    }
    
    It "Should use default values when parameters not provided" {
        Mock Function-Name { return $DefaultValue } -ParameterFilter { $Parameter -eq $null }
        
        $result = Function-Name
        
        $result | Should -Be $DefaultValue
    }
}
```

### 3. Test Error Handling

Ensure proper error handling:

```powershell
Describe "Error Handling" {
    It "Should handle service access errors gracefully" {
        # Arrange
        Mock Get-Service { throw "Access denied" }
        
        # Act & Assert
        { Get-ServiceStatus -ServiceName "TestService" } | Should -Not -Throw
        $result = Get-ServiceStatus -ServiceName "TestService"
        $result | Should -Be "NotFound"
    }
    
    It "Should log errors appropriately" {
        # Arrange
        Mock Write-Log {}
        Mock Get-Service { throw "Access denied" }
        
        # Act
        Get-ServiceStatus -ServiceName "TestService"
        
        # Assert
        Should -Invoke Write-Log -ParameterFilter { $Level -eq "ERROR" }
    }
}
```

## 🔄 Integration Testing

### 1. Script Execution Tests

Test the entire script execution:

```powershell
Describe "Script Execution" {
    It "Should execute without errors in WhatIf mode" {
        # Arrange
        $scriptPath = Join-Path $testScriptsPath "ScriptName.ps1"
        $logPath = Join-Path $testOutputPath "test.log"
        
        # Act
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $scriptPath,
            "-WhatIf",
            "-LogPath", $logPath
        ) -Wait -PassThru -NoNewWindow
        
        # Assert
        $process.ExitCode | Should -Be 0
        Test-Path $logPath | Should -Be $true
    }
}
```

### 2. Output Validation

Verify script output format:

```powershell
It "Should produce valid Nexthink output format" {
    # Act
    $output = & powershell.exe -NoProfile -File $scriptPath -WhatIf
    
    # Assert
    $nexthinkOutput = $output | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
    $nexthinkOutput | Should -Not -BeNullOrEmpty
    
    $jsonData = ($nexthinkOutput -split "NEXTHINK_OUTPUT: ")[1]
    $parsedJson = $jsonData | ConvertFrom-Json
    
    $parsedJson.Timestamp | Should -Not -BeNullOrEmpty
    $parsedJson.Success | Should -BeOfType [bool]
    $parsedJson.Message | Should -Not -BeNullOrEmpty
}
```

## 🔒 Security Testing

### 1. Credential Security

```powershell
Context "Security Tests" {
    It "Should not contain hardcoded credentials" {
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $scriptContent | Should -Not -Match 'password\s*=\s*["\x27][^"\x27]+["\x27]'
        $scriptContent | Should -Not -Match 'username\s*=\s*["\x27][^"\x27]+["\x27]'
        $scriptContent | Should -Not -Match 'apikey\s*=\s*["\x27][^"\x27]+["\x27]'
    }
}
```

### 2. Unsafe Practices

```powershell
It "Should not use dangerous functions" {
    $scriptContent = Get-Content -Path $scriptPath -Raw
    $scriptContent | Should -Not -Match 'Invoke-Expression|iex\s'
    $scriptContent | Should -Not -Match 'DownloadString'
    $scriptContent | Should -Not -Match 'Add-Type.*CSharpCode'
}
```

## 🎭 Mocking Strategies

### 1. External Commands

```powershell
BeforeAll {
    Mock Get-Service { 
        param($Name)
        if ($Name -eq "ExistingService") {
            return @{ Name = $Name; Status = "Running" }
        } else {
            throw "Service '$Name' was not found"
        }
    }
}
```

### 2. File System Operations

```powershell
BeforeAll {
    Mock Test-Path { return $true } -ParameterFilter { $Path -like "*existing*" }
    Mock Test-Path { return $false } -ParameterFilter { $Path -like "*nonexistent*" }
    
    Mock Get-ChildItem {
        return @(
            [PSCustomObject]@{ Name = "file1.txt"; LastWriteTime = (Get-Date).AddDays(-10) }
            [PSCustomObject]@{ Name = "file2.txt"; LastWriteTime = (Get-Date).AddDays(-5) }
        )
    }
}
```

### 3. Complex Return Values

```powershell
Mock Invoke-RestMethod {
    return @{
        Status = "Success"
        Data = @{
            Items = @(
                @{ Id = 1; Name = "Item1" }
                @{ Id = 2; Name = "Item2" }
            )
        }
    }
}
```

## 📊 Performance Testing

### 1. Execution Time

```powershell
It "Should complete within reasonable time" {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Main-Function -Parameter "Value"
    
    $stopwatch.Stop()
    $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000  # 5 seconds
}
```

### 2. Memory Usage

```powershell
It "Should not consume excessive memory" {
    $beforeMemory = [GC]::GetTotalMemory($false)
    
    Main-Function -Parameter "Value"
    
    $afterMemory = [GC]::GetTotalMemory($true)
    $memoryIncrease = $afterMemory - $beforeMemory
    
    # Should not increase memory by more than 10MB
    $memoryIncrease | Should -BeLessThan (10 * 1MB)
}
```

## 🎯 Test Data Management

### 1. Test Fixtures

```powershell
BeforeAll {
    $script:testData = @{
        ValidServices = @("Spooler", "BITS", "Themes")
        InvalidServices = @("NonExistent1", "NonExistent2")
        TestFiles = @(
            @{ Path = "C:\Temp\old.txt"; Age = 10 }
            @{ Path = "C:\Temp\new.txt"; Age = 1 }
        )
    }
}
```

### 2. Dynamic Test Generation

```powershell
Describe "Service Validation" {
    BeforeAll {
        $services = @("Spooler", "BITS", "Themes", "NonExistent")
    }
    
    It "Should validate service <ServiceName>" -ForEach @(
        @{ ServiceName = "Spooler"; Expected = $true }
        @{ ServiceName = "BITS"; Expected = $true }
        @{ ServiceName = "NonExistent"; Expected = $false }
    ) {
        param($ServiceName, $Expected)
        
        Mock Get-Service { 
            if ($ServiceName -in @("Spooler", "BITS", "Themes")) {
                return @{ Name = $ServiceName }
            } else {
                throw "Service not found"
            }
        } -ParameterFilter { $Name -eq $ServiceName }
        
        $result = Test-ServiceExists -ServiceName $ServiceName
        $result | Should -Be $Expected
    }
}
```

## 🧹 Test Cleanup

### 1. Cleanup After Each Test

```powershell
AfterEach {
    # Clean up test files
    if (Test-Path $testFile) {
        Remove-Item $testFile -Force
    }
    
    # Reset variables
    $script:testVariable = $null
}
```

### 2. Cleanup After All Tests

```powershell
AfterAll {
    # Clean up test directory
    if (Test-Path $testDirectory) {
        Remove-Item $testDirectory -Recurse -Force
    }
    
    # Unregister event handlers
    Get-EventSubscriber | Unregister-Event
}
```

## 🎨 Test Organization Tips

### 1. Logical Grouping

```powershell
Describe "ScriptName Tests" {
    Context "Input Validation" {
        # Parameter and input tests
    }
    
    Context "Core Functionality" {
        # Main business logic tests
    }
    
    Context "Error Handling" {
        # Exception and error tests
    }
    
    Context "Integration" {
        # End-to-end tests
    }
}
```

### 2. Shared Setup

```powershell
Describe "ScriptName Tests" {
    BeforeAll {
        # Setup that applies to all tests
    }
    
    Context "Feature A" {
        BeforeEach {
            # Setup specific to Feature A tests
        }
        
        # Feature A tests
    }
    
    Context "Feature B" {
        BeforeEach {
            # Setup specific to Feature B tests
        }
        
        # Feature B tests
    }
}
```

## 🚀 Advanced Techniques

### 1. Parameterized Tests

```powershell
It "Should handle <TestCase> correctly" -ForEach @(
    @{ TestCase = "Empty String"; Input = ""; Expected = $false }
    @{ TestCase = "Null Value"; Input = $null; Expected = $false }
    @{ TestCase = "Valid Input"; Input = "ValidService"; Expected = $true }
) {
    param($TestCase, $Input, $Expected)
    
    $result = Validate-Input -Value $Input
    $result | Should -Be $Expected
}
```

### 2. Custom Assertions

```powershell
function Should-BeValidService {
    param(
        [Parameter(ValueFromPipeline)]
        $ActualValue,
        
        [string]$Because
    )
    
    $success = $ActualValue -and 
               $ActualValue.Name -and
               $ActualValue.Status -in @("Running", "Stopped", "Paused")
    
    return [PSCustomObject]@{
        Succeeded = $success
        FailureMessage = "Expected a valid service object but got: $ActualValue"
    }
}

# Usage
$service | Should-BeValidService
```

### 3. Test Tags

```powershell
Describe "ScriptName Tests" -Tag "Unit" {
    It "Should work correctly" -Tag "Fast" {
        # Quick test
    }
    
    It "Should handle integration" -Tag "Slow", "Integration" {
        # Longer integration test
    }
}

# Run only fast tests
Invoke-Pester -Tag "Fast"

# Exclude slow tests
Invoke-Pester -ExcludeTag "Slow"
```

## ✅ Test Review Checklist

Before submitting tests, ensure:

- [ ] All functions are tested
- [ ] Error cases are covered
- [ ] Parameter validation is tested
- [ ] Security checks are included
- [ ] Tests run independently
- [ ] Cleanup is properly implemented
- [ ] Test names are descriptive
- [ ] Appropriate mocks are used
- [ ] Code coverage is adequate (>70%)
- [ ] Tests complete quickly (<30s total)

---

*This guide covers the essential patterns for writing comprehensive tests for PowerShell auto-remediation scripts.*
