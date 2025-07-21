# PowerShell 5.1 Compatibility

PowerShell 5.1 is the Windows PowerShell version included with Windows 10 and Windows Server 2016. This guide covers compatibility considerations for auto-remediation scripts.

---

## Key Compatibility Points

### Cmdlets and Modules
- Use cmdlets available in PowerShell 5.1 (avoid PowerShell Core/7+ specific features)
- Common modules like `Microsoft.PowerShell.Management`, `Microsoft.PowerShell.Utility` are available
- Test module availability with `Get-Module -ListAvailable`

### Syntax Considerations
- **Classes**: Supported, but limited compared to newer versions
- **Conditional operators**: Use `if-else` instead of ternary operators (`? :`)
- **Null coalescing**: Use `if ($null -eq $variable)` instead of `??` operator
- **String interpolation**: Use `"$($variable)"` format

### .NET Framework Version
- PowerShell 5.1 runs on .NET Framework 4.x
- Some .NET Core/5+ specific APIs are not available
- Use `[System.Environment]::Version` to check .NET Framework version

---

## Best Practices for PowerShell 5.1

### Error Handling
```powershell
try {
    # Your remediation code here
    Start-Service -Name "wuauserv" -ErrorAction Stop
    Write-Output "SUCCESS: Windows Update service started"
    exit 0
}
catch {
    Write-Output "ERROR: Failed to start Windows Update service - $($_.Exception.Message)"
    exit 1
}
```

### Parameter Validation
```powershell
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName
)
```

### Logging and Output
```powershell
# Use Write-Output for results that need to be captured
Write-Output "Starting remediation for service: $ServiceName"

# Use Write-Verbose for detailed logging (when -Verbose is used)
Write-Verbose "Checking current service status..."

# Use Write-Warning for non-fatal issues
Write-Warning "Service was already running, no action needed"
```

---

## Testing PowerShell 5.1 Compatibility

### Local Testing
1. Open PowerShell 5.1 console (not PowerShell 7)
2. Check version: `$PSVersionTable.PSVersion`
3. Test your script functionality
4. Verify error handling and output

### Common Compatibility Issues
- **Invoke-RestMethod**: JSON depth limitations in 5.1
- **ConvertFrom-Json**: Less flexible parsing than newer versions
- **Get-FileHash**: Available, but fewer algorithm options
- **Compress-Archive/Expand-Archive**: Available in 5.1+

---

## Environment Variables and Paths

### System Paths
```powershell
# Use environment variables for cross-system compatibility
$programFiles = $env:ProgramFiles
$system32 = "$env:windir\System32"
$temp = $env:TEMP
```

### Registry Access
```powershell
# Use registry provider for Windows-specific configurations
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
if (Test-Path $regPath) {
    $value = Get-ItemProperty -Path $regPath -Name "ProgramFilesDir"
}
```

---

## Security Considerations

### Execution Policy
- Scripts may need to handle execution policy restrictions
- Use `-ExecutionPolicy Bypass` parameter when invoking from Nexthink
- Consider signing scripts for production environments

### Credentials and Security Context
```powershell
# Avoid hardcoded credentials
# Use parameters or secure strings
param(
    [System.Management.Automation.PSCredential]$Credential
)

# Run with appropriate privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "ERROR: Script requires administrator privileges"
    exit 1
}
```

---

For more examples, see [../scripts/sample-remediation-script.ps1](../scripts/sample-remediation-script.ps1).