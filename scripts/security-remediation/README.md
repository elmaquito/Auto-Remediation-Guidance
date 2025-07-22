# Security Remediation Scripts - Quick Usage Guide

## 🛡️ Auto-Remediation Security Scripts

This collection provides automated remediation for common Windows 11 security issues detected during security audits.

### 📋 Available Remediation Scripts

1. **Fix-UAC-Settings.ps1** - Configures User Account Control
2. **Fix-Firewall-Settings.ps1** - Secures Windows Firewall
3. **Fix-Windows-Updates.ps1** - Configures automatic updates
4. **Fix-SMB-Registry-Settings.ps1** - Secures SMB/CIFS settings
5. **Fix-Network-Security.ps1** - Addresses network security issues
6. **Auto-Remediation-Master.ps1** - Orchestrates all remediations

### 🚀 Quick Start

#### Test All Remediation Scripts
```powershell
.\Test-Security-Remediations.ps1
```

#### Run Individual Remediation (Safe Mode)
```powershell
# Preview what would be changed
.\scripts\security-remediation\Fix-UAC-Settings.ps1 -WhatIf
.\scripts\security-remediation\Fix-Firewall-Settings.ps1 -WhatIf
.\scripts\security-remediation\Fix-Windows-Updates.ps1 -WhatIf
```

#### Run Master Remediation (Safe Mode)
```powershell
# Preview all changes
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -WhatIf -Categories All

# Preview specific categories
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -WhatIf -Categories UAC,Firewall
```

### 🔧 Execution Modes

#### WhatIf Mode (Recommended First)
- **Safe**: No changes made
- **Preview**: Shows what would be changed
- **Test**: Validates configuration

```powershell
# Safe preview mode
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -WhatIf
```

#### Apply Changes Mode
- **Requires**: Administrator privileges
- **Action**: Makes actual security changes
- **Risk**: Modifies system configuration

```powershell
# Apply changes (run as Administrator)
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -Categories UAC,Firewall
```

#### Force Mode
- **Advanced**: Applies aggressive changes
- **Use with caution**: May impact functionality

```powershell
# Force mode for network security (closes risky ports)
.\scripts\security-remediation\Fix-Network-Security.ps1 -Force
```

### 📊 Available Categories

| Category | Issues Addressed | Impact Level |
|----------|------------------|--------------|
| **UAC** | Admin Approval Mode, UAC prompts | High |
| **Firewall** | Default rules, inbound blocking | Medium |
| **WindowsUpdate** | Automatic updates, scheduling | Medium |
| **SMB** | SMB signing, registry security | High |
| **Network** | Open ports, wireless sharing | Variable |

### 🔍 Monitoring and Reporting

#### Generate Security Report
```powershell
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -GenerateReport -ReportPath "SecurityFix-Report.html"
```

#### Check Logs
```powershell
# View remediation logs
Get-Content "$env:TEMP\Auto-Remediation-Master.log" -Tail 50
```

### ⚠️ Important Safety Notes

1. **Always test with -WhatIf first**
2. **Run as Administrator for actual changes**
3. **Backup system before applying changes**
4. **Test applications after remediation**
5. **Some changes may require reboot**

### 🎯 Common Usage Scenarios

#### Scenario 1: Initial Security Hardening
```powershell
# 1. Test everything first
.\Test-Security-Remediations.ps1

# 2. Preview all changes
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -WhatIf -Categories All

# 3. Apply changes progressively
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -Categories UAC
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -Categories Firewall
# ... continue with other categories
```

#### Scenario 2: Address Specific Security Audit Findings
```powershell
# Fix only high-priority UAC and SMB issues
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -Categories UAC,SMB -MinimumSeverity High
```

#### Scenario 3: Comprehensive Security Remediation
```powershell
# Full remediation with report
.\scripts\security-remediation\Auto-Remediation-Master.ps1 -Categories All -GenerateReport -ReportPath "Full-Security-Remediation.html"
```

### 🔧 Advanced Parameters

#### Auto-Remediation-Master.ps1 Parameters
- `-Categories`: Specify which fixes to apply
- `-MinimumSeverity`: Filter by issue severity (Low, Medium, High, Critical)
- `-WhatIf`: Preview mode (no changes)
- `-Force`: Apply aggressive changes
- `-GenerateReport`: Create HTML report
- `-ReportPath`: Specify report location
- `-LogPath`: Specify log file location

### 📞 Support and Troubleshooting

#### Common Issues
1. **Access Denied**: Run as Administrator
2. **Script Execution Policy**: Use `-ExecutionPolicy Bypass`
3. **Service Dependencies**: Some services may need restart

#### Getting Help
```powershell
# Get help for any script
Get-Help .\scripts\security-remediation\Auto-Remediation-Master.ps1 -Full
```

### 🔄 Integration with Nexthink

All scripts output JSON format compatible with Nexthink:
```json
{
  "Timestamp": "2025-07-22T10:46:37.874Z",
  "Success": true,
  "Message": "Auto-remediation completed: 5/5 categories successful",
  "Categories": ["UAC", "Firewall", "WindowsUpdate", "SMB", "Network"],
  "TotalChanges": 12,
  "WhatIf": false
}
```

This enables integration with Nexthink remote actions and automated reporting.
