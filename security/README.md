# Security Folder - Advanced Windows 11 Security Suite

This folder contains a comprehensive collection of advanced security assessment and remediation scripts designed specifically for Windows 11 environments. These scripts work together to provide multi-layered security analysis, threat detection, vulnerability assessment, and automated remediation capabilities.

## 🛡️ Security Scripts Overview

### 1. Security-Audit-Master.ps1
**Comprehensive Security Configuration Audit**
- Windows Defender and antivirus status checks
- Windows Update security validation
- User Account Control (UAC) configuration analysis
- Windows Firewall security assessment  
- Password policy evaluation
- Network security configuration review
- Registry security settings analysis
- Service security configuration checks
- Automated remediation for identified issues

**Key Features:**
- Multi-category security assessments
- Automated remediation capabilities
- HTML report generation with severity classification
- Nexthink integration support
- WhatIf mode for safe testing

### 2. Advanced-Malware-Scanner.ps1
**Multi-Vector Malware Detection System**
- Signature-based malware detection
- Heuristic analysis for unknown threats
- Behavioral analysis of running processes
- Registry analysis for malware persistence
- File system anomaly detection
- Network connection monitoring
- Automated quarantine functionality

**Detection Methods:**
- Known malware hash comparison
- Suspicious process pattern analysis
- File extension and naming analysis
- Registry persistence indicators
- Network communication patterns
- File system behavioral indicators

### 3. Vulnerability-Assessment.ps1
**Comprehensive System Vulnerability Scanner**
- Windows OS vulnerability assessment
- Installed software vulnerability analysis
- Cryptographic configuration weaknesses
- Privilege escalation vulnerability detection
- Network service vulnerability analysis
- Automated vulnerability remediation

**Assessment Categories:**
- Operating system patches and updates
- Software version vulnerabilities
- SSL/TLS configuration weaknesses
- Service permission vulnerabilities
- Registry security misconfigurations

### 4. Ransomware-Protection.ps1
**Advanced Ransomware Detection and Protection**
- Real-time ransomware behavior monitoring
- File encryption pattern detection
- Ransomware process identification
- Network communication analysis
- Registry persistence detection
- Windows Defender integration
- Automated protection enablement

**Protection Features:**
- Controlled folder access configuration
- Network protection enablement
- Real-time protection optimization
- Cloud-based protection integration
- System restore point creation
- Critical file backup automation

### 5. Security-Test-Runner.ps1
**Integrated Security Testing Orchestrator**
- Coordinated execution of all security scripts
- Consolidated reporting and analysis
- Centralized configuration management
- Performance monitoring and metrics
- Error handling and recovery
- Comprehensive status reporting

## 🚀 Quick Start Guide

### Prerequisites
- Windows 11 (Build 22000 or later)
- PowerShell 5.1 or later
- Administrator privileges (recommended)
- Windows Defender enabled
- .NET Framework 4.7.2 or later

### Basic Usage

1. **Run Complete Security Assessment:**
   ```powershell
   .\Security-Test-Runner.ps1 -FullScan -AutoRemediate
   ```

2. **Quick Security Check:**
   ```powershell
   .\Security-Test-Runner.ps1 -QuickScan -WhatIf
   ```

3. **Individual Script Execution:**
   ```powershell
   .\Security-Audit-Master.ps1 -Remediate -SeverityLevel High
   .\Advanced-Malware-Scanner.ps1 -DeepScan -QuarantineMode
   .\Vulnerability-Assessment.ps1 -AutoRemediate -MinimumSeverity Medium
   .\Ransomware-Protection.ps1 -EnableProtection
   ```

## 📊 Parameters and Options

### Common Parameters
- `-WhatIf`: Preview actions without making changes
- `-AutoRemediate`: Automatically fix identified issues
- `-FullScan`: Perform comprehensive deep scanning
- `-QuickScan`: Execute essential checks only
- `-MinimumSeverity`: Filter findings by severity (Critical, High, Medium, Low, All)

### Security-Audit-Master.ps1 Specific
```powershell
.\Security-Audit-Master.ps1 
    -WhatIf                    # Preview mode
    -Remediate                 # Enable auto-remediation
    -DetailedReport           # Generate detailed analysis
    -SeverityLevel "High"     # Filter by severity
    -ReportPath "C:\Reports\" # Custom report location
    -LogPath "C:\Logs\"       # Custom log location
```

### Advanced-Malware-Scanner.ps1 Specific
```powershell
.\Advanced-Malware-Scanner.ps1
    -DeepScan                 # Comprehensive analysis
    -QuarantineMode          # Auto-quarantine threats
    -ScanPath "C:\"          # Custom scan path
    -ThreadCount 4           # Parallel processing
```

### Vulnerability-Assessment.ps1 Specific
```powershell
.\Vulnerability-Assessment.ps1
    -AutoRemediate           # Fix vulnerabilities
    -DetailedScan           # Extended analysis
    -MinimumSeverity "Medium" # Severity threshold
```

### Ransomware-Protection.ps1 Specific
```powershell
.\Ransomware-Protection.ps1
    -EnableProtection        # Activate protection
    -MonitorMode            # Continuous monitoring
    -ProtectedFolders "..."  # Custom protected paths
```

## 📈 Report Generation

All scripts generate comprehensive HTML reports with:
- Executive summary dashboards
- Detailed findings with severity classification
- Visual charts and graphs
- Remediation recommendations
- Action logs and timestamps
- System information and metadata

### Report Types
1. **Security Audit Report**: Configuration compliance and security posture
2. **Malware Scan Report**: Threat detection results and quarantine actions
3. **Vulnerability Report**: Security weaknesses and patch requirements
4. **Ransomware Report**: Protection status and threat indicators
5. **Consolidated Report**: Unified view of all security assessments

## 🔧 Integration Options

### Nexthink Integration
All scripts support Nexthink Remote Actions with:
- Structured JSON output format
- Standardized exit codes
- Metric collection support
- Alert generation capabilities

### Example Nexthink Output
```json
{
  "Timestamp": "2025-01-15T10:30:45.123Z",
  "Success": true,
  "TotalFindings": 15,
  "CriticalFindings": 2,
  "HighFindings": 5,
  "RemediationActions": 8,
  "ReportPath": "C:\\Temp\\SecurityReport.html"
}
```

### Scheduled Execution
Configure Windows Task Scheduler for automated execution:

```powershell
# Daily security check
schtasks /create /tn "DailySecurityCheck" /tr "powershell.exe -File 'C:\Scripts\Security-Test-Runner.ps1' -QuickScan" /sc daily /st 02:00

# Weekly comprehensive scan
schtasks /create /tn "WeeklySecurityScan" /tr "powershell.exe -File 'C:\Scripts\Security-Test-Runner.ps1' -FullScan -AutoRemediate" /sc weekly /d SUN /st 01:00
```

## 🛠️ Troubleshooting

### Common Issues

1. **Execution Policy Restrictions**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Insufficient Permissions**
   - Run PowerShell as Administrator
   - Ensure user has local administrative rights

3. **Windows Defender Interference**
   - Add script directory to exclusions
   - Temporarily disable real-time protection for testing

4. **Network Connectivity Issues**
   - Verify internet access for update checks
   - Configure proxy settings if required

### Debug Mode
Enable verbose logging with:
```powershell
$VerbosePreference = "Continue"
.\Security-Test-Runner.ps1 -Verbose
```

## 📋 Best Practices

### Security Considerations
1. **Test in Non-Production**: Always test scripts in isolated environments first
2. **Backup Systems**: Create system restore points before remediation
3. **Monitor Logs**: Review execution logs for errors and warnings
4. **Regular Updates**: Keep scripts updated with latest security patterns
5. **Access Control**: Restrict script access to authorized personnel

### Performance Optimization
1. **Staged Execution**: Run resource-intensive scans during maintenance windows
2. **Parallel Processing**: Utilize multi-threading capabilities where available  
3. **Incremental Scans**: Use quick scans for routine monitoring
4. **Resource Limits**: Monitor CPU and memory usage during execution

### Maintenance Schedule
- **Daily**: Quick security checks and monitoring
- **Weekly**: Comprehensive vulnerability assessments
- **Monthly**: Full malware scans and deep analysis
- **Quarterly**: Complete security posture reviews

## 🔐 Security Features

### Multi-Layered Protection
- **Preventive**: Configuration hardening and policy enforcement
- **Detective**: Threat monitoring and anomaly detection
- **Responsive**: Automated remediation and quarantine
- **Recovery**: Backup creation and restore point management

### Threat Intelligence
- **Signature Updates**: Latest malware definitions and indicators
- **Behavioral Analysis**: Dynamic threat detection capabilities
- **Network Monitoring**: Communication pattern analysis
- **Registry Surveillance**: Persistence mechanism detection

## 📞 Support and Maintenance

### Documentation
- Individual script headers contain detailed parameter documentation
- PowerShell help system integration: `Get-Help .\ScriptName.ps1 -Full`
- Inline code comments for complex logic sections

### Updates and Patches
- Monitor security advisories for new threat patterns
- Update malware signatures and vulnerability databases
- Review and enhance detection algorithms regularly
- Test script compatibility with Windows updates

### Community Contributions
- Follow coding standards and documentation requirements
- Test thoroughly in multiple environments
- Provide detailed commit messages and change logs
- Coordinate with security team for deployment approval

---

**⚠️ Important Notice**: These scripts perform advanced security operations that may affect system performance and stability. Always test thoroughly in non-production environments before deploying to critical systems. Ensure proper backups and recovery procedures are in place before executing remediation actions.

**🔒 Security Disclaimer**: While these scripts provide comprehensive security assessments, they should be used as part of a broader security strategy including regular updates, proper network segmentation, user education, and professional security monitoring services.
