# Windows Update Service Remediation Playbook

This playbook provides step-by-step guidance for implementing auto-remediation of Windows Update service issues using Nexthink v6 and PowerShell 5.1.

---

## 🎯 Scenario Overview

**Problem**: Windows Update service (wuauserv) stops unexpectedly, preventing security updates and patches from being installed.

**Impact**: 
- Security vulnerabilities remain unpatched
- Missing critical Windows updates
- Compliance issues
- End-user frustration with delayed updates

**Auto-Remediation Goal**: Automatically restart the Windows Update service when detected as stopped.

---

## 📋 Prerequisites

### Nexthink Environment
- Nexthink v6 Portal access with Remote Actions permissions
- Target devices enrolled in Nexthink
- PowerShell execution policy configured appropriately

### Script Requirements
- PowerShell 5.1+ on target devices
- Administrator privileges for service operations
- Network connectivity for script deployment

---

## 🔍 Detection Setup

### 1. Create Nexthink Investigation
Create an investigation to identify devices with stopped Windows Update service:

```sql
-- Investigation: Windows Update Service Status
(select (device)
from devices
where (service_status(device, "wuauserv") != "running"))
```

### 2. Configure Alert
Set up an alert to trigger when the investigation finds devices:

- **Alert Name**: Windows Update Service Down
- **Trigger Condition**: Investigation returns > 0 devices
- **Frequency**: Every 15 minutes
- **Action**: Launch Remote Action

---

## 🚀 Remediation Implementation

### 1. Upload Remediation Script
1. Navigate to **Remote Actions** in Nexthink Portal
2. Create new **PowerShell Script** action
3. Upload `sample-remediation-script.ps1`
4. Configure parameters:
   - **Name**: Restart Windows Update Service
   - **Description**: Auto-remediation for stopped Windows Update service
   - **Timeout**: 120 seconds
   - **Run As**: System (Administrator)

### 2. Script Parameters
Configure the script with appropriate parameters:

```powershell
# Basic remediation (restart only if stopped)
.\sample-remediation-script.ps1

# Forced restart (restart even if running)
.\sample-remediation-script.ps1 -Force

# Custom wait time between stop/start
.\sample-remediation-script.ps1 -Force -WaitTime 10
```

### 3. Target Device Selection
Set targeting criteria:
- **Operating System**: Windows 10, Windows 11
- **Device Status**: Online
- **Time Window**: Business hours (optional)
- **Maximum Concurrent Executions**: 50 devices

---

## 📊 Monitoring and Validation

### 1. Execution Monitoring
Monitor script execution through Nexthink Portal:

- Check **Remote Actions** execution status
- Review **Device Logs** for script output
- Monitor **Success Rate** and error patterns

### 2. Success Validation
Create follow-up investigation to verify remediation:

```sql
-- Investigation: Verify Windows Update Service Running
(select (device)
from devices
where (service_status(device, "wuauserv") = "running")
and (device in #[Devices_From_Previous_Alert]))
```

### 3. Expected Output Patterns
Look for these output patterns in logs:

**Success Pattern**:
```
[INFO] 2024-01-15 10:30:00: Starting Windows Update service remediation
[INFO] 2024-01-15 10:30:01: Found service: Windows Update - Current status: Stopped
[INFO] 2024-01-15 10:30:02: Starting Windows Update service...
[SUCCESS] 2024-01-15 10:30:05: Windows Update service started successfully
[SUCCESS] 2024-01-15 10:30:07: Service verification completed - Windows Update is healthy
```

**Error Pattern**:
```
[ERROR] 2024-01-15 10:30:00: Script requires administrator privileges
```

---

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Issue: Access Denied Errors
**Symptoms**: Exit code 3, "Script requires administrator privileges"
**Solution**: 
- Verify Remote Action is configured to "Run As System"
- Check device local security policies
- Ensure Nexthink agent has proper permissions

#### Issue: Service Start Timeout
**Symptoms**: Script hangs or timeout errors
**Solution**:
- Increase Remote Action timeout to 180+ seconds
- Check for Windows Update service dependencies
- Review Windows event logs for underlying service issues

#### Issue: Script Execution Policy Blocked
**Symptoms**: Script won't execute, execution policy errors
**Solution**:
- Configure Remote Action with `-ExecutionPolicy Bypass`
- Update group policy for PowerShell execution
- Consider script signing for production environments

### Escalation Triggers
Escalate to manual intervention when:
- Script fails consistently on same devices (>3 attempts)
- Exit code 2 (service not found) - may indicate OS issues
- High failure rate (>20%) across device population

---

## 📈 Success Metrics

### Key Performance Indicators
- **Remediation Success Rate**: Target >95%
- **Average Remediation Time**: Target <2 minutes
- **Reduction in Manual Tickets**: Measure before/after implementation
- **Service Uptime Improvement**: Track Windows Update service availability

### Reporting
Create dashboards to track:
1. **Daily Remediation Attempts**: Number of devices targeted
2. **Success/Failure Rates**: By device group, OS version, time period
3. **Time to Resolution**: From detection to successful remediation
4. **Cost Savings**: Reduced manual intervention hours

---

## 🔄 Maintenance and Updates

### Regular Review Tasks
- **Monthly**: Review failure patterns and success rates
- **Quarterly**: Update script with new error handling scenarios
- **Semi-annually**: Review and update targeting criteria

### Script Version Control
- Maintain version history of remediation scripts
- Test updates in non-production environment first
- Document changes and rollback procedures

### Documentation Updates
- Keep playbook updated with lessons learned
- Update troubleshooting section based on new issues
- Share best practices with other teams

---

## 📚 Related Resources

- [Introduction to Auto-Remediation](../docs/introduction.md)
- [Auto-Remediation Concepts](../docs/auto-remediation-concepts.md)
- [PowerShell 5.1 Compatibility Guide](../docs/powershell-5.1-compatibility.md)
- [Sample Remediation Script](../scripts/sample-remediation-script.ps1)

---

## 📞 Support and Contact

For questions about this playbook or implementation support:
- Create an issue in this repository
- Contact the Auto-Remediation Team
- Refer to Nexthink v6 documentation

**Last Updated**: [Current Date]  
**Version**: 1.0  
**Reviewed By**: [Team Name]