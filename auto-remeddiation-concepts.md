# Auto-Remediation Concepts

Auto-remediation uses automation to resolve IT issues as soon as they are detected. With Nexthink v6 and PowerShell 5.1, you can trigger scripts to fix problems on endpoints automatically.

---

## Key Concepts

- **Detection**: Nexthink identifies an issue (e.g., a stopped service, high CPU, failed update).
- **Trigger**: A Nexthink Remote Action is launched, often via an alert or scheduled event.
- **Remediation**: A PowerShell script runs on the endpoint to address the issue.
- **Feedback**: Script results are reported back to Nexthink for visibility and further action.

---

## Best Practices

1. **Test Scripts**  
   Always test remediation scripts on a few devices before broad deployment.

2. **Idempotence**  
   Write scripts so they can be safely run multiple times.

3. **Logging**  
   Output clear logs for success/failure to help troubleshooting.

4. **Security**  
   Avoid hardcoding credentials. Use parameters and secure context.

---

## Example Workflow

1. Nexthink detects Windows Update service is not running.
2. Nexthink triggers a Remote Action that runs a PowerShell script.
3. The script attempts to restart the Windows Update service.
4. Script reports success/failure to Nexthink.

---

See [../scripts/sample-remediation-script.ps1](../scripts/sample-remediation-script.ps1) for a sample script.
