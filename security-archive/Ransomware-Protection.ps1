# Ransomware-Protection.ps1
# Advanced ransomware detection and protection for Windows 11
# Implements multiple layers of ransomware defense

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$EnableProtection,
    [switch]$DisableProtection,
    [switch]$MonitorMode,
    [string]$ProtectedFolders = "$env:USERPROFILE\Documents;$env:USERPROFILE\Pictures;$env:USERPROFILE\Videos;$env:USERPROFILE\Desktop",
    [string]$LogPath = "$env:TEMP\RansomwareProtection.log",
    [int]$SuspiciousFileThreshold = 10,
    [string]$QuarantinePath = "$env:TEMP\RansomwareQuarantine"
)

# Initialize logging
function Write-RansomwareLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "PROTECTION"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] [$Category] $Message"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "ALERT" { "Magenta" }
        "CRITICAL" { "DarkRed" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    # Also write to Windows Event Log for monitoring
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("RansomwareProtection")) {
            [System.Diagnostics.EventLog]::CreateEventSource("RansomwareProtection", "Application")
        }
        $eventID = switch ($Level) {
            "CRITICAL" { 1001 }
            "ALERT" { 1002 }
            "ERROR" { 1003 }
            "WARNING" { 1004 }
            default { 1005 }
        }
        Write-EventLog -LogName Application -Source "RansomwareProtection" -EventId $eventID -EntryType Information -Message $logEntry
    }
    catch {
        # Event log writing failed, continue silently
    }
}

# Ransomware detection patterns
$script:RansomwareIndicators = @{
    FileExtensions = @(
        ".encrypt", ".encrypted", ".locked", ".crypto", ".crypt", ".zcrypt", ".locky", ".zepto", ".odin", ".shit", ".fuck",
        ".dharma", ".wallet", ".onion", ".wncry", ".wcry", ".cerber", ".sage", ".spora", ".mole", ".globeimposter",
        ".purge", ".crysis", ".arena", ".redrum", ".japanese", ".korean", ".china", ".russian", ".herbst", ".nuclear",
        ".xorist", ".xtbl", ".micro", ".encoded", ".xxx", ".ttt", ".mp3", ".bip", ".lol", ".OMG!", ".RDM", ".RRK",
        ".encryptedRSA", ".crjoker", ".EnCiPhErEd", ".LeChiffre", ".keybtc@inbox_com", ".0x0", ".bleep", ".1999",
        ".vault", ".ha3", ".toxcrypt", ".magic", ".SUPERCRYPT", ".CTBL", ".CTB2", ".locky", ".zepto", ".odin"
    )
    
    RansomwareNotes = @(
        "README", "DECRYPT", "RESTORE", "RECOVERY", "HOW_TO_DECRYPT", "FILES_ENCRYPTED", "RANSOM", "PAYMENT",
        "HOW_TO_RESTORE", "ENCRYPTED", "YOUR_FILES", "UNLOCK", "BITCOIN", "TOR", "DARKNET", "DECRYPT_INSTRUCTION",
        "FILE_RECOVERY", "RESTORE_FILES", "IMPORTANT", "ATTENTION", "WARNING", "NOTICE", "INFO", "INSTRUCTION"
    )
    
    SuspiciousProcessNames = @(
        "cryptolocker", "cryptowall", "locky", "cerber", "petya", "wannacry", "ransomware", "encrypt", "crypt",
        "locker", "dharma", "sage", "spora", "globe", "purge", "crysis", "badrabbit", "notpetya", "ryuk", "maze",
        "sodinokibi", "revil", "conti", "egregor", "darkside", "babuk", "avaddon", "ragnar", "ransomexx"
    )
    
    SuspiciousFilenames = @(
        "*.exe.encrypted", "*.pdf.locked", "*.jpg.crypto", "*.docx.enc", "*HELP*", "*DECRYPT*", "*README*",
        "*RESTORE*", "*RECOVERY*", "*HOW_TO*", "*FILES_ENCRYPTED*", "*RANSOM*", "*YOUR_FILES*"
    )
    
    RegistryIndicators = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*crypt*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*lock*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*ransom*"
    )
}

# Detection results storage
$script:RansomwareThreats = @()
$script:ProtectionActions = @()

function Add-RansomwareThreat {
    param(
        [string]$ThreatType,
        [string]$FilePath,
        [string]$ProcessName = "",
        [string]$Severity,
        [string]$Description,
        [hashtable]$Evidence = @{}
    )
    
    $threat = [PSCustomObject]@{
        Timestamp = Get-Date
        ThreatType = $ThreatType
        FilePath = $FilePath
        ProcessName = $ProcessName
        Severity = $Severity
        Description = $Description
        Evidence = $Evidence
        ActionTaken = $false
    }
    
    $script:RansomwareThreats += $threat
    Write-RansomwareLog "RANSOMWARE THREAT: [$Severity] $ThreatType - $Description" "ALERT" $ThreatType
}

# Enable Windows Defender ransomware protection features
function Enable-DefenderRansomwareProtection {
    Write-RansomwareLog "Configuring Windows Defender ransomware protection" "INFO" "DEFENDER"
    
    try {
        # Enable controlled folder access
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would enable Controlled Folder Access" "INFO" "DEFENDER"
        } else {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Write-RansomwareLog "Controlled Folder Access enabled" "SUCCESS" "DEFENDER"
        }
        
        # Enable network protection
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would enable Network Protection" "INFO" "DEFENDER"
        } else {
            Set-MpPreference -EnableNetworkProtection Enabled
            Write-RansomwareLog "Network Protection enabled" "SUCCESS" "DEFENDER"
        }
        
        # Enable real-time protection
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would enable Real-time Protection" "INFO" "DEFENDER"
        } else {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-RansomwareLog "Real-time Protection enabled" "SUCCESS" "DEFENDER"
        }
        
        # Configure additional folders for controlled folder access
        $folders = $ProtectedFolders -split ";"
        foreach ($folder in $folders) {
            if (Test-Path $folder.Trim()) {
                if ($WhatIf) {
                    Write-RansomwareLog "WhatIf: Would add protected folder: $($folder.Trim())" "INFO" "DEFENDER"
                } else {
                    try {
                        Add-MpPreference -ControlledFolderAccessProtectedFolders $folder.Trim()
                        Write-RansomwareLog "Added protected folder: $($folder.Trim())" "SUCCESS" "DEFENDER"
                    }
                    catch {
                        # Folder might already be protected
                        Write-RansomwareLog "Folder already protected or error adding: $($folder.Trim())" "INFO" "DEFENDER"
                    }
                }
            }
        }
        
        # Enable cloud protection
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would enable Cloud Protection" "INFO" "DEFENDER"
        } else {
            Set-MpPreference -MAPSReporting Advanced
            Set-MpPreference -SubmitSamplesConsent SendAllSamples
            Write-RansomwareLog "Cloud Protection configured" "SUCCESS" "DEFENDER"
        }
        
        Write-RansomwareLog "Windows Defender ransomware protection configuration completed" "SUCCESS" "DEFENDER"
    }
    catch {
        Write-RansomwareLog "Error configuring Windows Defender: $($_.Exception.Message)" "ERROR" "DEFENDER"
    }
}

# Disable ransomware protection (for testing or troubleshooting)
function Disable-DefenderRansomwareProtection {
    Write-RansomwareLog "Disabling Windows Defender ransomware protection" "WARNING" "DEFENDER"
    
    try {
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would disable Controlled Folder Access" "INFO" "DEFENDER"
            Write-RansomwareLog "WhatIf: Would disable Network Protection" "INFO" "DEFENDER"
        } else {
            Set-MpPreference -EnableControlledFolderAccess Disabled
            Set-MpPreference -EnableNetworkProtection Disabled
            Write-RansomwareLog "Ransomware protection features disabled" "SUCCESS" "DEFENDER"
        }
    }
    catch {
        Write-RansomwareLog "Error disabling protection: $($_.Exception.Message)" "ERROR" "DEFENDER"
    }
}

# Scan for active ransomware processes
function Scan-ActiveRansomwareProcesses {
    Write-RansomwareLog "Scanning for active ransomware processes" "INFO" "PROCESS_SCAN"
    
    try {
        $runningProcesses = Get-Process | Select-Object Name, Path, Id, CPU, WorkingSet64
        
        foreach ($process in $runningProcesses) {
            if (-not $process.Path) { continue }
            
            # Check against known ransomware process names
            foreach ($suspiciousName in $script:RansomwareIndicators.SuspiciousProcessNames) {
                if ($process.Name -like "*$suspiciousName*") {
                    Add-RansomwareThreat -ThreatType "ACTIVE_PROCESS" -FilePath $process.Path -ProcessName $process.Name -Severity "Critical" `
                        -Description "Known ransomware process detected" `
                        -Evidence @{ ProcessID = $process.Id; CPU = $process.CPU; Memory = $process.WorkingSet64 }
                    
                    # Attempt to terminate malicious process
                    if (-not $WhatIf) {
                        try {
                            Stop-Process -Id $process.Id -Force
                            Write-RansomwareLog "Terminated malicious process: $($process.Name) (PID: $($process.Id))" "SUCCESS" "PROCESS_SCAN"
                            $script:ProtectionActions += [PSCustomObject]@{
                                Action = "ProcessTermination"
                                Target = "$($process.Name) (PID: $($process.Id))"
                                Status = "Success"
                                Timestamp = Get-Date
                            }
                        }
                        catch {
                            Write-RansomwareLog "Failed to terminate process: $($process.Name)" "ERROR" "PROCESS_SCAN"
                        }
                    }
                }
            }
            
            # Check for processes running from temp directories
            if ($process.Path -match "\\Temp\\|\\AppData\\Local\\Temp\\") {
                $processInfo = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
                if ($processInfo -and $processInfo.CPU -gt 5) {  # High CPU usage
                    Add-RansomwareThreat -ThreatType "SUSPICIOUS_PROCESS" -FilePath $process.Path -ProcessName $process.Name -Severity "High" `
                        -Description "High CPU process running from temporary directory" `
                        -Evidence @{ ProcessID = $process.Id; CPU = $process.CPU; TempLocation = $true }
                }
            }
        }
        
        Write-RansomwareLog "Active process scan completed" "SUCCESS" "PROCESS_SCAN"
    }
    catch {
        Write-RansomwareLog "Error scanning active processes: $($_.Exception.Message)" "ERROR" "PROCESS_SCAN"
    }
}

# Scan for ransomware file indicators
function Scan-RansomwareFileIndicators {
    Write-RansomwareLog "Scanning for ransomware file indicators" "INFO" "FILE_SCAN"
    
    try {
        $scanPaths = @(
            $env:USERPROFILE,
            "C:\Users\Public",
            $env:TEMP,
            "$env:LOCALAPPDATA\Temp"
        )
        
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            
            Write-RansomwareLog "Scanning path: $scanPath" "INFO" "FILE_SCAN"
            
            # Look for encrypted files with suspicious extensions
            foreach ($extension in $script:RansomwareIndicators.FileExtensions) {
                $encryptedFiles = Get-ChildItem -Path $scanPath -Recurse -File -Filter "*$extension" -ErrorAction SilentlyContinue | Select-Object -First 100
                
                if ($encryptedFiles.Count -gt 0) {
                    Add-RansomwareThreat -ThreatType "ENCRYPTED_FILES" -FilePath $scanPath -Severity "Critical" `
                        -Description "Files with ransomware encryption extensions detected" `
                        -Evidence @{ Extension = $extension; FileCount = $encryptedFiles.Count; Files = ($encryptedFiles | Select-Object -First 10).FullName }
                }
            }
            
            # Look for ransom notes
            foreach ($notePattern in $script:RansomwareIndicators.RansomwareNotes) {
                $ransomNotes = Get-ChildItem -Path $scanPath -Recurse -File -Filter "*$notePattern*" -ErrorAction SilentlyContinue | 
                              Where-Object { $_.Extension -in @(".txt", ".html", ".htm", ".jpg", ".png", ".bmp") } |
                              Select-Object -First 50
                
                foreach ($note in $ransomNotes) {
                    try {
                        $content = Get-Content -Path $note.FullName -Raw -ErrorAction Stop
                        $suspiciousTerms = @("decrypt", "bitcoin", "ransom", "payment", "tor", "darknet", "encrypted", "restore your files")
                        $matchedTerms = $suspiciousTerms | Where-Object { $content -match $_ }
                        
                        if ($matchedTerms.Count -ge 2) {
                            Add-RansomwareThreat -ThreatType "RANSOM_NOTE" -FilePath $note.FullName -Severity "Critical" `
                                -Description "Suspected ransom note detected" `
                                -Evidence @{ MatchedTerms = $matchedTerms; FileSize = $note.Length }
                        }
                    }
                    catch {
                        # File might be locked or binary
                    }
                }
            }
            
            # Look for mass file modification patterns (recent rapid changes)
            $recentlyModified = Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue | 
                               Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-30) } |
                               Select-Object -First 1000
            
            if ($recentlyModified.Count -gt $SuspiciousFileThreshold) {
                $extensionGroups = $recentlyModified | Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 5
                $topExtension = $extensionGroups[0]
                
                if ($topExtension.Count -gt ($recentlyModified.Count * 0.5)) {
                    Add-RansomwareThreat -ThreatType "MASS_ENCRYPTION" -FilePath $scanPath -Severity "Critical" `
                        -Description "Mass file modification pattern detected (potential encryption)" `
                        -Evidence @{ RecentFiles = $recentlyModified.Count; TopExtension = $topExtension.Name; TopExtensionCount = $topExtension.Count }
                }
            }
        }
        
        Write-RansomwareLog "File indicator scan completed" "SUCCESS" "FILE_SCAN"
    }
    catch {
        Write-RansomwareLog "Error scanning file indicators: $($_.Exception.Message)" "ERROR" "FILE_SCAN"
    }
}

# Monitor network connections for ransomware communication
function Monitor-RansomwareNetwork {
    Write-RansomwareLog "Monitoring network connections for ransomware indicators" "INFO" "NETWORK_MONITOR"
    
    try {
        $networkConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        
        # Suspicious ports commonly used by ransomware
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337, 443, 80, 8080, 9050)
        
        foreach ($connection in $networkConnections) {
            if ($suspiciousPorts -contains $connection.RemotePort) {
                try {
                    $process = Get-Process -Id $connection.OwningProcess -ErrorAction Stop
                    
                    # Check if process is suspicious
                    $isSuspicious = $false
                    foreach ($suspiciousName in $script:RansomwareIndicators.SuspiciousProcessNames) {
                        if ($process.Name -like "*$suspiciousName*") {
                            $isSuspicious = $true
                            break
                        }
                    }
                    
                    if ($isSuspicious -or $connection.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999, 31337)) {
                        Add-RansomwareThreat -ThreatType "SUSPICIOUS_NETWORK" -FilePath $process.Path -ProcessName $process.Name -Severity "High" `
                            -Description "Suspicious network connection detected" `
                            -Evidence @{ RemoteAddress = $connection.RemoteAddress; RemotePort = $connection.RemotePort; ProcessID = $process.Id }
                    }
                }
                catch {
                    # Process might have ended or be inaccessible
                }
            }
        }
        
        Write-RansomwareLog "Network monitoring completed" "SUCCESS" "NETWORK_MONITOR"
    }
    catch {
        Write-RansomwareLog "Error monitoring network connections: $($_.Exception.Message)" "ERROR" "NETWORK_MONITOR"
    }
}

# Check registry for ransomware persistence
function Check-RansomwareRegistry {
    Write-RansomwareLog "Checking registry for ransomware persistence indicators" "INFO" "REGISTRY_SCAN"
    
    try {
        $registryLocations = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($regPath in $registryLocations) {
            try {
                $regEntries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regEntries) {
                    foreach ($property in $regEntries.PSObject.Properties) {
                        if ($property.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) { continue }
                        
                        $value = $property.Value
                        if ($value) {
                            # Check for suspicious patterns in registry values
                            $suspiciousPatterns = @("encrypt", "crypt", "lock", "ransom", "bitcoin", "tor", ".onion")
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($value -match $pattern) {
                                    Add-RansomwareThreat -ThreatType "REGISTRY_PERSISTENCE" -FilePath $regPath -Severity "High" `
                                        -Description "Suspicious registry persistence entry detected" `
                                        -Evidence @{ EntryName = $property.Name; EntryValue = $value; Pattern = $pattern }
                                }
                            }
                            
                            # Check for executables in temp directories
                            if ($value -match "\\Temp\\.*\.exe|\\AppData\\Local\\Temp\\.*\.exe") {
                                Add-RansomwareThreat -ThreatType "REGISTRY_PERSISTENCE" -FilePath $regPath -Severity "Medium" `
                                    -Description "Registry entry pointing to executable in temp directory" `
                                    -Evidence @{ EntryName = $property.Name; EntryValue = $value }
                            }
                        }
                    }
                }
            }
            catch {
                # Registry path might not exist or be inaccessible
            }
        }
        
        Write-RansomwareLog "Registry scan completed" "SUCCESS" "REGISTRY_SCAN"
    }
    catch {
        Write-RansomwareLog "Error checking registry: $($_.Exception.Message)" "ERROR" "REGISTRY_SCAN"
    }
}

# Create system restore point for recovery
function Create-RecoveryPoint {
    Write-RansomwareLog "Creating system restore point for ransomware protection" "INFO" "RECOVERY"
    
    try {
        if ($WhatIf) {
            Write-RansomwareLog "WhatIf: Would create system restore point" "INFO" "RECOVERY"
        } else {
            # Enable system restore if not enabled
            Enable-ComputerRestore -Drive "C:"
            
            # Create restore point
            Checkpoint-Computer -Description "RansomwareProtection_$(Get-Date -Format 'yyyyMMdd_HHmmss')" -RestorePointType "APPLICATION_INSTALL"
            Write-RansomwareLog "System restore point created successfully" "SUCCESS" "RECOVERY"
            
            $script:ProtectionActions += [PSCustomObject]@{
                Action = "RestorePointCreation"
                Target = "System Restore Point"
                Status = "Success"
                Timestamp = Get-Date
            }
        }
    }
    catch {
        Write-RansomwareLog "Error creating restore point: $($_.Exception.Message)" "ERROR" "RECOVERY"
    }
}

# Backup critical files to secure location
function Backup-CriticalFiles {
    Write-RansomwareLog "Creating backup of critical files" "INFO" "BACKUP"
    
    try {
        $backupPath = "$env:TEMP\RansomwareBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if (-not $WhatIf) {
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        }
        
        $criticalPaths = @(
            "$env:USERPROFILE\Documents\*.doc*",
            "$env:USERPROFILE\Documents\*.pdf",
            "$env:USERPROFILE\Pictures\*.jpg",
            "$env:USERPROFILE\Pictures\*.png",
            "$env:USERPROFILE\Desktop\*.txt"
        )
        
        $backedUpFiles = 0
        foreach ($path in $criticalPaths) {
            $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -First 100  # Limit for performance
            foreach ($file in $files) {
                if ($WhatIf) {
                    Write-RansomwareLog "WhatIf: Would backup $($file.FullName)" "INFO" "BACKUP"
                } else {
                    try {
                        Copy-Item -Path $file.FullName -Destination $backupPath -ErrorAction Stop
                        $backedUpFiles++
                    }
                    catch {
                        Write-RansomwareLog "Failed to backup $($file.FullName): $($_.Exception.Message)" "WARNING" "BACKUP"
                    }
                }
            }
        }
        
        if ($backedUpFiles -gt 0) {
            Write-RansomwareLog "Backed up $backedUpFiles critical files to $backupPath" "SUCCESS" "BACKUP"
            $script:ProtectionActions += [PSCustomObject]@{
                Action = "FileBackup"
                Target = "$backedUpFiles files"
                Status = "Success"
                Timestamp = Get-Date
            }
        }
    }
    catch {
        Write-RansomwareLog "Error during backup: $($_.Exception.Message)" "ERROR" "BACKUP"
    }
}

# Generate ransomware protection report
function Generate-RansomwareReport {
    Write-RansomwareLog "Generating ransomware protection report" "INFO" "REPORT"
    
    $reportPath = $LogPath.Replace(".log", "_Report.html")
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Ransomware Protection Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #ff6b6b, #ee5a24); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .status-dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .status-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 2px 15px rgba(0,0,0,0.1); }
        .status-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .critical-status { color: #e74c3c; }
        .warning-status { color: #f39c12; }
        .safe-status { color: #27ae60; }
        .threat-alert { background: linear-gradient(135deg, #ff6b6b, #ee5a24); color: white; margin: 20px; padding: 20px; border-radius: 10px; }
        .threat-item { background: white; margin: 15px 20px; padding: 20px; border-radius: 10px; border-left: 5px solid #e74c3c; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .protection-status { background: #d5edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; margin: 20px; border-radius: 10px; }
        .action-log { background: white; margin: 20px; padding: 20px; border-radius: 10px; }
        .action-table { width: 100%; border-collapse: collapse; }
        .action-table th, .action-table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        .action-table th { background: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Ransomware Protection Report</h1>
            <p>Advanced Ransomware Detection & Protection System</p>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Computer: $env:COMPUTERNAME</p>
        </div>
        
        <div class="status-dashboard">
            <div class="status-card">
                <div class="status-number $(if ($script:RansomwareThreats.Count -eq 0) { 'safe-status' } else { 'critical-status' })">
                    $($script:RansomwareThreats.Count)
                </div>
                <div>Threats Detected</div>
            </div>
            <div class="status-card">
                <div class="status-number critical-status">$(($script:RansomwareThreats | Where-Object Severity -eq "Critical").Count)</div>
                <div>Critical Threats</div>
            </div>
            <div class="status-card">
                <div class="status-number warning-status">$(($script:RansomwareThreats | Where-Object Severity -eq "High").Count)</div>
                <div>High Priority</div>
            </div>
            <div class="status-card">
                <div class="status-number safe-status">$($script:ProtectionActions.Count)</div>
                <div>Protection Actions</div>
            </div>
        </div>
        
        $(if ($script:RansomwareThreats.Count -eq 0) {
            '<div class="protection-status">
                <h3>✅ System Status: PROTECTED</h3>
                <p>No ransomware threats detected. Your system appears to be clean and protected.</p>
            </div>'
        } else {
            '<div class="threat-alert">
                <h3>⚠️ RANSOMWARE THREATS DETECTED</h3>
                <p>Immediate action required! Ransomware activity has been detected on your system.</p>
            </div>'
        })
        
        <h2 style="padding: 0 20px;">🔍 Threat Detection Results</h2>
"@
    
    if ($script:RansomwareThreats.Count -gt 0) {
        foreach ($threat in ($script:RansomwareThreats | Sort-Object Severity, ThreatType)) {
            $html += @"
        <div class="threat-item">
            <h4>[$($threat.ThreatType)] $($threat.Severity) Severity</h4>
            <p><strong>Description:</strong> $($threat.Description)</p>
            <p><strong>File/Path:</strong> $($threat.FilePath)</p>
            $(if ($threat.ProcessName) { "<p><strong>Process:</strong> $($threat.ProcessName)</p>" })
            <p><strong>Detected:</strong> $($threat.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            $(if ($threat.Evidence.Count -gt 0) { 
                "<p><strong>Evidence:</strong> $($threat.Evidence.Keys -join ', ')</p>" 
            })
        </div>
"@
        }
    } else {
        $html += '<div style="text-align: center; padding: 40px; color: #27ae60;"><h3>No threats detected - System is clean</h3></div>'
    }
    
    if ($script:ProtectionActions.Count -gt 0) {
        $html += @"
        
        <div class="action-log">
            <h3>🔧 Protection Actions Taken</h3>
            <table class="action-table">
                <tr>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                </tr>
"@
        
        foreach ($action in $script:ProtectionActions) {
            $html += @"
                <tr>
                    <td>$($action.Action)</td>
                    <td>$($action.Target)</td>
                    <td style="color: $(if ($action.Status -eq 'Success') { '#27ae60' } else { '#e74c3c' });">$($action.Status)</td>
                    <td>$($action.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                </tr>
"@
        }
        
        $html += "</table></div>"
    }
    
    $html += @"
        
        <div style="background: #f8f9fa; padding: 20px; margin: 20px; border-radius: 10px;">
            <h3>📋 Protection Summary</h3>
            <p><strong>Scan Coverage:</strong> Active Processes, File System, Network Connections, Registry</p>
            <p><strong>Protection Features:</strong> Windows Defender Integration, Real-time Monitoring, Behavioral Analysis</p>
            <p><strong>Recommendation:</strong> $(
                if (($script:RansomwareThreats | Where-Object Severity -eq "Critical").Count -gt 0) {
                    "🔴 URGENT: Disconnect from network immediately and contact IT security team."
                } elseif ($script:RansomwareThreats.Count -gt 0) {
                    "🟡 Monitor system closely and run additional security scans."
                } else {
                    "🟢 Continue regular security monitoring and keep protection enabled."
                }
            )</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-RansomwareLog "Ransomware protection report generated: $reportPath" "SUCCESS" "REPORT"
    return $reportPath
}

# Main execution function
function Start-RansomwareProtection {
    $script:ProtectionStartTime = Get-Date
    
    Write-RansomwareLog "Starting Advanced Ransomware Protection System" "INFO" "MAIN"
    Write-RansomwareLog "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "INFO" "MAIN"
    Write-RansomwareLog "Parameters: EnableProtection=$($EnableProtection.IsPresent), DisableProtection=$($DisableProtection.IsPresent), MonitorMode=$($MonitorMode.IsPresent)" "INFO" "MAIN"
    
    try {
        # Handle protection enable/disable
        if ($EnableProtection) {
            Enable-DefenderRansomwareProtection
            Create-RecoveryPoint
        } elseif ($DisableProtection) {
            Disable-DefenderRansomwareProtection
            return
        }
        
        # Always run detection scans
        Scan-ActiveRansomwareProcesses
        Scan-RansomwareFileIndicators
        Monitor-RansomwareNetwork
        Check-RansomwareRegistry
        
        # Backup critical files if threats detected
        if ($script:RansomwareThreats.Count -gt 0 -and -not $WhatIf) {
            Backup-CriticalFiles
        }
        
        # Generate comprehensive report
        $reportPath = Generate-RansomwareReport
        
        # Summary
        $duration = (Get-Date) - $script:ProtectionStartTime
        Write-RansomwareLog "Ransomware protection scan completed in $($duration.ToString('hh\:mm\:ss'))" "SUCCESS" "MAIN"
        Write-RansomwareLog "Total threats detected: $($script:RansomwareThreats.Count)" "INFO" "MAIN"
        Write-RansomwareLog "Report generated: $reportPath" "INFO" "MAIN"
        
        # Return results for Nexthink
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $true
            ThreatsDetected = $script:RansomwareThreats.Count
            CriticalThreats = ($script:RansomwareThreats | Where-Object Severity -eq "Critical").Count
            HighThreats = ($script:RansomwareThreats | Where-Object Severity -eq "High").Count
            MediumThreats = ($script:RansomwareThreats | Where-Object Severity -eq "Medium").Count
            ProtectionActions = $script:ProtectionActions.Count
            ProtectionEnabled = $EnableProtection.IsPresent
            ScanDuration = $duration.TotalMinutes
            ReportPath = $reportPath
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        
        # Exit code based on threat severity
        $criticalThreats = ($script:RansomwareThreats | Where-Object Severity -eq "Critical").Count
        
        if ($criticalThreats -gt 0) {
            exit 2  # Critical ransomware threats detected
        } elseif ($script:RansomwareThreats.Count -gt 0) {
            exit 1  # Some threats detected
        } else {
            exit 0  # No threats detected
        }
    }
    catch {
        Write-RansomwareLog "Critical error during ransomware protection: $($_.Exception.Message)" "ERROR" "MAIN"
        
        $errorOutput = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $false
            Error = $_.Exception.Message
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $errorOutput"
        exit 1
    }
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Start-RansomwareProtection
}
