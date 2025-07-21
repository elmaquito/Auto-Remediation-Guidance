# Clear-TempFiles.ps1
# Sample remediation script to clear temporary files
# This script demonstrates auto-remediation concepts for Nexthink v6

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [int]$MaxSizeMB = 100,
    [int]$OlderThanDays = 7,
    [string]$LogPath = "$env:TEMP\TempFilesRemediation.log"
)

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-FolderSize {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            return [math]::Round($size / 1MB, 2)
        }
        return 0
    }
    catch {
        return 0
    }
}

function Clear-TempFiles {
    [CmdletBinding()]
    param(
        [switch]$WhatIf,
        [int]$MaxSizeMB,
        [int]$OlderThanDays
    )
    
    $tempPaths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:WINDIR\Temp"
    )
    
    $cutoffDate = (Get-Date).AddDays(-$OlderThanDays)
    $totalSizeBeforeMB = 0
    $totalSizeAfterMB = 0
    $filesDeleted = 0
    
    Write-Log "Starting temp files cleanup"
    Write-Log "Parameters: MaxSize=${MaxSizeMB}MB, OlderThan=${OlderThanDays}days"
    
    foreach ($tempPath in $tempPaths) {
        if (-not (Test-Path $tempPath)) {
            Write-Log "Path not found: $tempPath" "WARNING"
            continue
        }
        
        $initialSize = Get-FolderSize -Path $tempPath
        $totalSizeBeforeMB += $initialSize
        
        Write-Log "Processing: $tempPath (${initialSize}MB)"
        
        if ($initialSize -lt $MaxSizeMB) {
            Write-Log "Folder size (${initialSize}MB) below threshold (${MaxSizeMB}MB), skipping"
            continue
        }
        
        if ($WhatIf) {
            $oldFiles = Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue | 
                       Where-Object { $_.LastWriteTime -lt $cutoffDate }
            $potentialSavings = [math]::Round(($oldFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
            Write-Log "WhatIf: Would delete $($oldFiles.Count) files, saving ${potentialSavings}MB"
            continue
        }
        
        try {
            $filesToDelete = Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue | 
                            Where-Object { $_.LastWriteTime -lt $cutoffDate }
            
            foreach ($file in $filesToDelete) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $filesDeleted++
                }
                catch {
                    Write-Log "Failed to delete: $($file.FullName) - $($_.Exception.Message)" "WARNING"
                }
            }
            
            $finalSize = Get-FolderSize -Path $tempPath
            $totalSizeAfterMB += $finalSize
            $saved = $initialSize - $finalSize
            
            Write-Log "Completed: $tempPath - Saved ${saved}MB"
        }
        catch {
            Write-Log "Error processing $tempPath : $($_.Exception.Message)" "ERROR"
        }
    }
    
    $totalSaved = $totalSizeBeforeMB - $totalSizeAfterMB
    
    Write-Log "Cleanup completed: $filesDeleted files deleted, ${totalSaved}MB saved"
    
    return @{
        Success = $true
        FilesDeleted = $filesDeleted
        SizeSavedMB = $totalSaved
        SizeBeforeMB = $totalSizeBeforeMB
        SizeAfterMB = $totalSizeAfterMB
        WhatIf = $WhatIf.IsPresent
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Clear-TempFiles -WhatIf:$WhatIf -MaxSizeMB $MaxSizeMB -OlderThanDays $OlderThanDays
        
        # Output for Nexthink (JSON format)
        $output = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Success = $result.Success
            FilesDeleted = $result.FilesDeleted
            SizeSavedMB = $result.SizeSavedMB
            SizeBeforeMB = $result.SizeBeforeMB
            SizeAfterMB = $result.SizeAfterMB
            WhatIf = $result.WhatIf
            LogPath = $LogPath
        } | ConvertTo-Json -Compress
        
        Write-Host "NEXTHINK_OUTPUT: $output"
        exit 0
    }
    catch {
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
