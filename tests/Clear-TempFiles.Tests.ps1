# Clear-TempFiles.Tests.ps1
# Pester tests for the temp files cleanup remediation script

Describe "Clear-TempFiles Tests" {
    
    BeforeAll {
        # Import the script being tested
        $scriptPath = Join-Path $PSScriptRoot "..\scripts\Clear-TempFiles.ps1"
        . $scriptPath
        
        # Mock external dependencies
        Mock Write-Host {}
        Mock Add-Content {}
    }
    
    Context "Helper Functions" {
        
        Describe "Get-FolderSize" {
            It "Should return 0 for non-existent path" {
                Mock Test-Path { return $false }
                Get-FolderSize -Path "C:\NonExistent" | Should -Be 0
            }
            
            It "Should calculate folder size correctly" {
                Mock Test-Path { return $true }
                Mock Get-ChildItem { 
                    return @(
                        @{ Length = 1024 },
                        @{ Length = 2048 }
                    )
                }
                Mock Measure-Object { return @{ Sum = 3072 } }
                
                $result = Get-FolderSize -Path "C:\TestPath"
                $result | Should -BeGreaterThan 0
            }
            
            It "Should handle access errors gracefully" {
                Mock Test-Path { return $true }
                Mock Get-ChildItem { throw "Access denied" }
                
                Get-FolderSize -Path "C:\Restricted" | Should -Be 0
            }
        }
    }
    
    Context "Main Function Tests" {
        
        Describe "Clear-TempFiles WhatIf Mode" {
            BeforeEach {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 150 }  # Above threshold
                Mock Get-ChildItem { 
                    $files = @()
                    for ($i = 0; $i -lt 5; $i++) {
                        $files += [PSCustomObject]@{
                            LastWriteTime = (Get-Date).AddDays(-10)
                            Length = 1024
                        }
                    }
                    return $files
                }
                Mock Measure-Object { return @{ Sum = 5120 } }
            }
            
            It "Should report potential savings in WhatIf mode" {
                $result = Clear-TempFiles -WhatIf -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
                $result.WhatIf | Should -Be $true
                $result.FilesDeleted | Should -Be 0
            }
        }
        
        Describe "Clear-TempFiles Parameter Validation" {
            It "Should skip folders below size threshold" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 50 }  # Below threshold
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
                $result.FilesDeleted | Should -Be 0
            }
            
            It "Should handle missing temp paths gracefully" {
                Mock Test-Path { return $false }
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
            }
        }
        
        Describe "Clear-TempFiles File Deletion" {
            BeforeEach {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { 
                    param($Path)
                    # Return different sizes for before/after
                    if ($script:afterDelete) { return 50 } else { return 150 }
                }
                Mock Get-ChildItem { 
                    if ($_ -match "Recurse.*File") {
                        $oldDate = (Get-Date).AddDays(-10)
                        return @(
                            [PSCustomObject]@{ 
                                FullName = "C:\Temp\file1.tmp"
                                LastWriteTime = $oldDate 
                            },
                            [PSCustomObject]@{ 
                                FullName = "C:\Temp\file2.tmp"
                                LastWriteTime = $oldDate 
                            }
                        )
                    }
                }
                Mock Remove-Item { 
                    $script:afterDelete = $true
                }
            }
            
            It "Should delete old files successfully" {
                $script:afterDelete = $false
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
                $result.FilesDeleted | Should -BeGreaterThan 0
                Should -Invoke Remove-Item -AtLeast 1
            }
            
            It "Should handle file deletion errors gracefully" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 150 }
                Mock Get-ChildItem { 
                    return @([PSCustomObject]@{ 
                        FullName = "C:\Temp\locked.tmp"
                        LastWriteTime = (Get-Date).AddDays(-10)
                    })
                }
                Mock Remove-Item { throw "File is locked" }
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
                $result.FilesDeleted | Should -Be 0
            }
        }
        
        Describe "Clear-TempFiles Date Filtering" {
            It "Should only delete files older than specified days" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 150 }
                
                $recentFile = [PSCustomObject]@{
                    FullName = "C:\Temp\recent.tmp"
                    LastWriteTime = (Get-Date).AddDays(-5)  # Recent file
                }
                $oldFile = [PSCustomObject]@{
                    FullName = "C:\Temp\old.tmp"
                    LastWriteTime = (Get-Date).AddDays(-10)  # Old file
                }
                
                Mock Get-ChildItem { return @($recentFile, $oldFile) }
                Mock Remove-Item {}
                
                Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                # Should only delete the old file
                Should -Invoke Remove-Item -Times 1 -ParameterFilter { 
                    $Path -eq "C:\Temp\old.tmp" 
                }
                Should -Invoke Remove-Item -Times 0 -ParameterFilter { 
                    $Path -eq "C:\Temp\recent.tmp" 
                }
            }
        }
    }
    
    Context "Integration Tests" {
        
        Describe "Script Output Format" {
            It "Should produce valid JSON output with required fields" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 50 }  # Below threshold
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Not -BeNullOrEmpty
                $result.FilesDeleted | Should -BeOfType [int]
                $result.SizeSavedMB | Should -BeOfType [double]
                $result.SizeBeforeMB | Should -BeOfType [double]
                $result.SizeAfterMB | Should -BeOfType [double]
                $result.WhatIf | Should -BeOfType [bool]
                
                # Test JSON serialization
                $jsonOutput = @{
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    Success = $result.Success
                    FilesDeleted = $result.FilesDeleted
                    SizeSavedMB = $result.SizeSavedMB
                    SizeBeforeMB = $result.SizeBeforeMB
                    SizeAfterMB = $result.SizeAfterMB
                    WhatIf = $result.WhatIf
                    LogPath = "$env:TEMP\TempFilesRemediation.log"
                } | ConvertTo-Json -Compress
                
                { $jsonOutput | ConvertFrom-Json } | Should -Not -Throw
            }
        }
        
        Describe "Logging Functionality" {
            It "Should call Write-Log function appropriately" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 50 }
                Mock Write-Log {}
                
                Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                Should -Invoke Write-Log -AtLeast 2
            }
        }
    }
    
    Context "Performance and Edge Cases" {
        
        Describe "Large File Scenarios" {
            It "Should handle large numbers of files efficiently" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 500 }  # Large folder
                
                # Mock many files
                $manyFiles = @()
                for ($i = 0; $i -lt 1000; $i++) {
                    $manyFiles += [PSCustomObject]@{
                        FullName = "C:\Temp\file$i.tmp"
                        LastWriteTime = (Get-Date).AddDays(-10)
                    }
                }
                Mock Get-ChildItem { return $manyFiles }
                Mock Remove-Item {}
                
                $result = Clear-TempFiles -MaxSizeMB 100 -OlderThanDays 7
                
                $result.Success | Should -Be $true
                $result.FilesDeleted | Should -Be 1000
            }
        }
        
        Describe "Edge Case Parameters" {
            It "Should handle zero parameters correctly" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 0 }
                
                $result = Clear-TempFiles -MaxSizeMB 0 -OlderThanDays 0
                
                $result.Success | Should -Be $true
            }
            
            It "Should handle very large parameters" {
                Mock Test-Path { return $true }
                Mock Get-FolderSize { return 50 }
                
                $result = Clear-TempFiles -MaxSizeMB 99999 -OlderThanDays 365
                
                $result.Success | Should -Be $true
            }
        }
    }
}
