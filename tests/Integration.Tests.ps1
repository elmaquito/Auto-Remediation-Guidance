Describe "Integration Tests for Auto-Remediation Scripts" {
    
    BeforeAll {
        # Test environment setup
        $script:testScriptsPath = Join-Path $PSScriptRoot "..\scripts"
        $script:testOutputPath = Join-Path $env:TEMP "AutoRemediationTests"
        
        if (Test-Path $script:testOutputPath) {
            Remove-Item $script:testOutputPath -Recurse -Force
        }
        New-Item -Path $script:testOutputPath -ItemType Directory -Force | Out-Null
    }
    
    AfterAll {
        # Cleanup test environment
        if (Test-Path $script:testOutputPath) {
            Remove-Item $script:testOutputPath -Recurse -Force
        }
    }
    
    Context "Script Execution Tests" {
        
        Describe "Restart-WindowsUpdateService Integration" {
            BeforeEach {
                $scriptPath = Join-Path $script:testScriptsPath "Restart-WindowsUpdateService.ps1"
                $logPath = Join-Path $script:testOutputPath "WindowsUpdate_Integration.log"
            }
            
            It "Should execute without errors in WhatIf mode" {
                $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", $scriptPath,
                    "-WhatIf",
                    "-LogPath", $logPath
                ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$script:testOutputPath\stdout.txt" -RedirectStandardError "$script:testOutputPath\stderr.txt"
                
                $process.ExitCode | Should -Be 0
                Test-Path $logPath | Should -Be $true
            }
            
            It "Should produce valid Nexthink output format" {
                $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -WhatIf -LogPath $logPath
                
                $nexthinkOutput = $output | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
                $nexthinkOutput | Should -Not -BeNullOrEmpty
                
                $jsonData = ($nexthinkOutput -split "NEXTHINK_OUTPUT: ")[1]
                $parsedJson = $jsonData | ConvertFrom-Json
                
                $parsedJson.Timestamp | Should -Not -BeNullOrEmpty
                $parsedJson.Success | Should -BeOfType [bool]
                $parsedJson.Message | Should -Not -BeNullOrEmpty
                $parsedJson.ServiceStatus | Should -Not -BeNullOrEmpty
            }
        }
        
        Describe "Clear-TempFiles Integration" {
            BeforeEach {
                $scriptPath = Join-Path $script:testScriptsPath "Clear-TempFiles.ps1"
                $logPath = Join-Path $script:testOutputPath "TempFiles_Integration.log"
                
                # Create test temp files
                $testTempPath = Join-Path $script:testOutputPath "TestTemp"
                New-Item -Path $testTempPath -ItemType Directory -Force | Out-Null
                
                # Create old test files
                $oldFile = Join-Path $testTempPath "old_file.tmp"
                "Test content" | Out-File -FilePath $oldFile
                (Get-Item $oldFile).LastWriteTime = (Get-Date).AddDays(-10)
                
                # Create recent test files
                $recentFile = Join-Path $testTempPath "recent_file.tmp"
                "Test content" | Out-File -FilePath $recentFile
            }
            
            It "Should execute without errors in WhatIf mode" {
                $process = Start-Process -FilePath "powershell.exe" -ArgumentList @(
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", $scriptPath,
                    "-WhatIf",
                    "-MaxSizeMB", "1",
                    "-OlderThanDays", "7",
                    "-LogPath", $logPath
                ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$script:testOutputPath\stdout_temp.txt" -RedirectStandardError "$script:testOutputPath\stderr_temp.txt"
                
                $process.ExitCode | Should -Be 0
                Test-Path $logPath | Should -Be $true
            }
            
            It "Should produce valid Nexthink output format" {
                $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -WhatIf -MaxSizeMB 1 -OlderThanDays 7 -LogPath $logPath
                
                $nexthinkOutput = $output | Where-Object { $_ -match "NEXTHINK_OUTPUT:" }
                $nexthinkOutput | Should -Not -BeNullOrEmpty
                
                $jsonData = ($nexthinkOutput -split "NEXTHINK_OUTPUT: ")[1]
                $parsedJson = $jsonData | ConvertFrom-Json
                
                $parsedJson.Timestamp | Should -Not -BeNullOrEmpty
                $parsedJson.Success | Should -BeOfType [bool]
                $parsedJson.FilesDeleted | Should -BeOfType [int]
                $parsedJson.SizeSavedMB | Should -BeOfType [double]
                $parsedJson.WhatIf | Should -Be $true
            }
        }
    }
    
    Context "Cross-Script Compatibility Tests" {
        
        Describe "All Scripts Parameter Consistency" {
            It "Should all support -WhatIf parameter" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                foreach ($script in $scriptFiles) {
                    $scriptContent = Get-Content -Path $script.FullName -Raw
                    $scriptContent | Should -Match '\[switch\]\$WhatIf'
                }
            }
            
            It "Should all produce consistent log format" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                foreach ($script in $scriptFiles) {
                    $scriptContent = Get-Content -Path $script.FullName -Raw
                    $scriptContent | Should -Match 'Write-Log'
                    $scriptContent | Should -Match 'NEXTHINK_OUTPUT:'
                }
            }
        }
        
        Describe "Error Handling Consistency" {
            It "Should all have proper error handling" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                foreach ($script in $scriptFiles) {
                    $scriptContent = Get-Content -Path $script.FullName -Raw
                    $scriptContent | Should -Match 'try\s*{'
                    $scriptContent | Should -Match 'catch\s*{'
                }
            }
        }
    }
    
    Context "Performance Tests" {
        
        Describe "Script Execution Time" {
            It "Scripts should complete within reasonable time (WhatIf mode)" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                foreach ($script in $scriptFiles) {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    
                    Start-Process -FilePath "powershell.exe" -ArgumentList @(
                        "-NoProfile",
                        "-ExecutionPolicy", "Bypass",
                        "-File", $script.FullName,
                        "-WhatIf"
                    ) -Wait -PassThru -NoNewWindow
                    
                    $stopwatch.Stop()
                    
                    # Scripts should complete within 30 seconds in WhatIf mode
                    $stopwatch.ElapsedMilliseconds | Should -BeLessThan 30000
                    Write-Host "✅ $($script.Name): $($stopwatch.ElapsedMilliseconds)ms"
                }
            }
        }
    }
    
    Context "Security Tests" {
        
        Describe "Script Security Analysis" {
            It "Should not contain hardcoded credentials" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                $suspiciousPatterns = @(
                    'password\s*=\s*["\x27][^"\x27]+["\x27]',
                    'username\s*=\s*["\x27][^"\x27]+["\x27]',
                    'apikey\s*=\s*["\x27][^"\x27]+["\x27]'
                )
                
                foreach ($script in $scriptFiles) {
                    $scriptContent = Get-Content -Path $script.FullName -Raw
                    
                    foreach ($pattern in $suspiciousPatterns) {
                        $scriptContent | Should -Not -Match $pattern -Because "Script should not contain hardcoded credentials"
                    }
                }
            }
            
            It "Should use proper parameter validation" {
                $scriptFiles = Get-ChildItem -Path $script:testScriptsPath -Filter "*.ps1"
                
                foreach ($script in $scriptFiles) {
                    $scriptContent = Get-Content -Path $script.FullName -Raw
                    $scriptContent | Should -Match '\[CmdletBinding\(\)\]' -Because "Scripts should use CmdletBinding"
                }
            }
        }
    }
}
