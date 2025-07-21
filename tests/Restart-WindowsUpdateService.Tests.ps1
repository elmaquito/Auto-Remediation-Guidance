# Restart-WindowsUpdateService.Tests.ps1
# Pester tests for the Windows Update service remediation script

Describe "Restart-WindowsUpdateService Tests" {
    
    BeforeAll {
        # Import the script being tested
        $scriptPath = Join-Path $PSScriptRoot "..\scripts\Restart-WindowsUpdateService.ps1"
        . $scriptPath
        
        # Mock external dependencies
        Mock Write-Host {}
        Mock Add-Content {}
    }
    
    Context "Helper Functions" {
        
        Describe "Test-ServiceExists" {
            It "Should return true for existing service" {
                Mock Get-Service { return @{ Name = "TestService" } }
                Test-ServiceExists -ServiceName "TestService" | Should -Be $true
            }
            
            It "Should return false for non-existing service" {
                Mock Get-Service { throw "Service not found" }
                Test-ServiceExists -ServiceName "NonExistentService" | Should -Be $false
            }
        }
        
        Describe "Get-ServiceStatus" {
            It "Should return correct service status" {
                Mock Get-Service { return @{ Status = "Running" } }
                Get-ServiceStatus -ServiceName "TestService" | Should -Be "Running"
            }
            
            It "Should return NotFound for non-existing service" {
                Mock Get-Service { throw "Service not found" }
                Get-ServiceStatus -ServiceName "NonExistentService" | Should -Be "NotFound"
            }
        }
    }
    
    Context "Main Function Tests" {
        
        Describe "Restart-WindowsUpdateService WhatIf Mode" {
            It "Should return success without making changes in WhatIf mode" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Stopped" }
                
                $result = Restart-WindowsUpdateService -WhatIf
                
                $result.Success | Should -Be $true
                $result.Message | Should -Be "WhatIf operation completed"
            }
        }
        
        Describe "Restart-WindowsUpdateService Service Not Found" {
            It "Should handle non-existent service gracefully" {
                Mock Test-ServiceExists { return $false }
                
                $result = Restart-WindowsUpdateService
                
                $result.Success | Should -Be $false
                $result.Message | Should -Be "Service not found"
                $result.ServiceStatus | Should -Be "NotFound"
            }
        }
        
        Describe "Restart-WindowsUpdateService Already Running" {
            It "Should return success if service is already running" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Running" }
                
                $result = Restart-WindowsUpdateService
                
                $result.Success | Should -Be $true
                $result.Message | Should -Be "Service already running"
                $result.ServiceStatus | Should -Be "Running"
            }
        }
        
        Describe "Restart-WindowsUpdateService Force Restart" {
            It "Should restart service even if running when Force is used" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Running" } -ParameterFilter { $ServiceName -eq "wuauserv" }
                Mock Get-ServiceStatus { return "Stopped" } -ParameterFilter { $ServiceName -eq "BITS" }
                Mock Get-ServiceStatus { return "Stopped" } -ParameterFilter { $ServiceName -eq "CryptSvc" }
                Mock Stop-Service {}
                Mock Start-Service {}
                Mock Start-Sleep {}
                
                # Mock final status check
                Mock Get-ServiceStatus { return "Running" } -ParameterFilter { $ServiceName -eq "wuauserv" }
                
                $result = Restart-WindowsUpdateService -Force
                
                $result.Success | Should -Be $true
                $result.Message | Should -Be "Service restarted successfully"
            }
        }
        
        Describe "Restart-WindowsUpdateService Error Handling" {
            It "Should handle service restart failures" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Stopped" }
                Mock Stop-Service { throw "Access denied" }
                
                $result = Restart-WindowsUpdateService
                
                $result.Success | Should -Be $false
                $result.Message | Should -Match "Access denied"
            }
        }
    }
    
    Context "Integration Tests" {
        
        Describe "Script Output Format" {
            It "Should produce valid JSON output" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Running" }
                
                $result = Restart-WindowsUpdateService
                $jsonOutput = @{
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                    Success = $result.Success
                    Message = $result.Message
                    ServiceStatus = $result.ServiceStatus
                    LogPath = "$env:TEMP\WindowsUpdateRemediation.log"
                } | ConvertTo-Json -Compress
                
                { $jsonOutput | ConvertFrom-Json } | Should -Not -Throw
            }
        }
        
        Describe "Logging Functionality" {
            It "Should call Write-Log function" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Running" }
                Mock Write-Log {}
                
                $result = Restart-WindowsUpdateService
                
                Should -Invoke Write-Log -AtLeast 2
            }
        }
    }
    
    Context "Security and Best Practices" {
        
        Describe "Parameter Validation" {
            It "Should accept valid parameters" {
                { Restart-WindowsUpdateService -WhatIf } | Should -Not -Throw
                { Restart-WindowsUpdateService -Force } | Should -Not -Throw
            }
        }
        
        Describe "Idempotency" {
            It "Should be safe to run multiple times" {
                Mock Test-ServiceExists { return $true }
                Mock Get-ServiceStatus { return "Running" }
                
                $result1 = Restart-WindowsUpdateService
                $result2 = Restart-WindowsUpdateService
                
                $result1.Success | Should -Be $true
                $result2.Success | Should -Be $true
                $result1.Message | Should -Be $result2.Message
            }
        }
    }
}
