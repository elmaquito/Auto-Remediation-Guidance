# Basic.Tests.ps1
# Basic Pester tests compatible with older versions

Describe "Basic Auto-Remediation Framework Tests" {
    
    Context "Script Files Exist" {
        It "Should have Restart-WindowsUpdateService script" {
            $scriptPath = Join-Path $PSScriptRoot "..\scripts\Restart-WindowsUpdateService.ps1"
            Test-Path $scriptPath | Should Be $true
        }
        
        It "Should have Clear-TempFiles script" {
            $scriptPath = Join-Path $PSScriptRoot "..\scripts\Clear-TempFiles.ps1"
            Test-Path $scriptPath | Should Be $true
        }
    }
    
    Context "Script Content Validation" {
        It "Scripts should contain CmdletBinding attribute" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Match '\[CmdletBinding\(\)\]'
            }
        }
        
        It "Scripts should support WhatIf parameter" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Match '\[switch\]\$WhatIf'
            }
        }
        
        It "Scripts should have proper error handling" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Match 'try\s*\{'
                $content | Should Match 'catch\s*\{'
            }
        }
    }
    
    Context "Security Validation" {
        It "Scripts should not contain hardcoded passwords" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Not Match 'password\s*=\s*["\x27][^"\x27]+["\x27]'
            }
        }
        
        It "Scripts should not use Invoke-Expression" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Not Match 'Invoke-Expression|iex\s'
            }
        }
    }
    
    Context "Output Format Validation" {
        It "Scripts should produce Nexthink output" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "..\scripts") -Filter "*.ps1"
            
            foreach ($script in $scriptFiles) {
                $content = Get-Content -Path $script.FullName -Raw
                $content | Should Match 'NEXTHINK_OUTPUT:'
            }
        }
    }
}
