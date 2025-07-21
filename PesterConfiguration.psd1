# PesterConfiguration.psd1
# Pester configuration file for auto-remediation testing

@{
    # Pester configuration
    Run = @{
        Path = @('.\tests')
        ExcludePath = @('.\tests\Integration.Tests.ps1')  # Run integration tests separately
        PassThru = $true
        SkipRemainingOnFailure = 'None'
    }
    
    # Code Coverage settings
    CodeCoverage = @{
        Enabled = $true
        Path = @('.\scripts\*.ps1')
        OutputFormat = 'JaCoCo'
        OutputPath = '.\TestResults\Coverage.xml'
        OutputEncoding = 'UTF8'
    }
    
    # Test Result settings
    TestResult = @{
        Enabled = $true
        OutputFormat = 'NUnitXml'
        OutputPath = '.\TestResults\TestResults.xml'
        OutputEncoding = 'UTF8'
    }
    
    # Output settings
    Output = @{
        Verbosity = 'Detailed'
        StackTraceVerbosity = 'Full'
        CIFormat = 'Auto'
    }
    
    # Should settings
    Should = @{
        ErrorAction = 'Stop'
    }
    
    # Debug settings
    Debug = @{
        ShowFullErrors = $true
        WriteDebugMessages = $false
        WriteDebugMessagesFrom = @('Discovery', 'Skip', 'Filter', 'Mock', 'CodeCoverage')
    }
}
