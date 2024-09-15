@{
    RootModule        = 'AvoidInsecureDeserialization.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '12345678-1234-1234-1234-123456789012'
    Author            = 'Your Name'
    Description       = 'Custom rule to avoid insecure deserialization.'
    FunctionsToExport = @('Invoke-AvoidInsecureDeserialization')
    PrivateData       = @{
        PSData = @{
            Tags = @('Security', 'PSScriptAnalyzer')
        }
    }
}