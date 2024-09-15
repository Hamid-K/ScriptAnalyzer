A dummy implementation of custom rule for PowerShell ScriptAnalyzer to detect usage of CLIXML, 
as described in the following blog post:

https://www.truesec.com/hub/blog/attacking-powershell-clixml-deserialization

### Import the custom module:

`Import-Module 'C:\AvoidInsecureDeserialization\AvoidInsecureDeserialization.psm1' -Force`

### Usage:
`Invoke-ScriptAnalyzer -Path 'C:\test\' -CustomRulePath 'C:\AvoidInsecureDeserialization' -Recurse -Verbose`







