function Invoke-AvoidInsecureDeserialization {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Language.ScriptBlockAst] $ScriptBlockAst,

        [Parameter(Mandatory = $false)]
        [string] $Path = $null  # Default to $null if not passed
    )

    $findings = @()

    if ($null -eq $Path) {
        Write-Host "Path parameter is missing, proceeding with default."
    } else {
        Write-Host "Processing script at path: $Path"
    }

    # Log AST details to ensure AST is passed
    Write-Host "AST details: $ScriptBlockAst"

    # Define deserialization cmdlets to detect
    $deserializationCmdlets = @('Import-Clixml', 'ConvertFrom-CliXml')

    # Search for deserialization cmdlets in the AST
    $ScriptBlockAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.CommandAst] -and
        $deserializationCmdlets -contains $ast.GetCommandName()
    }, $true) | ForEach-Object {
        # Create a finding for each deserialization cmdlet found
        $finding = New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord `
            -ArgumentList @(
                'Avoid using deserialization cmdlets with untrusted input.',
                $_.Extent,   # Provide the AST extent for highlighting the issue
                'AvoidInsecureDeserialization',
                'Error',  # Use "Error" or "Warning" instead of "Critical"
                $Path,
                $null
            )
        $findings += $finding
    }

    return $findings
}

# Export the function
Export-ModuleMember -Function Invoke-AvoidInsecureDeserialization