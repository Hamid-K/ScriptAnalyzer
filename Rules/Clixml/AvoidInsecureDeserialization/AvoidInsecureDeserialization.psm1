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

    # Define deserialization cmdlets and methods to detect
    $deserializationCmdlets = @('Import-Clixml', 'Export-Clixml')
    $deserializationMethods = @('[PSSerializer]::Serialize', '[PSSerializer]::Deserialize')

    # Detect deserialization cmdlets
    $ScriptBlockAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.CommandAst] -and
        ($deserializationCmdlets -contains $ast.GetCommandName())
    }, $true) | ForEach-Object {
        $finding = New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord `
            -ArgumentList @(
                'Avoid using deserialization cmdlets with untrusted input.',
                $_.Extent,
                'AvoidInsecureDeserialization',
                'Error',
                $Path,
                $null
            )
        $findings += $finding
    }

    # Detect deserialization methods as strings (using CommandAst instead of MethodCallAst)
    $ScriptBlockAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.CommandAst] -and
        ($deserializationMethods | ForEach-Object { $ast.Extent.Text -like "*$_*" })
    }, $true) | ForEach-Object {
        $finding = New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord `
            -ArgumentList @(
                'Avoid using PSSerializer deserialization methods with untrusted input.',
                $_.Extent,
                'AvoidInsecureDeserialization',
                'Error',
                $Path,
                $null
            )
        $findings += $finding
    }

    # Detect usage of rehydrated types like ScriptBlock (<SBK>) and CimInstance objects
    $ScriptBlockAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        ($ast.Value -match '<SBK>|Win32_PingStatus|Microsoft.Management.Infrastructure.CimInstance')
    }, $true) | ForEach-Object {
        $finding = New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord `
            -ArgumentList @(
                'Potential rehydrated ScriptBlock or CimInstance found, review for unsafe deserialization.',
                $_.Extent,
                'AvoidInsecureDeserialization',
                'Warning',
                $Path,
                $null
            )
        $findings += $finding
    }

    return $findings
}

# Export the function
Export-ModuleMember -Function Invoke-AvoidInsecureDeserialization
