# PSScriptAnalyzer settings for sus-hunt. Used by tools\lint.ps1 and CI.
# Each excluded rule says why; do not add to this list to silence a real finding.
@{
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # A command-line tool: coloured console output is the product, not a logging shortcut.
        'PSAvoidUsingWriteHost'
        # House naming: Get-ProcessSignals returns signals, and the plural says so.
        'PSUseSingularNouns'
        # New-Signal and New-Finding only build objects. The functions that change the machine
        # (Stop-SusConnection) do support -WhatIf/-Confirm.
        'PSUseShouldProcessForStateChangingFunctions'
    )

    Rules        = @{
        # The kit targets Windows PowerShell 5.1 with no installs: no ?., ??, ternary, &&.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }
}
