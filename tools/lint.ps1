<#
.SYNOPSIS
    Lints every PowerShell file in the repo with PSScriptAnalyzer and the repo settings.
.DESCRIPTION
    Run from anywhere in the repo:
        powershell -NoProfile -File tools\lint.ps1
    Prints "lint-ok" and exits 0 when clean; lists every finding and exits 1 otherwise.
    PSScriptAnalyzer is a developer tool, not something the kit needs to run. If it is missing,
    this prints the install command instead of installing anything.
#>
[CmdletBinding()]
param()

$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    Write-Host 'PSScriptAnalyzer is not installed. Install it for your user, then run this again:' -ForegroundColor Yellow
    Write-Host '    Install-Module PSScriptAnalyzer -Scope CurrentUser'
    exit 1
}
Import-Module PSScriptAnalyzer

$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
$findings = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' |
    Where-Object { $_.FullName -notmatch '\\(\.git|reports|baselines)\\' } |
    ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Settings $settings })

if ($findings.Count) {
    $findings | Sort-Object ScriptPath, Line | ForEach-Object {
        $rel = $_.ScriptPath.Substring($root.Length + 1)
        Write-Host ('{0}:{1} [{2}] {3}: {4}' -f $rel, $_.Line, $_.Severity, $_.RuleName, $_.Message)
    }
    Write-Host "$($findings.Count) lint finding(s)." -ForegroundColor Red
    exit 1
}
Write-Host 'lint-ok' -ForegroundColor Green
exit 0
