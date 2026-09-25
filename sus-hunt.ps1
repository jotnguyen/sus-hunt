<#
.SYNOPSIS
    Front door for the SusHunt module.
.DESCRIPTION
    triage    Score running processes and autostart entries, then explain the top findings.
    watch     Live view of new processes, console windows popping up, and new connections.
    conns     Connection table: who talks to whom, signed or not, public or private.
    autoruns  Every autostart entry, scored or not (an inventory, like Sysinternals Autoruns).
.EXAMPLE
    .\sus-hunt.ps1 triage
.EXAMPLE
    .\sus-hunt.ps1 watch -Quiet -LogPath .\reports\watch.csv
.EXAMPLE
    .\sus-hunt.ps1 conns -ResolveDns
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('triage', 'watch', 'conns', 'autoruns')]
    [string]$Command = 'triage',
    [int]$MinScore = 20,
    [string]$OutDir,
    [int]$Seconds = 0,
    [string]$LogPath,
    [switch]$Quiet,
    [switch]$AllNetwork,
    [switch]$ResolveDns
)

Import-Module (Join-Path $PSScriptRoot 'SusHunt.psm1') -Force

switch ($Command) {
    'triage' {
        $findings = @(Invoke-SusTriage -MinScore $MinScore -OutDir $OutDir)
        if (-not $findings.Count) {
            Write-Host "Nothing scored $MinScore or higher." -ForegroundColor Green
            return
        }
        $findings | Format-Table Score, Severity, Category, Name, Id, Summary -AutoSize -Wrap | Out-Host
        Write-Host 'Why these scored (top 10):' -ForegroundColor Cyan
        Show-SusFindingDetail ($findings | Select-Object -First 10)
    }
    'watch' {
        Watch-SusActivity -Seconds $Seconds -LogPath $LogPath -Quiet:$Quiet -AllNetwork:$AllNetwork
    }
    'conns' {
        Get-SusConnection -ResolveDns:$ResolveDns |
            Format-Table Protocol, State, Process, PID, Local, Remote, Scope, Signature, RemoteName, Note -AutoSize | Out-Host
    }
    'autoruns' {
        Get-SusPersistenceFinding -All | Sort-Object Category, Name |
            Format-Table Score, Category, Name, Id, Path, Summary -AutoSize -Wrap | Out-Host
    }
}
