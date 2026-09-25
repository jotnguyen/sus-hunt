<#
.SYNOPSIS
    Front door for the SusHunt module.
.DESCRIPTION
    triage    Score running processes and autostart entries, then explain the top findings.
    watch     Live view of new processes, console windows popping up, and new connections (polling).
    sysmon    Same idea, but reads Sysmon's event log as events arrive (needs Sysmon installed).
              Add -Hours N to score the past N hours instead of watching live.
    conns     Connection table: who talks to whom, signed or not, public or private.
    autoruns  Every autostart entry, scored or not (an inventory, like Sysinternals Autoruns).
    baseline  Save a snapshot of autoruns, listeners and running programs (with file hashes).
    diff      Compare the machine now against the newest baseline.
.EXAMPLE
    .\sus-hunt.ps1 triage -Html -Open
.EXAMPLE
    .\sus-hunt.ps1 baseline; .\sus-hunt.ps1 diff -Html -Open
.EXAMPLE
    .\sus-hunt.ps1 sysmon -Hours 24
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('triage', 'watch', 'sysmon', 'conns', 'autoruns', 'baseline', 'diff')]
    [string]$Command = 'triage',
    [int]$MinScore = 20,
    [string]$OutDir,
    [int]$Seconds = 0,
    [double]$Hours = 0,
    [string]$LogPath,
    [switch]$Quiet,
    [switch]$AllNetwork,
    [switch]$ResolveDns,
    [switch]$Html,
    [switch]$Open
)

Import-Module (Join-Path $PSScriptRoot 'SusHunt.psm1') -Force
$reportDir = if ($OutDir) { $OutDir } else { Join-Path $PSScriptRoot 'reports' }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

switch ($Command) {
    'triage' {
        $findings = @(Invoke-SusTriage -MinScore $MinScore -OutDir $OutDir)
        if ($Html) { Save-SusHtml (ConvertTo-SusFindingHtml $findings) (Join-Path $reportDir "triage_$stamp.html") -Open:$Open }
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
    'sysmon' {
        if ($Hours -gt 0) { Invoke-SysmonHunt -Hours $Hours -MinPoints $MinScore -LogPath $LogPath }
        else { Watch-SusSysmon -Seconds $Seconds -LogPath $LogPath -Quiet:$Quiet }
    }
    'conns' {
        Get-SusConnection -ResolveDns:$ResolveDns |
            Format-Table Protocol, State, Process, PID, Local, Remote, Scope, Signature, RemoteName, Note -AutoSize | Out-Host
    }
    'autoruns' {
        Get-SusPersistenceFinding -All | Sort-Object Category, Name |
            Format-Table Score, Category, Name, Id, Path, Summary -AutoSize -Wrap | Out-Host
    }
    'baseline' {
        $null = Save-SusBaseline
    }
    'diff' {
        $changes = @(Compare-SusBaseline)
        if ($Html) { Save-SusHtml (ConvertTo-SusChangeHtml $changes) (Join-Path $reportDir "diff_$stamp.html") -Open:$Open }
        if (-not $changes.Count) { Write-Host 'No changes since the baseline.' -ForegroundColor Green; return }
        $changes | Sort-Object Change, Kind | Format-Table Change, Kind, Key, After -AutoSize -Wrap | Out-Host
    }
}
