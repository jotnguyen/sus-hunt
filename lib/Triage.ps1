# One-shot triage: processes + network + autoruns, scored and sorted.

function Invoke-SusTriage {
    <#
    .SYNOPSIS
        Scores running processes and autostart entries. Highest score first.
    .PARAMETER MinScore
        Hide findings below this score (Low starts at 15, Medium at 30, High at 60).
    .PARAMETER OutDir
        Also write every finding (any score) plus the connection table to JSON and CSV here.
        Reports describe your machine; keep them out of git.
    .EXAMPLE
        $f = Invoke-SusTriage; $f | Format-Table; $f[0].Signals | Format-List
    #>
    [CmdletBinding()]
    param(
        [int]$MinScore = 20,
        [string]$OutDir,
        [switch]$SkipPersistence
    )
    if (-not (Test-IsAdmin)) {
        Write-Warning 'Not elevated: command lines of SYSTEM and elevated processes are hidden, so some checks are partial. Run as Administrator for full coverage.'
    }
    $allow = Get-Allowlist
    $snapshot = Get-ProcessSnapshot
    Write-Progress -Activity 'SusHunt' -Status 'Verifying signatures of running programs'
    Initialize-SignatureCache @($snapshot.Values | ForEach-Object { $_.ExecutablePath })
    Write-Progress -Activity 'SusHunt' -Status 'Network connections'
    $connections = @(Get-SusConnection -Snapshot $snapshot)
    $findings = @(Get-SusProcessFinding -Snapshot $snapshot -Connections $connections)
    if (-not $SkipPersistence) { $findings += @(Get-SusPersistenceFinding) }
    Write-Progress -Activity 'SusHunt' -Completed
    $findings = @($findings | Where-Object { -not (Test-Allowlisted $_ $allow) } | Sort-Object Score -Descending)

    if ($OutDir) {
        $null = New-Item -ItemType Directory -Path $OutDir -Force
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir "triage_$stamp.json") -Encoding UTF8
        $findings | Select-Object Score, Severity, Category, Name, Id, Path, Summary, Context, CommandLine |
            Export-Csv -LiteralPath (Join-Path $OutDir "triage_$stamp.csv") -NoTypeInformation
        $connections | Select-Object Protocol, State, Local, Remote, Scope, PID, Process, Path, Signature, Signer, Note |
            Export-Csv -LiteralPath (Join-Path $OutDir "connections_$stamp.csv") -NoTypeInformation
        Write-Host "Reports written to $OutDir" -ForegroundColor Cyan
    }
    $findings | Where-Object { $_.Score -ge $MinScore }
}

function Show-SusFindingDetail {
    # Prints the reasoning behind each finding: the part worth learning from.
    param([object[]]$Findings)
    foreach ($f in $Findings) {
        $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Magenta' } default { 'DarkYellow' } }
        Write-Host ''
        Write-Host ("[{0} {1}] {2}: {3} ({4})" -f $f.Score, $f.Severity, $f.Category, $f.Name, $f.Id) -ForegroundColor $color
        if ($f.Path) { Write-Host "    path:    $($f.Path)" }
        if ($f.Context) { Write-Host "    context: $(Limit-Text $f.Context 150)" }
        if ($f.CommandLine) { Write-Host "    command: $(Limit-Text $f.CommandLine 150)" }
        foreach ($s in $f.Signals | Sort-Object Points -Descending) {
            $attack = if ($s.Attack) { " $($s.Attack)" } else { '' }
            Write-Host ("    +{0,-3}{1} {2}: {3}" -f $s.Points, $attack, $s.Rule, $s.Why)
            if ($s.Evidence) { Write-Host "          evidence: $(Limit-Text $s.Evidence 140)" -ForegroundColor DarkGray }
        }
    }
}
