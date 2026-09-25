# SusHunt: a small, readable host-triage kit for Windows PowerShell 5.1+.
# One lib\ file per topic; the detection rules are plain data in lib\Rules.ps1.

foreach ($lib in 'Native', 'Rules', 'Common', 'Network', 'Processes', 'Persistence', 'Triage', 'Watch',
                 'Baseline', 'Report', 'Sysmon') {
    . (Join-Path $PSScriptRoot "lib\$lib.ps1")
}

Update-TypeData -TypeName 'SusHunt.Finding' -DefaultDisplayPropertySet Score, Severity, Name, Summary -Force
Update-TypeData -TypeName 'SusHunt.Connection' -DefaultDisplayPropertySet Process, State, Remote, Scope -Force
Update-TypeData -TypeName 'SusHunt.Change' -DefaultDisplayPropertySet Change, Kind, Key, After -Force

Export-ModuleMember -Function Invoke-SusTriage, Show-SusFindingDetail, Get-SusProcessFinding,
    Get-SusPersistenceFinding, Get-SusConnection, Stop-SusConnection, Watch-SusActivity,
    Save-SusBaseline, Compare-SusBaseline, ConvertTo-SusFindingHtml, ConvertTo-SusChangeHtml, Save-SusHtml,
    Watch-SusSysmon, Invoke-SysmonHunt
