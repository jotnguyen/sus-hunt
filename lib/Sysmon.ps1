# Sysmon mode: read Microsoft Sysinternals Sysmon's event log instead of polling.
# Sysmon is a driver + service that records events as they happen, so nothing is missed
# between polls, and it gives each process a ProcessGuid, which (unlike a PID) is never reused.
#   Event 1  = process created (full command line, parent, hashes)
#   Event 3  = network connection
#   Event 22 = DNS query (lets beacon tracking key on the domain, not a rotating CDN IP)
# Install Sysmon yourself (see README); this module only reads its log.

$script:SysmonLog = 'Microsoft-Windows-Sysmon/Operational'

function ConvertFrom-SysmonEventXml {
    # Turns one event's XML into a flat object: Id, Time, plus every <Data Name="..."> field.
    param([string]$Xml)
    $doc = [xml]$Xml
    $ns = New-Object System.Xml.XmlNamespaceManager $doc.NameTable
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $props = [ordered]@{
        Id   = [int]$doc.SelectSingleNode('/e:Event/e:System/e:EventID', $ns).InnerText
        Time = [datetime]$doc.SelectSingleNode('/e:Event/e:System/e:TimeCreated', $ns).GetAttribute('SystemTime')
    }
    foreach ($d in $doc.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $props[$d.GetAttribute('Name')] = $d.InnerText
    }
    [pscustomobject]$props
}

function Get-SysmonEventSignals {
    # Applies the same rules as the rest of the kit to one parsed Sysmon event.
    param($Record, [hashtable]$BeaconTimes, [hashtable]$BeaconAlerted)
    switch ($Record.Id) {
        1 {
            $proc = [pscustomobject]@{
                Name = Split-Path $Record.Image -Leaf; ProcessId = [int]$Record.ProcessId; ParentProcessId = [int]$Record.ParentProcessId
                CommandLine = $Record.CommandLine; ExecutablePath = $Record.Image; CreationDate = $Record.Time
            }
            $parent = [pscustomobject]@{
                Name = if ($Record.ParentImage) { Split-Path $Record.ParentImage -Leaf } else { $null }
                ProcessId = [int]$Record.ParentProcessId; ParentProcessId = 0; CreationDate = [datetime]::MinValue
            }
            $snapshot = @{ ([int]$Record.ParentProcessId) = $parent }
            $text = "$($proc.Name)[$($proc.ProcessId)] <- $($parent.Name)[$($parent.ProcessId)]  $(Limit-Text $Record.CommandLine 140)"
            return [pscustomobject]@{ Type = 'PROC'; Text = $text; Signals = @(Get-ProcessSignals -Process $proc -Snapshot $snapshot) }
        }
        3 {
            if ((Get-IpScope $Record.DestinationIp) -ne 'Public') { return }
            $name = Split-Path $Record.Image -Leaf
            $remote = Format-Endpoint $Record.DestinationIp $Record.DestinationPort
            $signals = @()
            if ($script:Lolbins -contains $name.ToLowerInvariant()) {
                $signals += New-Signal 'LolbinOnInternet' 35 'T1105' 'Built-in Windows tool connecting out.' $remote
            }
            if ($script:NotablePorts.ContainsKey([int]$Record.DestinationPort)) {
                $signals += New-Signal 'NotablePort' 20 'T1571' $script:NotablePorts[[int]$Record.DestinationPort] $remote
            }
            $host_ = if ($Record.DestinationHostname) { " ($($Record.DestinationHostname))" } else { '' }
            return [pscustomobject]@{ Type = 'NET'; Text = "$name[$($Record.ProcessId)] -> $remote$host_"; Signals = $signals }
        }
        22 {
            # Beacon tracking by (program, domain): CDNs rotate IPs, domains stay put.
            $name = Split-Path $Record.Image -Leaf
            $key = "$name -> $($Record.QueryName)"
            if (-not $BeaconTimes.ContainsKey($key)) { $BeaconTimes[$key] = New-Object System.Collections.Generic.List[double] }
            $BeaconTimes[$key].Add(($Record.Time - [datetime]'2000-01-01').TotalSeconds)
            $beacon = Test-Beacon $BeaconTimes[$key].ToArray()
            if ($beacon -and -not $BeaconAlerted.ContainsKey($key)) {
                $BeaconAlerted[$key] = $true
                $s = New-Signal 'Beacon' 40 'T1071' 'Looks up the same domain on a steady timer.' "every ~$($beacon.MeanSeconds)s"
                return [pscustomobject]@{ Type = 'BEACON'; Text = "$key every ~$($beacon.MeanSeconds) s (n=$($beacon.Events), cv=$($beacon.Cv))"; Signals = @($s) }
            }
            return [pscustomobject]@{ Type = 'DNS'; Text = $key; Signals = @() }
        }
    }
}

function Test-SysmonInstalled {
    [bool](Get-WinEvent -ListLog $script:SysmonLog -ErrorAction SilentlyContinue)
}

function Invoke-SysmonHunt {
    <#
    .SYNOPSIS
        Scores Sysmon events from the past N hours (process, network and DNS events).
    .EXAMPLE
        Invoke-SysmonHunt -Hours 24 -MinPoints 20
    #>
    [CmdletBinding()]
    param([double]$Hours = 24, [int]$MinPoints = 20, [string]$LogPath)
    if (-not (Test-SysmonInstalled)) { throw 'Sysmon is not installed (no Microsoft-Windows-Sysmon/Operational log). See README.' }
    $beaconTimes = @{}; $beaconAlerted = @{}
    $events = Get-WinEvent -FilterHashtable @{ LogName = $script:SysmonLog; Id = 1, 3, 22; StartTime = (Get-Date).AddHours(-$Hours) } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated
    foreach ($e in $events) {
        $r = Get-SysmonEventSignals (ConvertFrom-SysmonEventXml $e.ToXml()) $beaconTimes $beaconAlerted
        if (-not $r) { continue }
        $points = [int](($r.Signals | Measure-Object -Property Points -Sum).Sum)
        if ($points -ge $MinPoints) { Write-SusEvent -Type $r.Type -Text "$($e.TimeCreated.ToString('MM-dd HH:mm:ss')) $($r.Text)" -Signals $r.Signals -LogPath $LogPath }
    }
}

function Watch-SusEventLog {
    # Push-based log reader: EventLogWatcher raises an event for each new record, so this
    # waits instead of polling. Kept generic (any log + XPath) so it can be tested without Sysmon.
    param([string]$LogName, [string]$XPath = '*', [scriptblock]$OnRecord, [int]$Seconds = 0)
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery $LogName, ([System.Diagnostics.Eventing.Reader.PathType]::LogName), $XPath
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher $query
    $source = "SusHunt.EventLog.$([guid]::NewGuid())"
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier $source | Out-Null
    $watcher.Enabled = $true
    $stopAt = if ($Seconds -gt 0) { (Get-Date).AddSeconds($Seconds) } else { [datetime]::MaxValue }
    try {
        while ((Get-Date) -lt $stopAt) {
            $e = Wait-Event -SourceIdentifier $source -Timeout 1
            if (-not $e) { continue }
            Remove-Event -EventIdentifier $e.EventIdentifier
            $record = $e.SourceEventArgs.EventRecord
            if ($record) { & $OnRecord $record }
        }
    } finally {
        $watcher.Enabled = $false
        Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Remove-Event
        $watcher.Dispose()
    }
}

function Watch-SusSysmon {
    <#
    .SYNOPSIS
        Live view of Sysmon process (1), network (3) and DNS (22) events, scored as they arrive.
    .PARAMETER Quiet
        Only print events scoring 20 or more (DNS lookups are hidden unless they look like a beacon).
    #>
    [CmdletBinding()]
    param([int]$Seconds = 0, [string]$LogPath, [switch]$Quiet)
    if (-not (Test-SysmonInstalled)) { throw 'Sysmon is not installed (no Microsoft-Windows-Sysmon/Operational log). See README.' }
    $beaconTimes = @{}; $beaconAlerted = @{}
    # The callback runs later, inside Watch-SusEventLog; copy the parameters it needs into locals.
    $quietOnly = [bool]$Quiet; $logFile = $LogPath
    Write-Host 'SusHunt sysmon: reading events as Sysmon writes them. Ctrl+C to stop.' -ForegroundColor Cyan
    $xpath = '*[System[(EventID=1 or EventID=3 or EventID=22)]]'
    Watch-SusEventLog -LogName $script:SysmonLog -XPath $xpath -Seconds $Seconds -OnRecord {
        param($record)
        $r = Get-SysmonEventSignals (ConvertFrom-SysmonEventXml $record.ToXml()) $beaconTimes $beaconAlerted
        if (-not $r) { return }
        $points = [int](($r.Signals | Measure-Object -Property Points -Sum).Sum)
        if ($r.Type -eq 'DNS' -and $points -eq 0) { return }
        if ($quietOnly -and $points -lt 20) { return }
        Write-SusEvent -Type $r.Type -Text $r.Text -Signals $r.Signals -LogPath $logFile
    }
    Write-Host 'SusHunt sysmon stopped.' -ForegroundColor Cyan
}
