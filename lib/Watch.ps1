# Live watch: new processes, console windows that pop up, and new outbound connections.
# Everything here polls, so it runs without Administrator. README "Limitations" covers what
# polling can miss and what real EDR sensors do instead.

function ConvertFrom-ProcessEvent {
    param($NewEvent)
    $now = Get-Date
    if ($NewEvent.CimSystemProperties.ClassName -eq 'Win32_ProcessStartTrace') {
        # The trace event only carries names and PIDs; grab the command line while the process lives.
        $procId = [int]$NewEvent.ProcessID
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
        if (-not $p) {
            $p = [pscustomobject]@{ Name = $NewEvent.ProcessName; ProcessId = $procId; ParentProcessId = [int]$NewEvent.ParentProcessID; CommandLine = $null; ExecutablePath = $null; CreationDate = $now }
        }
    } else {
        $p = $NewEvent.TargetInstance
    }
    [pscustomobject]@{
        Name            = $p.Name
        ProcessId       = [int]$p.ProcessId
        ParentProcessId = [int]$p.ParentProcessId
        CommandLine     = $p.CommandLine
        ExecutablePath  = $p.ExecutablePath
        CreationDate    = if ($p.CreationDate) { $p.CreationDate } else { $now }
        Seen            = $now
    }
}

function Get-LiveProcess {
    param([int]$ProcessId, [hashtable]$Snapshot)
    $live = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
    if ($live) { $Snapshot[$ProcessId] = $live; return $live }
    $Snapshot[$ProcessId]   # already exited; this is what we recorded when it started, if anything
}

function Write-SusEvent {
    param([string]$Type, [string]$Text, [object[]]$Signals, [string]$LogPath, [string]$Color)
    $points = [int](($Signals | Measure-Object -Property Points -Sum).Sum)
    if (-not $Color) {
        $Color = if ($points -ge 60) { 'Red' } elseif ($points -ge 30) { 'Magenta' } elseif ($points -ge 20) { 'DarkYellow' } else { 'Gray' }
    }
    $time = Get-Date
    $why = ($Signals | ForEach-Object { $_.Rule }) -join ', '
    $line = '{0:HH:mm:ss.fff} {1,-6} {2}' -f $time, $Type, $Text
    if ($why -and $points -ge 20) { $line += "  !! $why" }
    elseif ($why) { $line += "  ($why)" }
    Write-Host $line -ForegroundColor $Color
    if ($LogPath) {
        [pscustomobject]@{ Time = $time.ToString('o'); Type = $Type; Points = $points; Reasons = $why; Text = $Text } |
            Export-Csv -LiteralPath $LogPath -Append -NoTypeInformation
    }
}

function Watch-SusActivity {
    <#
    .SYNOPSIS
        Live view of new processes, console windows appearing on screen, and new internet
        connections from risky programs, with beacon (timer) detection. Ctrl+C to stop.
    .PARAMETER Quiet
        Only print console windows and flagged events, not every process start.
    .PARAMETER AllNetwork
        Print every new public connection, not only ones from LOLBins, unsigned programs or odd ports.
    .EXAMPLE
        Watch-SusActivity -Quiet -LogPath .\reports\watch.csv
    #>
    [CmdletBinding()]
    param(
        [int]$Seconds = 0,
        [string]$LogPath,
        [switch]$Quiet,
        [switch]$AllNetwork
    )
    Initialize-SusNative
    $isAdmin = Test-IsAdmin
    if ($LogPath) { $null = New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force -ErrorAction SilentlyContinue }

    $source = 'SusHunt.ProcessStart'
    Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
    if ($isAdmin) {
        # Backed by kernel tracing: sees every start, even a process that lives for 5 ms.
        Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier $source
    } else {
        # WMI diffs the process list twice a second, so very short-lived processes can slip past.
        Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier $source
    }

    $snapshot = Get-ProcessSnapshot
    $windowClasses = [string[]]@('ConsoleWindowClass', 'CASCADIA_HOSTING_WINDOW_CLASS')
    $knownWindows = @{}
    foreach ($w in [SusHunt.Native]::GetVisibleWindows($windowClasses)) { $knownWindows[$w.Handle] = $true }
    $recent = New-Object System.Collections.Generic.List[object]
    $netSeen = @{}
    $netPrimed = $false
    $beaconTimes = @{}
    $beaconAlerted = @{}
    $started = Get-Date
    $nextNet = $started
    $stopAt = if ($Seconds -gt 0) { $started.AddSeconds($Seconds) } else { [datetime]::MaxValue }

    $mode = if ($isAdmin) { 'kernel process trace' } else { 'WMI polling (run as admin to catch very short-lived processes)' }
    Write-Host "SusHunt watch: processes via $mode, console windows every 100 ms, network every 2 s. Ctrl+C to stop." -ForegroundColor Cyan
    try {
        while ((Get-Date) -lt $stopAt) {
            # 1. Process starts. Polled events can arrive out of order, so record the whole batch
            #    first; otherwise a child printed before its parent shows the parent as exited.
            $batch = @(foreach ($e in @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue)) {
                Remove-Event -EventIdentifier $e.EventIdentifier
                ConvertFrom-ProcessEvent $e.SourceEventArgs.NewEvent
            })
            foreach ($proc in $batch) { $snapshot[$proc.ProcessId] = $proc }
            foreach ($proc in $batch | Sort-Object CreationDate) {
                if ($proc.ProcessId -eq $PID) { continue }
                if (-not $snapshot.ContainsKey($proc.ParentProcessId)) { $null = Get-LiveProcess $proc.ParentProcessId $snapshot }
                $recent.Add($proc)
                $signals = @(Get-ProcessSignals -Process $proc -Snapshot $snapshot)
                $points = [int](($signals | Measure-Object -Property Points -Sum).Sum)
                if ($Quiet -and $points -lt 20) { continue }
                Write-SusEvent -Type 'PROC' -Text "$(Get-ProcessChain $proc $snapshot 4)  $(Limit-Text $proc.CommandLine 140)" -Signals $signals -LogPath $LogPath
            }
            $cutoff = (Get-Date).AddSeconds(-5)
            while ($recent.Count -and $recent[0].Seen -lt $cutoff) { $recent.RemoveAt(0) }

            # 2. Console windows that just became visible
            $current = @{}
            foreach ($w in [SusHunt.Native]::GetVisibleWindows($windowClasses)) {
                $current[$w.Handle] = $true
                if ($knownWindows.ContainsKey($w.Handle)) { continue }
                $owner = Get-LiveProcess $w.ProcessId $snapshot
                $who = if ($owner) { Get-ProcessChain $owner $snapshot 6 } else { "pid $($w.ProcessId) (already exited)" }
                $text = "$($w.ClassName) '$(Limit-Text $w.Title 60)'  owner: $who"
                $others = ($recent | Where-Object { $_.ProcessId -ne $w.ProcessId } | Select-Object -Last 4 | ForEach-Object { "$($_.Name)[$($_.ProcessId)]" }) -join ', '
                if ($others) { $text += "  | also started in last 5 s: $others" }
                Write-SusEvent -Type 'WINDOW' -Text $text -LogPath $LogPath -Color 'Yellow'
            }
            $knownWindows = $current

            # 3. New TCP connections to the internet, every 2 seconds
            if ((Get-Date) -ge $nextNet) {
                $now = Get-Date
                $nextNet = $now.AddSeconds(2)
                $live = @{}
                foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
                    if ($c.OwningProcess -le 4 -or @('Listen', 'Bound', 'TimeWait') -contains [string]$c.State) { continue }
                    $key = '{0}|{1}|{2}|{3}|{4}' -f $c.OwningProcess, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort
                    $live[$key] = $true
                    if ($netSeen.ContainsKey($key)) { continue }
                    $netSeen[$key] = $true
                    if (-not $netPrimed -or (Get-IpScope $c.RemoteAddress) -ne 'Public') { continue }

                    $proc = $snapshot[[int]$c.OwningProcess]
                    if (-not $proc) { $proc = Get-LiveProcess $c.OwningProcess $snapshot }
                    $name = if ($proc) { $proc.Name } else { "pid $($c.OwningProcess)" }
                    $remote = Format-Endpoint $c.RemoteAddress $c.RemotePort
                    $signals = @()
                    if ($script:Lolbins -contains $name.ToLowerInvariant()) {
                        $signals += New-Signal 'LolbinOnInternet' 35 'T1105' 'Built-in Windows tool connecting out.' $remote
                    }
                    $sig = if ($proc -and $proc.ExecutablePath) { Get-FileSignature $proc.ExecutablePath } else { $null }
                    if ($sig -and $sig.Exists -and $sig.Status -ne 'Valid') {
                        $signals += New-Signal 'UnsignedOnInternet' 15 'T1071' 'Unsigned program connecting out.' $remote
                    }
                    if ($script:NotablePorts.ContainsKey([int]$c.RemotePort)) {
                        $signals += New-Signal 'NotablePort' 20 'T1571' $script:NotablePorts[[int]$c.RemotePort] $remote
                    }
                    if ($signals.Count -or $AllNetwork) {
                        Write-SusEvent -Type 'NET' -Text "$name[$($c.OwningProcess)] -> $remote" -Signals $signals -LogPath $LogPath
                    }

                    # Beacon tracking: same program, same destination, over and over.
                    $bkey = "$name -> $remote"
                    if (-not $beaconTimes.ContainsKey($bkey)) { $beaconTimes[$bkey] = New-Object System.Collections.Generic.List[double] }
                    $beaconTimes[$bkey].Add(($now - $started).TotalSeconds)
                    $beacon = Test-Beacon $beaconTimes[$bkey].ToArray()
                    if ($beacon -and -not $beaconAlerted.ContainsKey($bkey)) {
                        $beaconAlerted[$bkey] = $true
                        $s = New-Signal 'Beacon' 40 'T1071' 'Reconnects on a steady timer.' "every ~$($beacon.MeanSeconds)s"
                        Write-SusEvent -Type 'BEACON' -Text "$bkey every ~$($beacon.MeanSeconds) s (n=$($beacon.Events), cv=$($beacon.Cv)). Timers are normal for updaters; unexpected ones deserve a look." -Signals @($s) -LogPath $LogPath
                    }
                }
                # Forget closed connections so a reconnect on the same ports counts as new.
                foreach ($k in @($netSeen.Keys)) { if (-not $live.ContainsKey($k)) { $netSeen.Remove($k) } }
                $netPrimed = $true
            }
            Start-Sleep -Milliseconds 100
        }
    } finally {
        Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Remove-Event
        Write-Host 'SusHunt watch stopped.' -ForegroundColor Cyan
    }
}
