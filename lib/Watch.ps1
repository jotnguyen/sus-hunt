# Live watch: new processes, console windows that pop up, and new outbound connections.
# Uses direct Win32 queries (lib\Native.ps1), not WMI: a WMI lookup costs ~200-800 ms and
# stalls the loop, which is how short popups get missed and log lines arrive late.
# With admin rights the kernel process-start trace is added, so even 5 ms processes are seen.

function Get-LiveProcess {
    # Current details for a PID, or what we recorded earlier if it has already exited.
    param([int]$ProcessId, [hashtable]$Snapshot)
    $p = Get-NativeProcess -ProcessId $ProcessId
    $known = $Snapshot[$ProcessId]
    if ($p.CreationDate) {
        if (-not $p.Name -and $known) { $p.Name = $known.Name }
        $Snapshot[$ProcessId] = $p
        return $p
    }
    $known
}

function Get-NativeSnapshot {
    # Same shape as Get-ProcessSnapshot, from Toolhelp + limited queries (~1 ms per process).
    $map = @{}
    foreach ($info in [SusHunt.V3.Win32]::ListProcesses()) {
        [SusHunt.V3.Win32]::DescribeProcess($info)
        $map[[int]$info.ProcessId] = ConvertFrom-NativeProcess $info
    }
    $map
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
        # Kernel-backed trace: reports every start, even a process that lives for 5 ms.
        Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier $source
    }

    [SusHunt.V3.Win32]::ResetProcessPolling()
    $null = [SusHunt.V3.Win32]::PollNewProcesses()   # primes the list; returns nothing the first time
    $nextPoll = Get-Date
    $snapshot = Get-NativeSnapshot
    # Seen PIDs and their image names; a known PID with a new name means the PID was reused.
    $seen = @{}
    foreach ($p in $snapshot.Values) { $seen[$p.ProcessId] = $p.Name }
    # Checking signatures of big binaries takes seconds. Do it in the background (half the cores
    # at most) and start watching straight away; results merge in as they finish.
    $warmup = Start-SignatureWarmup @($snapshot.Values | ForEach-Object { $_.ExecutablePath })

    $windowClasses = [string[]]@('ConsoleWindowClass', 'CASCADIA_HOSTING_WINDOW_CLASS')
    $knownWindows = @{}
    foreach ($w in [SusHunt.V3.Win32]::GetVisibleWindows($windowClasses)) { $knownWindows[$w.Handle] = $true }
    $recent = New-Object System.Collections.Generic.List[object]
    $pendingImage = New-Object System.Collections.Generic.List[object]
    $netSeen = @{}
    $netPrimed = $false
    $beaconTimes = @{}
    $beaconAlerted = @{}
    $started = Get-Date
    $nextNet = $started
    $stopAt = if ($Seconds -gt 0) { $started.AddSeconds($Seconds) } else { [datetime]::MaxValue }

    # One place that handles a newly seen process, whichever source reported it first.
    $onNewProcess = {
        param([int]$ProcessId, [int]$ParentProcessId, [string]$Name)
        if ($ProcessId -eq $PID -or ($seen.ContainsKey($ProcessId) -and $seen[$ProcessId] -eq $Name)) { return }
        $seen[$ProcessId] = $Name
        $now = Get-Date
        $proc = Get-NativeProcess -ProcessId $ProcessId -ParentProcessId $ParentProcessId -Name $Name
        if (-not $proc.CreationDate) { $proc.CreationDate = $now }   # exited already, or protected
        $proc | Add-Member -NotePropertyName Seen -NotePropertyValue $now
        $snapshot[$ProcessId] = $proc
        if (-not $snapshot.ContainsKey($proc.ParentProcessId)) { $null = Get-LiveProcess $proc.ParentProcessId $snapshot }
        $recent.Add($proc)

        $signals = @(Get-ProcessSignals -Process $proc -Snapshot $snapshot)
        # "File gone" at launch is often an installer mid-rename. Confirm it 3 s later first.
        $gone = @($signals | Where-Object { $_.Rule -eq 'ImageGone' })
        if ($gone.Count) {
            $pendingImage.Add([pscustomobject]@{ Proc = $proc; Due = $now.AddSeconds(3); Signal = $gone[0] })
            $signals = @($signals | Where-Object { $_.Rule -ne 'ImageGone' })
        }
        $points = [int](($signals | Measure-Object -Property Points -Sum).Sum)
        if ($Quiet -and $points -lt 20) { return }
        Write-SusEvent -Type 'PROC' -Text "$(Get-ProcessChain $proc $snapshot 4)  $(Limit-Text $proc.CommandLine 140)" -Signals $signals -LogPath $LogPath
    }

    $mode = if ($isAdmin) { 'kernel trace (+1 s list backstop)' } else { '100 ms process list (run as admin to also catch sub-100 ms processes)' }
    Write-Host "SusHunt watch: processes via $mode, console windows every 100 ms, network every 1 s. Ctrl+C to stop." -ForegroundColor Cyan
    if ($Quiet) { Write-Host 'Quiet mode: silence means nothing flagged and no console window appeared.' -ForegroundColor DarkGray }
    try {
        while ((Get-Date) -lt $stopAt) {
            $tick = [Diagnostics.Stopwatch]::StartNew()
            if ($warmup.Pool -and -not (Receive-SignatureWarmup $warmup)) {
                Write-Host "Signature check of $($warmup.Total) running programs finished in the background." -ForegroundColor DarkGray
            }

            # 1a. Kernel trace (admin): every process start, however brief.
            if ($isAdmin) {
                foreach ($e in @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue)) {
                    Remove-Event -EventIdentifier $e.EventIdentifier
                    $ev = $e.SourceEventArgs.NewEvent
                    & $onNewProcess ([int]$ev.ProcessID) ([int]$ev.ParentProcessID) ([string]$ev.ProcessName)
                }
            }
            # 1b. Process list diff (one system call; only new PIDs reach PowerShell). Every tick
            #     without admin; once a second with admin, as a backstop for the trace.
            if (-not $isAdmin -or (Get-Date) -ge $nextPoll) {
                $nextPoll = (Get-Date).AddSeconds(1)
                foreach ($info in [SusHunt.V3.Win32]::PollNewProcesses()) {
                    & $onNewProcess $info.ProcessId $info.ParentProcessId $info.Name
                }
            }
            $cutoff = (Get-Date).AddSeconds(-5)
            while ($recent.Count -and $recent[0].Seen -lt $cutoff) { $recent.RemoveAt(0) }

            # 1c. Deferred "image gone" checks: report only if the file is still missing.
            for ($i = $pendingImage.Count - 1; $i -ge 0; $i--) {
                $item = $pendingImage[$i]
                if ((Get-Date) -lt $item.Due) { continue }
                $pendingImage.RemoveAt($i)
                $sig = Get-FileSignature $item.Proc.ExecutablePath
                if (-not $sig.Exists -and -not (Test-Path -LiteralPath $item.Proc.ExecutablePath)) {
                    $s = New-Signal 'ImageGone' $item.Signal.Points $item.Signal.Attack $item.Signal.Why "$($item.Proc.ExecutablePath) (still missing after 3 s; $($sig.Reason))"
                    Write-SusEvent -Type 'PROC' -Text "$(Get-ProcessChain $item.Proc $snapshot 4)  $(Limit-Text $item.Proc.CommandLine 140)" -Signals @($s) -LogPath $LogPath
                }
            }

            # 2. Console windows that just became visible
            $current = @{}
            foreach ($w in [SusHunt.V3.Win32]::GetVisibleWindows($windowClasses)) {
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

            # 3. New TCP connections to the internet, every second (~3 ms via GetExtendedTcpTable)
            if ((Get-Date) -ge $nextNet) {
                $now = Get-Date
                $nextNet = $now.AddSeconds(1)
                $live = @{}
                foreach ($c in [SusHunt.V3.Win32]::GetTcpConnections()) {
                    # Skip our own traffic: verifying signatures makes Windows fetch certificate
                    # revocation data (OCSP/CRL) over HTTP, which would flag ourselves.
                    if ($c.OwningProcess -le 4 -or $c.OwningProcess -eq $PID -or @('Listen', 'TimeWait', 'Closed', 'DeleteTCB') -contains $c.State) { continue }
                    $key = '{0}|{1}|{2}|{3}|{4}' -f $c.OwningProcess, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort
                    $live[$key] = $true
                    if ($netSeen.ContainsKey($key)) { continue }
                    $netSeen[$key] = $true
                    if (-not $netPrimed -or (Get-IpScope $c.RemoteAddress) -ne 'Public') { continue }

                    $proc = $snapshot[[int]$c.OwningProcess]
                    if (-not $proc) { $proc = Get-LiveProcess $c.OwningProcess $snapshot }
                    $name = if ($proc -and $proc.Name) { $proc.Name } else { "pid $($c.OwningProcess)" }
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

            # Sleep only for what is left of the 100 ms tick.
            $rest = 100 - [int]$tick.ElapsedMilliseconds
            if ($rest -gt 5) { Start-Sleep -Milliseconds $rest }
        }
    } finally {
        Stop-SignatureWarmup $warmup
        if ($isAdmin) {
            Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
            Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Remove-Event
        }
        Write-Host 'SusHunt watch stopped.' -ForegroundColor Cyan
    }
}
