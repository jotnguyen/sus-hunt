# Process checks. For each running program: is it where it should be, started by whom it
# should be, signed, and is its command line or network use out of character?

# Unicode bidirectional controls (U+202A-U+202E, U+2066-U+2069). Built from code points so this
# file stays plain ASCII, which Windows PowerShell 5.1 needs to read it correctly.
$script:BidiControls = '[{0}-{1}{2}-{3}]' -f [char]0x202A, [char]0x202E, [char]0x2066, [char]0x2069

# Full expected folders for each Windows binary, worked out once instead of per process.
$script:SystemBinaryDirs = @{}
foreach ($name in $script:SystemBinaries.Keys) {
    $script:SystemBinaryDirs[$name] = @(foreach ($d in $script:SystemBinaries[$name].Dirs) {
        if ($d -eq '.') { $env:windir } else { [IO.Path]::Combine($env:windir, $d) }
    })
}

function Get-ProcessSignals {
    param($Process, [hashtable]$Snapshot, [object[]]$Connections)
    $name = [string]$Process.Name
    $lname = $name.ToLowerInvariant()
    $path = ConvertTo-NormalPath $Process.ExecutablePath
    $parent = Get-ParentProcess $Process $Snapshot
    $sig = $null

    # Masquerading: right name, wrong folder.
    $known = $script:SystemBinaries[$lname]
    if ($known -and $path) {
        $dir = [IO.Path]::GetDirectoryName($path).TrimEnd('\')
        $expected = $script:SystemBinaryDirs[$lname]
        if (-not ($expected | Where-Object { $_ -eq $dir })) {
            New-Signal 'WrongFolder' 60 'T1036.005' "The real $lname only lives in $($expected -join ' or ')." $path
        }
    }

    # Right name, wrong parent. Parents can be forged (T1134.004), so a match proves nothing either.
    if ($known -and $known.Parents.Count -and $parent -and $known.Parents -notcontains $parent.Name.ToLowerInvariant()) {
        New-Signal 'UnexpectedParent' 40 'T1036' "$lname is normally started by $($known.Parents -join ' or ')." "parent: $($parent.Name) [$($parent.ProcessId)]"
    }

    $twin = Get-LookalikeName $name
    if ($twin) {
        New-Signal 'LookalikeName' 45 'T1036.005' "One letter away from the Windows program $twin. A cheap and common disguise." $name
    }
    if ($name -match '(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rar)\.(exe|scr|com|pif|bat|cmd)$') {
        New-Signal 'DoubleExtension' 40 'T1036.007' 'Explorer hides known extensions, so invoice.pdf.exe shows up as invoice.pdf.' $name
    }
    if ($name -match $script:BidiControls) {
        New-Signal 'BidiTrick' 50 'T1036.002' 'Contains a Unicode right-to-left control character, used to make the extension read backwards.' $name
    }

    if ($path) {
        $risk = Get-PathRisk $path
        $sig = Get-FileSignature $path
        if (-not $sig.Exists) {
            New-Signal 'ImageGone' 40 'T1070.004' 'Running, but its file is gone from disk. Updaters do this briefly; droppers delete themselves on purpose.' $path
        } elseif ($sig.Status -eq 'HashMismatch') {
            New-Signal 'TamperedBinary' 60 'T1554' 'Signed, but the file changed after signing. Someone modified it.' $path
        } elseif ($sig.Status -ne 'Valid') {
            $pts = switch ($risk) { 'HighRisk' { 25 } 'UserWritable' { 15 } 'Windows' { 20 } default { 10 } }
            New-Signal 'Unsigned' $pts '' "No valid Authenticode signature ($($sig.Status)). Normal for many dev tools; the file lives in a $risk location." $path
        }
        if ($risk -eq 'HighRisk') {
            New-Signal 'RunsFromTemp' 25 'T1204.002' 'Runs from Temp, Downloads, Public or the Recycle Bin. Installers do this briefly; long-running programs should not.' $path
        }
    }

    Get-CommandLineSignals $Process.CommandLine

    if ($parent -and $script:DocumentApps -contains $parent.Name.ToLowerInvariant() -and $script:ShellLike -contains $lname) {
        New-Signal 'DocumentSpawnedShell' 50 'T1204.002' "A document program ($($parent.Name)) started $lname. Classic sign of a malicious macro or exploit." (Get-ProcessChain $Process $Snapshot 3)
    }

    if ($Connections) {
        $external = @($Connections | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' -and $_.Scope -eq 'Public' })
        $listeners = @($Connections | Where-Object { $_.State -eq 'Listen' -and $_.LocalScope -eq 'Unspecified' })
        $unsigned = $sig -and $sig.Exists -and $sig.Status -ne 'Valid'
        $sample = ($external | Select-Object -First 3 | ForEach-Object { $_.Remote }) -join ', '
        if ($external.Count -and $script:Lolbins -contains $lname) {
            New-Signal 'LolbinOnInternet' 35 'T1105' "$lname has live internet connections. Plenty of scripts do this; so do download cradles." $sample
        }
        if ($external.Count -and $unsigned) {
            New-Signal 'UnsignedOnInternet' 15 'T1071' 'Unsigned program with live internet connections.' $sample
        }
        if ($listeners.Count -and $unsigned) {
            $ports = ($listeners | ForEach-Object { "$($_.Protocol)/$($_.LocalPort)" } | Sort-Object -Unique) -join ', '
            New-Signal 'UnsignedListener' 15 '' 'Unsigned program listening on every network interface. Make sure the firewall covers it.' $ports
        }
        foreach ($c in $external | Where-Object { $script:NotablePorts.ContainsKey([int]$_.RemotePort) } | Sort-Object RemotePort -Unique) {
            New-Signal 'NotablePort' 20 'T1571' "Remote port $($c.RemotePort): $($script:NotablePorts[[int]$c.RemotePort])." $c.Remote
        }
    }
}

function Get-SusProcessFinding {
    <#
    .SYNOPSIS
        Scores every running process. Returns only processes with at least one signal.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Snapshot,
        [object[]]$Connections
    )
    if (-not $Snapshot) { $Snapshot = Get-ProcessSnapshot }
    $byPid = @{}
    foreach ($c in $Connections) {
        if (-not $byPid.ContainsKey($c.PID)) { $byPid[$c.PID] = New-Object System.Collections.Generic.List[object] }
        $byPid[$c.PID].Add($c)
    }
    $i = 0
    foreach ($p in @($Snapshot.Values)) {
        $i++
        if ($i % 25 -eq 1) {   # Write-Progress costs ~20 ms a call in Windows PowerShell
            Write-Progress -Activity 'SusHunt: processes' -Status $p.Name -PercentComplete (100 * $i / [Math]::Max(1, $Snapshot.Count))
        }
        if ($p.ProcessId -le 4) { continue }   # System Idle Process and System
        $procId = [int]$p.ProcessId
        $signals = @(Get-ProcessSignals -Process $p -Snapshot $Snapshot -Connections $(if ($byPid.ContainsKey($procId)) { $byPid[$procId].ToArray() }))
        if (-not $signals.Count) { continue }
        New-Finding -Category 'Process' -Name $p.Name -Id "pid $procId" -Path (ConvertTo-NormalPath $p.ExecutablePath) `
            -CommandLine $p.CommandLine -Context (Get-ProcessChain $p $Snapshot) -Signals $signals
    }
    Write-Progress -Activity 'SusHunt: processes' -Completed
}
