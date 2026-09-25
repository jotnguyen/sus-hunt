# Baseline and diff. Most hunting value is in change: "what is new since last week?" beats
# any single rule. A baseline records autostart entries, listening ports and the programs seen
# running, with a SHA-256 of each file, so a quietly replaced binary shows up as Changed.

$script:HashCheck = {
    param([string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
}

function Get-FileHashes {
    # Same runspace-pool idea as signature checks: hashing big files is the slow part.
    param([string[]]$Paths)
    $result = @{}
    $todo = @($Paths | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $todo.Count) { return $result }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min(8, [Environment]::ProcessorCount))
    $pool.Open()
    try {
        $jobs = foreach ($p in $todo) {
            $shell = [powershell]::Create().AddScript($script:HashCheck).AddArgument($p)
            $shell.RunspacePool = $pool
            [pscustomobject]@{ Path = $p; Shell = $shell; Handle = $shell.BeginInvoke() }
        }
        foreach ($j in $jobs) {
            $result[$j.Path] = $j.Shell.EndInvoke($j.Handle) | Select-Object -First 1
            $j.Shell.Dispose()
        }
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
    $result
}

function Get-SusStateItems {
    # One flat list of comparable items. Key identifies an item across scans; Value is what
    # counts as "changed".
    $snapshot = Get-ProcessSnapshot
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in Get-SusPersistenceFinding -All) {
        $items.Add([pscustomobject]@{ Kind = $f.Category; Key = "$($f.Category)|$($f.Context)|$($f.Name)"; Path = $f.Path; Detail = $f.CommandLine })
    }
    # UDP sockets in the dynamic range (49152+) are mostly short-lived client sockets, not
    # services, so tracking them would make every diff noisy.
    $listeners = Get-SusConnection -Snapshot $snapshot | Where-Object {
        $_.State -eq 'Listen' -and ($_.Protocol -eq 'TCP' -or [int]$_.LocalPort -lt 49152)
    }
    foreach ($c in $listeners) {
        $items.Add([pscustomobject]@{ Kind = 'Listener'; Key = "Listener|$($c.Protocol)|$($c.Local)|$($c.Process)"; Path = $c.Path; Detail = $null })
    }
    $programs = $snapshot.Values | ForEach-Object { ConvertTo-NormalPath $_.ExecutablePath } | Where-Object { $_ } | Sort-Object -Unique
    foreach ($p in $programs) {
        $items.Add([pscustomobject]@{ Kind = 'Program'; Key = "Program|$p"; Path = $p; Detail = $null })
    }
    $hashes = Get-FileHashes @($items | ForEach-Object { $_.Path })
    foreach ($i in $items) {
        $i | Add-Member -NotePropertyName Hash -NotePropertyValue $(if ($i.Path) { $hashes[$i.Path] } else { $null })
    }
    $items
}

function Get-BaselineDir {
    Join-Path (Split-Path $PSScriptRoot -Parent) 'baselines'
}

function Save-SusBaseline {
    <#
    .SYNOPSIS
        Records autostart entries, listeners and running programs (with SHA-256 hashes) to a JSON file.
    .NOTES
        The file describes your machine and is git-ignored. Anyone who can edit it can hide a
        change from the next diff, so keep a copy somewhere only you can write.
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) {
        $dir = Get-BaselineDir
        $null = New-Item -ItemType Directory -Path $dir -Force
        $Path = Join-Path $dir ("baseline_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    $items = @(Get-SusStateItems)
    [pscustomobject]@{ Created = (Get-Date).ToString('o'); Items = $items } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Host "Baseline saved: $Path ($($items.Count) items)" -ForegroundColor Cyan
    $Path
}

function Compare-SusBaseline {
    <#
    .SYNOPSIS
        Compares the machine now against a saved baseline (default: the newest one).
        Reports Added and Removed items, and Changed ones (different command line or file hash).
        Programs are only reported when new: programs that stopped running are not news.
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) {
        $latest = Get-ChildItem -Path (Get-BaselineDir) -Filter 'baseline_*.json' -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if (-not $latest) { throw 'No baseline yet. Run: .\sus-hunt.ps1 baseline' }
        $Path = $latest.FullName
    }
    $saved = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Write-Verbose "Comparing against $Path (taken $($saved.Created))"
    $old = @{}
    foreach ($i in $saved.Items) { $old[$i.Key] = $i }
    $new = @{}
    foreach ($i in Get-SusStateItems) { $new[$i.Key] = $i }

    foreach ($key in $new.Keys) {
        $n = $new[$key]
        if (-not $old.ContainsKey($key)) {
            [pscustomobject]@{ PSTypeName = 'SusHunt.Change'; Change = 'Added'; Kind = $n.Kind; Key = $key; Before = $null; After = (Format-StateValue $n) }
            continue
        }
        $o = $old[$key]
        if ($o.Detail -ne $n.Detail -or ($o.Hash -and $n.Hash -and $o.Hash -ne $n.Hash)) {
            [pscustomobject]@{ PSTypeName = 'SusHunt.Change'; Change = 'Changed'; Kind = $n.Kind; Key = $key; Before = (Format-StateValue $o); After = (Format-StateValue $n) }
        }
    }
    foreach ($key in $old.Keys) {
        if ($new.ContainsKey($key) -or $old[$key].Kind -eq 'Program') { continue }
        $o = $old[$key]
        [pscustomobject]@{ PSTypeName = 'SusHunt.Change'; Change = 'Removed'; Kind = $o.Kind; Key = $key; Before = (Format-StateValue $o); After = $null }
    }
}

function Format-StateValue {
    param($Item)
    $hash = if ($Item.Hash) { " sha256:$($Item.Hash.Substring(0, 12))..." } else { '' }
    (Limit-Text "$($Item.Detail) $($Item.Path)$hash" 200)
}
