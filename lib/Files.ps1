# Files on disk. Everything else in the kit looks at what is running or registered to run; a
# dropper that has not launched yet, or a script waiting for the next logon, sits in a folder the
# user can write to. This scans recent files there. It only reads: bytes, headers, the
# Zone.Identifier stream and .lnk fields. Nothing it finds is ever run.

function Get-ShannonEntropy {
    # Bits per byte, 0 (all the same byte) to 8 (every byte value equally likely). Compressed or
    # encrypted data sits near 8; compiled code around 6; text around 4-5.
    param([byte[]]$Bytes, [int]$Offset = 0, [int]$Count = -1)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return 0.0 }
    if ($Count -lt 0 -or $Offset + $Count -gt $Bytes.Length) { $Count = $Bytes.Length - $Offset }
    Initialize-SusNative
    [SusHunt.V4.Win32]::ShannonEntropy($Bytes, $Offset, $Count)
}

$script:PeMachines = @{ 0x14c = 'x86'; 0x8664 = 'x64'; 0xAA64 = 'ARM64'; 0x1c4 = 'ARM' }

function Get-PeInfo {
    # Reads the PE (Portable Executable) headers from the first bytes of a file:
    #   'MZ' DOS header -> e_lfanew at 0x3C points to 'PE\0\0' -> COFF header (machine, section
    #   count, compile time) -> optional header (magic 0x10B = 32-bit, 0x20B = 64-bit) -> section
    #   table, 40 bytes per section. Returns $null for anything that is not a PE file.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $null }
    $pe = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($pe -lt 0x40 -or $pe + 24 -gt $Bytes.Length) { return $null }
    if ($Bytes[$pe] -ne 0x50 -or $Bytes[$pe + 1] -ne 0x45 -or $Bytes[$pe + 2] -ne 0 -or $Bytes[$pe + 3] -ne 0) { return $null }

    $coff = $pe + 4
    $machine = [int][BitConverter]::ToUInt16($Bytes, $coff)
    $sectionCount = [int][BitConverter]::ToUInt16($Bytes, $coff + 2)
    $stamp = [BitConverter]::ToUInt32($Bytes, $coff + 4)
    $optSize = [int][BitConverter]::ToUInt16($Bytes, $coff + 16)
    $flags = [int][BitConverter]::ToUInt16($Bytes, $coff + 18)
    $opt = $coff + 20
    $magic = if ($opt + 2 -le $Bytes.Length) { [int][BitConverter]::ToUInt16($Bytes, $opt) } else { 0 }

    $sections = New-Object System.Collections.Generic.List[object]
    $table = $opt + $optSize
    $truncated = $false
    for ($i = 0; $i -lt [Math]::Min($sectionCount, 96); $i++) {
        $at = $table + 40 * $i
        if ($at + 40 -gt $Bytes.Length) { $truncated = $true; break }
        $chars = [BitConverter]::ToUInt32($Bytes, $at + 36)
        $sections.Add([pscustomobject]@{
            Name       = [Text.Encoding]::ASCII.GetString($Bytes, $at, 8).TrimEnd([char]0)
            RawSize    = [BitConverter]::ToUInt32($Bytes, $at + 16)
            RawOffset  = [BitConverter]::ToUInt32($Bytes, $at + 20)
            Executable = [bool]($chars -band 0x20000020)   # MEM_EXECUTE or CNT_CODE
        })
    }
    $machineName = $script:PeMachines[$machine]
    if (-not $machineName) { $machineName = '0x{0:X4}' -f $machine }
    [pscustomobject]@{
        Machine     = $machineName
        Is64        = $magic -eq 0x20B
        IsDll       = [bool]($flags -band 0x2000)
        CompileTime = ([datetime]'1970-01-01Z').ToUniversalTime().AddSeconds($stamp)
        Sections    = $sections.ToArray()
        Truncated   = $truncated
    }
}

function ConvertFrom-ZoneIdentifier {
    # The Zone.Identifier alternate data stream is Mark-of-the-Web: a small INI file browsers and
    # mail clients attach to downloads. ZoneId 3 = Internet, 4 = Restricted. SmartScreen and
    # Office Protected View key off it.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $out = [ordered]@{ ZoneId = $null; HostUrl = $null; ReferrerUrl = $null }
    foreach ($line in $Text -split "`r?`n") {
        if ($line -match '^\s*ZoneId\s*=\s*(\d+)') { $out.ZoneId = [int]$Matches[1] }
        elseif ($line -match '^\s*HostUrl\s*=\s*(.+?)\s*$') { $out.HostUrl = $Matches[1] }
        elseif ($line -match '^\s*ReferrerUrl\s*=\s*(.+?)\s*$') { $out.ReferrerUrl = $Matches[1] }
    }
    if ($null -eq $out.ZoneId) { return $null }
    [pscustomobject]$out
}

function Test-MzHeader {
    param([byte[]]$Bytes)
    $Bytes -and $Bytes.Length -ge 2 -and $Bytes[0] -eq 0x4D -and $Bytes[1] -eq 0x5A
}

function Test-ExtensionMismatch {
    # A Windows program named like a document or picture.
    param([string]$Name, [byte[]]$Header)
    (Test-MzHeader $Header) -and $script:DecoyExtensions -contains [IO.Path]::GetExtension($Name).ToLowerInvariant()
}

function Get-FileRuleSignal {
    param([string]$Rule, [string]$Evidence, [string]$Attack)
    $r = $script:FileRules[$Rule]
    if (-not $Attack) { $Attack = $r.Attack }
    New-Signal $Rule $r.Points $Attack $r.Why $Evidence
}

function Get-FileSignals {
    # Scores one file from facts already read off disk, so it can be tested with made-up input.
    # $Info keys: Name, Path, Header (byte[]), Pe, Zone, Signature, Hidden, Risk, Entropy
    # (@{ Section; Value }), Shortcut (@{ Target; Arguments }).
    param([hashtable]$Info)
    $name = [string]$Info.Name
    $ext = [IO.Path]::GetExtension($name).ToLowerInvariant()
    $isPe = [bool]$Info.Pe
    $isScript = $script:ScriptExtensions -contains $ext

    Get-FileNameSignals $name
    if (Test-ExtensionMismatch $name $Info.Header) { Get-FileRuleSignal 'ExtensionMismatch' $name }

    $zone = $Info.Zone
    if ($zone -and $zone.ZoneId -ge 3) {
        $from = @($zone.HostUrl, $zone.ReferrerUrl | Where-Object { $_ }) -join ' via '
        if (-not $from) { $from = "ZoneId=$($zone.ZoneId), no URL recorded" }
        Get-FileRuleSignal 'DownloadedExecutable' $from
        if ($script:DiskImageExtensions -contains $ext) { Get-FileRuleSignal 'DiskImage' $from }
    }

    $unsigned = $isPe -and $Info.Signature -and $Info.Signature.Status -ne 'Valid'
    if ($unsigned -and $Info.Risk -eq 'HighRisk') {
        Get-FileRuleSignal 'UnsignedInHighRisk' "$($Info.Signature.Status): $($Info.Path)"
    }
    if ($isPe -and $Info.Signature -and $Info.Signature.Status -eq 'HashMismatch') {
        New-Signal 'TamperedBinary' 60 'T1554' 'Signed, but the file changed after signing. Someone modified it.' $Info.Path
    }
    if ($unsigned -and $Info.Entropy -and $Info.Entropy.Value -gt $script:PackedEntropy) {
        Get-FileRuleSignal 'PackedSection' ('section {0}: {1:N2} bits/byte' -f $Info.Entropy.Section, $Info.Entropy.Value)
    }
    $validlySigned = $Info.Signature -and $Info.Signature.Status -eq 'Valid'
    if ($isPe -and -not $validlySigned) {
        $t = $Info.Pe.CompileTime
        if ($t -gt [datetime]::UtcNow.AddDays(1) -or $t -lt [datetime]'2000-01-01') {
            Get-FileRuleSignal 'OddCompileTime' ('compiled {0:yyyy-MM-dd HH:mm} UTC' -f $t)
        }
    }
    if ($Info.Hidden -and ($isPe -or $isScript)) { Get-FileRuleSignal 'HiddenInUserDir' $Info.Path }

    $lnk = $Info.Shortcut
    if ($lnk -and $lnk.Target) {
        $leaf = [IO.Path]::GetFileName($lnk.Target).ToLowerInvariant()
        $line = ('"{0}" {1}' -f $lnk.Target, $lnk.Arguments).Trim()
        if ($script:ShellLike -contains $leaf -or $script:Lolbins -contains $leaf) {
            Get-FileRuleSignal 'LnkRunsShell' (Limit-Text $line 200)
        }
        Get-CommandLineSignals $line
    }
}

function Get-DownloadsFolder {
    # Downloads can be moved, so ask Explorer's shell-folder table instead of guessing.
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $raw = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).'{374DE290-123F-4565-9164-39C4925E467B}'
    if ($raw) { return [Environment]::ExpandEnvironmentVariables($raw) }
    Join-Path $env:USERPROFILE 'Downloads'
}

function Get-FileScanRoot {
    # Folders a standard user (and so malware without admin) can write to.
    param([string[]]$Extra)
    $roots = @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA, (Get-DownloadsFolder), $env:ProgramData, $env:PUBLIC)
    $roots += @($script:UserWritableWindowsDirs | ForEach-Object { Join-Path $env:windir $_ })
    $roots += $Extra
    $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') } | Sort-Object -Unique
}

function Test-SkippedDir {
    # Same test FindRecentFiles applies in C#, kept here so the patterns can be unit tested.
    param([string]$Path)
    foreach ($rx in $script:FileScanSkipDirs) { if ($Path -match $rx) { return $true } }
    $false
}

function Find-RecentFile {
    # Walks the roots in C# (lib/Native.ps1): skips junctions, cloud placeholders (reading one
    # downloads it) and the cache folders in $script:FileScanSkipDirs.
    param([string[]]$Roots, [datetime]$Since)
    Initialize-SusNative
    [SusHunt.V4.Win32]::FindRecentFiles([string[]]$Roots, $Since.ToUniversalTime(), [string[]]$script:FileScanSkipDirs)
}

function Get-MaxSectionEntropy {
    # Highest entropy among the executable sections. Reads at most 8 MB per section.
    param([string]$Path, $Pe)
    $best = $null
    try {
        $fs = New-Object IO.FileStream $Path, 'Open', 'Read', 'ReadWrite, Delete'
        try {
            foreach ($s in $Pe.Sections | Where-Object { $_.Executable -and $_.RawSize -gt 0 }) {
                if ($s.RawOffset -ge $fs.Length) { continue }
                $len = [int][Math]::Min([Math]::Min([long]$s.RawSize, $fs.Length - $s.RawOffset), 8MB)
                $buf = New-Object byte[] $len
                $null = $fs.Seek($s.RawOffset, 'Begin')
                $read = $fs.Read($buf, 0, $len)
                $h = Get-ShannonEntropy $buf 0 $read
                if (-not $best -or $h -gt $best.Value) { $best = @{ Section = $s.Name; Value = $h } }
            }
        } finally { $fs.Dispose() }
    } catch { Write-Verbose "entropy failed for ${Path}: $($_.Exception.Message)" }
    $best
}

function Get-ZoneIdentifier {
    param([string]$Path)
    $text = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -Raw -ErrorAction SilentlyContinue
    ConvertFrom-ZoneIdentifier $text
}

function Resolve-YaraExe {
    param([string]$YaraExe)
    if ($YaraExe) {
        if (Test-Path -LiteralPath $YaraExe -PathType Leaf) { return (Resolve-Path -LiteralPath $YaraExe).Path }
        return $null
    }
    foreach ($n in 'yara64.exe', 'yara.exe') {
        $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    $null
}

function ConvertFrom-YaraOutput {
    # 'RuleName [attack="T1059.001",author="x"] C:\path\file' (with -m) or 'RuleName C:\path\file'.
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        $m = [regex]::Match($line, '^(\S+)\s+(?:\[(.*)\]\s+)?((?:[A-Za-z]:\\|\\\\).+)$')
        if (-not $m.Success) { continue }
        $attack = [regex]::Match($m.Groups[2].Value, '\bT\d{4}(\.\d{3})?\b').Value
        [pscustomobject]@{ Rule = $m.Groups[1].Value; Attack = $attack; Path = $m.Groups[3].Value.Trim() }
    }
}

function Invoke-YaraScan {
    # Runs the yara binary the human installed, over the candidate files only, in one process.
    # Local only: yara makes no network calls.
    param([string[]]$Paths, [string]$Rules, [string]$YaraExe)
    $ruleFiles = if (Test-Path -LiteralPath $Rules -PathType Container) {
        @(Get-ChildItem -LiteralPath $Rules -Recurse -File -Include '*.yar', '*.yara' | ForEach-Object { $_.FullName })
    } else { @((Resolve-Path -LiteralPath $Rules).Path) }
    if (-not $ruleFiles.Count) { Write-Warning "No .yar or .yara files found in $Rules."; return @() }
    $list = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllLines($list, [string[]]$Paths, (New-Object Text.UTF8Encoding $false))
        $argList = @('-w', '-m', '--scan-list') + $ruleFiles + @($list)
        $out = & $YaraExe @argList 2>&1
        foreach ($e in $out | Where-Object { $_ -is [Management.Automation.ErrorRecord] }) { Write-Verbose "yara: $e" }
        ConvertFrom-YaraOutput @($out | Where-Object { $_ -is [string] })
    } finally {
        Remove-Item -LiteralPath $list -ErrorAction SilentlyContinue
    }
}

function Get-SusFileFinding {
    <#
    .SYNOPSIS
        Scores recent programs, scripts, shortcuts and disk images in folders any user can write to.
    .PARAMETER Days
        Only files created or modified in the last N days.
    .PARAMETER Path
        Extra folders to scan, on top of Temp, AppData, Downloads, ProgramData, Public and the
        user-writable folders inside Windows.
    .PARAMETER Yara
        A .yar file, or a folder of them. Needs yara64.exe on PATH or -YaraExe.
    .EXAMPLE
        Get-SusFileFinding -Days 1 | Format-Table Score, Name, Summary
    #>
    [CmdletBinding()]
    param(
        [int]$Days = 7,
        [string[]]$Path,
        [string]$Yara,
        [string]$YaraExe,
        [int]$MinScore = 15
    )
    $yaraBin = $null
    if ($Yara) {
        $yaraBin = Resolve-YaraExe $YaraExe
        if (-not $yaraBin) { Write-Warning 'yara64.exe not found (put it on PATH or pass -YaraExe). Skipping YARA.' }
        elseif (-not (Test-Path -LiteralPath $Yara)) { Write-Warning "YARA rules not found: $Yara. Skipping YARA."; $yaraBin = $null }
    }
    $allow = Get-Allowlist
    $roots = @(Get-FileScanRoot -Extra $Path)
    Write-Verbose "roots: $($roots -join '; ')"
    $clock = [Diagnostics.Stopwatch]::StartNew()

    # 1. Pick candidates: a scan extension, or a program header under any other name. Scripts
    #    and shortcuts need no header, so they are never opened here.
    $picked = New-Object System.Collections.Generic.List[object]
    $toRead = New-Object System.Collections.Generic.List[string]
    foreach ($fi in Find-RecentFile -Roots $roots -Since (Get-Date).AddDays(-$Days)) {
        $ext = $fi.Extension.ToLowerInvariant()
        $wanted = $script:ScanExtensions -contains $ext
        $sniff = $script:SniffExtensions -contains $ext -and $fi.Length -le $script:FileSniffMaxBytes
        if (-not $wanted -and -not $sniff) { continue }
        $read = $fi.Length -ge 2 -and ($sniff -or $script:PeExtensions -contains $ext)
        $picked.Add([pscustomobject]@{ File = $fi; Wanted = $wanted; Read = $read })
        if ($read) { $toRead.Add($fi.FullName) }
    }
    Write-Progress -Activity 'SusHunt: files' -Status "Reading the headers of $($toRead.Count) files"
    $heads = @{}
    if ($toRead.Count) {
        Initialize-SusNative
        $bytes = [SusHunt.V4.Win32]::ReadHeads($toRead.ToArray(), 4096)
        for ($i = 0; $i -lt $toRead.Count; $i++) { $heads[$toRead[$i]] = $bytes[$i] }
    }
    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($p in $picked) {
        $head = if ($p.Read) { $heads[$p.File.FullName] } else { $null }
        if (-not $p.Wanted -and -not (Test-MzHeader $head)) { continue }
        $candidates.Add([pscustomobject]@{ File = $p.File; Head = $head; Pe = (Get-PeInfo $head) })
    }
    Write-Verbose ("candidates: {0} after {1:N1} s" -f $candidates.Count, $clock.Elapsed.TotalSeconds)

    # 2. Signatures in parallel (Authenticode hashes the whole file).
    #    Big binaries outside Temp/Downloads/Public are skipped: they are almost always app updates
    #    (Electron apps run to 200 MB each), and hashing them would take most of the scan time.
    foreach ($c in $candidates) {
        $c | Add-Member NoteProperty CheckSignature ([bool]($c.Pe -and ($c.File.Length -le $script:FileSignatureMaxBytes -or
            (Get-PathRisk $c.File.FullName) -eq 'HighRisk')))
    }
    $toVerify = @($candidates | Where-Object { $_.CheckSignature } | ForEach-Object { $_.File.FullName })
    Write-Progress -Activity 'SusHunt: files' -Status "Verifying signatures of $($toVerify.Count) programs"
    Initialize-SignatureCache $toVerify
    Write-Verbose ("signatures: {0} checked by {1:N1} s" -f $toVerify.Count, $clock.Elapsed.TotalSeconds)

    $yaraHits = @{}
    if ($yaraBin -and $candidates.Count) {
        Write-Progress -Activity 'SusHunt: files' -Status 'YARA'
        foreach ($h in Invoke-YaraScan -Paths @($candidates | ForEach-Object { $_.File.FullName }) -Rules $Yara -YaraExe $yaraBin) {
            if (-not $yaraHits.ContainsKey($h.Path)) { $yaraHits[$h.Path] = New-Object System.Collections.Generic.List[object] }
            $yaraHits[$h.Path].Add($h)
        }
    }

    # 3. Score each candidate.
    $shell = $null
    try {
        $i = 0
        foreach ($c in $candidates) {
            $i++
            if ($i % 50 -eq 1) { Write-Progress -Activity 'SusHunt: files' -Status $c.File.Name -PercentComplete (100 * $i / $candidates.Count) }
            $fi = $c.File
            $full = $fi.FullName
            $info = @{
                Name = $fi.Name; Path = $full; Header = $c.Head; Pe = $c.Pe
                Zone = Get-ZoneIdentifier $full
                Risk = Get-PathRisk $full
                Hidden = [bool]($fi.Attributes -band ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
            }
            if ($c.CheckSignature) {
                $info.Signature = Get-FileSignature $full
                if ($info.Signature.Status -ne 'Valid') { $info.Entropy = Get-MaxSectionEntropy $full $c.Pe }
            }
            if ($fi.Extension -eq '.lnk') {
                if (-not $shell) { $shell = New-Object -ComObject WScript.Shell }
                try {
                    $lnk = $shell.CreateShortcut($full)   # reads the .lnk fields; does not run anything
                    $info.Shortcut = @{ Target = $lnk.TargetPath; Arguments = $lnk.Arguments }
                } catch { Write-Verbose "unreadable shortcut ${full}" }
            }
            $signals = @(Get-FileSignals $info)
            if ($yaraHits.ContainsKey($full)) {
                foreach ($h in $yaraHits[$full]) { $signals += Get-FileRuleSignal 'YaraMatch' $h.Rule $h.Attack }
            }
            if (-not $signals.Count) { continue }

            $sha = (Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $context = 'size {0:N0} bytes, created {1:yyyy-MM-dd HH:mm}, modified {2:yyyy-MM-dd HH:mm}' -f $fi.Length, $fi.CreationTime, $fi.LastWriteTime
            if ($c.Pe) { $context += ", PE $($c.Pe.Machine)$(if ($c.Pe.IsDll) { ' DLL' })" }
            if ($info.Signature -and $info.Signature.Signer) { $context += ", signed by $($info.Signature.Signer)" }
            if ($info.Zone -and $info.Zone.HostUrl) { $context += ", from $($info.Zone.HostUrl)" }
            $cmd = if ($info.Shortcut) { ('"{0}" {1}' -f $info.Shortcut.Target, $info.Shortcut.Arguments).Trim() } else { $null }
            $f = New-Finding -Category 'File' -Name $fi.Name -Id $sha -Path $full -CommandLine $cmd -Context $context -Signals $signals
            if ($f.Score -ge $MinScore -and -not (Test-Allowlisted $f $allow)) { $f }
        }
    } finally {
        if ($shell) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
        Write-Progress -Activity 'SusHunt: files' -Completed
        Write-Verbose ("done after {0:N1} s" -f $clock.Elapsed.TotalSeconds)
    }
}
