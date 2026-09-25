# Shared plumbing: scoring, paths, signatures, process trees and command-line parsing.

$script:SigCache = @{}
$script:MissingReason = @{}

function New-Signal {
    param([string]$Rule, [int]$Points, [string]$Attack, [string]$Why, [string]$Evidence)
    [pscustomobject]@{ Rule = $Rule; Points = $Points; Attack = $Attack; Why = $Why; Evidence = $Evidence }
}

function Get-Severity {
    param([int]$Score)
    if ($Score -ge 60) { 'High' } elseif ($Score -ge 30) { 'Medium' } elseif ($Score -ge 15) { 'Low' } else { 'Info' }
}

function New-Finding {
    param(
        [string]$Category, [string]$Name, [string]$Id, [string]$Path,
        [string]$CommandLine, [string]$Context, [object[]]$Signals
    )
    $Signals = @($Signals | Where-Object { $_ })
    $score = [int][Math]::Min(100, [int](($Signals | Measure-Object -Property Points -Sum).Sum))
    [pscustomobject]@{
        PSTypeName  = 'SusHunt.Finding'
        Score       = $score
        Severity    = Get-Severity $score
        Category    = $Category
        Name        = $Name
        Id          = $Id
        Path        = $Path
        CommandLine = $CommandLine
        Context     = $Context
        Summary     = ($Signals | Sort-Object Points -Descending | ForEach-Object { $_.Rule }) -join ', '
        Signals     = $Signals
    }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 160)
    if (-not $Text) { return $Text }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -le $Max) { return $t }
    $t.Substring(0, $Max - 3) + '...'
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-NormalPath {
    # Paths arrive in many dialects: %SystemRoot%\..., \??\C:\..., \\?\C:\..., \SystemRoot\...
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    $p = $p -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
    if ($p -match '^(?i)\\SystemRoot\\') { $p = Join-Path $env:windir $p.Substring(12) }
    elseif ($p -match '^(?i)system32\\') { $p = Join-Path $env:windir $p }
    $p
}

function Get-PathRisk {
    # Standard users can write to their profile, Temp and ProgramData, but not to Windows or
    # Program Files. Malware without admin rights has to live somewhere it can write.
    param([string]$Path)
    $p = ConvertTo-NormalPath $Path
    if (-not $p) { return 'Unknown' }
    $l = $p.ToLowerInvariant()
    $win = $env:windir.ToLowerInvariant().TrimEnd('\')
    if ($l -match '\\(appdata\\local\\temp|downloads|users\\public|\$recycle\.bin)\\') { return 'HighRisk' }
    # A few folders inside Windows grant standard users create/write access, so "under
    # C:\Windows" does not mean "only admins could have put it there".
    foreach ($dir in $script:UserWritableWindowsDirs) {
        if ($l.StartsWith("$win\$dir\")) { return 'HighRisk' }
    }
    if ($l.StartsWith("$win\")) { return 'Windows' }
    if ($l -match '^[a-z]:\\program files( \(x86\))?\\') { return 'ProgramFiles' }
    if ($l -match '^[a-z]:\\(users|programdata)\\') { return 'UserWritable' }
    'Other'
}

function Get-SignerName {
    # 'CN="Anthropic, PBC", O=...' -> 'Anthropic, PBC'; 'CN=Microsoft Windows, O=...' -> 'Microsoft Windows'
    param([string]$Subject)
    if ($Subject -match '^CN=(?:"([^"]+)"|([^,]+))') {
        if ($Matches[1]) { return $Matches[1] }
        return $Matches[2]
    }
    $Subject
}

# Authenticode: a signature over the file's hash, chained to a trusted publisher certificate.
# Most Windows files are "catalog signed" (their hash is listed in a signed .cat file), which
# Get-AuthenticodeSignature also checks. Runs in other runspaces too, so it must stand alone.
$script:SignatureCheck = {
    param([string]$Path)
    $exists = $true
    $reason = $null
    try { $null = [IO.File]::GetAttributes($Path) }
    catch {
        $inner = $_.Exception.InnerException
        if ($inner -is [IO.FileNotFoundException] -or $inner -is [IO.DirectoryNotFoundException]) {
            $exists = $false
            $reason = $inner.GetType().Name
        }
    }
    if (-not $exists) { return [pscustomobject]@{ Status = 'Missing'; Subject = $null; Exists = $false; Reason = $reason } }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }
        [pscustomobject]@{ Status = [string]$s.Status; Subject = $subject; Exists = $true }
    } catch {
        [pscustomobject]@{ Status = 'Unreadable'; Subject = $null; Exists = $true }
    }
}

function Get-FileStamp {
    # Size + last-write time: cheap to read, and changes when an updater replaces the file.
    param([string]$Path)
    try {
        $fi = New-Object IO.FileInfo $Path
        if ($fi.Exists) { return '{0}|{1}' -f $fi.Length, $fi.LastWriteTimeUtc.Ticks }
    } catch { }
    $null
}

function Add-SignatureResult {
    param([string]$Path, $Raw)
    # Never cache "missing": the file may be mid-install, and a cached miss would repeat for
    # every later launch from that path.
    if (-not $Raw.Exists) {
        $script:SigCache.Remove($Path)
        $script:MissingReason[$Path] = $Raw.Reason
        return
    }
    $signer = if ($Raw.Subject) { Get-SignerName $Raw.Subject } else { $null }
    $script:SigCache[$Path] = [pscustomobject]@{ Status = $Raw.Status; Signer = $signer; Exists = $true; Stamp = Get-FileStamp $Path }
}

function Test-SignatureCached {
    param([string]$Path)
    $hit = $script:SigCache[$Path]
    $hit -and $hit.Stamp -and $hit.Stamp -eq (Get-FileStamp $Path)
}

function Initialize-SignatureCache {
    # Verifying a signature means hashing the whole file, and an Electron app is 200+ MB, so
    # checking every running program one by one can take half a minute. Use several threads.
    param([string[]]$Paths)
    $todo = @($Paths | ForEach-Object { ConvertTo-NormalPath $_ } |
        Where-Object { $_ -and -not (Test-SignatureCached $_) } | Sort-Object -Unique)
    if ($todo.Count -le 2) {
        foreach ($p in $todo) { Add-SignatureResult $p (& $script:SignatureCheck $p) }
        return
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min(8, [Environment]::ProcessorCount))
    $pool.Open()
    try {
        $jobs = foreach ($p in $todo) {
            $shell = [powershell]::Create().AddScript($script:SignatureCheck).AddArgument($p)
            $shell.RunspacePool = $pool
            [pscustomobject]@{ Path = $p; Shell = $shell; Handle = $shell.BeginInvoke() }
        }
        foreach ($j in $jobs) {
            Add-SignatureResult $j.Path ($j.Shell.EndInvoke($j.Handle) | Select-Object -First 1)
            $j.Shell.Dispose()
        }
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
}

function Start-SignatureWarmup {
    # Background version of Initialize-SignatureCache: returns at once; call
    # Receive-SignatureWarmup now and then to move finished results into the cache.
    param([string[]]$Paths)
    $todo = @($Paths | ForEach-Object { ConvertTo-NormalPath $_ } |
        Where-Object { $_ -and -not (Test-SignatureCached $_) } | Sort-Object -Unique)
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, [Math]::Min(4, [Environment]::ProcessorCount / 2)))
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($p in $todo) {
        $shell = [powershell]::Create().AddScript($script:SignatureCheck).AddArgument($p)
        $shell.RunspacePool = $pool
        $jobs.Add([pscustomobject]@{ Path = $p; Shell = $shell; Handle = $shell.BeginInvoke() })
    }
    [pscustomobject]@{ Pool = $pool; Jobs = $jobs; Total = $todo.Count }
}

function Receive-SignatureWarmup {
    # Merges finished checks into the cache. Returns $true while work is still pending.
    param($Warmup)
    if (-not $Warmup -or -not $Warmup.Pool) { return $false }
    for ($i = $Warmup.Jobs.Count - 1; $i -ge 0; $i--) {
        $j = $Warmup.Jobs[$i]
        if (-not $j.Handle.IsCompleted) { continue }
        Add-SignatureResult $j.Path ($j.Shell.EndInvoke($j.Handle) | Select-Object -First 1)
        $j.Shell.Dispose()
        $Warmup.Jobs.RemoveAt($i)
    }
    if ($Warmup.Jobs.Count) { return $true }
    $Warmup.Pool.Close()
    $Warmup.Pool.Dispose()
    $Warmup.Pool = $null
    $false
}

function Stop-SignatureWarmup {
    param($Warmup)
    if (-not $Warmup -or -not $Warmup.Pool) { return }
    foreach ($j in $Warmup.Jobs) { try { $j.Shell.Stop(); $j.Shell.Dispose() } catch { } }
    $Warmup.Pool.Close()
    $Warmup.Pool.Dispose()
    $Warmup.Pool = $null
}

function Get-FileSignature {
    param([string]$Path)
    $p = ConvertTo-NormalPath $Path
    if (-not $p) { return [pscustomobject]@{ Status = 'Unknown'; Signer = $null; Exists = $false } }
    if (-not (Test-SignatureCached $p)) { Initialize-SignatureCache @($p) }
    $hit = $script:SigCache[$p]
    if ($hit) { return $hit }
    [pscustomobject]@{ Status = 'Missing'; Signer = $null; Exists = $false; Reason = $script:MissingReason[$p] }
}

function Test-MicrosoftSigned {
    param([string]$Path)
    $sig = Get-FileSignature $Path
    $sig.Status -eq 'Valid' -and $sig.Signer -match '^Microsoft '
}

function Get-ExecutableFromCommand {
    # Mirrors how CreateProcess reads an unquoted command line: it tries "C:\Program.exe", then
    # "C:\Program Files\My.exe", and so on, taking the first file that exists. That search is
    # exactly what makes unquoted service paths exploitable (T1574.009).
    param([string]$CommandLine, [string]$WorkingDirectory, [ValidateSet('User', 'Machine')][string]$PathScope = 'User')
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        $first = if ($end -gt 1) { ConvertTo-NormalPath $cmd.Substring(1, $end - 1) } else { ConvertTo-NormalPath $cmd }
    } else {
        $tokens = $cmd -split ' '
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $candidate = ConvertTo-NormalPath ($tokens[0..$i] -join ' ')
            if ($candidate -notmatch '\\') { break }
            foreach ($c in @($candidate, "$candidate.exe")) {
                if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
            }
        }
        $first = ConvertTo-NormalPath $tokens[0]
    }
    if ($first -match '\\') { return $first }
    $found = Resolve-BareCommand -Name $first -WorkingDirectory $WorkingDirectory -PathScope $PathScope
    if ($found) { return $found }
    $first
}

function Get-CommandSearchDirs {
    # The folders CreateProcess searches for a bare program name, in order (see the
    # CreateProcess docs): the launcher's folder (System32 for services and tasks), the
    # current directory, System32, the 16-bit System folder, Windows, then PATH. A service or
    # task gets the machine PATH, not the PATH of whoever runs this script.
    param([string]$WorkingDirectory, [ValidateSet('User', 'Machine')][string]$PathScope = 'User')
    $sys32 = Join-Path $env:windir 'System32'
    $dirs = @($sys32)
    if ($WorkingDirectory) { $dirs += ConvertTo-NormalPath $WorkingDirectory }
    $dirs += $sys32, (Join-Path $env:windir 'System'), $env:windir
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($PathScope -eq 'User') { $path = "$path;$([Environment]::GetEnvironmentVariable('Path', 'User'))" }
    $dirs += @($path -split ';' | Where-Object { $_ } | ForEach-Object { ConvertTo-NormalPath $_ })
    $dirs | Where-Object { $_ }
}

function Resolve-BareCommand {
    param([string]$Name, [string]$WorkingDirectory, [ValidateSet('User', 'Machine')][string]$PathScope = 'User')
    if (-not $Name -or $Name -match '[\\/*?]') { return $null }
    $names = if ([IO.Path]::HasExtension($Name)) { @($Name) } else { @("$Name.exe", $Name) }
    foreach ($dir in Get-CommandSearchDirs -WorkingDirectory $WorkingDirectory -PathScope $PathScope) {
        foreach ($n in $names) {
            $candidate = try { [IO.Path]::Combine($dir, $n) } catch { continue }
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    $null
}

function Get-SearchOrderSignal {
    # A bare name ("powershell.exe") that resolves to a folder normal users can write means
    # whoever controls that folder decides what actually runs (T1574.008).
    param([string]$CommandLine, [string]$Executable)
    if (-not $CommandLine -or -not $Executable) { return }
    $first = ($CommandLine.Trim() -split '\s+')[0].Trim('"')
    if ($first -match '\\') { return }
    if (@('HighRisk', 'UserWritable') -contains (Get-PathRisk $Executable)) {
        New-Signal 'BareNameWritableDir' 40 'T1574.008' "The bare name '$first' resolves to a folder standard users can write." $Executable
    }
}

function Test-UnquotedServicePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $false }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) { return $false }
    $exeEnd = $p.ToLowerInvariant().IndexOf('.exe')
    if ($exeEnd -lt 0) { return $false }
    $exe = $p.Substring(0, $exeEnd + 4)
    $exe.Contains(' ') -and -not $exe.ToLowerInvariant().StartsWith($env:windir.ToLowerInvariant() + '\')
}

function Get-ProcessSnapshot {
    $map = @{}
    foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) { $map[[int]$p.ProcessId] = $p }
    $map
}

function Get-ParentProcess {
    # Windows recycles PIDs. If the "parent" started after the child, the real parent exited
    # and its PID was handed to some unrelated process, so we must not trust it.
    param($Process, [hashtable]$Snapshot)
    $parent = $Snapshot[[int]$Process.ParentProcessId]
    if (-not $parent -or $parent.ProcessId -eq $Process.ProcessId) { return $null }
    if ($Process.CreationDate -and $parent.CreationDate -and $parent.CreationDate -gt $Process.CreationDate) { return $null }
    $parent
}

function Get-ProcessChain {
    param($Process, [hashtable]$Snapshot, [int]$Depth = 5)
    $parts = @()
    $cur = $Process
    for ($i = 0; $i -lt $Depth -and $cur; $i++) {
        $parts += "$($cur.Name)[$($cur.ProcessId)]"
        $next = Get-ParentProcess $cur $Snapshot
        if (-not $next -and $cur.ParentProcessId) { $parts += "[$($cur.ParentProcessId) exited]" }
        $cur = $next
    }
    $parts -join ' <- '
}

function Get-EditDistance {
    # Optimal string alignment distance: Levenshtein (insert, delete, substitute) plus swapping
    # two neighbouring letters, so 'scvhost' is 1 away from 'svchost' instead of 2.
    param([string]$A, [string]$B)
    # Only the last two rows of the usual (len A + 1) x (len B + 1) table are ever needed.
    $a = $A.ToLowerInvariant(); $b = $B.ToLowerInvariant()
    $prev2 = $null
    $prev = [int[]](0..$b.Length)
    for ($i = 1; $i -le $a.Length; $i++) {
        $cur = New-Object int[] ($b.Length + 1)
        $cur[0] = $i
        for ($j = 1; $j -le $b.Length; $j++) {
            $cost = [int]($a[$i - 1] -ne $b[$j - 1])
            $insert = $cur[$j - 1] + 1
            $delete = $prev[$j] + 1
            $substitute = $prev[$j - 1] + $cost
            $best = [Math]::Min([Math]::Min($insert, $delete), $substitute)
            if ($i -gt 1 -and $j -gt 1 -and $a[$i - 1] -eq $b[$j - 2] -and $a[$i - 2] -eq $b[$j - 1]) {
                $best = [Math]::Min($best, $prev2[$j - 2] + 1)
            }
            $cur[$j] = $best
        }
        $prev2 = $prev
        $prev = $cur
    }
    $prev[$b.Length]
}

$script:LookalikeCache = @{}

function Get-LookalikeName {
    # Typosquatted names (svch0st.exe, scvhost.exe) sit one edit away from the real thing.
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    if ($script:LookalikeCache.ContainsKey($n)) { return $script:LookalikeCache[$n] }
    $match = $null
    if (-not $script:SystemBinaries.ContainsKey($n) -and $script:LookalikeExceptions -notcontains $n) {
        $base = $n -replace '\.exe$'
        foreach ($real in $script:SystemBinaries.Keys) {
            $realBase = $real -replace '\.exe$'
            if ($realBase.Length -lt 4 -or [Math]::Abs($realBase.Length - $base.Length) -gt 1) { continue }
            if ((Get-EditDistance $base $realBase) -eq 1) { $match = $real; break }
        }
    }
    $script:LookalikeCache[$n] = $match
    $match
}

function ConvertFrom-EncodedCommand {
    # -EncodedCommand is base64 over UTF-16LE text.
    param([string]$CommandLine)
    $m = [regex]::Match($CommandLine, '(?i)(?:^|\s)[-/]e[a-z]*\s+"?([a-z0-9+/]{20,}={0,2})')
    if (-not $m.Success) { return $null }
    $b64 = $m.Groups[1].Value
    while ($b64.Length % 4) { $b64 += '=' }
    try { [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64)) } catch { $null }
}

function Get-CommandLineSignals {
    param([string]$CommandLine, [switch]$Decoded)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return }
    foreach ($rule in $script:CommandLineRules) {
        if ($rule.AppliesTo -and $CommandLine -notmatch $rule.AppliesTo) { continue }
        $m = [regex]::Match($CommandLine, $rule.Pattern)
        if (-not $m.Success) { continue }
        $name = $rule.Name
        if ($Decoded) { $name += '(decoded)' }
        $evidence = $m.Value
        if ($rule.Name -eq 'EncodedPowerShell' -and -not $Decoded) {
            $text = ConvertFrom-EncodedCommand $CommandLine
            if ($text) {
                $evidence = 'decodes to: ' + $text
                Get-CommandLineSignals -CommandLine $text -Decoded
            }
        }
        New-Signal $name $rule.Points $rule.Attack $rule.Why (Limit-Text $evidence 200)
    }
}

function Get-LaunchSignals {
    # Scores "what will this autostart entry run?" by the program, any script it runs, and the
    # command line itself.
    param([string]$CommandLine, [string]$Executable)
    if (-not $Executable) { $Executable = Get-ExecutableFromCommand $CommandLine }
    if ($Executable) {
        $risk = Get-PathRisk $Executable
        $sig = Get-FileSignature $Executable
        if (-not $sig.Exists) {
            New-Signal 'TargetMissing' 10 '' 'Points at a file that no longer exists. Usually an uninstall leftover, but it is a slot someone could fill if the folder is writable.' $Executable
        } elseif ($sig.Status -eq 'HashMismatch') {
            New-Signal 'TamperedBinary' 60 'T1554' 'Signed, but the file changed after signing. Someone modified it.' $Executable
        } elseif ($sig.Status -ne 'Valid') {
            $pts = switch ($risk) { 'HighRisk' { 25 } 'UserWritable' { 15 } 'Windows' { 20 } default { 10 } }
            New-Signal 'Unsigned' $pts '' "No valid Authenticode signature ($($sig.Status)); the file lives in a $risk location." $Executable
        }
        if ($risk -eq 'HighRisk') {
            New-Signal 'LaunchesFromTemp' 25 'T1204.002' 'Starts a program out of Temp, Downloads, Public or the Recycle Bin.' $Executable
        }
    }
    if ($CommandLine) {
        $scripts = [regex]::Matches($CommandLine, '(?i)[a-z]:\\[^"<>|*?\r\n]*?\.(ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd)\b')
        foreach ($s in $scripts) {
            if ((Get-PathRisk $s.Value) -eq 'HighRisk') {
                New-Signal 'ScriptFromTemp' 30 'T1204.002' 'Runs a script stored in Temp, Downloads, Public or the Recycle Bin.' $s.Value
            }
        }
        Get-CommandLineSignals $CommandLine
    }
}

function Get-Allowlist {
    $file = Join-Path (Split-Path $PSScriptRoot -Parent) 'allowlist.txt'
    if (-not (Test-Path -LiteralPath $file)) { return @() }
    @(Get-Content -LiteralPath $file | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}

function Test-Allowlisted {
    param($Finding, [string[]]$Patterns)
    foreach ($p in $Patterns) {
        if (($Finding.Path -and $Finding.Path -like $p) -or $Finding.Name -like $p) { return $true }
    }
    $false
}
