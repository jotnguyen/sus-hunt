# Detection rules, kept as plain data so they are easy to read, argue with and tune.
# Points add up per process or autorun entry and are capped at 100.
# Attack = MITRE ATT&CK technique ID: https://attack.mitre.org/techniques/T1036/005/ for T1036.005.

# Where genuine Windows binaries live (relative to %windir%, '.' is %windir% itself) and which
# parent normally starts them. An empty Parents list means the parent varies or has already
# exited by design (smss.exe starts csrss.exe and winlogon.exe, then quits), so it is not checked.
$script:SystemBinaries = @{
    'smss.exe'          = @{ Dirs = @('System32'); Parents = @('system', 'smss.exe') }
    'csrss.exe'         = @{ Dirs = @('System32'); Parents = @() }
    'wininit.exe'       = @{ Dirs = @('System32'); Parents = @() }
    'winlogon.exe'      = @{ Dirs = @('System32'); Parents = @() }
    'services.exe'      = @{ Dirs = @('System32'); Parents = @('wininit.exe') }
    'lsass.exe'         = @{ Dirs = @('System32'); Parents = @('wininit.exe') }
    'lsaiso.exe'        = @{ Dirs = @('System32'); Parents = @('wininit.exe') }
    'svchost.exe'       = @{ Dirs = @('System32', 'SysWOW64'); Parents = @('services.exe') }
    'spoolsv.exe'       = @{ Dirs = @('System32'); Parents = @('services.exe') }
    'taskhostw.exe'     = @{ Dirs = @('System32'); Parents = @('svchost.exe') }
    'sihost.exe'        = @{ Dirs = @('System32'); Parents = @('svchost.exe') }
    'runtimebroker.exe' = @{ Dirs = @('System32'); Parents = @('svchost.exe') }
    'wmiprvse.exe'      = @{ Dirs = @('System32\wbem', 'SysWOW64\wbem'); Parents = @('svchost.exe') }
    'dllhost.exe'       = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'conhost.exe'       = @{ Dirs = @('System32'); Parents = @() }
    'userinit.exe'      = @{ Dirs = @('System32'); Parents = @() }
    'explorer.exe'      = @{ Dirs = @('.', 'SysWOW64'); Parents = @() }
    'dwm.exe'           = @{ Dirs = @('System32'); Parents = @() }
    'ctfmon.exe'        = @{ Dirs = @('System32'); Parents = @() }
    'cmd.exe'           = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'powershell.exe'    = @{ Dirs = @('System32\WindowsPowerShell\v1.0', 'SysWOW64\WindowsPowerShell\v1.0'); Parents = @() }
    'rundll32.exe'      = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'regsvr32.exe'      = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'mshta.exe'         = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'wscript.exe'       = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
    'cscript.exe'       = @{ Dirs = @('System32', 'SysWOW64'); Parents = @() }
}

# Folders under %windir% where standard users can create files (check with Get-Acl on your build).
$script:UserWritableWindowsDirs = @(
    'temp', 'tasks', 'tracing', 'system32\tasks', 'system32\spool\drivers\color',
    'system32\microsoft\crypto\rsa\machinekeys', 'syswow64\tasks'
)

# Real Windows names that sit one edit away from a name above, so the lookalike check skips them.
$script:LookalikeExceptions = @('taskhost.exe')

# Programs attackers borrow because every Windows machine already has them ("living off the land").
# See https://lolbas-project.github.io for the full catalogue.
$script:Lolbins = @(
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
    'certutil.exe', 'bitsadmin.exe', 'wscript.exe', 'cscript.exe', 'msbuild.exe', 'installutil.exe',
    'wmic.exe', 'cmstp.exe', 'odbcconf.exe', 'hh.exe', 'msxsl.exe', 'regasm.exe', 'regsvcs.exe', 'forfiles.exe'
)

# Documents should not start shells. When Word starts PowerShell, a macro or an exploit is the usual reason.
$script:DocumentApps = @(
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe', 'msaccess.exe',
    'mspub.exe', 'visio.exe', 'acrord32.exe', 'acrobat.exe', 'foxitpdfreader.exe', 'wordpad.exe'
)
$script:ShellLike = @(
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
    'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'schtasks.exe', 'wmic.exe'
)

# Remote ports with a history. Seeing one is a reason to look closer, not proof of anything.
$script:NotablePorts = @{
    4444  = 'Metasploit default handler'
    1337  = 'hacker-culture port, common in tooling'
    31337 = 'Back Orifice / "eleet"'
    6667  = 'IRC, classic botnet C2'
    6697  = 'IRC over TLS'
    5555  = 'Android ADB, common RAT default'
    9001  = 'Tor relay (ORPort)'
    9050  = 'Tor SOCKS proxy'
    9150  = 'Tor Browser SOCKS proxy'
}

# Command-line patterns. AppliesTo (optional) must also match, to keep a rule on the program it is about.
$script:CommandLineRules = @(
    @{
        Name = 'EncodedPowerShell'; Points = 35; Attack = 'T1027'; AppliesTo = '(?i)powershell|pwsh'
        Pattern = '(?i)(^|\s)[-/]e[a-z]*\s+"?[a-z0-9+/]{20,}={0,2}"?(\s|$)'
        Why = 'PowerShell -EncodedCommand hides the script as base64. Admin tools use it too, so read the decoded text.'
    }
    @{
        Name = 'DownloadAndRun'; Points = 40; Attack = 'T1105'
        Pattern = '(?i)(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer).{0,300}(\biex\b|invoke-expression)|(\biex\b|invoke-expression).{0,300}(downloadstring|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)'
        Why = 'Fetches code from the internet and runs it straight from memory. Some real installers work this way (irm ... | iex), which is exactly why attackers can blend in.'
    }
    @{
        Name = 'HiddenWindow'; Points = 10; Attack = 'T1564.003'; AppliesTo = '(?i)powershell|pwsh'
        Pattern = '(?i)(^|\s)[-/]w[a-z]*\s+h[a-z]*(\s|$)'
        Why = 'Asks for no visible window. Normal for scheduled jobs, also normal for malware.'
    }
    @{
        Name = 'PolicyBypass'; Points = 5; Attack = 'T1059.001'; AppliesTo = '(?i)powershell|pwsh'
        Pattern = '(?i)(^|\s)[-/](ep|ex[a-z]*)\s+(bypass|unrestricted)(\s|$)'
        Why = 'Skips the execution policy. That policy is a speed bump, not a security boundary, so this alone means little.'
    }
    @{
        Name = 'CertutilDownload'; Points = 40; Attack = 'T1105'
        Pattern = '(?i)certutil(\.exe)?\b.*\s[-/](urlcache|verifyctl|decode|decodehex)\b'
        Why = 'certutil is a certificate tool; -urlcache downloads files and -decode unpacks base64 payloads.'
    }
    @{
        Name = 'MshtaScript'; Points = 45; Attack = 'T1218.005'
        Pattern = '(?i)mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)'
        Why = 'mshta runs HTML applications with full user rights. Remote or inline script is rarely legitimate.'
    }
    @{
        Name = 'Rundll32Script'; Points = 45; Attack = 'T1218.011'
        Pattern = '(?i)rundll32(\.exe)?\b.*(javascript:|vbscript:|\\\\[a-z0-9.-]+(@[0-9]+)?\\)'
        Why = 'rundll32 running inline script, or loading a DLL from a network share, is a known proxy-execution trick.'
    }
    @{
        Name = 'Regsvr32Remote'; Points = 45; Attack = 'T1218.010'
        Pattern = '(?i)regsvr32(\.exe)?\b.*[-/]i:\s*"?(https?:|\\\\)'
        Why = 'The "Squiblydoo" technique: regsvr32 fetches and runs a remote scriptlet.'
    }
    @{
        Name = 'BitsTransfer'; Points = 30; Attack = 'T1197'
        Pattern = '(?i)bitsadmin(\.exe)?\b.*[-/](transfer|addfile|setnotifycmdline)\b'
        Why = 'BITS downloads survive reboots and can run a command when done. Windows Update uses BITS; so do droppers.'
    }
    @{
        Name = 'WmicProcessCreate'; Points = 30; Attack = 'T1047'
        Pattern = '(?i)wmic(\.exe)?\b.*process\s+call\s+create'
        Why = 'Starts a process through WMI, which breaks the parent-child chain defenders look at.'
    }
    @{
        Name = 'InhibitRecovery'; Points = 60; Attack = 'T1490'
        Pattern = '(?i)vssadmin(\.exe)?\b.*delete\s+shadows|wmic(\.exe)?\b.*shadowcopy\s+delete|wbadmin(\.exe)?\b.*delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\b.*recoveryenabled\s+no'
        Why = 'Deletes shadow copies or backups. Ransomware does this right before it encrypts files.'
    }
    @{
        Name = 'DefenderTamper'; Points = 50; Attack = 'T1562.001'
        Pattern = '(?i)set-mppreference\b.*-disable[a-z]+\s+(\$true|1)|add-mppreference\b.*-exclusion(path|process|extension)'
        Why = 'Turns off Defender features or adds exclusions so a payload is not scanned.'
    }
    @{
        Name = 'LsassDump'; Points = 70; Attack = 'T1003.001'
        Pattern = '(?i)sekurlsa::|comsvcs(\.dll)?\W+(minidump|#\s*24)|procdump(64)?(\.exe)?\b.*\blsass'
        Why = 'Dumps LSASS memory, where Windows keeps credentials for logged-on users.'
    }
    @{
        Name = 'CreatesScheduledTask'; Points = 15; Attack = 'T1053.005'
        Pattern = '(?i)schtasks(\.exe)?\b.*[-/]create\b'
        Why = 'Creates a scheduled task. Installers do this often; malware does it to survive reboots.'
    }
    @{
        Name = 'WritesRunKey'; Points = 20; Attack = 'T1547.001'
        Pattern = '(?i)reg(\.exe)?\s+add\b.*\\currentversion\\run'
        Why = 'Adds a Run key entry, the oldest way to start at every logon.'
    }
)
