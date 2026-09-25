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

# ---- files command (lib/Files.ps1) -------------------------------------------------------------

# File types worth a look when they turn up in a folder any user can write to: programs, scripts,
# shortcuts, installers and disk images. Any other file that starts with 'MZ' is looked at too.
$script:ScanExtensions = @(
    '.exe', '.dll', '.scr', '.cpl', '.sys', '.ocx', '.com', '.ps1', '.psm1', '.bat', '.cmd', '.vbs',
    '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk', '.msi', '.iso', '.img', '.vhd', '.vhdx'
)
$script:PeExtensions = @('.exe', '.dll', '.scr', '.cpl', '.sys', '.ocx', '.com')
$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta')
$script:DiskImageExtensions = @('.iso', '.img', '.vhd', '.vhdx')

# Extensions that say "document, picture or media" to a person. A program (MZ header) wearing one
# of these is in disguise. Other non-program extensions (.tmp, .dat, .bin) hold real PE files all
# the time (installers, caches), so they are not on this list.
$script:DecoyExtensions = @(
    '.txt', '.log', '.csv', '.pdf', '.rtf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp', '.mp3', '.mp4', '.wav', '.avi',
    '.mkv', '.mov', '.zip', '.rar', '.7z', '.html', '.htm', '.xml', '.json'
)

# Files with these extensions (or none) get their first bytes read to look for an 'MZ' header.
# Opening a file costs several ms once antivirus has looked at it, so not every file is opened.
$script:SniffExtensions = @('', '.tmp', '.dat', '.bin') + $script:DecoyExtensions

# Only sniff the first bytes of files up to this size.
$script:FileSniffMaxBytes = 50MB

# Programs bigger than this are only signature-checked in Temp, Downloads and Public. Checking a
# signature hashes the whole file, and big recent binaries are nearly always app updates.
$script:FileSignatureMaxBytes = 32MB

# A section above this many bits per byte (8 is the maximum) is packed or encrypted. Compiled
# code usually sits around 6.
$script:PackedEntropy = 7.2

# Signals for files on disk. Evidence is filled in by lib/Files.ps1.
$script:FileRules = @{
    DownloadedExecutable = @{ Points = 15; Attack = 'T1204.002'
        Why = 'Came from the internet (Mark-of-the-Web zone 3 or 4). Every installer you download has this; check that you meant to download it.' }
    ExtensionMismatch = @{ Points = 40; Attack = 'T1036.008'
        Why = 'The file is a Windows program (starts with MZ) but its extension says document or picture. Real files do not do that.' }
    UnsignedInHighRisk = @{ Points = 20; Attack = 'T1204.002'
        Why = 'Unsigned program in Temp, Downloads or Public. Installers unpack unsigned helpers here; so do droppers.' }
    PackedSection = @{ Points = 15; Attack = 'T1027.002'
        Why = 'An executable section is close to random (high entropy): packed or encrypted code. Packers are also used for honest reasons, so this only counts on unsigned files.' }
    OddCompileTime = @{ Points = 5; Attack = 'T1070.006'
        Why = 'The PE compile time is in the future or before 2000. Timestomped, or a reproducible build that stores a hash in that field (all of Windows does), so it only counts on files that are not validly signed.' }
    HiddenInUserDir = @{ Points = 10; Attack = 'T1564.001'
        Why = 'A program or script with the Hidden or System attribute in a user folder. Explorer hides it by default.' }
    LnkRunsShell = @{ Points = 35; Attack = 'T1204.002'
        Why = 'A shortcut that starts a shell or LOLBin. Phishing uses .lnk files to run PowerShell when someone double-clicks a "document".' }
    DiskImage = @{ Points = 10; Attack = 'T1553.005'
        Why = 'A downloaded disk image. Files inside a mounted .iso lose Mark-of-the-Web, which is why phishing ships payloads in them.' }
    YaraMatch = @{ Points = 50; Attack = ''
        Why = 'A YARA rule you supplied matched this file. Read the rule to see what it looks for.' }
}

# Folders the file scan does not walk into: browser caches and site storage. They hold tens of
# thousands of small data files, which makes the walk take minutes, and a browser does not run
# anything from them. The trade-off is deliberate: a payload hidden in a cache folder is missed.
# Add to this list if a scan is slow on your machine (-Verbose prints the roots).
$script:FileScanSkipDirs = @(
    '(?i)\\Mozilla\\Firefox\\Profiles\\[^\\]+\\(storage|cache2|datareporting|saved-telemetry-pings)$'
    '(?i)\\(Cache|Code Cache|GPUCache|DawnCache|DawnGraphiteCache|DawnWebGPUCache|GrShaderCache|ShaderCache|IndexedDB|Service Worker|CacheStorage|File System|blob_storage|Session Storage|Local Storage)$'
    '(?i)\\Microsoft\\Windows\\(INetCache|WebCache|Explorer\\ThumbCacheToDelete)$'
    '(?i)\\Packages\\[^\\]+\\(AC|TempState|LocalCache)$'
    '(?i)\\node_modules$'
)
