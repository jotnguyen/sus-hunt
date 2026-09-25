# sus-hunt

A small PowerShell kit for triaging a Windows machine the way an analyst would: score what is
running and what starts at boot, watch activity live, and cut off a connection you do not like.
Every rule explains *why* it fired and maps to a [MITRE ATT&CK](https://attack.mitre.org/)
technique, so the output doubles as study material.

It is **not** an antivirus. Keep Defender on. This is for learning how detection works and for
answering "what is that thing doing?" on your own machines.

Runs on the Windows PowerShell 5.1 that ships with Windows 10/11. No installs, no network calls
(unless you ask for reverse DNS).

## Quick start

```powershell
cd sus-hunt
.\sus-hunt.ps1 triage -Html -Open  # score processes + autoruns, explain them, open an HTML report
.\sus-hunt.ps1 baseline            # snapshot autoruns, listeners and programs (with SHA-256)
.\sus-hunt.ps1 diff -Html -Open    # what changed since the newest baseline
.\sus-hunt.ps1 watch -Quiet        # live (polling): console popups, flagged processes, odd connections
.\sus-hunt.ps1 sysmon -Quiet       # live (event-driven) from Sysmon's log; -Hours 24 to look back
.\sus-hunt.ps1 conns               # who is talking to whom, signed or not
.\sus-hunt.ps1 autoruns            # every autostart entry, scored or not
.\sus-hunt.ps1 files -Html -Open   # recent programs/scripts/shortcuts in Temp, AppData, Downloads...
.\sus-hunt.ps1 gui                 # a window: pick a scan, run it, sort and click into the results
```

A good routine: take a `baseline` on a day you trust the machine, then run `diff` weekly or
after installing something. New is more interesting than suspicious.

Run from an **elevated** PowerShell for full coverage. Without admin, command lines of SYSTEM
and elevated processes are hidden, and `watch` falls back to slower process polling.
If Windows refuses to run the script, the files are probably marked as downloaded:
`Get-ChildItem -Recurse | Unblock-File`.

As a module:

```powershell
Import-Module .\SusHunt.psm1
$f = Invoke-SusTriage -MinScore 0 -OutDir .\reports   # objects, plus JSON/CSV reports
$f | Format-Table Score, Category, Name, Summary
$f[0].Signals | Format-List                           # the reasoning behind one finding

# Pick connections in a grid, then block them in Windows Firewall (asks first; -WhatIf works)
Get-SusConnection | Out-GridView -PassThru | Stop-SusConnection -Action BlockRemote
Get-NetFirewallRule -Group SusHunt | Remove-NetFirewallRule            # undo
```

## What it looks at

| Area | Rule | Points | ATT&CK | The idea |
|---|---|---|---|---|
| Process | WrongFolder | 60 | T1036.005 | `svchost.exe` outside System32 is not svchost |
| Process | UnexpectedParent | 40 | T1036 | `lsass.exe` should be started by `wininit.exe` |
| Process | LookalikeName | 45 | T1036.005 | `svch0st.exe` is one edit from `svchost.exe` |
| Process | DoubleExtension / BidiTrick | 40 / 50 | T1036.007 / .002 | `invoice.pdf.exe`, right-to-left override tricks |
| Process | TamperedBinary | 60 | T1554 | signed file whose hash no longer matches |
| Process | ImageGone | 40 | T1070.004 | running, but its file was deleted |
| Process | Unsigned / RunsFromTemp | 10-25 / 25 | T1204.002 | where a binary lives matters as much as what it is |
| Process | DocumentSpawnedShell | 50 | T1204.002 | Word starting PowerShell: macro or exploit |
| Process | LolbinOnInternet | 35 | T1105 | `rundll32`, `mshta`, `certutil`... talking to the internet |
| Process | NotablePort | 20 | T1571 | 4444, 31337, IRC, Tor ports |
| Command line | EncodedPowerShell | 35 | T1027 | decodes the base64 and scans the result too |
| Command line | DownloadAndRun | 40 | T1105 | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| Command line | Certutil / Mshta / Rundll32 / Regsvr32 / BITS | 30-45 | T1218.x, T1197 | living-off-the-land binaries used as loaders |
| Command line | InhibitRecovery | 60 | T1490 | `vssadmin delete shadows`: ransomware's last step |
| Command line | DefenderTamper / LsassDump | 50 / 70 | T1562.001 / T1003.001 | disabling AV, dumping credentials |
| Autoruns | Run keys, Startup folder | varies | T1547.001 | the oldest persistence there is |
| Autoruns | Scheduled tasks, MasqueradedTask | varies / 30 | T1053.005, T1036.004 | non-Microsoft programs hiding under `\Microsoft\` |
| Autoruns | TaskWithoutSD / TaskHiddenFromApi | 60 / 40 | T1053.005 | tasks in the registry index that Task Scheduler does not show (admin) |
| Autoruns | BareNameWritableDir | 40 | T1574.008 | a task or service runs `tool.exe` by bare name and Windows would find it in a user-writable folder |
| Autoruns | Services, ServiceDll | varies | T1543.003 | svchost services hide their real code in a registry DLL path |
| Autoruns | UnquotedServicePath | 15 | T1574.009 | `C:\Program Files\A B\svc.exe` makes Windows try `C:\Program.exe` first |
| Autoruns | IFEO Debugger, SilentProcessExit | 40 | T1546.012 | "when X starts, run Y instead" |
| Autoruns | Winlogon Shell/Userinit, AppInit_DLLs | 60 / 50 | T1547.004 / T1546.010 | logon hijacks, DLLs injected everywhere |
| Autoruns | WMI subscriptions | 50 | T1546.003 | fileless persistence: code that runs on a WMI event |
| Live | Beacon | 40 | T1071 | same program, same destination, on a steady timer |
| File | DownloadedExecutable / DiskImage | 15 / +10 | T1204.002 / T1553.005 | Mark-of-the-Web says it came from the internet, and from which URL; `.iso` payloads lose that mark once mounted |
| File | ExtensionMismatch | 40 | T1036.008 | `notes.txt` that starts with `MZ` is a program |
| File | DoubleExtension / BidiTrick / LookalikeName | 40 / 50 / 45 | T1036.007 / .002 / .005 | the same name checks as for processes, before the file ever runs |
| File | UnsignedInHighRisk | 20 | T1204.002 | unsigned program in Temp, Downloads or Public |
| File | PackedSection | 15 | T1027.002 | an unsigned program whose code section is near-random (Shannon entropy > 7.2) |
| File | OddCompileTime | 5 | T1070.006 | unsigned PE compiled "in the future" or before 2000 |
| File | HiddenInUserDir | 10 | T1564.001 | hidden program or script in a user folder |
| File | LnkRunsShell | 35 | T1204.002 | a shortcut that starts PowerShell or a LOLBin; its arguments get the command-line rules too |
| File | YaraMatch | 50 | from the rule | your YARA rules matched (optional, needs `yara64.exe`) |

Points add up per item and cap at 100. Low starts at 15, Medium at 30, High at 60. The numbers
are judgement calls: tune them in [`lib/Rules.ps1`](lib/Rules.ps1), which is plain data.

## Why console windows flash on Windows

This tool started with a question: *why do black console windows keep popping up?*

Windows programs are built for one of two subsystems. GUI programs draw their own windows.
Console programs (`cmd.exe`, `powershell.exe`, `git.exe`, `node.exe`) need a console, which
Windows provides by starting a `conhost.exe` next to them. Whether that console gets a visible
window is decided by the **parent**, at the moment it calls `CreateProcess`:

* `CREATE_NO_WINDOW` gives the child a console with no window. (Node.js: `windowsHide: true`.)
* `STARTUPINFO.wShowWindow = SW_HIDE` creates the window hidden.
* Neither flag: the window appears, even if it closes 200 ms later. That is the "flash".

The child cannot fix this itself. `powershell.exe -WindowStyle Hidden` hides the window only
*after* PowerShell has started and parsed its arguments, so the window has already flashed.
That is why scheduled tasks that run PowerShell flash briefly even with `-WindowStyle Hidden`.
A task set to "Run whether user is logged on or not" runs in a session with no desktop, so it
has no window to flash.

So a popup tells you about a parent process that forgot a flag. Buggy but benign apps do this
all the time. Malware usually does not, because a popup is a great way to get caught. Many
`conhost.exe` entries in Task Manager are normal. Each console program has one, and most are
windowless.

To find the culprit, run `.\sus-hunt.ps1 watch` and wait for it to happen:

```
12:01:02.410 WINDOW ConsoleWindowClass 'C:\WINDOWS\system32\cmd.exe'  owner: cmd.exe[1200] <- someapp.exe[1100] <- explorer.exe[900]
```

The owner chain is the answer. (For a classic console window, `GetWindowThreadProcessId`
reports the program running *inside* the console, not `conhost.exe`.)

## Files on disk

```powershell
.\sus-hunt.ps1 files                      # last 7 days, Low (15) and up
.\sus-hunt.ps1 files -Days 1 -Html -Open  # just today, as an HTML report
.\sus-hunt.ps1 files -Path D:\Shared      # add folders to the default list
.\sus-hunt.ps1 files -Yara .\my-rules     # also run your YARA rules (yara64.exe on PATH, or -YaraExe)
```

Malware without admin rights has to live somewhere a normal user can write: Temp, AppData,
Downloads, ProgramData, Public, and a few folders inside Windows. `files` looks at programs,
scripts, shortcuts, installers and disk images created or changed there in the last `-Days` days,
plus any file whose first two bytes are `MZ` (the start of every Windows program) under a document,
picture or `.tmp`-style name. For each one it reads:

* **Mark-of-the-Web.** Browsers write a `Zone.Identifier` stream next to a download, with the
  URL it came from. See it yourself: `Get-Content .\file.exe -Stream Zone.Identifier`.
* **The PE header.** Machine type, compile time and the section table, parsed by hand in
  `Get-PeInfo`. Packed code shows up as a section with entropy near 8 bits per byte.
* **The signature** (Authenticode), and the SHA-256 of every file that scores, so you can look it
  up by hand. Nothing is uploaded.
* **Shortcuts.** The target and arguments of each `.lnk`, read with `WScript.Shell` without
  running it.

It never runs what it finds. Browser caches and site storage are skipped (tens of thousands of
data files, and a browser does not run programs from them); the list is `$script:FileScanSkipDirs`
in `lib/Rules.ps1`. OneDrive "online-only" files are skipped too, because reading one downloads it.
A 7-day scan takes about a minute on a busy machine; the first run is the slowest because
antivirus scans each file the first time it is opened.

## Baseline and diff

`baseline` saves autostart entries, listening ports and the programs currently running, each
with a SHA-256 of its file, to `baselines\` (git-ignored). `diff` compares the machine now with
the newest baseline and reports **Added**, **Removed** and **Changed** (different command line or
file hash). Programs are only reported when new. Temporary UDP ports (49152 and up) are left out
because they change constantly.

Anyone who can edit the baseline file can hide a change from the next diff. If that matters to
you, copy baselines somewhere only you can write.

## HTML reports

`-Html` writes a single self-contained page to `reports\` (git-ignored). `-Open` opens it. It uses
light and dark themes, and each finding expands to show its reasons with links to ATT&CK.
Process names and command lines come from the machine being examined, and an attacker can
choose them, so every value is HTML-encoded before it goes into the page.

## GUI

`.\sus-hunt.ps1 gui`, or double-click `tools\SusHunt.cmd`, opens a window (WPF, built into
Windows PowerShell 5.1: nothing to install, no listening port). Pick Triage, Files, Autoruns,
Connections, Baseline or Diff; only the options that scan uses are shown. Press Run. The scan
runs in its own runspace, so the window stays responsive, the status line shows its progress, and
Cancel stops it.

*Screenshot placeholder: the scan buttons across the top, a results grid coloured by severity
in the middle, and the detail pane for the selected row (signals, ATT&CK links, Why, evidence)
with the row actions below it.*

Results are a grid you can sort by any column, filter by text (Name, Path, Summary) and by
severity. The detail pane shows the same fields and signals as the HTML report. Row actions:

- **Copy SHA-256**, to look the file up by hand.
- **Open folder** shows the file selected in Explorer (`explorer /select`). It never opens or runs it.
- **Add to allowlist** appends the exact path to `allowlist.txt`, after a confirm.
- **Save HTML report** writes the same report as `-Html` to `reports\`.

The GUI only calls the exported scan functions, so it can never disagree with the CLI. It has no
kill or firewall actions, and it never elevates itself: the badge at the top right says whether
you are admin. For full coverage, start it with "Run as administrator". It follows the Windows
light or dark app mode.

## Sysmon mode

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is a free Microsoft
Sysinternals driver and service that logs process starts, network connections and DNS queries as
they happen. `sysmon` mode reads that log instead of polling:

* nothing is missed between polls, however short-lived the process;
* the full command line is recorded when the process starts;
* DNS events (ID 22) let beacon tracking key on the domain, which stays the same when a CDN
  rotates IPs.

Install it yourself from the link above, as Administrator, with a community configuration such
as SwiftOnSecurity's `sysmon-config` or Olaf Hartong's `sysmon-modular`:

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Then `.\sus-hunt.ps1 sysmon -Quiet` watches live (events are pushed by `EventLogWatcher`, not
polled), and `.\sus-hunt.ps1 sysmon -Hours 24` scores the last day of events.

## Concepts it exercises

**Networking**

* TCP states: `Listen`, `SynSent`, `Established`, `CloseWait`, `TimeWait`. A listener on
  `0.0.0.0` or `::` accepts connections on every interface.
* CIDR math by hand: [`Test-IpInCidr`](lib/Network.ps1) compares the first *n* bits with
  byte comparisons and a mask. The same code handles IPv4 and IPv6.
* Address scopes: RFC 1918 private ranges, `100.64.0.0/10` CGNAT (also used by Tailscale),
  link-local/APIPA, multicast, and IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
* Byte order: `MIB_TCPROW` wants ports and addresses in network (big-endian) order on a
  little-endian CPU. See `ConvertTo-NetworkOrderPort` (443 becomes 0xBB01).
* Killing a connection: disposing the object `Get-NetTCPConnection` returned does nothing to
  the socket. `SetTcpEntry(... DELETE_TCB)` makes the stack send a RST. The program can
  reconnect, which is why a firewall rule is the real fix.
* Reverse DNS privacy: every PTR lookup tells a DNS server which IPs you talk to. `-ResolveDns`
  is off by default and uses your system resolver unless you pass `-DnsServer`.
* Beaconing: implants check in on a timer. The coefficient of variation (stddev / mean) of the
  gaps between connections is near 0 for a timer and near 1 for human traffic.

**Operating system internals**

* The process tree, and PID reuse: a "parent" that started *after* its child is an unrelated
  process that inherited a recycled PID ([`Get-ParentProcess`](lib/Common.ps1)).
* Parents can be forged (PPID spoofing, T1134.004). A correct-looking parent proves nothing.
* Authenticode vs catalog signing. Verification hashes the whole file, so 200 MB Electron apps
  are slow to check, which is why signatures are verified on a runspace pool.
* How `CreateProcess` reads an unquoted path (`C:\Program.exe`, then `C:\Program Files\My.exe`,
  and so on), which is what makes unquoted service paths exploitable.
* `svchost.exe` is a shell. The real service code is the `ServiceDll` in the registry.
* Autostart locations beyond Run keys: IFEO, Winlogon, AppInit_DLLs, WMI event subscriptions.
* String metrics: typosquat detection uses optimal string alignment distance (Levenshtein plus
  adjacent swaps), so `scvhost` is 1 edit from `svchost`.

## Limitations (read these)

* **`watch` polls; `sysmon` does not.** `watch` diffs the process list every 100 ms through
  direct Win32 calls (Toolhelp, `QueryFullProcessImageName`, `GetExtendedTcpTable`), because a
  single WMI query costs 200-800 ms and would stall the loop. A process that lives for less than
  100 ms can still slip past unless you run as admin, which adds the kernel-backed
  `Win32_ProcessStartTrace`. Network snapshots every second miss connections shorter than that.
  Use `sysmon` mode when you can.
* **"File gone" is confirmed before it is reported.** At launch, an installer can be renaming the
  file, so `watch` rechecks 3 s later and reports only if it is still missing.
* **Admin-only checks.** The hidden-task check reads Task Scheduler's registry index, which only
  Administrators can open. Without admin it is skipped quietly.
* **User-mode view.** A rootkit can lie to every API this uses. Signed malware exists. So do
  legitimate tools that trip every rule: installers run from Temp, dev tools are unsigned, and
  some well-known apps launch PowerShell with `-EncodedCommand`. Treat a score as a reason to
  look, not a verdict.
* **`files` trades coverage for speed.** It skips browser cache folders and `node_modules`, and
  only checks the signature of programs over 32 MB when they sit in Temp, Downloads or Public.
  A payload parked in one of those places is missed.
* **Coverage.** It skips DLL search-order hijacking, COM hijacking, browser extensions, drivers,
  and memory injection. Those are good next rules to write; the plan is in
  [`docs/backlog/`](docs/backlog/README.md).

Where to go next: [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) (event IDs
1 process create, 3 network, 11 file create, 13 registry, 22 DNS) with a community config;
Sysinternals Autoruns and Process Explorer; [Sigma](https://github.com/SigmaHQ/sigma) rules;
[LOLBAS](https://lolbas-project.github.io/).

## Allowlist

Copy `allowlist.example.txt` to `allowlist.txt` (git-ignored) and add wildcard patterns, one per
line. Findings whose path or name match are hidden. Keep it short, because every line is a
place you have decided not to look.

## Tests

```powershell
Invoke-Pester .\tests                          # Pester 3.4 ships with Windows; Pester 4 also works
powershell -NoProfile -File tools\lint.ps1     # PSScriptAnalyzer with the repo settings
```

The linter needs `Install-Module PSScriptAnalyzer -Scope CurrentUser` once (a developer tool; the
kit itself still needs no installs). CI (`.github/workflows/check.yml`) runs the linter, the tests
and the hygiene gate on every pull request, on Windows PowerShell 5.1.

The tests cover the logic that does not depend on your machine's state: CIDR matching, scopes,
byte order, edit distance, command-line rules (including decoding `-EncodedCommand`), path
parsing and program search order, the signature cache, PID-reuse checks, HTML encoding, Sysmon
event parsing, beacon math, and for `files`: entropy, the PE parser, Mark-of-the-Web, extension
checks, file scoring and the folder walk; for `gui`: grid rows, the filter, per-scan options,
the detail lines and allowlist appends.

## Layout

```
sus-hunt.ps1          front door: triage | watch | sysmon | conns | autoruns | baseline | diff | files | gui
SusHunt.psm1          module; loads lib\
lib\Rules.ps1         detection rules as data
lib\Common.ps1        paths, signatures, process tree, command-line parsing, scoring
lib\Processes.ps1     per-process checks
lib\Persistence.ps1   autostart locations
lib\Network.ps1       connections, CIDR/byte order, response actions, beacon math
lib\Watch.ps1         live watcher (polling)
lib\Sysmon.ps1        Sysmon event parsing, live (event-driven) and look-back modes
lib\Baseline.ps1      baseline and diff, parallel SHA-256
lib\Report.ps1        HTML reports (all values encoded)
lib\Files.ps1         files command: folder walk, PE parser, entropy, Mark-of-the-Web, .lnk, YARA
lib\Gui.ps1, Gui.xaml gui command: WPF window, scans run in a runspace (no rule logic here)
lib\Native.ps1        C# for what PowerShell lacks or does slowly (windows, processes, TCP, file walk, entropy)
tests\                Pester tests
tools\hygiene-gate.ps1 pre-commit check: no machine or personal details in tracked files
tools\SusHunt.cmd     double-click launcher for the gui command
tools\lint.ps1        PSScriptAnalyzer with PSScriptAnalyzerSettings.psd1 (5.1-compatible syntax)
.github\workflows\    CI: lint, tests, hygiene gate
docs\backlog\       roadmap: one ticket per planned feature
CLAUDE.md, AGENTS.md  notes for AI coding agents working on this repo (.ai\, .claude\skills\)
```

Reports, HTML pages, baselines and watch logs describe your machine. They are git-ignored by
default. Keep it that way.

## License

MIT. See [LICENSE](LICENSE).
