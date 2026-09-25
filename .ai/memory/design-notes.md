# Design notes: why the code looks the way it does

Facts a new session would otherwise rediscover the hard way. Edit in place.

- **WMI is too slow for live loops.** One `Get-CimInstance Win32_Process` lookup costs about
  200-800 ms, and `Get-NetTCPConnection` costs about 800 ms. `watch` uses Toolhelp,
  `NtQuerySystemInformation` and `GetExtendedTcpTable` through `lib/Native.ps1` instead (about
  1-3 ms). Do not reintroduce WMI calls inside a per-tick path.
- **Native types are versioned** (`SusHunt.V3`). `Add-Type` cannot replace a loaded type, so
  re-importing the module after a C# change fails unless the namespace changes.
- **Signature checks are slow on big binaries** (Authenticode hashes the whole file; Electron apps
  run to 200 MB). They run on a runspace pool (`Initialize-SignatureCache`,
  `Start-SignatureWarmup`) and are cached by path + size + mtime. Missing-file results are never
  cached. Any new scanner that checks many files (TICKET-002) should warm the cache first.
- **`ImageGone` is confirmed after 3 s.** Installers rename files while they launch, so the first
  "file missing" is often false.
- **`watch` ignores its own network traffic.** Signature checks make Windows fetch OCSP/CRL data
  over HTTP, which would otherwise flag PowerShell itself as a LOLBin on the internet.
- **`Get-SusPersistenceFinding -All` feeds `baseline`/`diff`.** A new autostart source added to its
  `$sources` table shows up in diffs automatically. TICKET-003 (Defender exclusions) and
  TICKET-005 (COM, drivers, extensions) should plug in there.
- **`Watch-SusEventLog` (lib/Sysmon.ps1) is generic**: any log plus an XPath filter. TICKET-004
  (event logs without Sysmon) should reuse it and `ConvertFrom-SysmonEventXml`, which already
  flattens any event's `<Data Name=...>` fields.
- **Test fixtures use `C:\Users\someone\`.** The hygiene gate allows that placeholder, so reuse it.
