# TICKET-002: `files` command — scan user-writable folders for suspicious files

**Type:** feature
**Priority:** high
**Sprint:** 1
**Parallelizable:** yes. It adds a new file, `lib/Files.ps1`, and appends to the hot files `sus-hunt.ps1`, `SusHunt.psm1`, `lib/Rules.ps1`, `README.md` and the tests.
**Human-blocked:** no for the code; acceptance has human steps (plant test files, download a file in a browser). YARA is optional and needs the human to install it.
**Status:** in review (branch `ticket-002-file-scan`)

## Links

- Related to: [TICKET-003](TICKET-003-defender-tamper.md) (exclusions are often on the same folders)
- Enables: [TICKET-005](TICKET-005-coverage-gaps.md) (the PE parser is reused for drivers)

## Description

Everything so far looks at what is *running* or *registered to run*. A dropper that has not
launched yet, a payload waiting for the next logon, or a script someone downloaded sits on disk
where none of that sees it. Malware without admin rights has to live in a folder the user can
write to (Temp, AppData, Downloads, ProgramData, Public), so scanning recent files there is cheap
and useful. It also teaches three things: Mark-of-the-Web, the PE file format, and entropy as a
sign of packing.

## Design

New `lib/Files.ps1`, exported `Get-SusFileFinding`, new command:

```powershell
.\sus-hunt.ps1 files [-Days 7] [-Path D:\extra] [-Yara .\rules] [-MinScore 20] [-Html -Open]
```

**Where.** `$env:TEMP`, `$env:LOCALAPPDATA`, `$env:APPDATA`, the Downloads known folder (from
`HKCU:\...\Explorer\User Shell Folders`, value `{374DE290-123F-4565-9164-39C4925E467B}`, because
Downloads can be moved), `$env:ProgramData`, `$env:PUBLIC`, `%windir%\Temp` (admin), and the
`$script:UserWritableWindowsDirs` already in `lib/Rules.ps1`. Add `-Path` for extra roots.
Recurse with `[IO.Directory]::EnumerateFiles` and skip reparse points, because AppData has
junction loops. Keep only files created or written in the last `-Days` days.

**What.** Extensions as data in `lib/Rules.ps1`, `$script:ScanExtensions`: `.exe .dll .scr .cpl .sys
.ocx .com .ps1 .psm1 .bat .cmd .vbs .vbe .js .jse .wsf .hta .lnk .msi .iso .img .vhd`, plus any file whose
first two bytes are `MZ`. Only sniff the header of files under 50 MB, to keep it fast.

**Rules** (each an entry in `lib/Rules.ps1`; points are a starting guess):

| Rule | Points | ATT&CK | Fires when |
|---|---|---|---|
| DownloadedExecutable | 15 | T1204.002 | Mark-of-the-Web ZoneId 3/4. Evidence is the `HostUrl` and `ReferrerUrl` from the `Zone.Identifier` stream. |
| ExtensionMismatch | 40 | T1036.008 | `MZ` header, but the extension is not an executable type (`notes.txt`, `photo.jpg`). |
| DoubleExtension / BidiTrick | 40 / 50 | T1036.007 / .002 | Reuse the name checks in `Get-ProcessSignals`, moved into a shared `Get-FileNameSignals`. |
| UnsignedInHighRisk | 20 | T1204.002 | PE, not validly signed, and `Get-PathRisk` says HighRisk. |
| PackedSection | 15 | T1027.002 | An executable section with Shannon entropy > 7.2 (packed or encrypted). Installers and signed apps trip this, so it only adds points on unsigned files. |
| OddCompileTime | 5 | T1070.006 | PE `TimeDateStamp` in the future or before 2000. Reproducible builds put a hash there, so this is low. |
| HiddenInUserDir | 10 | T1564.001 | Hidden or System attribute on an executable in a user folder. |
| LnkRunsShell | 35 | T1204.002 | A `.lnk` target is a shell or LOLBin. Its arguments go through `Get-CommandLineSignals`, so encoded PowerShell in a shortcut is scored too. Read with `WScript.Shell.CreateShortcut` (reading only; never invoke). |
| DiskImage | 10 | T1553.005 | `.iso`/`.img`/`.vhd` downloaded with Mark-of-the-Web. Files inside a mounted image lose Mark-of-the-Web, which is why phishing uses them. |
| YaraMatch | 50 | (from rule meta) | `-Yara <rules>` given and `yara64.exe` found on PATH or at `-YaraExe`. Run `yara64 -r -w <rules> <file>`. |

**PE parsing** is pure PowerShell over a `byte[]`: `e_lfanew` at 0x3C → `PE\0\0` → COFF header
(machine, TimeDateStamp, NumberOfSections) → optional header magic (PE32/PE32+) → section table
(name, raw offset and size, characteristics). `Get-PeInfo [byte[]]` and `Get-ShannonEntropy
[byte[]]` are the testable units.

**Output.** `New-Finding -Category 'File'`, with `Path` = file, `Id` = SHA-256 (hash only scored
files, to stay fast), and `Context` = size, created/modified times, and Mark-of-the-Web URL. The existing
allowlist, table output and `ConvertTo-SusFindingHtml` work unchanged. Warm the signature cache
for all candidate PEs first (`Initialize-SignatureCache`).

**Privacy.** `HostUrl` is browsing history. Reports are already git-ignored. Never put a real one
in docs or tests.

## Plan

1. [agent] `Get-ShannonEntropy`, `Get-PeInfo`, `ConvertFrom-ZoneIdentifier` (text → ZoneId,
   HostUrl, ReferrerUrl) and `Test-ExtensionMismatch`, all with Pester tests on synthetic bytes
   and strings. Build a minimal PE header in the test; do not commit a binary.
2. [agent] Move the name checks out of `Get-ProcessSignals` into `Get-FileNameSignals`, and make
   sure the existing tests still pass.
3. [agent] `Get-SusFileFinding`: enumerate, filter, warm signatures, score, hash the scored files.
4. [agent] Wire up the `files` command, `-Days`, `-Path`, `-Yara`, `-YaraExe` and `-Html`.
   Update the README (rule table, Quick start, Layout).
5. [agent] Time a run on this machine with `-Days 7` and note the time in the ticket. Target: under 60 s.
6. [human] Acceptance steps below.

## Acceptance criteria

- [x] `Invoke-Pester .\tests` passes, with new tests for entropy (all zeros = 0; 256 distinct
      bytes = 8), the PE parser, the Zone.Identifier parser and extension mismatch.
- [x] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [x] Human: `Copy-Item $env:windir\System32\notepad.exe $env:TEMP\invoice.pdf.exe` and
      `Copy-Item $env:windir\System32\notepad.exe $env:TEMP\notes.txt`, run `files -Days 1`, and see
      DoubleExtension and ExtensionMismatch. Delete both files afterwards.
- [ ] Human: download any installer in a browser, run `files -Days 1`, and see DownloadedExecutable
      with the right source URL.
- [ ] Nothing is executed, and there are no network calls (a `-Yara` run is local).

## Rollback

Revert the merge commit. There is no machine state to undo.

## Comments

- **2026-09-25** — Created from the roadmap (idea 1). The owner picked it for sprint 1.
- **2026-09-25** � Built on `ticket-002-file-scan`. Differences from the design above, and why:
  - The folder walk, the parallel header read and the entropy loop are C# in `lib/Native.ps1`
    (namespace bumped to `SusHunt.V4`). In PowerShell the walk took about 3 minutes and the
    entropy loop seconds per file.
  - Only names that could hide a program are sniffed for `MZ` (`$script:SniffExtensions`: no
    extension, `.tmp .dat .bin`, and the document and picture names in `$script:DecoyExtensions`).
    Opening a file the first time costs up to ~100 ms because antivirus scans it, and sniffing
    every recent file took about 10 minutes. ExtensionMismatch fires only for decoy names, since
    `.tmp`, `.node` and similar names hold real programs all the time.
  - Browser caches, site storage and `node_modules` are skipped (`$script:FileScanSkipDirs`).
    One browser profile alone held over 100k small files.
  - Programs over 32 MB get a signature check only in Temp, Downloads and Public.
  - OddCompileTime counts only on files that are not validly signed: all of Windows uses
    reproducible builds, which store a hash in that field.
  - `files` defaults to `-MinScore 15`, so a downloaded installer (DownloadedExecutable, 15) shows.
  - Timing (plan step 5): `-Days 7` took about 62 s on the dev machine (about 24 s of that is the
    folder walk), `-Days 1` about 50 s. Runs after the first are faster.
  - Agent check of the first human step: copies of notepad as `invoice.pdf.exe` and `notes.txt`
    in a scratch folder scored DoubleExtension and ExtensionMismatch. The human steps are still open.
- **2026-09-25** � Merged in PR #2. The owner ran the planted-notepad check with
  `files -Days 1 -Html`: both files showed as Medium 40 (ExtensionMismatch, DoubleExtension).
  Still open: the browser-download check (DownloadedExecutable).
