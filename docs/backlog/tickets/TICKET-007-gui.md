# TICKET-007: `gui` command — a point-and-click window over the existing commands

**Type:** feature
**Priority:** medium
**Sprint:** 2 (see `../README.md`)
**Parallelizable:** mostly. It adds new files (`lib/Gui.ps1`, `lib/Gui.xaml`) and appends to the hot files `sus-hunt.ps1`, `SusHunt.psm1`, `README.md` and the tests. It adds no rules. Each later command (003, 004, 005, 006) should add its own button when it lands, so merge order does not matter.
**Human-blocked:** no for the code. The acceptance steps need a human to click through the window.
**Status:** backlog

## Links

- Related to: [TICKET-001](TICKET-001-watch-heartbeat-summary.md) (a live `watch` tab would need its heartbeat and counters)
- Related to: [TICKET-002](TICKET-002-file-scan.md) (first command to show in the GUI; its HTML report already looks right)

## Description

The kit is a command-line tool. That is fine once you know the commands, but it is a wall for a
learner who does not. The owner asked for a window where you pick a scan, press a button, and read
results you can sort, filter and click into, without remembering flags.

The GUI must stay a thin shell. Every scan already returns objects (`SusHunt.Finding`,
`SusHunt.Change`, `SusHunt.Connection`). The GUI only calls the existing exported functions and
shows what they return. No detection logic goes in the GUI, so the CLI and the GUI can never
disagree. It also teaches something: WPF from PowerShell, and why long work has to run off the UI
thread.

## Design

**Technology: WPF in Windows PowerShell 5.1.** `Add-Type -AssemblyName PresentationFramework`
ships with Windows, so there is nothing to install, which keeps the "no installs" rule. The layout
is XAML in `lib/Gui.xaml`, loaded with `[Windows.Markup.XamlReader]::Load`. Rejected options:

- WinForms: works, but looks dated and has poor high-DPI support.
- A local web server with an HTML UI: it opens a listening port, which conflicts with "no network
  calls" and is one more attack surface on a security tool.
- A browser-only page: it cannot run scans.

**Entry point.** `.\sus-hunt.ps1 gui`, plus `Show-SusGui` exported from the module. WPF needs an
STA thread. `powershell.exe` 5.1 is STA by default, but check
`[Threading.Thread]::CurrentThread.ApartmentState` and, if it is not STA, relaunch with
`powershell -STA -NoProfile -File sus-hunt.ps1 gui`. Add an optional `tools\SusHunt.cmd`
(one line, `powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0..\sus-hunt.ps1" gui`)
so a double-click opens it. Do not create desktop shortcuts or Start-menu entries from code.

**Window layout** (one window, ~1100x700, respects the Windows light or dark theme):

```
+--------------------------------------------------------------------------+
| [Triage] [Files] [Autoruns] [Connections] [Baseline] [Diff]    (admin: no)|
| Options: Min score [20v]  Days [7]  Extra folder [.......][...]          |
| [ Run ]  [ Cancel ]   status: Scanning 1,364 files... 00:41              |
+--------------------------------------------------------------------------+
| Filter: [___________]  [x] High [x] Medium [x] Low [ ] Info              |
| Score | Severity | Category | Name            | Summary                  |
|  40   | Medium   | File     | notes.txt       | ExtensionMismatch        |
|  ...                                                                      |
+--------------------------------------------------------------------------+
| Detail pane for the selected row: path, context, SHA-256, each signal    |
| with points, ATT&CK link, Why and evidence.                               |
| [Copy SHA-256] [Open folder] [Add to allowlist] [Save HTML report]       |
+--------------------------------------------------------------------------+
```

- **Scan buttons** map 1:1 to functions: Triage → `Invoke-SusTriage`, Files →
  `Get-SusFileFinding`, Autoruns → `Get-SusPersistenceFinding -All`, Connections →
  `Get-SusConnection`, Baseline → `Save-SusBaseline`, Diff → `Compare-SusBaseline`. Only show the
  options that apply to the selected scan (Days and Extra folder only for Files).
- **Results grid:** a WPF `DataGrid` bound to an `ObservableCollection`. Sortable columns, a
  text filter over Name, Path and Summary, and severity check boxes. Rows are coloured by
  severity, using the same colours as `lib/Report.ps1`.
- **Detail pane:** the same content as `Show-SusFindingDetail` and the HTML report. The ATT&CK
  ID is a link to `https://attack.mitre.org/techniques/T1036/008/`. Opening that link in the
  user's browser is the user's click, not a network call from the tool.
- **Actions on a row**, all read-only or local:
  - Copy SHA-256 to the clipboard.
  - Open folder: `explorer.exe /select,"<path>"`. It must never open or run the file itself.
  - Add to allowlist: append the exact path to `allowlist.txt` (git-ignored) after a confirm dialog.
  - Save HTML report: reuse `ConvertTo-SusFindingHtml` and `Save-SusHtml`.
- **Admin badge:** show whether the session is elevated (`Test-IsAdmin`) and what that means,
  for example "not admin: SYSTEM command lines are hidden". Never self-elevate. If the user wants
  admin, tell them to relaunch with "Run as administrator".
- **Response actions** (`Stop-SusConnection`): leave them out of v1. If added later, they go
  behind a second confirm dialog that shows exactly what will happen, and only if the owner asks
  (CLAUDE.md).

**Threading (the part that is easy to get wrong).** Scans take 10-90 s. Running them on the UI
thread freezes the window. Run each scan in a separate runspace that imports `SusHunt.psm1`, and:

- Return findings to the UI with `Dispatcher.BeginInvoke`, or poll a `ConcurrentQueue` from a
  `DispatcherTimer`, which is simpler and easier to test.
- Show progress. Capture `Write-Progress` from the runspace's `Streams.Progress` and show
  `StatusDescription` in the status bar.
- Cancel calls `$ps.Stop()` on the runspace. Disable Run while a scan is going.
- Only one scan at a time in v1.

**Code shape.** Keep the testable parts pure and outside WPF:

- `ConvertTo-SusGridRow` (Finding → flat row object for the grid)
- `Test-SusRowFilter` (row + filter text + severities → bool)
- `Get-SusScanOption` (scan name → which option controls to show)
- `Add-SusAllowlistEntry` (path, file → appends, skips duplicates, returns whether it added)

The WPF wiring in `Show-SusGui` stays thin and is checked by hand.

**Security.** Everything in the grid comes from the examined machine and is attacker-controlled.
WPF `TextBlock` and `DataGrid` show text as text, so there is no injection risk as long as the
code never builds XAML from strings that contain scan data. Load the XAML from the file only;
never concatenate finding values into it. Use no `Invoke-Expression`.

**Open questions for the owner:**

1. Should there be a live `watch` tab (a rolling log of new processes, windows and connections)?
   It needs TICKET-001's heartbeat and a streaming design. Proposal: v2.
2. Dark mode: follow the Windows theme automatically, or add a toggle? Proposal: follow the
   Windows theme (read `AppsUseLightTheme` under `HKCU:\...\Themes\Personalize`).

## Plan

1. [agent] Pure helpers (`ConvertTo-SusGridRow`, `Test-SusRowFilter`, `Get-SusScanOption`,
   `Add-SusAllowlistEntry`) with Pester tests on synthetic findings.
2. [agent] `lib/Gui.xaml` layout and `Show-SusGui`: load the XAML, bind the grid, wire the detail
   pane and the row actions.
3. [agent] Runspace scan runner with progress, cancel and a single-scan lock. Check by hand that
   the window stays responsive during a 60 s Files scan.
4. [agent] Wire `gui` into `sus-hunt.ps1` (`ValidateSet`, `switch`) and `SusHunt.psm1` (loader
   list, `Export-ModuleMember`). Add `tools\SusHunt.cmd`. Update the README (Quick start, a short
   "GUI" section with a placeholder screenshot description, and Layout). ASCII only in `lib/`.
5. [agent] Lint clean (`tools\lint.ps1` prints `lint-ok`). WPF event handlers often trip
   `PSReviewUnusedParameter` on `$sender`/`$e`, so name them `$null`-safe or use them.
6. [human] Acceptance steps below.

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes, with new tests for the four pure helpers.
- [ ] `tools\lint.ps1` prints `lint-ok`, and `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] Human: double-click `tools\SusHunt.cmd`, and the window opens with no console errors.
- [ ] Human: plant the two notepad copies from TICKET-002 in `%TEMP%`, click Files, then Run.
      The window stays responsive, progress text updates, and both files appear as Medium. Clicking
      one shows the signals, the Why text and a working ATT&CK link. Delete the files afterwards.
- [ ] Human: Cancel stops a running scan within about 2 s, and Run works again after it.
- [ ] Human: Open folder highlights the file in Explorer without opening it. Add to allowlist,
      then rescan, and the row is gone.
- [ ] Human: Save HTML report gives the same content as `files -Html`.
- [ ] The GUI calls only exported module functions. `lib/Gui.ps1` has no rule logic and no
      network calls, and it never runs a scanned file.

## Rollback

Revert the merge commit. The only machine state is lines the human added to `allowlist.txt`
through the GUI (git-ignored). Remove them by hand if you want.

## Comments

- **2026-09-25** — Created at the owner's request after TICKET-002 merged. The owner wants a GUI
  so they do not need to remember CLI flags. WPF was chosen because it ships with Windows (no
  installs) and needs no listening port.
