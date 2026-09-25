# TICKET-003: Defender tamper check

**Type:** feature
**Priority:** high
**Sprint:** 1
**Parallelizable:** yes. It adds a new file, `lib/Defender.ps1`, and appends to the hot files `lib/Persistence.ps1` (`$sources`), `SusHunt.psm1`, `lib/Rules.ps1`, `README.md` and the tests.
**Human-blocked:** partly. Reading exclusions needs admin. The acceptance test needs a human to add and then remove a test exclusion; the code never changes Defender settings.
**Status:** backlog

## Links

- Related to: [TICKET-002](TICKET-002-file-scan.md), [TICKET-004](TICKET-004-event-log-hunt.md) (both read event logs)

## Description

One of the first things real intrusions do is add a Defender exclusion or switch off real-time
protection, so the payload is never scanned (T1562.001). The check is cheap and the signal is
high: legitimate exclusions are rare and usually point somewhere boring, like a dev build folder.
Defender also keeps its own record of detections and of every configuration change (event 5007,
with the old and new values), which the kit does not read yet.

## Design

New `lib/Defender.ps1` with `Get-DefenderFindings`, added to `$sources` in
`Get-SusPersistenceFinding` as `'Defender'`. That means `triage`, `autoruns` and
`baseline`/`diff` all pick it up; a new exclusion shows in `diff` with no extra work. The
`Defender` module may be missing, or Defender may be in passive mode behind a third-party AV.
In either case, emit one 0-point Info finding that says so and stop.

**State** (`Get-MpComputerStatus`, `Get-MpPreference`):

| Rule | Points | ATT&CK | Fires when |
|---|---|---|---|
| RealtimeOff | 60 | T1562.001 | `RealTimeProtectionEnabled` is false while `AMRunningMode` is Normal |
| ProtectionFeatureOff | 30 | T1562.001 | Behavior monitoring, IOAV, on-access or antispyware is off (one signal each; score caps at 100) |
| TamperProtectionOff | 15 | T1562.001 | `IsTamperProtected` is false |
| PolicyDisablesDefender | 50 | T1562.001 | `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` has `DisableAntiSpyware` or `Real-Time Protection\DisableRealtimeMonitoring` = 1 |
| StaleSignatures | 15 | T1562.001 | `AntivirusSignatureAge` > 7 days (updates blocked?) |

**Exclusions**, one finding each (`ExclusionPath`, `ExclusionProcess`, `ExclusionExtension`,
`ExclusionIpAddress`). Without admin, `Get-MpPreference` returns the text "N/A: Must be an
administrator to view exclusions". Detect that and say so once; do not treat the text as an
exclusion. Scoring (pure helper `Get-ExclusionSignals -Kind -Value`, testable):

- base `DefenderExclusion` 20
- +30 `BroadExclusion`: a whole drive (`C:\`), a profile root, `%TEMP%`, Downloads, or anything `Get-PathRisk` rates HighRisk
- +30 `RiskyExtensionExcluded`: `.exe .dll .ps1 .bat .vbs .js .hta .scr`
- +20 `LolbinExcluded`: a process exclusion that is in `$script:Lolbins`

**Events** (`Microsoft-Windows-Windows Defender/Operational`, last `-Days`, default 7):

| Event | Rule | Points | Meaning |
|---|---|---|---|
| 1116 / 1117 | DefenderDetection | 30 | Malware detected / action taken. Evidence: threat name and path. |
| 1118 / 1119 | DefenderActionFailed | 50 | Remediation failed. The threat may still be there. |
| 5001 | RealtimeDisabledEvent | 40 | Real-time protection was switched off. |
| 5007 | DefenderConfigChanged | 10, or 50 if the new value mentions `Exclusions` | Configuration changed. Evidence: old value → new value. |
| 5013 | TamperBlocked | 20 | Tamper protection blocked a change. Someone tried. |

Parse with `ConvertFrom-SysmonEventXml`, which works for any event (see `.ai/memory/design-notes.md`).

## Plan

1. [agent] `Get-ExclusionSignals` and a 5007 message parser, with Pester tests (a drive root, a
   Temp path, `.ps1`, `powershell.exe`, the "N/A: Must be an administrator" text).
2. [agent] `Get-DefenderFindings`: state, exclusions, events, and the missing or passive case.
3. [agent] Register it in `$sources`, `SusHunt.psm1` and the README (rule table, new "Defender" line
   under What it looks at). Run `triage` and `autoruns` elevated and not elevated.
4. [agent] Take a `baseline`, then check that `diff` is quiet.
5. [human] Acceptance steps below (admin PowerShell).

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes, with new tests for exclusion scoring and the 5007 parser.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] Not elevated: `triage` says exclusions need admin and does not error.
- [ ] Human, elevated: `New-Item -ItemType Directory $env:TEMP\sushunt-test`, then
      `Add-MpPreference -ExclusionPath $env:TEMP\sushunt-test`. `triage` shows a BroadExclusion
      finding scoring 50 or more, a 5007 event appears with the exclusion in the evidence, and `diff`
      lists the exclusion as Added. Then `Remove-MpPreference -ExclusionPath $env:TEMP\sushunt-test`
      and delete the folder.
- [ ] No code path calls `Set-MpPreference`, `Add-MpPreference` or `Remove-MpPreference`
      (`git grep -n "MpPreference" lib` shows only `Get-MpPreference`).

## Rollback

Revert the merge commit. If the acceptance test was interrupted, remove the test exclusion by
hand (`Remove-MpPreference`, as admin) and check with `Get-MpPreference`.

## Comments

- **2026-09-25** — Created from the roadmap (idea 2). The owner picked it for sprint 1.
