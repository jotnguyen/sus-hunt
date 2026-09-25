# TICKET-004: `events` command — hunt the built-in Windows logs without Sysmon

**Type:** feature
**Priority:** medium
**Sprint:** 2
**Parallelizable:** yes. It adds a new file, `lib/EventLogs.ps1`, and appends to the hot files.
**Human-blocked:** partly. The Security log needs admin. Some events exist only if audit policy is on, and turning it on is the human's choice.
**Status:** backlog

## Links

- Related to: [TICKET-003](TICKET-003-defender-tamper.md) (Defender events live there, not here)

## Description

`sysmon -Hours N` is the best look-back, but only if Sysmon was installed *before* the thing
happened. Windows already records a lot on its own: services installed, tasks registered, logs
cleared, logons, PowerShell script blocks. A learner should know which of those are on by default,
which need audit policy, and what each one looks like when an attacker trips it.

## Design

`.\sus-hunt.ps1 events [-Hours 24] [-MinScore 20] [-LogPath x.csv]`. Output goes through
`Write-SusEvent`, like `sysmon -Hours`. A live mode (`-Watch`) reusing `Watch-SusEventLog` is a
stretch goal.

| Log / ID | On by default? | Rule | Points | ATT&CK |
|---|---|---|---|---|
| System 7045 | yes | ServiceInstalled, plus `Get-LaunchSignals` on ImagePath | 20 + | T1543.003 |
| System 104, Security 1102 | yes | LogCleared | 60 | T1070.001 |
| TaskScheduler/Operational 106 | often | TaskRegistered, plus launch signals on the action (look it up by task name) | 15 + | T1053.005 |
| Security 4698 | needs "Other Object Access" auditing | TaskCreated (full XML, including the action) | 15 + | T1053.005 |
| Security 4720 / 4732 (group S-1-5-32-544) | yes (domain) / varies | AccountCreated / AddedToAdmins | 30 / 50 | T1136.001 / T1098 |
| Security 4624 type 10 or 3 from a Public IP (`Get-IpScope`) | yes | RemoteLogonFromInternet | 40 | T1021.001 |
| Security 4625 bursts (≥ 20 from one source in 10 min) | yes | LogonBruteForce | 40 | T1110 |
| Security 4688 | needs "Process Creation" auditing (+ command-line policy) | as Sysmon 1: `Get-CommandLineSignals`, parent checks | varies | varies |
| PowerShell/Operational 4104 | Warning-level ones by default; all with script block logging | ScriptBlock: `Get-CommandLineSignals` on ScriptBlockText. +20 if PowerShell itself logged it as Warning (it thought it looked suspicious) | varies | T1059.001 |

At startup, print which sources are readable and which audit settings are off. Where admin
allows, parse `auditpol /get /category:*` read-only, then print the `auditpol /set ...` command
the human can run if they want more coverage. Never run it.

Generalize `ConvertFrom-SysmonEventXml` to `ConvertFrom-EventXml`, keeping the old name as an alias
so the Sysmon code and tests do not change. 4104 script blocks are split across several events
(MessageNumber/MessageTotal, keyed by ScriptBlockId). Join the parts before scoring.

## Plan

1. [agent] Pester tests from hand-written event XML strings (7045, 4104 in two parts, 4624 type 10
   with a public IP, 4625 burst counting). Use documentation IPs (203.0.113.x) and placeholder
   names only.
2. [agent] `lib/EventLogs.ps1` with one small function per source. The command and README.
3. [agent] Run `events -Hours 72` elevated and not elevated; note in the ticket which sources were
   present on a default Windows 11 install (counts only, no content).
4. [human] Optional: enable process-creation auditing or script block logging, and rerun.

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] Not elevated: the Security-log sources are reported as skipped, with no errors.
- [ ] Human, elevated: `sc.exe create SusHuntTest binPath= "C:\Windows\System32\cmd.exe /c exit"`
      then `sc.exe delete SusHuntTest`. `events -Hours 1` shows ServiceInstalled for it.

## Rollback

Revert the merge commit. Undo any audit policy the human turned on with the matching
`auditpol /set ... /success:disable`.

## Comments

- **2026-09-25** — Created from the roadmap (idea 3).
