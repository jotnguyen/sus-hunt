# TICKET-006: Named pipes — known C2 and lateral-movement pipe names

**Type:** feature
**Priority:** low
**Sprint:** 3
**Parallelizable:** yes. It adds a new file, `lib/Pipes.ps1`; optional small edit to `lib/Watch.ps1` (coordinate with TICKET-001 if both are open).
**Human-blocked:** no
**Status:** backlog

## Links

- Related to: [TICKET-001](TICKET-001-watch-heartbeat-summary.md) (watch loop)

## Description

Command-and-control frameworks and remote-admin tools talk between processes (and across the
network over SMB) through named pipes. Many of them ship with default pipe names that attackers
forget to change, and the detection community keeps lists of these (Sigma rules "CobaltStrike
Named Pipe", "PsExec Pipes"). Listing pipes is cheap and teaches a Windows IPC primitive most
people never look at.

## Design

- `Get-SusPipeFinding` lists `\\.\pipe\` with `[IO.Directory]::GetFiles('\\.\pipe\')`. This lists
  names only. It does **not** open any pipe: opening one connects to its server, which can block
  or be logged by it.
- Patterns as data in `lib/Rules.ps1`, `$script:PipeRules`, each with Name, Pattern, Points, Attack and
  Why. Copy the patterns from the current Sigma rules, not from memory, and link each rule in
  its `Why`. For example:
  - Cobalt Strike defaults (`msagent_\w+`, `MSSE-\d+-server`, `postex_\w+`, `status_\w+`, and the
    two specific `mojo.5688.8052.<number>` names in the Sigma rule): **C2DefaultPipe 50**, T1071 / T1570.
  - PsExec-style (`PSEXESVC`, `RemCom_\w+`, `paexec\w*`, `csexec\w*`): **RemoteExecPipe 20**, T1569.002.
    These are legitimate admin tools, so the score stays low.
- Owner PID: an opt-in `-ResolveOwner` flag, which opens the pipe and calls `GetNamedPipeServerProcessId`,
  with a warning in the help. Off by default.
- Surface through `triage` (a new source) and the `watch` loop: diff the pipe list every 5 s and
  report new pipes that match a rule. Unmatched new pipes are shown only with `-AllPipes`.

## Plan

1. [agent] `$script:PipeRules` and `Test-PipeName`, with Pester tests (positive and negative
   names, including Chrome's normal `mojo.*` pipes, which must not match).
2. [agent] `Get-SusPipeFinding`, triage source, optional watch hook, README rows.

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes, and ordinary browser `mojo.*` pipe names are not flagged.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] Human: in one PowerShell,
      `$s = New-Object IO.Pipes.NamedPipeServerStream 'msagent_test'`. Then `triage` shows
      C2DefaultPipe for it. Run `$s.Dispose()` afterwards.

## Rollback

Revert the merge commit.

## Comments

- **2026-09-25** — Created from the roadmap (idea 5).
