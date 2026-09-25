# Backlog

One ticket per piece of work in [`tickets/`](tickets/), using [`TEMPLATE.md`](tickets/TEMPLATE.md).
The ticket owns the status, plan, acceptance criteria and comment history. This page is the index
and the order.

## Open tickets

| Ticket | What | Priority | Sprint | Status |
|---|---|---|---|---|
| [TICKET-001](tickets/TICKET-001-watch-heartbeat-summary.md) | `watch`: heartbeat, sleep-gap detection, summary on exit | high | 1 | backlog |
| [TICKET-002](tickets/TICKET-002-file-scan.md) | `files` command: recent executables in user-writable folders, Mark-of-the-Web, PE checks, optional YARA | high | 1 | backlog |
| [TICKET-003](tickets/TICKET-003-defender-tamper.md) | Defender tamper check: exclusions, disabled protection, detection and config-change events | high | 1 | backlog |
| [TICKET-004](tickets/TICKET-004-event-log-hunt.md) | `events` command: hunt the built-in Windows logs without Sysmon | medium | 2 | backlog |
| [TICKET-005](tickets/TICKET-005-coverage-gaps.md) | New autostart sources: COM hijacks, kernel drivers (BYOVD), browser extensions, DLL search order | medium | 2 | backlog |
| [TICKET-006](tickets/TICKET-006-named-pipes.md) | Named pipes: known C2 and lateral-movement pipe names | low | 3 | backlog |

These are ideas 1-6 from the 2026-09-25 roadmap discussion, renumbered into sprint order:
idea 6 (heartbeat) → 001, 1 (file scan) → 002, 2 (Defender) → 003, 3 (event logs) → 004,
4 (coverage gaps) → 005, 5 (named pipes) → 006.

## Sprints

- **Sprint 1: 001, 002, 003.** Chosen by the owner. Do 001 first: it is small and touches only
  `lib/Watch.ps1`. Then 003 and 002 in either order.
- **Sprint 2: 004, 005.** 005 has four independent phases, and each can be its own PR.
- **Sprint 3: 006.**

## Multi-agent hot files

Almost every ticket edits these. If two branches both touch one, merge the second one by hand,
and keep additions append-only (new rows or new entries at the end of a list) to make that easy:

- `sus-hunt.ps1`: `ValidateSet`, `param`, `switch`
- `SusHunt.psm1`: loader list, `Export-ModuleMember`
- `lib/Rules.ps1`: new rule data
- `lib/Persistence.ps1`: the `$sources` table in `Get-SusPersistenceFinding`
- `README.md`: rule table, Quick start, Layout
- `tests/SusHunt.Tests.ps1`: add a new `Describe` block at the end

## Won't do (and what to use instead)

- **Memory injection scanning** (unbacked executable memory, hollowed processes). PowerShell
  is the wrong tool for this. Use [PE-sieve](https://github.com/hasherezade/pe-sieve) or
  [Moneta](https://github.com/forrest-orr/moneta). A `-External` hook that runs one of them, if the
  human has installed it, could be a later ticket.
- **Cloud reputation lookups** (VirusTotal and similar). They conflict with the no-network rule, and
  they leak what is on the machine. Print the SHA-256 so the human can look it up by hand.
