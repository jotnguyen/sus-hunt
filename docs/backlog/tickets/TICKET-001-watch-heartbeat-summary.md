# TICKET-001: watch — heartbeat, sleep-gap detection, summary on exit

**Type:** feature
**Priority:** high
**Sprint:** 1
**Parallelizable:** yes. It touches `lib/Watch.ps1` (nothing else edits it) plus small edits to hot files `sus-hunt.ps1`, `README.md` and the tests.
**Human-blocked:** no for the code; the sleep test in acceptance needs a human.
**Status:** backlog

## Links

- Related to: [TICKET-006](TICKET-006-named-pipes.md) (it may add a pipe check to the watch loop)

## Description

An overnight `watch -Quiet` run printed nothing. That is the expected result, but the owner could
not tell "nothing happened" from "the loop hung" or "the PC slept for six hours". Quiet mode
needs a pulse and a record of what it saw, and the end of a run should summarize what normal
looked like, which is the part a learner learns most from.

## Design

All in `Watch-SusActivity` (`lib/Watch.ps1`), plus pure helpers for tests.

- **Heartbeat.** New parameter `-HeartbeatMinutes` (int, default 15, 0 = off), passed through by
  `sus-hunt.ps1`. Every N minutes, print one DarkGray line even with `-Quiet`:
  `HH:mm:ss ALIVE  up 2h15m | 1,204 processes, 3 flagged | 12 windows | 88 new public connections`.
  With `-LogPath`, write it as a CSV row with `Type = ALIVE` and `Points = 0`, so a gap in the log's
  ALIVE rows shows when the watcher was not running.
- **Sleep / suspend gap.** Each tick compares wall-clock time elapsed with a monotonic
  `Stopwatch` elapsed time. When the wall clock jumped more than 30 s past the stopwatch (sleep,
  hibernate, or a large clock change), print and log:
  `GAP    no data from 01:12:40 to 06:58:03 (5h45m): sleep, hibernate or clock change`.
  Also re-prime the network table after a gap, so every connection re-established on wake is not
  reported as new. Pure helper: `Get-ClockGap -WallElapsed <timespan> -MonoElapsed <timespan> -Threshold 30`.
- **Summary on exit.** In the `finally` block (runs on Ctrl+C), print:
  - duration, and total time lost to gaps
  - counts: processes seen, flagged (by severity), console windows, public connections, beacons
  - the top 10 new-process names by count, with their most common parent. This is "what normal
    looks like on this machine" and is the main learning output.
  - the log path, if any.
  Keep counters in one `$stats` hashtable, plus a `Dictionary[string,int]` for name counts. Pure
  helper `Format-WatchSummary $stats` returns lines, so it can be tested.
- **Optional (same PR if small):** the same heartbeat and summary in `Watch-SusSysmon`.
- Update the startup banner to mention the heartbeat interval and README's `watch` section.

## Plan

1. [agent] Add `Get-ClockGap` and `Format-WatchSummary` with Pester tests (a gap under the
   threshold returns nothing, a gap over it returns the duration; the summary sorts and caps the top
   names).
2. [agent] Add `$stats` counters, the heartbeat, gap detection and the `finally` summary to
   `Watch-SusActivity`. Add the `-HeartbeatMinutes` pass-through in `sus-hunt.ps1`.
3. [agent] Run `.\sus-hunt.ps1 watch -Quiet -Seconds 150 -HeartbeatMinutes 1 -LogPath $env:TEMP\w.csv`
   and check for two ALIVE lines, a summary at exit, and ALIVE rows in the CSV.
4. [agent] Update the README and write a session log.
5. [human] Sleep test (below).

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes, with new tests for `Get-ClockGap` and `Format-WatchSummary`.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] A `watch -Quiet -Seconds 150 -HeartbeatMinutes 1` run shows 2 ALIVE lines and a summary.
- [ ] Ctrl+C mid-run still prints the summary.
- [ ] Human: start `watch -Quiet -HeartbeatMinutes 1`, put the PC to sleep for 2+ minutes, wake it.
      A single GAP line appears with the right times, and there is no flood of NET lines.

## Rollback

Revert the merge commit. There is no machine state to undo.

## Comments

- **2026-09-25** — Created from the overnight quiet-run discussion (roadmap idea 6).
