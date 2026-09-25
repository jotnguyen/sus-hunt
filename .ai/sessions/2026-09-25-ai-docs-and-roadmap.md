# 2026-09-25 — Agent docs and roadmap

Ask: after an overnight `watch -Quiet` run printed nothing, find which flags to use, suggest
additions, then add agent docs (modeled on another of the owner's repos) with a plan for all
six ideas and commit it with no personal info.

## 1. The quiet night

`watch -Quiet` ran elevated (kernel trace mode) overnight and printed only the banner and the
background signature-check notice.

Result: expected. Quiet mode prints only processes scoring 20 or more, console windows and
flagged connections. But without `-LogPath` nothing is kept, and without a heartbeat, silence
looks the same as a hung loop or a sleeping PC. Suggested for the next run:
`watch -AllNetwork -LogPath .\reports\watch_overnight.csv` (full record), then `diff -Html` and
`triage -MinScore 10 -Html` in the morning. The heartbeat gap became TICKET-001.

## 2. Roadmap

Six ideas became tickets in `docs/backlog/tickets/` (renumbered into sprint order; the mapping is
in the backlog README). The owner chose file scan, Defender tamper and heartbeat for sprint 1.
Memory scanning and cloud reputation lookups are recorded as won't-do, with pointers to other tools.

## 3. Agent docs

Added `CLAUDE.md`, `AGENTS.md`, `.ai/` (README, `memory/design-notes.md`, this log),
`docs/backlog/` (index, template, TICKET-001..006) and `.claude/skills/` (`add-detection`,
`pick-next-task`, `session-log`).

## 4. Hygiene gate

`tools/hygiene-gate.ps1` fails when a tracked file is git-ignored output, or contains this
machine's user, computer or domain name, the git e-mail, a real `C:\Users\<name>` path, or a
non-noreply e-mail. The identity values are read at run time, so the script never contains them.

```powershell
git add -A; powershell -NoProfile -File tools\hygiene-gate.ps1
```

Result: `hygiene-ok` on the repo. A planted test file with all three kinds of leak, and a
force-added HTML report, each made it fail as expected. Both were unstaged and deleted afterwards.

## Open

- Human: nothing blocking. Sprint 1 can start with TICKET-001.
- No code changed this session; the Pester suite was run only as a regression check.

## 5. No AI attribution (owner decision, same day)

The owner banned `Co-Authored-By: Claude` trailers, matching their other repos. Added
`.claude/settings.json` (attribution off), a commit-message check in the hygiene gate, and a rule in
`CLAUDE.md`. All earlier commits were rewritten with `git filter-branch --msg-filter` to drop the
trailer, and `main` plus this branch were force-pushed with `--force-with-lease`. Commit hashes in
older notes no longer exist.
