# AGENTS.md — session brain for sus-hunt

Working notes for picking this project up in a fresh session. Not user-facing docs (that is
`README.md`). Tool-agnostic; Claude Code specifics are in `CLAUDE.md` and `.claude/skills/`.

## What this repo is

A Windows PowerShell 5.1 host-triage kit for **learning** how detection works: it scores running
processes, autostart entries and connections against rules mapped to MITRE ATT&CK, watches live
activity, and diffs the machine against a trusted baseline. Every finding says *why* it fired.
No dependencies, no network calls by default. It is a public repo, so git hygiene matters.

## Current status (as of 2026-09-25)

- Commands: `triage`, `watch`, `sysmon`, `conns`, `autoruns`, `baseline`, `diff`. HTML reports.
- `watch` uses native Win32 queries (not WMI) and, when elevated, the kernel process-start trace.
- An overnight `watch -Quiet` run on the owner's machine printed nothing. That is the expected
  result, but it showed two gaps: no heartbeat (silence looks the same as a hung loop or a sleeping
  PC) and nothing is kept without `-LogPath`. That is TICKET-001.
- The roadmap is six tickets in `docs/backlog/`. Sprint 1 (TICKET-001, 002, 003) is the owner's
  chosen next work.

## Where things live

| Need | File |
|---|---|
| What the tool does, rule table, limitations | `README.md` |
| What to do next, in order | `docs/backlog/README.md` |
| One piece of work: plan, acceptance, rollback | `docs/backlog/tickets/TICKET-NNN-*.md` |
| Durable facts not obvious from code | `.ai/memory/*.md` |
| What past sessions did | `.ai/sessions/*.md` |
| How to do recurring things | `.claude/skills/*/SKILL.md` |
| Project rules for Claude Code | `CLAUDE.md` |
| Pre-commit personal-info check | `tools/hygiene-gate.ps1` |

## Conventions to keep following

- Detection only; never change security settings from code; no network calls by default; never
  run what a scan finds. The full list is in `CLAUDE.md` under Non-negotiables.
- No AI attribution in commits or PRs (no `Co-Authored-By: Claude`). History was rewritten on
  2026-09-25 to remove it.
- No personal info in git: run `tools/hygiene-gate.ps1` after `git add -A`, before every commit.
- Rules as data in `lib/Rules.ps1`, each with an ATT&CK ID and a teaching `Why`, mirrored in the
  README table.
- PowerShell 5.1 syntax, ASCII-only `lib/` files, Pester 3.4 tests.
- End every session with the `session-log` skill.
