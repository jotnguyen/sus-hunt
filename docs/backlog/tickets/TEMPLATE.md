# TICKET-XXX: Title

**Type:** feature | bug | chore
**Priority:** high | medium | low
**Sprint:** N (see `../README.md`)
**Parallelizable:** yes/no, and which hot files it touches
**Human-blocked:** yes/no, and which step needs a human (run as admin, change a setting, download a list)
**Status:** backlog | in-progress | blocked | done

## Links

Relation words: `Blocked by`, `Blocks`, `Related to`, `Enables`, `Duplicates`. Keep
`Blocks`/`Blocked by` pairs reciprocal.

- Related to: [TICKET-NNN](TICKET-NNN-slug.md)

## Description

What this is, why it matters, and what a learner gets out of it. One or two paragraphs.

## Design

Files, functions, parameters and rules (with points and ATT&CK IDs). Enough that an agent can
start without re-deriving it. Mark open questions.

## Plan

Ordered steps. Mark each `[agent]` or `[human]`.

1. [agent] ...

## Acceptance criteria

- [ ] `Invoke-Pester .\tests` passes, including new tests for the pure logic.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] Human check: run `X`, see `Y`.

## Rollback

How to undo it (usually: revert the merge commit; note any machine state a human changed).

## Comments

Append-only. `- **YYYY-MM-DD** — what changed / what you learned.` Newest at the bottom. Add one
whenever Status changes, the plan turns out wrong, or work is handed off or closed (with commit hash).
