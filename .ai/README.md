# .ai/ — agent notes for this repo

Committed so they travel with the code.

```
.ai/
├── README.md     this file
├── memory/       durable facts not in README or code (one topic per file, edited in place)
└── sessions/     dated, append-only logs of what an agent did and why
```

## Overlap with Claude Code auto-memory

Claude Code keeps its own per-developer memory under `~/.claude/projects/`. That memory stays on
one machine and is never committed. `.ai/memory/` is committed and shared.

Rule: a fact every agent needs goes here or in the README. A fact about one person's workflow or
machine goes in auto-memory. **Nothing about the owner's machine goes here**: no user names,
host names, paths under a real profile, or real scan output. `tools/hygiene-gate.ps1` checks.

## Where current truth lives

| Topic | Authoritative file |
|---|---|
| Features, rules, limitations | `README.md` |
| Open work and order | `docs/backlog/README.md` |
| Gotchas behind design choices | `.ai/memory/design-notes.md` |
| Recurring procedures | `.claude/skills/` |

Do not create a second file for the same topic. Update the existing one.
