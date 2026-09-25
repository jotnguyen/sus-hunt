---
name: pick-next-task
description: Choose the single best next sus-hunt backlog ticket, given sprint order, blockers and work already in flight. Use when the user asks "what's next" or starts a session with no assigned task.
---

# Pick next task

1. Read `docs/backlog/README.md`. Find the earliest sprint with a ticket not `done`.
2. Open each of that sprint's tickets and read `Status` and `Links`. Drop anything `Blocked by`
   an open ticket, or already `in-progress`.
3. Check what else is in flight: `git branch -a`, `git worktree list`, `gh pr list`. A
   `ticket-NNN-*` branch means someone started it. Offer to continue it rather than start over.
4. If two candidates touch the same hot file (listed in the backlog README), prefer the one
   that does not collide with an open branch.
5. Pick: higher priority first, then `Human-blocked: no`, then smaller.
6. Tell the user which ticket, the one reason it won, and the first `[agent]` step of its Plan.
   Before you start, set `Status: in-progress` and add a dated comment to the ticket, on a
   `ticket-NNN-<slug>` branch.

Done when you have named one ticket and are ready to start its first step. Do not give a ranked list.
