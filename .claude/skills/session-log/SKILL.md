---
name: session-log
description: End-of-session ritual for sus-hunt — write .ai/sessions/<date>-<title>.md, update the ticket comments and backlog index, refresh .ai/memory, run the hygiene gate, commit. Use at the end of every working session.
---

# Session log

1. **Session file** `.ai/sessions/YYYY-MM-DD-short-title.md` (append-only; never edit old ones):
   - Ask, in one line.
   - What was done and why: numbered sections, each with the commands that mattered, then a
     one- or two-sentence "Result:".
   - Tests: the `Invoke-Pester` summary line (passed/failed counts).
   - What failed or was skipped, and why. Human steps still open.
   - **No machine details:** no user or host names, no real paths under a profile, no real scan
     output. Describe results in counts and rule names ("3 findings: 2 Unsigned, 1 RunsFromTemp").
2. **Ticket:** update `Status`, tick acceptance boxes that are proven, and add a dated comment
   (with the commit hash when closing). Mirror the status in the table in `docs/backlog/README.md`.
3. **Memory:** if you learned a non-obvious fact (a gotcha, a timing, why a design is the way it
   is), edit `.ai/memory/design-notes.md` in place. Do not duplicate the README.
4. **Gate and commit:**

   ```powershell
   git add -A
   powershell -NoProfile -File tools\hygiene-gate.ps1   # must print hygiene-ok
   git commit -m "Log session: <title>"
   ```

5. Final chat message: what is verified working, open human steps, and what was skipped. No filler.
