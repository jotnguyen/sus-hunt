# CLAUDE.md — sus-hunt

Project instructions for any Claude Code session in this repo. Short on purpose; details live in
the files linked below.

## Read first, in this order

1. `README.md` — what the kit does, every rule, and its limitations.
2. `docs/backlog/README.md` — open work, the sprint order, and which files collide.
3. The ticket you are working on: `docs/backlog/tickets/TICKET-NNN-*.md`.
4. `.ai/memory/` — durable facts that are not obvious from the code.
5. `.claude/skills/` — how to do recurring things here (add a detection, pick the next ticket,
   end a session).

## Non-negotiables

- **Detection and learning only.** No payloads, no evasion, no credential access, no exploit
  code, no persistence of our own. Response actions (kill, TCP reset, firewall block) already
  exist behind `ShouldProcess`; do not add new ones without the owner asking.
- **Never change the machine's security settings from code.** Defender, audit policy, firewall
  (outside the existing opt-in `Stop-SusConnection`), UAC. If a check needs a setting on, print the
  command and let the human run it.
- **No network calls by default.** `-ResolveDns` is the only one, and it is opt-in. Never upload
  hashes or files anywhere (VirusTotal and similar). Lists like LOLDrivers are files the human
  downloads and passes in by path.
- **Never execute what a scan finds.** Read bytes, hash, parse headers. Treat every string from the
  examined machine as attacker-controlled: HTML-encode it (`lib/Report.ps1`), never
  `Invoke-Expression` it.
- **No personal info in git.** Reports, baselines, watch logs and `allowlist.txt` stay git-ignored.
  Do not paste real output from this machine into docs, tests or session logs; use placeholders
  (`C:\Users\someone\`, `HOST-01`, `you@example.com`). After `git add -A` and before every commit:

  ```powershell
  powershell -NoProfile -File tools\hygiene-gate.ps1   # must print hygiene-ok
  ```

## Code rules

- **Windows PowerShell 5.1, no installs.** No `?.`, `??`, ternary, `ForEach-Object -Parallel`,
  `ConvertFrom-Json -AsHashtable`, or `&&`. Use runspace pools for parallel work (see
  `Initialize-SignatureCache` in `lib/Common.ps1`).
- **`lib/*.ps1` stay plain ASCII.** 5.1 misreads BOM-less UTF-8. Build special characters from
  code points (see `$script:BidiControls` in `lib/Processes.ps1`).
- **Rules are data.** Points, ATT&CK IDs and patterns go in `lib/Rules.ps1`. Every signal has an
  ATT&CK ID and a `Why` that teaches something. Add each new rule to the README table.
- **C# in `lib/Native.ps1`:** `Add-Type` cannot reload a type in a live session, so if you change
  the C#, bump the namespace (`SusHunt.V3` → `SusHunt.V4`) everywhere it is used.
- **Tests:** `Invoke-Pester .\tests` must pass. It runs on Pester 3.4, which ships with Windows, so use
  `Should Be`, not `Should -Be`. Test the pure logic (parsers, scoring, math) with synthetic input;
  do not write tests that depend on this machine's state.
- New command: add it to the `ValidateSet` and `switch` in `sus-hunt.ps1`, the loader list and
  `Export-ModuleMember` in `SusHunt.psm1`, and the Quick start and Layout sections of the README.

## Git

- Branch per ticket (`ticket-NNN-<slug>`); the owner merges to `main`.
- Commit style follows history: plain imperative subject ("Add ...", "Make ..."), no `feat:`
  prefix, body explains why, bullets for the pieces.
- Log what a session did in `.ai/sessions/` (skill: `session-log`).
