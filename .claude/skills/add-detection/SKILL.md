---
name: add-detection
description: Add or change a detection rule or a new scan source in sus-hunt the house way — rule as data in lib/Rules.ps1, ATT&CK ID, teaching Why, Pester test, README table row. Use for any ticket that adds a signal, a command, or an autostart source.
---

# Add a detection

1. **Rule data first.** Add the rule to `lib/Rules.ps1` (or a new `$script:` table there):
   name, points, ATT&CK technique ID, and a `Why` a learner can read. Say what is normal as well as
   what is bad ("Installers do this too"). Points scale: Low from 15, Medium 30, High 60,
   capped at 100 per item. Start low if legitimate software trips it.
2. **Signal code.** Emit with `New-Signal <Rule> <Points> <Attack> <Why> <Evidence>`. Evidence is
   the specific value that fired (the path, the decoded text, the old → new value). Build findings
   with `New-Finding`, so scoring, severity and the HTML report work unchanged.
3. **Where it plugs in:**
   - A new autostart or config source: add a `Get-XxxFindings` function and one line in
     `$sources` in `Get-SusPersistenceFinding` (`lib/Persistence.ps1`). `triage`, `autoruns` and
     `baseline`/`diff` pick it up automatically.
   - Command-line pattern: add an entry to `$script:CommandLineRules`. It then applies everywhere
     command lines are scored (processes, tasks, services, WMI, Sysmon).
   - A new command: `lib/<Topic>.ps1`, then the loader list and `Export-ModuleMember` in
     `SusHunt.psm1`, then `ValidateSet`, `param` and `switch` in `sus-hunt.ps1`.
4. **Pure helper + test.** Put the parsing and scoring logic in a function that takes plain
   input (a string, a `byte[]`, a hashtable) and add a `Describe` block at the end of
   `tests/SusHunt.Tests.ps1`, in Pester 3.4 syntax (`Should Be`). Use synthetic inputs and placeholder
   paths (`C:\Users\someone\`). Never commit real output from this machine or a real binary.
5. **Try it for real.** Run the command elevated and not elevated. Not elevated must degrade
   quietly (`Write-Verbose` or one warning), not throw.
6. **Docs.** Add a row to the README "What it looks at" table. If a limitation went away or appeared, update
   Limitations too.
7. **Check.**

   ```powershell
   Invoke-Pester .\tests
   git add -A; powershell -NoProfile -File tools\hygiene-gate.ps1
   ```

Guardrails (from `CLAUDE.md`): read-only on the machine, no network calls, never execute what a scan
finds, HTML-encode anything that reaches a report, ASCII-only `lib/` files.
