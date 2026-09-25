# 2026-09-25: TICKET-002 `files` command, linter, CI

**Ask:** build TICKET-002 (the file scan). Have GitHub delete branches when a PR merges. Add a
PowerShell linter. Keep personal data out of git.

## 1. Repo setting: delete branch on merge

`gh api -X PATCH repos/<owner>/sus-hunt -F delete_branch_on_merge=true`. CLAUDE.md now says to
start each ticket from a fresh `origin/main`.

Result: the setting is on.

## 2. `files` command (lib/Files.ps1)

- Pure helpers: `Get-ShannonEntropy`, `Get-PeInfo`, `ConvertFrom-ZoneIdentifier`,
  `Test-ExtensionMismatch`, `Get-FileSignals` (scores one file from facts already read),
  `ConvertFrom-YaraOutput`, `Test-SkippedDir`.
- The name checks moved out of `Get-ProcessSignals` into `Get-FileNameSignals` (lib/Common.ps1),
  so processes and files share them.
- C# in `lib/Native.ps1` (namespace now `SusHunt.V4`): `FindRecentFiles`, `ReadHeads` and
  `ShannonEntropy`.
- Rules are data in `lib/Rules.ps1` (`$script:FileRules` and the extension and skip lists).
- Wired into `sus-hunt.ps1` (`files`, `-Days`, `-Path`, `-Yara`, `-YaraExe`) and `SusHunt.psm1`.

Performance work, measured with `Get-SusFileFinding -Days 7 -Verbose` (it prints phase times):

| Change | 7-day run |
|---|---|
| First version (PowerShell walk, sniff every recent file) | more than 5 minutes |
| Skip browser caches and site storage | about 5 minutes |
| C# walk, sniff only decoy and `.tmp`-style names, never open scripts | about 95 s |
| Skip signature checks for programs over 32 MB outside Temp, Downloads and Public | about 75 s |
| Parallel header reads in C# | about 62 s |

Result: a quick check in a scratch folder gave copies of notepad named `invoice.pdf.exe` and
`notes.txt` the rules DoubleExtension and ExtensionMismatch. On the dev machine, a 7-day scan
found 4 items at the default threshold, all UnsignedInHighRisk (installer helper DLLs in Temp).

## 3. Linter and CI

- `PSScriptAnalyzerSettings.psd1`: Error and Warning severity; `PSUseCompatibleSyntax` targets
  5.1. Three rules are excluded, each with a reason (Write-Host, plural nouns, ShouldProcess on
  pure constructors).
- `tools/lint.ps1` prints `lint-ok`, or prints the install command if the module is missing.
- `.github/workflows/check.yml`: lint, Pester 3.4 and the hygiene gate on `windows-latest`
  under Windows PowerShell 5.1.

Result: see the PR checks. PSScriptAnalyzer is not installed on the dev machine, so the first
lint run happened in CI.

## Tests

`Invoke-Pester .\tests`: 100 passed, 0 failed (29 of them are new, for `files`).

## Open

- Human acceptance steps in TICKET-002: plant the two notepad copies in `%TEMP%`, and download
  an installer in a browser, then run `files -Days 1`.
- YARA was not tried end to end (`yara64.exe` is not installed). The output parser has tests.
