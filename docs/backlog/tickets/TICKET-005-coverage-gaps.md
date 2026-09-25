# TICKET-005: New autostart sources — COM hijacks, drivers, browser extensions, DLL search order

**Type:** feature
**Priority:** medium
**Sprint:** 2
**Parallelizable:** yes. Each phase is its own PR and adds its own function to `lib/Persistence.ps1` (a hot file: append to `$sources`).
**Human-blocked:** phase B needs the human to download the LOLDrivers list if they want BYOVD matching.
**Status:** backlog

## Links

- Blocked by: none. Phase B reuses the PE parser from [TICKET-002](TICKET-002-file-scan.md) if it has landed, but can check signatures without it.

## Description

The README's Limitations section lists what the kit skips: COM hijacking, drivers, browser
extensions and DLL search-order hijacking. Each is a real, common persistence or privilege path.
Each one plugs into `Get-SusPersistenceFinding`'s `$sources`, so `triage`, `autoruns` and
`baseline`/`diff` get it for free. Do the phases in order; each is one sitting.

## Phase A: COM hijacks (T1546.015)

- `HKCU:\Software\Classes\CLSID\{guid}\InprocServer32` or `LocalServer32` where the same CLSID also exists
  under `HKLM:\Software\Classes\CLSID`. The per-user key wins, so a standard user can redirect a
  COM object that system programs load. **UserComOverride 40.** Add `Get-LaunchSignals` on the DLL path.
- `TreatAs` and `ScriptletURL` values under HKCU CLSIDs: **ComTreatAs 30**, **ComScriptlet 50**.
- Only report HKCU entries. HKLM is the normal case and would be a flood.

## Phase B: kernel drivers (T1543.003, T1068)

- Services with Type 1 or 2 (`HKLM:\SYSTEM\CurrentControlSet\Services`), with the ImagePath
  normalized (`\SystemRoot\`, `System32\drivers\`). Signature via `Get-FileSignature`.
- **DriverUserWritablePath 60** (Get-PathRisk is not Windows or ProgramFiles), **DriverUnsigned 60**,
  **DriverNotMicrosoft 0** (information for the inventory only).
- **VulnerableDriver 70 (T1068, "bring your own vulnerable driver"):** `-DriverList <path>` points to a
  `drivers.json` the human downloaded from loldrivers.io. Match on SHA-256. No download in code.
- **BlocklistOff 20:** `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config` `VulnerableDriverBlocklistEnable` = 0.

## Phase C: browser extensions (T1176)

- Chromium (Chrome, Edge, Brave): `%LOCALAPPDATA%\<vendor>\User Data\<profile>\Extensions\<id>\<ver>\manifest.json`.
  Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json`.
- **ExtensionPowerfulPermissions 20** for `<all_urls>`, `nativeMessaging`, `debugger`,
  `webRequestBlocking`, `cookies`, `proxy` (evidence lists which). **ExtensionOffStore 30** when
  `update_url` is missing or not the vendor's store. **ExtensionForceInstalled 40** when it is in
  `HKLM|HKCU:\SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge}\ExtensionInstallForcelist`.
- Resolve `__MSG_name__` from `_locales` so the name is readable. Privacy: extension lists reveal
  habits, so keep them in git-ignored reports only.

## Phase D: DLL search-order hijack (T1574.001), stretch

- For running processes outside `%windir%`: list DLLs in the program's own folder whose names match
  a DLL in System32 that is *not* in `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
  (KnownDLLs cannot be hijacked this way). Flag it when the copy is unsigned or signed by someone
  other than Microsoft: **SideloadCandidate 30**.
- High false-positive risk (apps ship their own runtimes). Start at `Info` and tune on a real machine.

## Acceptance criteria (each phase)

- [ ] Pester tests for the pure parts: CLSID path parsing, ImagePath normalization, manifest
      permission scoring from a JSON string, KnownDLLs filtering.
- [ ] `tools\hygiene-gate.ps1` prints `hygiene-ok`.
- [ ] README rule table and Limitations section updated.
- [ ] Phase A, human: `reg add "HKCU\Software\Classes\CLSID\{<a CLSID that exists in HKLM>}\InprocServer32" /ve /d C:\Users\Public\x.dll /f`,
      then `autoruns` shows UserComOverride. Remove it with `reg delete` of the same key.
- [ ] Phase B: `autoruns` runs in < 30 s and reports no Microsoft driver as unsigned.

## Rollback

Revert the merge commit for the phase. Remove any test registry key.

## Comments

- **2026-09-25** — Created from the roadmap (idea 4), split into phases A-D.
