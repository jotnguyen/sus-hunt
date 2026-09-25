<#
.SYNOPSIS
    Pre-commit hygiene gate. Fails if a commit would publish something about this machine or its owner.
.DESCRIPTION
    Run from anywhere in the repo, after `git add -A`:
        powershell -NoProfile -File tools\hygiene-gate.ps1
    Prints "hygiene-ok" and exits 0 when clean; lists every hit and exits 1 otherwise.

    Checks every tracked file for:
      1. Files .gitignore says must stay local (reports, baselines, watch logs, allowlist.txt)
         that are tracked anyway (added with -f, or tracked before the ignore rule existed).
      2. This machine's user name, computer name, domain and git e-mail. They are read at run
         time, so this script never contains them.
      3. Windows profile paths with a real user name (C:\Users\<name>\...). Placeholder names
         used in tests and docs (someone, Public, Default, All) are allowed.
      4. E-mail addresses, except noreply and example.* ones.
#>
[CmdletBinding()]
param()

$root = (git rev-parse --show-toplevel) -replace '/', '\'
if (-not $root) { Write-Error 'Not inside a git repository.'; exit 1 }
Push-Location $root
try {
    $problems = New-Object System.Collections.Generic.List[string]

    # 1. Ignored-but-tracked files: the output of a scan describes this machine.
    foreach ($f in @(git ls-files -ci --exclude-standard)) { $problems.Add("TRACKED BUT IGNORED: $f") }

    # 2. Identity strings of this machine. Generic account names would match everywhere, so skip them.
    $generic = @('admin', 'administrator', 'user', 'owner', 'guest', 'workgroup')
    $identity = @($env:USERNAME, $env:COMPUTERNAME, $env:USERDOMAIN, (git config user.email)) |
        Where-Object { $_ -and $_.Length -ge 3 -and $generic -notcontains $_.ToLowerInvariant() } |
        Select-Object -Unique
    $identityRx = @($identity | ForEach-Object { '(?i)(?<![a-z0-9])' + [regex]::Escape($_) + '(?![a-z0-9])' })

    $profileRx = '(?i)\b[a-z]:\\users\\([^\\\s"''<>%*$`]+)'
    $placeholderProfiles = '^(?i)(someone|public|default|all)$'
    $emailRx = '(?i)[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}'
    $allowedEmail = '(?i)noreply|@example\.(com|org|net)$'

    foreach ($file in @(git ls-files)) {
        $full = Join-Path $root $file
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }   # deleted, not yet staged
        $text = [IO.File]::ReadAllText($full)
        if ($text.IndexOf([char]0) -ge 0) { continue }                          # binary
        $lines = $text -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $at = '{0}:{1}' -f $file, ($i + 1)
            foreach ($rx in $identityRx) {
                # The value itself is not printed: this output may be pasted somewhere.
                if ($line -match $rx) { $problems.Add("IDENTITY ${at}: this machine's user, computer, domain or git e-mail") }
            }
            foreach ($m in [regex]::Matches($line, $profileRx)) {
                if ($m.Groups[1].Value -notmatch $placeholderProfiles) { $problems.Add("PROFILE PATH ${at}: $($m.Value)") }
            }
            foreach ($m in [regex]::Matches($line, $emailRx)) {
                if ($m.Value -notmatch $allowedEmail) { $problems.Add("E-MAIL ${at}: $($m.Value)") }
            }
        }
    }

    if ($problems.Count) {
        Write-Host 'Hygiene gate failed. Replace with placeholders (C:\Users\someone\, HOST-01, you@example.com):' -ForegroundColor Red
        $problems | Select-Object -Unique | ForEach-Object { Write-Host "  $_" }
        exit 1
    }
    Write-Host 'hygiene-ok' -ForegroundColor Green
    exit 0
} finally {
    Pop-Location
}
