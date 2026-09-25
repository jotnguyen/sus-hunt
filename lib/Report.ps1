# Single-file HTML report. Everything that came from the machine (names, paths, command lines)
# is attacker-controllable, so every value is HTML-encoded: a process named <script>...
# must show up as text, not run in your browser.

function ConvertTo-HtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$script:ReportCss = @'
:root { --bg:#fbfbfa; --fg:#1d1d1f; --muted:#6b6b70; --line:#e3e3e0; --card:#ffffff;
        --high:#c62828; --medium:#ad5a00; --low:#6d6d00; --info:#6b6b70; --added:#2e7d32; --removed:#8e24aa; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161618; --fg:#ececef; --muted:#9a9aa2; --line:#2c2c30; --card:#1e1e21;
          --high:#ff6b6b; --medium:#ffb454; --low:#d4d46a; --info:#9a9aa2; --added:#7ad483; --removed:#d59be3; }
}
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
       font:14px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif; }
main { max-width:1100px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; }
.meta { color:var(--muted); margin-bottom:20px; }
.counts { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
.count { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:8px 14px; }
.count b { font-size:18px; display:block; }
details { background:var(--card); border:1px solid var(--line); border-radius:8px; margin-bottom:8px; }
summary { cursor:pointer; padding:10px 14px; display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }
summary .score { font-weight:700; min-width:3ch; }
summary .sev { font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
summary .rules { color:var(--muted); }
.body { padding:0 14px 12px; overflow-wrap:anywhere; }
.body dt { color:var(--muted); font-size:12px; margin-top:6px; }
.body dd { margin:0; font-family:ui-monospace, Consolas, monospace; font-size:12.5px; }
.sig { border-top:1px solid var(--line); padding-top:6px; margin-top:8px; }
.sig .pts { font-weight:700; }
.High { color:var(--high); } .Medium { color:var(--medium); } .Low { color:var(--low); } .Info { color:var(--info); }
.Added { color:var(--added); } .Removed { color:var(--removed); } .Changed { color:var(--medium); }
'@

function Get-HtmlPage {
    param([string]$Title, [string]$Body)
    $t = ConvertTo-HtmlText $Title
    $stamp = ConvertTo-HtmlText (Get-Date -Format 'yyyy-MM-dd HH:mm')
    "<!DOCTYPE html>`n<html lang=`"en`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width, initial-scale=1`">" +
    "<title>$t</title><style>$script:ReportCss</style></head><body><main><h1>$t</h1><div class=`"meta`">Generated $stamp by sus-hunt</div>$Body</main></body></html>"
}

function ConvertTo-SusFindingHtml {
    param([object[]]$Findings, [string]$Title = 'SusHunt triage')
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<div class="counts">')
    foreach ($sev in 'High', 'Medium', 'Low', 'Info') {
        $n = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
        $null = $sb.Append("<div class=`"count`"><b class=`"$sev`">$n</b>$sev</div>")
    }
    $null = $sb.Append('</div>')
    foreach ($f in $Findings) {
        $null = $sb.Append("<details><summary><span class=`"score $($f.Severity)`">$($f.Score)</span>")
        $null = $sb.Append("<span class=`"sev $($f.Severity)`">$($f.Severity)</span>")
        $null = $sb.Append("<span>$(ConvertTo-HtmlText $f.Category): <b>$(ConvertTo-HtmlText $f.Name)</b> $(ConvertTo-HtmlText $f.Id)</span>")
        $null = $sb.Append("<span class=`"rules`">$(ConvertTo-HtmlText $f.Summary)</span></summary><div class=`"body`"><dl>")
        foreach ($field in 'Path', 'Context', 'CommandLine') {
            if ($f.$field) { $null = $sb.Append("<dt>$field</dt><dd>$(ConvertTo-HtmlText $f.$field)</dd>") }
        }
        $null = $sb.Append('</dl>')
        foreach ($s in $f.Signals | Sort-Object Points -Descending) {
            $attack = if ($s.Attack) {
                $id = ConvertTo-HtmlText $s.Attack
                $url = 'https://attack.mitre.org/techniques/' + ($s.Attack -replace '\.', '/') + '/'
                " <a href=`"$(ConvertTo-HtmlText $url)`">$id</a>"
            } else { '' }
            $null = $sb.Append("<div class=`"sig`"><span class=`"pts`">+$($s.Points)</span>$attack <b>$(ConvertTo-HtmlText $s.Rule)</b>: $(ConvertTo-HtmlText $s.Why)")
            if ($s.Evidence) { $null = $sb.Append("<dl><dt>evidence</dt><dd>$(ConvertTo-HtmlText $s.Evidence)</dd></dl>") }
            $null = $sb.Append('</div>')
        }
        $null = $sb.Append('</div></details>')
    }
    if (-not $Findings) { $null = $sb.Append('<p>No findings at this threshold.</p>') }
    Get-HtmlPage -Title $Title -Body $sb.ToString()
}

function ConvertTo-SusChangeHtml {
    param([object[]]$Changes, [string]$Title = 'SusHunt changes since baseline')
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<div class="counts">')
    foreach ($kind in 'Added', 'Changed', 'Removed') {
        $n = @($Changes | Where-Object { $_.Change -eq $kind }).Count
        $null = $sb.Append("<div class=`"count`"><b class=`"$kind`">$n</b>$kind</div>")
    }
    $null = $sb.Append('</div>')
    foreach ($c in $Changes | Sort-Object Change, Kind, Key) {
        $null = $sb.Append("<details><summary><span class=`"sev $($c.Change)`">$($c.Change)</span><span>$(ConvertTo-HtmlText $c.Kind)</span>")
        $null = $sb.Append("<span class=`"rules`">$(ConvertTo-HtmlText $c.Key)</span></summary><div class=`"body`"><dl>")
        if ($c.Before) { $null = $sb.Append("<dt>before</dt><dd>$(ConvertTo-HtmlText $c.Before)</dd>") }
        if ($c.After) { $null = $sb.Append("<dt>after</dt><dd>$(ConvertTo-HtmlText $c.After)</dd>") }
        $null = $sb.Append('</dl></div></details>')
    }
    if (-not $Changes) { $null = $sb.Append('<p>No changes since the baseline.</p>') }
    Get-HtmlPage -Title $Title -Body $sb.ToString()
}

function Save-SusHtml {
    param([string]$Html, [string]$Path, [switch]$Open)
    $dir = Split-Path $Path -Parent
    if ($dir) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [IO.File]::WriteAllText($Path, $Html, (New-Object Text.UTF8Encoding $false))
    Write-Host "HTML report: $Path" -ForegroundColor Cyan
    if ($Open) { Invoke-Item -LiteralPath $Path }
}
