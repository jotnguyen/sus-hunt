# gui command: a WPF window over the exported scan functions. A thin shell on purpose: no rule
# logic lives here, so the window and the CLI can never disagree. Everything shown comes from
# the examined machine and is attacker-controlled: it is only ever set as Text on WPF controls
# (shown as text), never built into XAML, never run. Scans run in their own runspace, because a
# 60 s scan on the UI thread would freeze the window.

# Which options each scan uses, its default minimum score and its HTML report title.
$script:GuiScans = [ordered]@{
    Triage      = @{ Options = @('MinScore'); MinScore = 20; Report = 'SusHunt triage'
                     Help = 'Running processes and autostart entries, scored.' }
    Files       = @{ Options = @('MinScore', 'Days', 'Path'); MinScore = 15; Report = 'SusHunt files'
                     Help = 'Recent programs, scripts and shortcuts in user-writable folders.' }
    Autoruns    = @{ Options = @(); MinScore = 0; Report = 'SusHunt autoruns'
                     Help = 'Every autostart entry, scored or not.' }
    Connections = @{ Options = @(); MinScore = 0; Report = $null
                     Help = 'Who is talking to whom. No DNS lookups.' }
    Baseline    = @{ Options = @(); MinScore = 0; Report = $null
                     Help = 'Save a snapshot of autoruns, listeners and programs to compare against later.' }
    Diff        = @{ Options = @(); MinScore = 0; Report = 'SusHunt changes since baseline'
                     Help = 'What changed since the newest baseline.' }
}

# Runs inside the scan runspace. It only calls exported module functions, with the same
# arguments the CLI uses.
$script:GuiScanScript = @'
param($ModulePath, $Scan, $Opt)
Import-Module $ModulePath -Force
switch ($Scan) {
    'Triage'      { Invoke-SusTriage -MinScore $Opt.MinScore }
    'Files'       { Get-SusFileFinding -Days $Opt.Days -Path $Opt.Path -MinScore $Opt.MinScore }
    'Autoruns'    { Get-SusPersistenceFinding -All }
    'Connections' { Get-SusConnection }
    'Baseline'    { Save-SusBaseline }
    'Diff'        { Compare-SusBaseline }
}
'@

function Get-SusScanOption {
    # Scan name -> the option controls to show, the default min score and the report title.
    param([Parameter(Mandatory)][string]$Scan)
    $s = $script:GuiScans[$Scan]
    if (-not $s) { throw "Unknown scan: $Scan" }
    [pscustomobject]@{ Scan = $Scan; Options = @($s.Options); MinScore = $s.MinScore; Report = $s.Report; Help = $s.Help }
}

function ConvertTo-SusGridRow {
    # One scan result (Finding, Change, Connection or a plain string) -> a flat row for the grid.
    # The original object rides along in Item for the detail pane and the row actions.
    param([Parameter(Mandatory)]$Item)
    $types = $Item.PSObject.TypeNames
    if ($types -contains 'SusHunt.Finding') {
        return [pscustomobject]@{ Kind = 'Finding'; Score = $Item.Score; Severity = $Item.Severity; Category = $Item.Category
            Name = $Item.Name; Path = $Item.Path; Summary = $Item.Summary; Item = $Item }
    }
    if ($types -contains 'SusHunt.Change') {
        return [pscustomobject]@{ Kind = 'Change'; Score = $null; Severity = $Item.Change; Category = $Item.Kind
            Name = $Item.Key; Path = $null; Summary = $(if ($Item.After) { $Item.After } else { $Item.Before }); Item = $Item }
    }
    if ($types -contains 'SusHunt.Connection') {
        $summary = ('{0} {1} -> {2} ({3}, {4})' -f $Item.Protocol, $Item.Local, $Item.Remote, $Item.Scope, $Item.Signature)
        if ($Item.Note) { $summary += " $($Item.Note)" }
        return [pscustomobject]@{ Kind = 'Connection'; Score = $null; Severity = $null; Category = "$($Item.Protocol) $($Item.State)".Trim()
            Name = $(if ($Item.Process) { "$($Item.Process) ($($Item.PID))" } else { "PID $($Item.PID)" }); Path = $Item.Path
            Summary = $summary; Item = $Item }
    }
    [pscustomobject]@{ Kind = 'Text'; Score = $null; Severity = $null; Category = 'Output'; Name = [string]$Item
        Path = $null; Summary = $null; Item = $Item }
}

function Test-SusRowFilter {
    # True when the row should be shown: its text matches (Name, Path or Summary, any case) and,
    # for scored rows, its severity is ticked. Other rows (diff, connections) ignore the ticks.
    param([Parameter(Mandatory)]$Row, [string]$Text, [string[]]$Severities)
    if (@('High', 'Medium', 'Low', 'Info') -contains $Row.Severity -and @($Severities) -notcontains $Row.Severity) { return $false }
    if (-not $Text -or -not $Text.Trim()) { return $true }
    $needle = $Text.Trim()
    foreach ($field in $Row.Name, $Row.Path, $Row.Summary) {
        if ($field -and ([string]$field).IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    $false
}

function Add-SusAllowlistEntry {
    # Appends one exact path to the allowlist. Wildcard characters in the path are escaped, since
    # the allowlist is read with -like. Returns $true if it added a line, $false for a duplicate.
    param([Parameter(Mandatory)][string]$Path, [string]$File)
    if (-not $File) { $File = Join-Path (Split-Path $PSScriptRoot -Parent) 'allowlist.txt' }
    $entry = [Management.Automation.WildcardPattern]::Escape($Path.Trim())
    if (Test-Path -LiteralPath $File) {
        foreach ($line in Get-Content -LiteralPath $File) {
            if ($line.Trim() -eq $entry) { return $false }   # -eq ignores case, like Windows paths
        }
        $text = [IO.File]::ReadAllText($File)
        if ($text.Length -and -not $text.EndsWith("`n")) { $entry = [Environment]::NewLine + $entry }
    }
    [IO.File]::AppendAllText($File, $entry + [Environment]::NewLine, (New-Object Text.UTF8Encoding $false))
    $true
}

function Get-SusDetailLine {
    # The detail pane for one row: the same fields and signals as the HTML report, as lines of
    # { Label; Text; Link; Url }. Kept free of WPF so it can be tested.
    param([Parameter(Mandatory)]$Row)
    $f = $Row.Item
    $line = { param($Label, $Text, $Link, $Url) [pscustomobject]@{ Label = $Label; Text = $Text; Link = $Link; Url = $Url } }
    switch ($Row.Kind) {
        'Finding' {
            & $line '' ('[{0} {1}] {2}: {3} {4}' -f $f.Score, $f.Severity, $f.Category, $f.Name, $f.Id).TrimEnd()
            foreach ($field in 'Path', 'Context', 'CommandLine') {
                if ($f.$field) { & $line $field $f.$field }
            }
            foreach ($s in $f.Signals | Sort-Object Points -Descending) {
                & $line "+$($s.Points)" "$($s.Rule): $($s.Why)" $s.Attack (Get-AttackUrl $s.Attack)
                if ($s.Evidence) { & $line '  evidence' $s.Evidence }
            }
        }
        'Change' {
            & $line '' "$($f.Change) $($f.Kind): $($f.Key)"
            if ($f.Before) { & $line 'before' $f.Before }
            if ($f.After) { & $line 'after' $f.After }
        }
        'Connection' {
            foreach ($field in 'Protocol', 'State', 'Local', 'Remote', 'Scope', 'PID', 'Process', 'Path', 'Signature', 'Signer', 'Note') {
                if ($null -ne $f.$field -and "$($f.$field)" -ne '') { & $line $field $f.$field }
            }
        }
        default { & $line '' ([string]$f) }
    }
}

function Get-SusGuiPalette {
    # Colours for the window, matching the HTML report (lib\Report.ps1) in light and dark.
    param([bool]$Dark)
    if ($Dark) {
        @{ Bg = '#161618'; Fg = '#ececef'; Muted = '#9a9aa2'; Line = '#2c2c30'; Panel = '#1e1e21'
           High = '#ff6b6b'; Medium = '#ffb454'; Low = '#d4d46a'; Info = '#9a9aa2'; Added = '#7ad483'; Removed = '#d59be3' }
    } else {
        @{ Bg = '#fbfbfa'; Fg = '#1d1d1f'; Muted = '#6b6b70'; Line = '#e3e3e0'; Panel = '#ffffff'
           High = '#c62828'; Medium = '#ad5a00'; Low = '#6d6d00'; Info = '#6b6b70'; Added = '#2e7d32'; Removed = '#8e24aa' }
    }
}

function Test-WindowsDarkMode {
    # Apps follow the "Choose your app mode" setting: AppsUseLightTheme = 0 means dark.
    $v = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction SilentlyContinue
    [bool]($v -and $v.AppsUseLightTheme -eq 0)
}

function Show-SusGui {
    <#
    .SYNOPSIS
        Opens a window to pick a scan, run it, and sort, filter and click into the results.
    .DESCRIPTION
        Needs an STA thread (Windows PowerShell 5.1 is STA by default). Row actions are read-only
        or local: copy the SHA-256, show the file in Explorer (never opens it), add the path to
        allowlist.txt, save an HTML report. It never elevates and has no kill or block actions.
    #>
    [CmdletBinding()]
    param()
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The GUI needs an STA thread. Start it with: powershell -STA -NoProfile -File sus-hunt.ps1 gui'
    }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    $root = Split-Path $PSScriptRoot -Parent
    [xml]$xaml = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Gui.xaml') -Raw
    $window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
    $ui = @{}
    foreach ($n in 'AdminBadge', 'ScanHelp', 'OptMinScore', 'OptDays', 'OptPath', 'MinScoreBox', 'DaysBox', 'PathBox',
                   'BrowseButton', 'RunButton', 'CancelButton', 'StatusText', 'FilterBox', 'SevHigh', 'SevMedium', 'SevLow',
                   'SevInfo', 'CountText', 'Grid', 'DetailText', 'CopyHashButton', 'OpenFolderButton', 'AllowButton', 'SaveHtmlButton') {
        $ui[$n] = $window.FindName($n)
    }
    $scanButtons = @{}
    foreach ($name in $script:GuiScans.Keys) { $scanButtons[$name] = $window.FindName("Scan$name") }

    $palette = Get-SusGuiPalette (Test-WindowsDarkMode)
    $brushes = New-Object Windows.Media.BrushConverter
    foreach ($k in $palette.Keys) {
        $window.Resources["${k}Brush"] = $brushes.ConvertFromString($palette[$k])
    }

    if (Test-IsAdmin) {
        $ui.AdminBadge.Text = 'admin: yes (full coverage)'
    } else {
        $ui.AdminBadge.Text = 'admin: no. SYSTEM command lines are hidden. For full coverage, relaunch with "Run as administrator".'
        $ui.AdminBadge.Foreground = $window.Resources['MediumBrush']
    }

    # Mutable state lives in one hashtable: event handlers run in child scopes, so assigning a
    # plain variable there would only create a local copy.
    $state = @{ Scan = 'Triage'; LastScan = $null; Results = (New-Object System.Collections.Generic.List[object]); Job = $null
                Stopping = (New-Object System.Collections.Generic.List[object])
                FilterText = ''; Severities = @() }
    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $ui.Grid.ItemsSource = $rows
    $view = [Windows.Data.CollectionViewSource]::GetDefaultView($rows)

    $selectedSeverities = {
        $sev = @()
        foreach ($n in 'High', 'Medium', 'Low', 'Info') { if ($ui["Sev$n"].IsChecked) { $sev += $n } }
        $sev
    }
    $updateCount = { $ui.CountText.Text = '{0} of {1} shown' -f @($view).Count, $rows.Count }
    # The predicate reads $state when WPF calls it, so changing the filter is just a Refresh.
    $view.Filter = [Predicate[object]] { param($row) Test-SusRowFilter -Row $row -Text $state.FilterText -Severities $state.Severities }
    $applyFilter = {
        $state.FilterText = $ui.FilterBox.Text
        $state.Severities = @(& $selectedSeverities)
        $view.Refresh()
        & $updateCount
    }
    & $applyFilter
    $ui.FilterBox.add_TextChanged({ & $applyFilter })
    foreach ($n in 'High', 'Medium', 'Low', 'Info') {
        $ui["Sev$n"].add_Checked({ & $applyFilter })
        $ui["Sev$n"].add_Unchecked({ & $applyFilter })
    }

    $selectScan = {
        param([string]$Name)
        $state.Scan = $Name
        $opt = Get-SusScanOption $Name
        $ui.ScanHelp.Text = $opt.Help
        foreach ($o in 'MinScore', 'Days', 'Path') {
            $ui["Opt$o"].Visibility = if ($opt.Options -contains $o) { 'Visible' } else { 'Collapsed' }
        }
        $ui.MinScoreBox.Text = [string]$opt.MinScore
        if ($Name -eq 'Autoruns') { $ui.SevInfo.IsChecked = $true }   # an inventory: most entries score 0
    }
    & $selectScan 'Triage'
    foreach ($name in $script:GuiScans.Keys) {
        $scanButtons[$name].Tag = $name
        $scanButtons[$name].add_Checked({ & $selectScan $this.Tag })
    }
    $ui.BrowseButton.add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Extra folder for the Files scan'
        if ($dlg.ShowDialog() -eq 'OK') { $ui.PathBox.Text = $dlg.SelectedPath }
        $dlg.Dispose()
    })

    # Detail pane: built from Runs and Hyperlinks, which show text as text.
    $showDetail = {
        $row = $ui.Grid.SelectedItem
        $ui.DetailText.Inlines.Clear()
        $isFinding = $row -and $row.Kind -eq 'Finding'
        $hasFile = $row -and $row.Path -and (Test-Path -LiteralPath $row.Path -PathType Leaf)
        $ui.CopyHashButton.IsEnabled = [bool]$hasFile
        $ui.OpenFolderButton.IsEnabled = [bool]($row -and $row.Path)
        $ui.AllowButton.IsEnabled = [bool]($isFinding -and $row.Path)
        if (-not $row) { return }
        $first = $true
        foreach ($l in Get-SusDetailLine $row) {
            if (-not $first) { $ui.DetailText.Inlines.Add((New-Object Windows.Documents.LineBreak)) }
            $first = $false
            if ($l.Label) {
                $label = New-Object Windows.Documents.Run ("{0,-12} " -f $l.Label)
                $label.Foreground = $window.Resources['MutedBrush']
                $ui.DetailText.Inlines.Add($label)
            }
            if ($l.Url) {
                $link = New-Object Windows.Documents.Hyperlink (New-Object Windows.Documents.Run $l.Link)
                $link.NavigateUri = [Uri]$l.Url
                $link.ToolTip = $l.Url
                $link.add_RequestNavigate({
                    # Only ever opens attack.mitre.org, in the user's browser, on the user's click.
                    if ($_.Uri.Host -eq 'attack.mitre.org' -and $_.Uri.Scheme -eq 'https') { Start-Process $_.Uri.AbsoluteUri }
                })
                $ui.DetailText.Inlines.Add($link)
                $ui.DetailText.Inlines.Add((New-Object Windows.Documents.Run ' '))
            }
            $run = New-Object Windows.Documents.Run ([string]$l.Text)
            if (-not $l.Label) { $run.FontWeight = 'SemiBold' }
            $ui.DetailText.Inlines.Add($run)
        }
    }
    $ui.Grid.add_SelectionChanged({ & $showDetail })

    $ui.CopyHashButton.add_Click({
        $row = $ui.Grid.SelectedItem
        if (-not $row) { return }
        # File findings already carry the hash as their Id; for anything else, hash the bytes.
        $sha = if ($row.Kind -eq 'Finding' -and $row.Item.Category -eq 'File' -and $row.Item.Id -match '^[0-9A-F]{64}$') { $row.Item.Id }
               else { (Get-FileHash -LiteralPath $row.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash }
        if ($sha) { [Windows.Clipboard]::SetText($sha); $ui.StatusText.Text = "Copied SHA-256 $sha" }
        else { $ui.StatusText.Text = 'Could not read the file to hash it.' }
    })
    $ui.OpenFolderButton.add_Click({
        $row = $ui.Grid.SelectedItem
        if (-not $row -or -not $row.Path) { return }
        # /select only highlights the item in its folder; Explorer never opens or runs it.
        if (Test-Path -LiteralPath $row.Path) { Start-Process explorer.exe -ArgumentList "/select,`"$($row.Path)`"" }
        else {
            $dir = Split-Path $row.Path -Parent
            if ($dir -and (Test-Path -LiteralPath $dir -PathType Container)) { Start-Process explorer.exe -ArgumentList "`"$dir`"" }
            else { $ui.StatusText.Text = 'The path no longer exists.' }
        }
    })
    $ui.AllowButton.add_Click({
        $row = $ui.Grid.SelectedItem
        if (-not $row -or -not $row.Path) { return }
        $msg = "Hide this exact path from future scans?`n`n$($row.Path)`n`nIt is added to allowlist.txt. Every line there is a place you have decided not to look."
        if ([Windows.MessageBox]::Show($window, $msg, 'Add to allowlist', 'YesNo', 'Question') -ne 'Yes') { return }
        if (Add-SusAllowlistEntry -Path $row.Path) { $ui.StatusText.Text = 'Added to allowlist.txt. Rescan to apply.' }
        else { $ui.StatusText.Text = 'Already in allowlist.txt.' }
        $null = $rows.Remove($row)
        & $updateCount
    })
    $ui.SaveHtmlButton.add_Click({
        $opt = Get-SusScanOption $state.LastScan
        if (-not $opt.Report) { return }
        $items = @($state.Results | Where-Object { $_ -isnot [string] })
        $html = if ($state.LastScan -eq 'Diff') { ConvertTo-SusChangeHtml $items $opt.Report }
                else { ConvertTo-SusFindingHtml @($items | Sort-Object Score -Descending) $opt.Report }
        $file = Join-Path (Join-Path $root 'reports') ('{0}_{1}.html' -f $state.LastScan.ToLowerInvariant(), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Save-SusHtml $html $file
        $ui.StatusText.Text = "Saved $file"
        if ([Windows.MessageBox]::Show($window, "Saved:`n$file`n`nOpen it in your browser?", 'HTML report', 'YesNo', 'Information') -eq 'Yes') {
            Invoke-Item -LiteralPath $file
        }
    })

    # Scan runner: one runspace per scan, polled from a DispatcherTimer on the UI thread.
    $setRunning = {
        param([bool]$Running)
        $ui.RunButton.IsEnabled = -not $Running
        $ui.CancelButton.IsEnabled = $Running
        foreach ($b in $scanButtons.Values) { $b.IsEnabled = -not $Running }
    }
    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.add_Tick({
        # Cancelled scans are detached at once and disposed here when their runspace has stopped.
        foreach ($old in $state.Stopping.ToArray()) {   # not @(): 5.1 throws "Argument types do not match" on this List
            if ($old.Handle.IsCompleted) {
                try { $null = $old.PS.EndInvoke($old.Handle) } catch { Write-Verbose "cancelled scan ended: $_" }
                $old.PS.Dispose(); $old.Runspace.Dispose()
                $null = $state.Stopping.Remove($old)
            }
        }
        $job = $state.Job
        if (-not $job) {
            if (-not $state.Stopping.Count) { $timer.Stop() }
            return
        }
        $done = $job.Handle.IsCompleted   # read before draining, so no late output is missed
        while ($job.Taken -lt $job.Output.Count) {
            $item = $job.Output[$job.Taken]
            $job.Taken++
            $state.Results.Add($item)
            $rows.Add((ConvertTo-SusGridRow $item))
        }
        & $updateCount
        $elapsed = '{0:mm\:ss}' -f $job.Clock.Elapsed
        if (-not $done) {
            $p = $job.PS.Streams.Progress
            $what = if ($p.Count) { $p[$p.Count - 1].StatusDescription } else { 'working' }
            $ui.StatusText.Text = "$($job.Scan): $what ... $elapsed"
            return
        }
        $failed = $null
        try { $null = $job.PS.EndInvoke($job.Handle) } catch { $failed = $_.Exception.InnerException; if (-not $failed) { $failed = $_.Exception } }
        $errors = @($job.PS.Streams.Error)
        $job.PS.Dispose(); $job.Runspace.Dispose()
        $state.Job = $null
        & $setRunning $false
        if ($failed) { $ui.StatusText.Text = "$($job.Scan) failed: $($failed.Message)" }
        elseif ($errors.Count) { $ui.StatusText.Text = "$($job.Scan) finished in $elapsed with an error: $($errors[0])" }
        else { $ui.StatusText.Text = "$($job.Scan) finished in $elapsed. $($rows.Count) result(s)." }
        $ui.SaveHtmlButton.IsEnabled = [bool](Get-SusScanOption $job.Scan).Report
    })

    $ui.RunButton.add_Click({
        if ($state.Job) { return }   # one scan at a time
        $scan = $state.Scan
        $opt = Get-SusScanOption $scan
        $scanOpt = @{ MinScore = $opt.MinScore; Days = 7; Path = $null }
        $n = 0
        if ([int]::TryParse($ui.MinScoreBox.Text, [ref]$n) -and $n -ge 0) { $scanOpt.MinScore = $n }
        if ([int]::TryParse($ui.DaysBox.Text, [ref]$n) -and $n -gt 0) { $scanOpt.Days = $n }
        if ($ui.PathBox.Text.Trim()) { $scanOpt.Path = @($ui.PathBox.Text.Trim()) }

        $rows.Clear(); $state.Results.Clear(); $state.LastScan = $scan
        $ui.DetailText.Inlines.Clear()
        $ui.SaveHtmlButton.IsEnabled = $false
        $rs = [runspacefactory]::CreateRunspace()
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        $null = $ps.AddScript($script:GuiScanScript).AddArgument((Join-Path $root 'SusHunt.psm1')).AddArgument($scan).AddArgument($scanOpt)
        $output = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $noInput = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $noInput.Complete()
        $state.Job = @{ Scan = $scan; PS = $ps; Runspace = $rs; Output = $output; Taken = 0
                        Clock = [Diagnostics.Stopwatch]::StartNew(); Handle = $ps.BeginInvoke($noInput, $output) }
        & $setRunning $true
        $ui.StatusText.Text = "$scan`: starting..."
        $timer.Start()
    })
    $ui.CancelButton.add_Click({
        $job = $state.Job
        if (-not $job) { return }
        # Stop() only takes effect between pipeline steps, and a C# folder walk can take many
        # seconds to reach one. So detach the scan now and let the timer dispose it later.
        $null = $job.PS.BeginStop($null, $null)
        $state.Job = $null
        $state.Stopping.Add($job)
        & $setRunning $false
        $ui.StatusText.Text = "$($job.Scan) cancelled after {0:mm\:ss}. $($rows.Count) result(s) so far." -f $job.Clock.Elapsed
    })
    $window.add_Closing({
        $timer.Stop()
        $all = @($state.Stopping.ToArray())
        if ($state.Job) { $all += $state.Job }
        foreach ($job in $all) { $null = $job.PS.BeginStop($null, $null) }   # the process exits with the window
    })

    $null = $window.ShowDialog()
}
