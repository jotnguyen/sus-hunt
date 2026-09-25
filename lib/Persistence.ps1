# Autostart locations ("autoruns"). Malware that cannot survive a reboot is a one-time problem;
# persistence is what makes it a permanent one. These are the classic spots. All are readable
# as a normal user, though a few details (some service keys) need Administrator.

function Get-RunKeyFindings {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $entries = foreach ($key in $keys) {
        $item = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($valueName in $item.GetValueNames()) {
            $cmd = [string]$item.GetValue($valueName)
            if (-not $cmd) { continue }
            $label = if ($valueName) { $valueName } else { '(default)' }
            [pscustomobject]@{ Key = $key; Name = $label; Cmd = $cmd; Exe = Get-ExecutableFromCommand $cmd }
        }
    }
    Initialize-SignatureCache @($entries | ForEach-Object { $_.Exe })
    foreach ($e in $entries) {
        New-Finding -Category 'RunKey' -Name $e.Name -Id ($e.Key -replace '^.*\\CurrentVersion\\', '') -Path $e.Exe `
            -CommandLine $e.Cmd -Context $e.Key -Signals @(Get-LaunchSignals $e.Cmd $e.Exe)
    }
}

function Get-StartupFolderFindings {
    $shell = New-Object -ComObject WScript.Shell
    foreach ($folder in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $signals = @()
            if ($f.Extension -eq '.lnk') {
                $lnk = $shell.CreateShortcut($f.FullName)
                $exe = ConvertTo-NormalPath $lnk.TargetPath
                $cmd = if ($exe) { ('"{0}" {1}' -f $exe, $lnk.Arguments).Trim() } else { $null }
            } else {
                $exe = $f.FullName
                $cmd = $f.FullName
                if ($f.Extension -match '^\.(bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1)$') {
                    $signals += New-Signal 'ScriptInStartup' 20 'T1547.001' 'A script placed straight in the Startup folder. Apps normally put a shortcut here, not code.' $f.FullName
                }
            }
            $signals += @(Get-LaunchSignals $cmd $exe)
            New-Finding -Category 'Startup' -Name $f.Name -Id 'StartupFolder' -Path $exe -CommandLine $cmd -Context $folder -Signals $signals
        }
    }
}

function Get-TaskFindings {
    $entries = foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($action in $task.Actions) {
            if (-not $action.Execute) { continue }   # COM-handler actions have no program to inspect
            $cmd = ('"{0}" {1}' -f $action.Execute.Trim('"'), $action.Arguments).Trim()
            [pscustomobject]@{ Task = $task; Cmd = $cmd; Exe = Get-ExecutableFromCommand $cmd }
        }
    }
    Initialize-SignatureCache @($entries | ForEach-Object { $_.Exe })
    foreach ($e in $entries) {
        $task = $e.Task
        $signals = @(Get-LaunchSignals $e.Cmd $e.Exe)
        if ($task.TaskPath -like '\Microsoft\*' -and $e.Exe -and (Get-PathRisk $e.Exe) -ne 'Windows' -and -not (Test-MicrosoftSigned $e.Exe)) {
            $signals += New-Signal 'MasqueradedTask' 30 'T1036.004' 'Filed under \Microsoft\ in Task Scheduler but runs a non-Microsoft program. Attackers hide tasks there.' $e.Exe
        }
        New-Finding -Category 'Task' -Name $task.TaskName -Id ([string]$task.State) -Path $e.Exe -CommandLine $e.Cmd `
            -Context "$($task.TaskPath)$($task.TaskName)" -Signals $signals
    }
}

function Get-ServiceFindings {
    $entries = foreach ($svc in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if (-not $svc.PathName) { continue }
        $exe = Get-ExecutableFromCommand $svc.PathName
        $dll = $null
        # Shared svchost services keep their real code in a DLL named in the registry (T1543.003).
        # Plain .NET registry access: the PowerShell registry provider is ~50x slower here.
        # A few service keys are locked to SYSTEM; opening those throws rather than returning null.
        if ($exe -and (Split-Path $exe -Leaf) -eq 'svchost.exe') {
            $dll = try {
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters")
                if ($key) { ConvertTo-NormalPath ([string]$key.GetValue('ServiceDll')); $key.Close() }
            } catch { $null }
        }
        [pscustomobject]@{ Service = $svc; Exe = $exe; Dll = $dll }
    }
    Initialize-SignatureCache @($entries | ForEach-Object { $_.Exe; $_.Dll })
    foreach ($e in $entries) {
        $svc = $e.Service
        $signals = @(Get-LaunchSignals $svc.PathName $e.Exe)
        if (Test-UnquotedServicePath $svc.PathName) {
            $signals += New-Signal 'UnquotedServicePath' 15 'T1574.009' 'Path has spaces and no quotes, so Windows tries C:\Program.exe and friends first. Exploitable if one of those folders is writable.' $svc.PathName
        }
        if ($e.Dll) {
            foreach ($s in @(Get-LaunchSignals -CommandLine $null -Executable $e.Dll)) {
                $signals += New-Signal "ServiceDll:$($s.Rule)" $s.Points 'T1543.003' "The service DLL: $($s.Why)" $s.Evidence
            }
        }
        New-Finding -Category 'Service' -Name $svc.Name -Id "$($svc.StartMode)/$($svc.State)" -Path $e.Exe `
            -CommandLine $svc.PathName -Context $svc.DisplayName -Signals $signals
    }
}

function Get-HijackFindings {
    # Image File Execution Options: a "Debugger" value makes Windows launch that program instead
    # of the one requested. Meant for debugging; abused to hijack or block programs (T1546.012).
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($k in Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue) {
        $debugger = $k.GetValue('Debugger')
        if (-not $debugger) { continue }
        $exe = Get-ExecutableFromCommand $debugger
        $signals = @(New-Signal 'IfeoDebugger' 40 'T1546.012' "Launching $($k.PSChildName) runs this program instead. Some tools do this on purpose (Process Explorer replacing Task Manager)." $debugger)
        $signals += @(Get-LaunchSignals $debugger $exe)
        New-Finding -Category 'Hijack' -Name $k.PSChildName -Id 'IFEO Debugger' -Path $exe -CommandLine $debugger -Context $k.Name -Signals $signals
    }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    foreach ($k in Get-ChildItem -LiteralPath $spe -ErrorAction SilentlyContinue) {
        $monitor = $k.GetValue('MonitorProcess')
        if (-not $monitor) { continue }
        $signals = @(New-Signal 'SilentExitMonitor' 40 'T1546.012' "Runs this program whenever $($k.PSChildName) exits." $monitor)
        $signals += @(Get-LaunchSignals $monitor $null)
        New-Finding -Category 'Hijack' -Name $k.PSChildName -Id 'SilentProcessExit' -Path (Get-ExecutableFromCommand $monitor) -CommandLine $monitor -Context $k.Name -Signals $signals
    }

    # Winlogon starts the shell and userinit at every logon (T1547.004).
    $wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wl = Get-ItemProperty -LiteralPath $wlKey -ErrorAction SilentlyContinue
    $signals = @()
    if ($wl.Shell -and $wl.Shell.Trim() -notmatch '(?i)^"?([a-z]:\\windows\\)?explorer\.exe"?$') {
        $signals += New-Signal 'WinlogonShell' 60 'T1547.004' 'The logon shell should be explorer.exe.' $wl.Shell
    }
    if ($wl.Userinit -and $wl.Userinit.Trim() -notmatch '(?i)^[a-z]:\\windows\\system32\\userinit\.exe,?$') {
        $signals += New-Signal 'WinlogonUserinit' 60 'T1547.004' 'Userinit should only run userinit.exe; extra entries after the comma run at every logon.' $wl.Userinit
    }
    $userShell = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).Shell
    if ($userShell) {
        $signals += New-Signal 'WinlogonUserShell' 60 'T1547.004' 'A per-user shell override. Kiosk setups use it; so does malware.' $userShell
    }
    New-Finding -Category 'Hijack' -Name 'Winlogon' -Id 'Shell/Userinit' -Path $null -CommandLine "Shell=$($wl.Shell) Userinit=$($wl.Userinit)" -Context $wlKey -Signals $signals

    # AppInit_DLLs: DLLs loaded into every process that loads user32.dll (T1546.010).
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $w = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($w.AppInit_DLLs -and $w.LoadAppInit_DLLs -eq 1) {
            $s = New-Signal 'AppInitDlls' 50 'T1546.010' 'These DLLs are injected into nearly every GUI process.' $w.AppInit_DLLs
            New-Finding -Category 'Hijack' -Name 'AppInit_DLLs' -Id 'AppInit' -Path $null -CommandLine $w.AppInit_DLLs -Context $key -Signals @($s)
        }
    }
}

function Get-WmiSubscriptionFindings {
    # A WMI event filter + consumer + binding runs code when something happens (a logon, a
    # timer), with no file in any Run key or task. Favoured by fileless malware (T1546.003).
    try {
        $bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)
    } catch {
        Write-Verbose "WMI subscriptions not readable without Administrator: $($_.Exception.Message)"
        return
    }
    foreach ($b in $bindings) {
        $class = $b.Consumer.CimSystemProperties.ClassName
        $name = $b.Consumer.Name
        $consumer = Get-CimInstance -Namespace root\subscription -ClassName $class -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $name } | Select-Object -First 1
        $filter = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $b.Filter.Name } | Select-Object -First 1
        $signals = @()
        $payload = $null
        switch ($class) {
            'CommandLineEventConsumer' {
                $payload = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate } else { $consumer.ExecutablePath }
                $signals += New-Signal 'WmiCommandConsumer' 50 'T1546.003' 'A WMI subscription that runs a command line.' $payload
                $signals += @(Get-LaunchSignals $payload $null)
            }
            'ActiveScriptEventConsumer' {
                $payload = $consumer.ScriptText
                $signals += New-Signal 'WmiScriptConsumer' 50 'T1546.003' 'A WMI subscription that runs VBScript or JScript.' (Limit-Text $payload 200)
                $signals += @(Get-CommandLineSignals $payload)
            }
        }
        New-Finding -Category 'WMI' -Name $name -Id $class -Path $null -CommandLine $payload `
            -Context "filter: $($filter.Query)" -Signals $signals
    }
}

function Get-SusPersistenceFinding {
    <#
    .SYNOPSIS
        Scores autostart entries: Run keys, Startup folders, scheduled tasks, services, IFEO,
        Winlogon, AppInit_DLLs and WMI subscriptions.
    .PARAMETER All
        Return every entry, even those with no signals, as an autoruns inventory.
    #>
    [CmdletBinding()]
    param([switch]$All)
    $sources = [ordered]@{
        'Run keys'          = { Get-RunKeyFindings }
        'Startup folders'   = { Get-StartupFolderFindings }
        'Scheduled tasks'   = { Get-TaskFindings }
        'Services'          = { Get-ServiceFindings }
        'Hijack points'     = { Get-HijackFindings }
        'WMI subscriptions' = { Get-WmiSubscriptionFindings }
    }
    $i = 0
    foreach ($label in $sources.Keys) {
        Write-Progress -Activity 'SusHunt: autoruns' -Status $label -PercentComplete (100 * $i / $sources.Count)
        $i++
        foreach ($f in & $sources[$label]) {
            if ($All -or $f.Signals.Count) { $f }
        }
    }
    Write-Progress -Activity 'SusHunt: autoruns' -Completed
}
