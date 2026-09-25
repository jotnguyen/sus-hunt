# Network view: who is talking to whom, how to cut them off, and how to spot a timer-driven beacon.

$script:PtrCache = @{}

# First match wins. Everything that matches nothing is 'Public'.
$script:IpScopes = @(
    @{ Cidr = '127.0.0.0/8';    Scope = 'Loopback' }
    @{ Cidr = '::1/128';        Scope = 'Loopback' }
    @{ Cidr = '0.0.0.0/32';     Scope = 'Unspecified' }   # "any address": how listeners on every interface show up
    @{ Cidr = '::/128';         Scope = 'Unspecified' }
    @{ Cidr = '10.0.0.0/8';     Scope = 'Private' }       # RFC 1918
    @{ Cidr = '172.16.0.0/12';  Scope = 'Private' }
    @{ Cidr = '192.168.0.0/16'; Scope = 'Private' }
    @{ Cidr = 'fc00::/7';       Scope = 'Private' }       # IPv6 unique local
    @{ Cidr = '100.64.0.0/10';  Scope = 'CGNAT' }         # RFC 6598 carrier-grade NAT; Tailscale uses it too
    @{ Cidr = '169.254.0.0/16'; Scope = 'LinkLocal' }     # APIPA: no DHCP answer
    @{ Cidr = 'fe80::/10';      Scope = 'LinkLocal' }
    @{ Cidr = '224.0.0.0/4';    Scope = 'Multicast' }
    @{ Cidr = 'ff00::/8';       Scope = 'Multicast' }
)

function Test-IpInCidr {
    # A prefix /n means "the first n bits must match". Compare whole bytes first, then mask
    # the leftover bits of the last partial byte. Same code for IPv4 (4 bytes) and IPv6 (16).
    param([string]$Ip, [string]$Cidr)
    $network, $length = $Cidr.Split('/')
    $a = [Net.IPAddress]::Parse($Ip).GetAddressBytes()
    $n = [Net.IPAddress]::Parse($network).GetAddressBytes()
    if ($a.Length -ne $n.Length) { return $false }
    $bits = [int]$length
    $fullBytes = [int][Math]::Floor($bits / 8)
    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($a[$i] -ne $n[$i]) { return $false }
    }
    $rest = $bits % 8
    if ($rest -eq 0) { return $true }
    $mask = (0xFF -shl (8 - $rest)) -band 0xFF
    ($a[$fullBytes] -band $mask) -eq ($n[$fullBytes] -band $mask)
}

$script:ScopeCache = @{}

function Get-IpScope {
    param([string]$Ip)
    if (-not $Ip) { return 'Invalid' }
    if (-not $script:ScopeCache.ContainsKey($Ip)) { $script:ScopeCache[$Ip] = Get-IpScopeUncached $Ip }
    $script:ScopeCache[$Ip]
}

function Get-IpScopeUncached {
    param([string]$Ip)
    $addr = $null
    if (-not [Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return 'Invalid' }
    # Dual-stack sockets can report IPv4 peers as ::ffff:a.b.c.d. Judge the real IPv4 address.
    if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
    $text = $addr.ToString() -replace '%.*$'
    foreach ($s in $script:IpScopes) {
        if (Test-IpInCidr $text $s.Cidr) { return $s.Scope }
    }
    'Public'
}

function ConvertTo-NetworkOrderPort {
    # Network byte order is big-endian. The x86 CPU is little-endian, so the two bytes swap:
    # port 443 = 0x01BB is stored as BB 01, which a little-endian uint32 reads as 0xBB01.
    param([int]$Port)
    [uint32]((($Port -band 0xFF) -shl 8) -bor (($Port -shr 8) -band 0xFF))
}

function ConvertTo-NetworkOrderAddress {
    # GetAddressBytes() is already big-endian (a.b.c.d in that order). Reading those bytes as a
    # little-endian uint32 gives the value whose memory layout is network order.
    param([string]$Ip)
    [BitConverter]::ToUInt32([Net.IPAddress]::Parse($Ip).GetAddressBytes(), 0)
}

function Format-Endpoint {
    param([string]$Address, $Port)
    if ($null -eq $Port -or -not $Address) { return $Address }
    if ($Address.Contains(':')) { return "[$Address]:$Port" }
    "${Address}:$Port"
}

function Resolve-PtrName {
    # Reverse DNS (PTR record). Privacy note: every lookup tells the DNS server an IP you talk to.
    param([string]$Ip, [string]$Server)
    if ($script:PtrCache.ContainsKey($Ip)) { return $script:PtrCache[$Ip] }
    $query = @{ Name = $Ip; Type = 'PTR'; QuickTimeout = $true; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($Server) { $query.Server = $Server }
    $name = try { (Resolve-DnsName @query | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1).NameHost } catch { $null }
    $script:PtrCache[$Ip] = $name
    $name
}

function New-ConnectionRow {
    param($Protocol, $State, $LocalAddress, $LocalPort, $RemoteAddress, $RemotePort, $OwningProcess, [hashtable]$Snapshot)
    $proc = $Snapshot[[int]$OwningProcess]
    $path = if ($proc) { ConvertTo-NormalPath $proc.ExecutablePath } else { $null }
    $sig = if ($path) { Get-FileSignature $path } else { $null }
    $scope = if ($RemoteAddress) { Get-IpScope $RemoteAddress } else { 'Unspecified' }
    $note = $null
    if ($RemotePort -and $scope -eq 'Public' -and $script:NotablePorts.ContainsKey([int]$RemotePort)) { $note = $script:NotablePorts[[int]$RemotePort] }
    [pscustomobject]@{
        PSTypeName    = 'SusHunt.Connection'
        Protocol      = $Protocol
        State         = $State
        Local         = Format-Endpoint $LocalAddress $LocalPort
        Remote        = Format-Endpoint $RemoteAddress $RemotePort
        Scope         = $scope
        LocalScope    = Get-IpScope $LocalAddress
        PID           = [int]$OwningProcess
        ProcessStart  = if ($proc) { $proc.CreationDate } else { $null }
        Process       = if ($proc) { $proc.Name } else { $null }
        Path          = $path
        Signature     = if ($sig) { $sig.Status } else { 'Unknown' }
        Signer        = if ($sig) { $sig.Signer } else { $null }
        RemoteName    = $null
        Note          = $note
        LocalAddress  = $LocalAddress
        LocalPort     = $LocalPort
        RemoteAddress = $RemoteAddress
        RemotePort    = $RemotePort
    }
}

function Get-SusConnection {
    <#
    .SYNOPSIS
        TCP connections and UDP listeners with the owning program, its signature and the remote scope.
    .EXAMPLE
        Get-SusConnection | Where-Object Scope -eq 'Public' | Format-Table Process, Remote, Signature
    .EXAMPLE
        Get-SusConnection -ResolveDns | Out-GridView -PassThru | Stop-SusConnection -Action BlockRemote
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeLoopback,
        [switch]$ResolveDns,
        [string]$DnsServer,
        [hashtable]$Snapshot
    )
    if (-not $Snapshot) { $Snapshot = Get-ProcessSnapshot }
    $rows = New-Object System.Collections.Generic.List[object]
    $keep = 'Listen', 'Established', 'SynSent', 'SynReceived', 'CloseWait'
    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    $owners = @($tcp; $udp) | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique
    Initialize-SignatureCache @($owners | ForEach-Object { if ($Snapshot[$_]) { $Snapshot[$_].ExecutablePath } })
    foreach ($c in $tcp) {
        if ($keep -notcontains [string]$c.State) { continue }
        $remote = if ([string]$c.State -eq 'Listen') { $null } else { $c.RemoteAddress }
        $rport = if ([string]$c.State -eq 'Listen') { $null } else { $c.RemotePort }
        $rows.Add((New-ConnectionRow 'TCP' ([string]$c.State) $c.LocalAddress $c.LocalPort $remote $rport $c.OwningProcess $Snapshot))
    }
    foreach ($u in $udp) {
        $rows.Add((New-ConnectionRow 'UDP' 'Listen' $u.LocalAddress $u.LocalPort $null $null $u.OwningProcess $Snapshot))
    }
    $result = $rows
    if (-not $IncludeLoopback) { $result = $rows | Where-Object { $_.LocalScope -ne 'Loopback' -and $_.Scope -ne 'Loopback' } }
    if ($ResolveDns) {
        foreach ($r in $result | Where-Object { $_.Scope -eq 'Public' }) { $r.RemoteName = Resolve-PtrName $r.RemoteAddress $DnsServer }
    }
    $result | Sort-Object Scope, Process, Remote
}

function Test-SameProcess {
    # Between listing a connection and acting on it, the process can exit and Windows can hand
    # its PID to something else. Same PID + same start time + same image = same process.
    param($Connection)
    $now = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$Connection.PID)" -ErrorAction SilentlyContinue
    if (-not $now) { return $false }
    if ($Connection.ProcessStart -and $now.CreationDate -ne $Connection.ProcessStart) { return $false }
    if ($Connection.Path -and (ConvertTo-NormalPath $now.ExecutablePath) -ne $Connection.Path) { return $false }
    $true
}

function Test-ConnectionStillOwned {
    param($Connection)
    $live = Get-NetTCPConnection -LocalAddress $Connection.LocalAddress -LocalPort $Connection.LocalPort `
        -RemoteAddress $Connection.RemoteAddress -RemotePort $Connection.RemotePort -ErrorAction SilentlyContinue
    [bool]($live | Where-Object { [int]$_.OwningProcess -eq [int]$Connection.PID })
}

function Stop-SusConnection {
    <#
    .SYNOPSIS
        Response actions for a connection from Get-SusConnection. Asks before acting; supports -WhatIf.
    .DESCRIPTION
        Reset       Send a TCP RST and drop the connection (SetTcpEntry). IPv4 only, needs admin.
                    The program can simply reconnect, so pair it with BlockRemote.
        BlockRemote Add inbound and outbound Windows Firewall block rules for the remote IP (group
                    'SusHunt'). Undo with: Get-NetFirewallRule -Group SusHunt | Remove-NetFirewallRule
        KillProcess Stop the owning process.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]$Connection,
        [ValidateSet('Reset', 'BlockRemote', 'KillProcess')]
        [string]$Action = 'Reset'
    )
    process {
        $c = $Connection
        $label = "$($c.Process) [$($c.PID)] $($c.Local) -> $($c.Remote)"
        switch ($Action) {
            'Reset' {
                if ($c.Protocol -ne 'TCP' -or $c.State -eq 'Listen' -or -not $c.RemoteAddress) { Write-Error "Only established TCP connections can be reset: $label"; return }
                if ($c.RemoteAddress.Contains(':')) { Write-Error "SetTcpEntry is IPv4 only. Use -Action BlockRemote or KillProcess for $label"; return }
                if (-not $PSCmdlet.ShouldProcess($label, 'Reset TCP connection')) { return }
                if (-not (Test-ConnectionStillOwned $c) -or -not (Test-SameProcess $c)) { Write-Error "Connection or process changed since it was listed; not touching it: $label"; return }
                Initialize-SusNative
                $rc = [SusHunt.Native]::ResetTcp(
                    (ConvertTo-NetworkOrderAddress $c.LocalAddress), (ConvertTo-NetworkOrderPort $c.LocalPort),
                    (ConvertTo-NetworkOrderAddress $c.RemoteAddress), (ConvertTo-NetworkOrderPort $c.RemotePort))
                switch ($rc) {
                    0       { Write-Host "Reset: $label" }
                    5       { Write-Error "Access denied. Run PowerShell as Administrator. ($label)" }
                    317     { Write-Error "Windows refused (usually: not elevated, or the connection already closed). ($label)" }
                    default { Write-Error "SetTcpEntry returned $rc for $label" }
                }
            }
            'BlockRemote' {
                if (-not $c.RemoteAddress) { Write-Error "No remote address to block: $label"; return }
                if (-not $PSCmdlet.ShouldProcess($c.RemoteAddress, 'Add firewall block rules (in + out)')) { return }
                foreach ($dir in 'Outbound', 'Inbound') {
                    New-NetFirewallRule -DisplayName "SusHunt block $($c.RemoteAddress) ($dir)" -Group 'SusHunt' `
                        -Direction $dir -Action Block -RemoteAddress $c.RemoteAddress -ErrorAction Stop | Out-Null
                }
                Write-Host "Blocked $($c.RemoteAddress). Undo: Get-NetFirewallRule -Group SusHunt | Remove-NetFirewallRule"
            }
            'KillProcess' {
                if (-not $PSCmdlet.ShouldProcess("$($c.Process) [$($c.PID)]", 'Stop process')) { return }
                if (-not (Test-SameProcess $c)) { Write-Error "PID $($c.PID) now belongs to a different process (or it exited); not killing it."; return }
                Stop-Process -Id $c.PID -Force -ErrorAction Stop
                Write-Host "Stopped $($c.Process) [$($c.PID)]"
            }
        }
    }
}

function Test-Beacon {
    # Implants "phone home" on a timer (with some jitter). People and most apps are bursty.
    # Coefficient of variation = stddev / mean of the gaps between connections: near 0 means
    # clockwork, around 1 means random. Returns $null when the pattern does not look periodic.
    param([double[]]$Times, [int]$MinEvents = 6, [double]$MaxCv = 0.2, [double]$MinIntervalSeconds = 4)
    if ($Times.Count -lt $MinEvents) { return $null }
    $t = @($Times | Sort-Object | Select-Object -Last 20)
    $gaps = for ($i = 1; $i -lt $t.Count; $i++) { $t[$i] - $t[$i - 1] }
    $mean = ($gaps | Measure-Object -Average).Average
    if ($mean -lt $MinIntervalSeconds) { return $null }
    $variance = ($gaps | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Average).Average
    $cv = [Math]::Sqrt($variance) / $mean
    if ($cv -gt $MaxCv) { return $null }
    [pscustomobject]@{ Events = $t.Count; MeanSeconds = [Math]::Round($mean, 1); Cv = [Math]::Round($cv, 3) }
}
