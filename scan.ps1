#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated Windows System Health & Security Check
.DESCRIPTION
    Collects system resources, network, storage, firewall, users, and selected event logs.
.PARAMETER Status
    What to collect: All | Quick | Network | Security | Storage
.PARAMETER UserName
    Prefix used in export filenames
.PARAMETER OutputPath
    Folder where JSON reports will be saved (default: current directory)
.PARAMETER EventCount
    Maximum number of recent events to collect per log (default: 200)
.PARAMETER Export
    Switch to export results to JSON files
.EXAMPLE
    .\SysCheck.ps1 -Status All -UserName "John" -Export
.EXAMPLE
    .\SysCheck.ps1 -Status Network -UserName "Admin"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Quick", "Network", "Security", "Storage")]
    [string]$Status = "All",

    [Parameter(Mandatory = $true)]
    [string]$UserName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PWD,

    [Parameter(Mandatory = $false)]
    [ValidateRange(50, 1000)]
    [int]$EventCount = 200,

    [switch]$Export
)


function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Green
}

function Write-WarnCustom {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Export-Result {
    param(
        [Parameter(Mandatory)]
        $Data,
        [Parameter(Mandatory)]
        [string]$Name
    )
    if (-not $Export) { return }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $fileName  = "{0}-{1}-{2}.json" -f $UserName, $Name, $timestamp
    $fullPath  = Join-Path -Path $OutputPath -ChildPath $fileName

    try {
        $Data | ConvertTo-Json -Depth 6 | Out-File -FilePath $fullPath -Encoding utf8
        Write-Info "Exported → $fullPath"
    }
    catch {
        Write-WarnCustom "Failed to export $Name : $_"
    }
}


function Get-SystemResources {
    Write-Section "System Resources"

    $os = Get-CimInstance Win32_OperatingSystem
    $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
    $freeMB  = [math]::Round($os.FreePhysicalMemory / 1024, 2)
    $usedMB  = $totalMB - $freeMB
    $percent = [math]::Round(($usedMB / $totalMB) * 100, 2)

    $ram = [PSCustomObject]@{
        TotalRAM_MB   = $totalMB
        UsedRAM_MB    = $usedMB
        FreeRAM_MB    = $freeMB
        PercentUsed   = "$percent%"
    }

    Write-Host "RAM:" -ForegroundColor Yellow
    Write-Host ($ram | Format-List | Out-String)

    $cpuSample = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
    $cpuUsage  = [math]::Round($cpuSample.CounterSamples.CookedValue, 2)

    Write-Host "CPU Usage: $cpuUsage%" -ForegroundColor Yellow

    $topProcesses = Get-Process | Sort-Object CPU -Descending |Select-Object -First 5 Name, Id, CPU, @{N='WorkingSetMB';E={[math]::Round($_.WorkingSet64/1MB,2)}}

    Write-Host "`nTop 5 Processes by CPU:" -ForegroundColor Yellow
    Write-Host ($topProcesses | Format-Table -AutoSize | Out-String)

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType, DisplayName

    Write-Host "Print Spooler:" -ForegroundColor Yellow
    Write-Host ($spooler | Format-List | Out-String)

    return [PSCustomObject]@{
        RAM           = $ram
        CPUUsage      = $cpuUsage
        TopProcesses  = $topProcesses
        Spooler       = $spooler
    }
}

function Get-StorageHealth {
    Write-Section "Storage Health"

    $disks = Get-PhysicalDisk | ForEach-Object {
        $rel = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            DeviceID            = $_.DeviceID
            FriendlyName        = $_.FriendlyName
            MediaType           = $_.MediaType
            HealthStatus        = $_.HealthStatus
            OperationalStatus   = $_.OperationalStatus
            SizeGB              = [math]::Round($_.Size / 1GB, 2)
            Temperature         = $rel.Temperature
            ReadErrorsTotal     = $rel.ReadErrorsTotal
            WriteErrorsTotal    = $rel.WriteErrorsTotal
            ReadLatencyMax      = $rel.ReadLatencyMax
            WriteLatencyMax     = $rel.WriteLatencyMax
        }
    }

    Write-Host ($disks | Format-Table -AutoSize | Out-String)
    return $disks
}

function Get-NetworkInfo {
    Write-Section "Network Information"

    $adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed, MediaType
    Write-Host "Adapters:" -ForegroundColor Yellow
    Write-Host ($adapters | Format-Table -AutoSize| Out-String)

    $ipInfo = @()
    foreach ($adapter in $adapters) {
        $ips = Get-NetIPAddress -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue |
            Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily, AddressState

        $dns = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue).ServerAddresses

        $ipInfo += [PSCustomObject]@{
            AdapterName = $adapter.Name
            Status      = $adapter.Status
            IPAddresses = $ips
            DNSServers  = $dns
        }
    }

    Write-Host "`nIP Configuration:" -ForegroundColor Yellow
    $ipInfo | ForEach-Object {
        Write-Host "  $($_.AdapterName) [$($_.Status)]" -ForegroundColor Cyan
        $_.IPAddresses | Format-Table -AutoSize
        if ($_.DNSServers) {
            Write-Host "  DNS: $($_.DNSServers -join ', ')" -ForegroundColor Gray
        }
    }

    # Wi-Fi Profiles
    Write-Host "`nSaved Wi-Fi Profiles:" -ForegroundColor Yellow
    $profiles = @()
    $rawProfiles = netsh wlan show profiles 2>$null

    $profileNames = $rawProfiles | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

    foreach ($name in $profileNames) {
        $detail = netsh wlan show profile name="$name" key=clear 2>$null
        $auth   = ($detail | Select-String "Authentication\s*:\s*(.+)").Matches.Groups[1].Value.Trim()
        $cipher = ($detail | Select-String "Cipher\s*:\s*(.+)").Matches.Groups[1].Value.Trim()
        $key    = ($detail | Select-String "Key Content\s*:\s*(.+)").Matches.Groups[1].Value.Trim()

        $profiles += [PSCustomObject]@{
            ProfileName    = $name
            Authentication = $auth
            Cipher         = $cipher
            # KeyContent   = $key          # Uncomment only if you really need the password
            HasKey         = [bool]$key
        }
    }

    Write-Host ($profiles | Format-Table -AutoSize | Out-String)

    # Active TCP connections
    Write-Host "`nActive / Listening TCP Connections:" -ForegroundColor Yellow
    $connections = Get-NetTCPConnection |
        Where-Object { $_.State -in @('Listen', 'Established') } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Sort-Object State, LocalPort

    Write-Host ($connections | Format-Table -AutoSize | Out-String)

    return [PSCustomObject]@{
        Adapters     = $adapters
        IPInfo       = $ipInfo
        WifiProfiles = $profiles
        Connections  = $connections
    }
}

function Get-SecurityInfo {
    Write-Section "Security Information"

    $fwProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

    Write-Host "Firewall Profiles:" -ForegroundColor Yellow
    $fwProfiles | Format-Table -AutoSize

    Write-Host "Enabled Firewall Rules (summary):" -ForegroundColor Yellow
    $fwRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object Name, DisplayName, Direction, Action, Profile

    Write-Host "Total enabled rules: $($fwRules.Count)" -ForegroundColor Gray

    # Local Users powershell 2.0 
    Write-Host "`nLocal Users:" -ForegroundColor Yellow
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, Description
    Write-Host($users | Format-Table -AutoSize | Out-String)

    # Local Groups + Members powershell 2.0
    Write-Host "`nLocal Groups & Members:" -ForegroundColor Yellow
    $groups = @()
    foreach ($g in Get-LocalGroup) {
        $members = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource

        $groups += [PSCustomObject]@{
            GroupName   = $g.Name
            Description = $g.Description
            Members     = $members
        }

        Write-Host "  [$($g.Name)]" -ForegroundColor Cyan
        if ($members) {
            $members | Format-Table -AutoSize
        } else {
            Write-Host "    (no members)" -ForegroundColor DarkGray
        }
    }

    return [PSCustomObject]@{
        FirewallProfiles = $fwProfiles
        EnabledRules     = $fwRules
        LocalUsers       = $users
        LocalGroups      = $groups
    }
}

function Get-EventLogs {
    Write-Section "Recent Event Logs (last $EventCount events)"
    $logNames = @("Application", "System", "Security", "Setup")
    $allEvents = @{}
    foreach ($log in $logNames) {
        Write-Info "Collecting $log log..."
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents $EventCount -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
            $allEvents[$log] = $events
            Write-Host "  → $($events.Count) events collected" -ForegroundColor Gray
        }
        catch {
            Write-WarnCustom "Could not read $log log: $_"
            $allEvents[$log] = @()
        }
    }
    return $allEvents
}

function Get-PnPAndLCM {
    Write-Section "PnP Devices & DSC LCM"
    $pnp = Get-PnpDevice | Select-Object Status, Class, FriendlyName, InstanceId
    Write-Host "PnP Devices (summary): $($pnp.Count) devices found" -ForegroundColor Yellow
    $lcm = $null
    try {
        $lcm = Get-DscLocalConfigurationManager | Select-Object *
        Write-Host "DSC Local Configuration Manager retrieved." -ForegroundColor Yellow
    }
    catch {
        Write-WarnCustom "DSC LCM not available or not configured."
    }

    return [PSCustomObject]@{
        PnPDevices = $pnp
        LCM        = $lcm
    }
}


Clear-Host
Write-Host "Windows System Health Check" -ForegroundColor Magenta
Write-Host "User      : $UserName" -ForegroundColor Gray
Write-Host "Mode      : $Status" -ForegroundColor Gray
Write-Host "Export    : $Export" -ForegroundColor Gray
Write-Host "OutputPath: $OutputPath" -ForegroundColor Gray
Write-Host "Started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$results = [ordered]@{}

try {
    switch ($Status) {
        "All" {
            $results.Resources = Get-SystemResources
            $results.Storage   = Get-StorageHealth
            $results.Network   = Get-NetworkInfo
            $results.Security  = Get-SecurityInfo
            $results.Events    = Get-EventLogs
            $results.PnP_LCM   = Get-PnPAndLCM
        }
        "Quick" {
            $results.Resources = Get-SystemResources
            $results.Storage   = Get-StorageHealth
            $results.Network   = Get-NetworkInfo
        }
        "Network" {
            $results.Network = Get-NetworkInfo
        }
        "Security" {
            $results.Security = Get-SecurityInfo
            $results.Events   = Get-EventLogs
        }
        "Storage" {
            $results.Storage = Get-StorageHealth
        }
    }

    # Export if requested
    if ($Export) {
        Write-Section "Exporting Results"
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        foreach ($key in $results.Keys) {
            Export-Result -Data $results[$key] -Name $key
        }

        # Also export a combined summary
        Export-Result -Data $results -Name "FullReport"
    }

    Write-Section "Completed"
    Write-Host "Check finished successfully at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green
}
catch {
    Write-Host "`n[ERROR] Something went wrong:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
}
