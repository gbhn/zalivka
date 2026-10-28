param([switch]$Apply)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
$taskRoot = $null
$taskNativeLog = New-Object System.Collections.Generic.List[object]

function Save-Json($Value, [string]$Name) {
    ConvertTo-Json -InputObject $Value -Depth 12 | Set-Content -LiteralPath (Join-Path $taskRoot $Name) -Encoding UTF8
}
function Apple-Devices {
    @(Get-PnpDevice | Where-Object { $_.InstanceId -match '^USB\\VID_05AC(?:&|\\)' } |
        Select-Object Status, Class, FriendlyName, InstanceId, Problem)
}
function Apple-Packages {
    @(Get-ChildItem "$env:windir\INF\oem*.inf" | Where-Object {
        (Get-Content -LiteralPath $_.FullName -Raw) -match '(?im)^[^;\r\n]*USB\\VID_05AC'
    } | ForEach-Object {
        [pscustomobject]@{
            PublishedName = $_.Name
            Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            Header = (Get-Content -LiteralPath $_.FullName -TotalCount 24) -join "`n"
        }
    })
}
function Run-Pnp([string[]]$Arguments, [string]$Label) {
    $stdout = Join-Path $taskRoot ($Label + '.stdout.txt')
    $stderr = Join-Path $taskRoot ($Label + '.stderr.txt')
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]') { throw 'Invalid native argument' }
        '"' + $_ + '"'
    }) -join ' '
    $process = Start-Process -FilePath "$env:windir\System32\pnputil.exe" -ArgumentList $quoted -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $taskNativeLog.Add([pscustomobject]@{Arguments=$Arguments; ExitCode=$process.ExitCode; Output=$stdout; Error=$stderr})
    Save-Json @($taskNativeLog.ToArray()) 'commands.json'
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "PnPUtil failed ($($process.ExitCode)): $quoted. See $stdout and $stderr"
    }
    Write-Host "$Label : $($process.ExitCode)"
}

if (-not $Apply) {
    $devices = @(Apple-Devices)
    $packages = @(Apple-Packages)
    $devices | Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
    $packages | Select-Object PublishedName, Header | Format-List
    [pscustomobject]@{Devices=$devices.Count; Packages=@($packages | ForEach-Object { $_.PublishedName }); Apply=$false} | ConvertTo-Json
    Write-Host 'Preview only. To remove Apple USB devices and drivers, run as administrator with -Apply.'
    exit 0
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required. Run this script using Run as administrator.'
    }
    $taskRoot = Join-Path $PSScriptRoot ('runs\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Path $taskRoot | Out-Null
    Write-Host "Backups and report: $taskRoot"
    $packages = @(Apple-Packages)
    $devices = @(Apple-Devices)
    Save-Json $packages 'packages-plan.json'
    Save-Json $devices 'devices-before.json'
    foreach ($package in $packages) {
        if ($package.PublishedName -notmatch '^oem[0-9]+\.inf$') { throw 'Unexpected OEM package name' }
        $inf = Join-Path "$env:windir\INF" $package.PublishedName
        if ((Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash -ne $package.Sha256) { throw "INF changed: $inf" }
        $vendors = @([regex]::Matches((Get-Content -LiteralPath $inf -Raw), '(?i)USB\\VID_([0-9A-F]{4})') | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() } | Sort-Object -Unique)
        if ($vendors.Count -ne 1 -or $vendors[0] -ne '05AC') { throw "Package is not exclusive to Apple USB: $inf" }
    }
    $properties = @()
    if ($devices.Count -gt 0) {
        $properties = @(Get-PnpDeviceProperty -InstanceId @($devices.InstanceId) -KeyName 'DEVPKEY_Device_Parent', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_Service', 'DEVPKEY_Device_IsPresent' -ErrorAction SilentlyContinue |
            Select-Object InstanceId, KeyName, Type, Data)
    }
    Save-Json $properties 'device-properties-before.json'
    foreach ($package in $packages) {
        $destination = Join-Path $taskRoot ('driver-backup\' + $package.PublishedName)
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Run-Pnp @('/export-driver', $package.PublishedName, $destination) ('export-' + $package.PublishedName)
        if (@(Get-ChildItem -LiteralPath $destination -Filter '*.inf' -Recurse).Count -eq 0) { throw 'Driver export contains no INF' }
    }
    foreach ($package in $packages) {
        Run-Pnp @('/delete-driver', $package.PublishedName, '/uninstall') ('delete-' + $package.PublishedName)
    }
    # Parent removal includes all interfaces and descendants of that Apple USB device.
    $parents = @($devices | Where-Object { ($_.InstanceId -split '\\')[1] -notmatch '&MI_[0-9A-F]{2}' })
    $index = 0
    foreach ($device in $parents) {
        if (@(Apple-Devices | Where-Object InstanceId -eq $device.InstanceId).Count -eq 0) { continue }
        Run-Pnp @('/remove-device', $device.InstanceId, '/subtree') ('remove-parent-' + $index)
        $index++
    }
    foreach ($device in @(Apple-Devices)) {
        Run-Pnp @('/remove-device', $device.InstanceId, '/subtree') ('remove-interface-' + $index)
        $index++
    }
    $remainingPackages = @(Apple-Packages)
    $remainingDevices = @(Apple-Devices)
    Save-Json $remainingPackages 'packages-after.json'
    Save-Json $remainingDevices 'devices-after.json'
    $summary = [pscustomobject]@{
        Success = ($remainingPackages.Count -eq 0 -and $remainingDevices.Count -eq 0)
        RemovedPackages = @($packages | ForEach-Object { $_.PublishedName })
        DeviceRecordsBefore = $devices.Count
        RemainingPackages = @($remainingPackages | ForEach-Object { $_.PublishedName })
        RemainingDeviceRecords = $remainingDevices.Count
        RestartRequired = (@($taskNativeLog | Where-Object ExitCode -eq 3010).Count -gt 0)
        NativeWinUsbPreserved = (Test-Path "$env:windir\INF\winusb.inf")
        ReportDirectory = $taskRoot
    }
    Save-Json $summary 'result.json'
    $summary | ConvertTo-Json
    if (-not $summary.Success) { exit 2 }
} catch {
    if ($taskRoot -and (Test-Path -LiteralPath $taskRoot)) {
        Save-Json ([pscustomobject]@{Success=$false; Error=$_.Exception.Message; Detail=($_ | Out-String)}) 'error.json'
    }
    Write-Error $_ -ErrorAction Continue
    exit 1
}
