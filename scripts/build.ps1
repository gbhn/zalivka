<#
.SYNOPSIS
Build Zalivka with Cargo. Defaults to a release build with the GUI enabled.
.EXAMPLE
.\scripts\build.ps1
.EXAMPLE
.\scripts\build.ps1 -DebugBuild
.EXAMPLE
.\scripts\build.ps1 -CliOnly
.EXAMPLE
.\scripts\build.ps1 -Target aarch64-pc-windows-msvc
.EXAMPLE
.\scripts\build.ps1 -Check
#>
param(
    [switch]$DebugBuild,
    [switch]$CliOnly,
    [switch]$Check,
    [string]$Target
)

$ErrorActionPreference = 'Stop'

$cargo = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $cargo) { $cargo = Get-Command cargo.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
if (-not $cargo) {
    throw 'Cargo was not found. Install Rust and add its bin directory to PATH, then restart the terminal.'
}

$projectRoot = Split-Path -Parent $PSScriptRoot
# Cargo's executable is a staging file. Only published, versioned copies are run,
# so a running release never locks the next build's output.
$buildArguments = @('build', '--locked', '--bin', 'zalivka', '--target-dir', (Join-Path $projectRoot 'target\build'), '--message-format=json-render-diagnostics')
if (-not $DebugBuild) {
    $buildArguments += '--release'
}
if (-not $CliOnly) {
    $buildArguments += @('--features', 'gui')
}
if ($Target) {
    $buildArguments += @('--target', $Target)
}

Push-Location $projectRoot
try {
    if ($Check) {
        & $cargo.Source fmt --all -- --check
        if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
        & $cargo.Source clippy --locked --all-targets --all-features -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Clippy failed.' }
        & $cargo.Source test --locked --all-features
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    }
    $messages = @(& $cargo.Source @buildArguments)
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $artifact = $null
    $buildInfo = @{}
    $features = @()
    foreach ($line in $messages) {
        $message = $line | ConvertFrom-Json
        if ($message.reason -eq 'compiler-artifact' -and $message.target.name -eq 'zalivka' -and $message.executable) {
            $artifact = $message.executable
            $features = @($message.features)
        }
        if ($message.reason -eq 'build-script-executed') {
            foreach ($entry in $message.env) {
                if ($entry[0].StartsWith('ZALIVKA_')) { $buildInfo[$entry[0]] = $entry[1] }
            }
        }
    }
    $version = $buildInfo.ZALIVKA_VERSION
    if (-not $artifact -or -not $version) { throw 'Cargo returned no executable or build identity.' }
    $directory = Join-Path $projectRoot 'artifacts'
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $localeDirectory = Join-Path $directory 'locales'
    New-Item -ItemType Directory -Force -Path $localeDirectory | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'locales') -Filter '*.json' -File |
        Copy-Item -Destination $localeDirectory -Force
    $destination = Join-Path $directory ('zalivka-' + $version + [IO.Path]::GetExtension($artifact))
    $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if (Test-Path -LiteralPath $destination) {
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
            throw "A different binary already exists for build $version. The published file was preserved."
        }
    } else {
        Copy-Item -LiteralPath $artifact -Destination $destination
    }
    [pscustomobject]@{ version = $version; sha256 = $hash; built_at_unix_nanos = $buildInfo.ZALIVKA_BUILT_AT; target = $buildInfo.ZALIVKA_TARGET; compiler = $buildInfo.ZALIVKA_COMPILER; profile = $buildInfo.ZALIVKA_PROFILE; features = $features; executable = [IO.Path]::GetFileName($destination) } |
        ConvertTo-Json | Set-Content -LiteralPath ($destination + '.json') -Encoding UTF8
    Write-Output $destination
} finally {
    Pop-Location
}
