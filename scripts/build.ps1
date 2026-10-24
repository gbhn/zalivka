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
#>
param(
    [switch]$DebugBuild,
    [switch]$CliOnly,
    [string]$Target
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Cargo was not found. Install Rust and add its bin directory to PATH, then restart the terminal.'
}

$buildArguments = @('build', '--locked', '--bin', 'zalivka')
if (-not $DebugBuild) {
    $buildArguments += '--release'
}
if (-not $CliOnly) {
    $buildArguments += @('--features', 'gui')
}
if ($Target) {
    $buildArguments += @('--target', $Target)
}

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    & cargo @buildArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
