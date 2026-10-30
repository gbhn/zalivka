<#
.SYNOPSIS
Build Zalivka with Cargo. Defaults to a release build with the GUI enabled.
.PARAMETER DebugBuild
Build the debug profile instead of release.
.PARAMETER CliOnly
Build without the GUI feature.
.PARAMETER Check
Run formatting, Clippy, and tests before building.
.PARAMETER Target
Rust target triple (for example, aarch64-pc-windows-msvc).
.PARAMETER OutputDirectory
Directory for the versioned executable, metadata and locales.
Defaults to <project>/artifacts. Relative paths are resolved against the caller's location.
.EXAMPLE
./scripts/build.ps1
.EXAMPLE
./scripts/build.ps1 -DebugBuild
.EXAMPLE
./scripts/build.ps1 -CliOnly
.EXAMPLE
./scripts/build.ps1 -Target aarch64-pc-windows-msvc
.EXAMPLE
./scripts/build.ps1 -Target x86_64-apple-darwin -OutputDirectory ./target/mac-x86_64
.EXAMPLE
./scripts/build.ps1 -Check
#>
param(
    [switch]$DebugBuild,
    [switch]$CliOnly,
    [switch]$Check,
    [string]$Target,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

$cargo = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $cargo) {
    $cargo = Get-Command cargo.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $cargo) {
    throw 'Cargo was not found. Install Rust and add its bin directory to PATH, then restart the terminal.'
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$buildDirectory = Join-Path (Join-Path $projectRoot 'target') 'build'

# Resolve the output directory before changing into the project directory.
$directory = if ($OutputDirectory) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
} else {
    Join-Path $projectRoot 'artifacts'
}

# Cargo's executable is a staging file. Only published, versioned copies are run,
# so a running release never locks the next build's output.
$buildArguments = @(
    'build', '--locked', '--bin', 'zalivka',
    '--target-dir', $buildDirectory,
    '--message-format=json-render-diagnostics'
)
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

        $checkTarget = @()
        if ($Target) { $checkTarget = @('--target', $Target) }

        & $cargo.Source clippy --locked @checkTarget --all-targets --all-features -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Clippy failed.' }

        & $cargo.Source test --locked @checkTarget --all-features
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    }

    $messages = @(& $cargo.Source @buildArguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo build failed with exit code $LASTEXITCODE."
    }

    $artifact = $null
    $buildInfo = @{}
    $features = @()

    foreach ($line in $messages) {
        if (-not $line) { continue }
        $message = $line | ConvertFrom-Json

        if ($message.reason -eq 'compiler-artifact' -and
            $message.target.name -eq 'zalivka' -and $message.executable) {
            $artifact = $message.executable
            $features = @($message.features)
        }
        if ($message.reason -eq 'build-script-executed') {
            foreach ($entry in $message.env) {
                if ($entry[0].StartsWith('ZALIVKA_')) {
                    $buildInfo[$entry[0]] = $entry[1]
                }
            }
        }
    }

    $version = $buildInfo.ZALIVKA_VERSION
    if (-not $artifact -or -not $version) {
        throw 'Cargo returned no executable or build identity.'
    }

    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $localeDirectory = Join-Path $directory 'locales'
    New-Item -ItemType Directory -Force -Path $localeDirectory | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'locales') -Filter '*.json' -File |
        Copy-Item -Destination $localeDirectory -Force

    $destination = Join-Path $directory ('zalivka-' + $version + [IO.Path]::GetExtension($artifact))
    $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()

    if (Test-Path -LiteralPath $destination) {
        $existingHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existingHash -ne $hash) {
            throw "A different binary already exists for build $version. The published file was preserved."
        }
    } else {
        Copy-Item -LiteralPath $artifact -Destination $destination
    }

    [pscustomobject]@{
        version = $version
        sha256 = $hash
        built_at_unix_nanos = $buildInfo.ZALIVKA_BUILT_AT
        target = $buildInfo.ZALIVKA_TARGET
        compiler = $buildInfo.ZALIVKA_COMPILER
        profile = $buildInfo.ZALIVKA_PROFILE
        features = $features
        executable = [IO.Path]::GetFileName($destination)
    } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath ($destination + '.json') -Encoding utf8NoBOM

    # stdout is intentionally only the destination path (for CI callers).
    Write-Output $destination
} finally {
    Pop-Location
}
