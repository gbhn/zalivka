# Zalivka

Zalivka is an experimental native Rust client for restoring Apple Silicon and T2
Mac firmware over USB in DFU mode. It includes a command-line interface and an
optional desktop GUI built with egui. USB communication is direct and does not
require usbmuxd.

**Restore erases the target Mac.** Revive uses an Upgrade identity and never falls
back to an erase restore.

## Getting started

Download the Windows x64 ZIP or Linux x64 tar.gz from
[GitHub Releases](https://github.com/gbhn/zalivka/releases) and extract it. Each
archive includes the GUI and CLI, language packs, and a JSON file with build
metadata and the executable's SHA-256. An adjacent `.sha256` file verifies the
archive itself.

Executables have versioned names. Use the extracted filename, or rename it to
`zalivka.exe` on Windows or `zalivka` on Linux. The commands below assume
`zalivka` is available on your `PATH`.

Start the executable without arguments to open the GUI, or run:

```sh
zalivka gui
```

Connect the target Mac with a suitable USB cable and put it into DFU mode before
running device commands.

### Windows USB setup

Run Zalivka under your normal user account. Driver operations request elevation
through Windows UAC when needed:

```sh
zalivka drivers status
zalivka drivers prepare
zalivka doctor
```

`drivers prepare` installs missing bundled Apple USB drivers, stops Apple Mobile
Device Service if present, and checks USB access. If Windows requests a reboot,
restart before continuing.

If a Mac stops appearing after a restore, use **Settings → Reset Apple USB
drivers** or `zalivka drivers reset`, then reconnect it and enter DFU mode again.
Reset temporarily disconnects Apple DFU, Recovery, and Restore devices.

### Linux USB setup

Install the bundled udev rule from the directory containing the renamed binary:

```sh
sudo ./zalivka drivers install-udev
```

Reconnect the USB cable after installation. The rule grants access to the active
local session. Use `zalivka doctor` to diagnose access or interface claim errors.

## Command-line usage

Find the connected device and copy its hexadecimal ECID:

```sh
zalivka detect --json
```

Inspect and verify a local IPSW without opening a USB device:

```sh
zalivka inspect firmware.ipsw --json
zalivka verify firmware.ipsw
zalivka verify firmware.ipsw --checksum TRUSTED_SHA256
zalivka plan firmware.ipsw --identity 0
```

`verify` checks ZIP streams, CRCs, and supported manifest digests. `--checksum`
accepts a trusted SHA-1 or SHA-256 for the entire archive. Encrypted AEA content
is reported separately when its plaintext checksum cannot be verified.

`plan --identity` selects a build identity by index for an offline check. Use
`plan firmware.ipsw --ecid HEX_ECID` to select an identity for a connected device;
`--identity` and `--ecid` are mutually exclusive. Add `--revive` to check the
Revive path.

Download firmware or start an operation using the ECID returned by `detect`:

```sh
zalivka fetch --ecid HEX_ECID
zalivka revive firmware.ipsw --ecid HEX_ECID
zalivka restore firmware.ipsw --ecid HEX_ECID --erase
```

Omit `firmware.ipsw` from `revive` or `restore` to select and download compatible
firmware automatically. `--firmware-dir` chooses the automatic download directory
and cannot be combined with a local IPSW path. Restore and Revive verify the
selected filesystem images before booting the target; compressed images require
space in the host's temporary directory.

Use `zalivka --help` or `zalivka <command> --help` for additional commands and
options.

## Network access and activation

The host needs access to Apple services for firmware downloads and restoration.
On Windows, Zalivka uses the current user's proxy settings, including PAC/WPAD,
and supports Negotiate/NTLM proxy authentication through Windows SSPI. HTTPS
validation uses the Windows trust store, including corporate roots.

For FDR, the target Mac establishes TLS through Zalivka's tunnel. The network
must allow CONNECT to `tbsc.apple.com:443` without TLS interception; the host's
corporate trust roots do not apply to that connection.

After restoration, connect the Mac itself to Wi-Fi or Ethernet if it displays
an activation screen. A successful restore does not confirm activation.

## Building from source

Requirements: Rust 1.99 or newer and native compiler/linker tools for the chosen
target. Windows MSVC builds need the matching Visual C++ build tools. On Ubuntu,
install the GUI dependencies used by CI:

```sh
sudo apt-get install libxkbcommon-dev libwayland-dev
```

Build a release executable with both interfaces:

```sh
cargo build --release --locked --features gui
cargo run --locked --features gui -- gui
```

Cargo writes release binaries to `target/release/`. To build only the CLI:

```sh
cargo build --release --locked
```

The PowerShell build script creates a versioned executable in `artifacts/`, copies
language packs, and writes JSON build metadata with its SHA-256:

```powershell
.\scripts\build.ps1
.\scripts\build.ps1 -Check
```

| Option | Behavior |
| --- | --- |
| `-Check` | Run formatting, Clippy, and native tests before building. |
| `-DebugBuild` | Build with the debug profile. |
| `-CliOnly` | Build without the GUI. |
| `-Target aarch64-pc-windows-msvc` | Build for an explicitly installed Rust target. |

The script requires `cargo` on `PATH` and compiler tools for the chosen target.
`-Check` tests the host platform; `-Target` selects the build target. Intermediate
files go to `target/build/`. Run the copy in `artifacts/` so a running Windows
executable does not lock the next build's output.

Local build versions include the Git revision and build timestamp. The adjacent
JSON records the version, SHA-256, timestamp, compiler, target, profile, and
enabled features. An existing executable with the same version is reused only
if its SHA-256 matches; a different binary is not overwritten.

## GitHub Actions and releases

The [Check workflow](.github/workflows/check.yml) runs formatting, Clippy, and
tests on Windows and Linux for pushes and pull requests.

The [Build and release workflow](.github/workflows/release.yml) builds Windows
x64 and Linux x64 packages after the same checks. Push a version tag on a commit
containing the workflow to publish a GitHub Release:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The tag supplies the version: `v0.2.0` becomes `0.2.0` in the program, package
metadata, and filenames. SemVer tags with or without `v` are accepted, including
prerelease and build metadata. The workflow updates `Cargo.toml` and `Cargo.lock`
only in the runner's checkout; no version bump commit is required.

Publication waits for both platform builds to succeed. Releases include the
Windows ZIP, Linux tar.gz, archive checksums, and generated release notes.
Prerelease tags such as `v0.2.0-rc.1` are marked as prereleases and do not become
latest. Publication uses the built-in `GITHUB_TOKEN` without additional secrets.
An existing release is not overwritten; use a new tag for another release.

For a build without publication, select a branch under **Actions → Build and
release → Run workflow**. Download the resulting archives from **Artifacts**.

## Languages and logs

English and Russian are embedded in the executable. The GUI follows the system
language, with an override in **Settings → Language**. Additional JSON language
packs can be loaded from `locales/` beside the executable or the user's settings
directory. See [Language packs](locales/README.md) for the format.

Logs and CLI diagnostics use English. CLI logs go to stderr, while JSON reports
go to stdout. GUI logs are saved under `%LOCALAPPDATA%\zalivka\logs` on Windows
and `$XDG_CACHE_HOME/zalivka/logs` or `~/.cache/zalivka/logs` on Linux. Use
**Technical details** to view DEBUG and TRACE entries in the GUI. Diagnostic logs
can contain device data and protocol dumps; review them before sharing.

## License

Zalivka source code is available under the [MIT License](LICENSE). Bundled Apple
USB drivers are separate proprietary components; see
[their provenance and licensing notes](packaging/apple-usb/README.md).
