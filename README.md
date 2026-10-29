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

`drivers prepare` installs missing bundled Apple USB and KIS recovery drivers
for native Windows x64 or ARM64, stops Apple Mobile Device Service if present,
and checks USB access. KIS installation includes its required RSM driver. All
packages are signed originals from Microsoft Update Catalog and are embedded
in the executable; setup does not need to download them or install iTunes.
See [driver provenance and checks](packaging/apple-usb/README.md).
If Windows requests a reboot, restart before continuing.

If a Mac stops appearing after a restore, use **Settings → Reset Apple USB
drivers** or `zalivka drivers reset`, then reconnect it and enter DFU mode again.
Reset temporarily disconnects Apple DFU, Recovery, Restore, Port DFU and KIS
devices and reinstalls the three driver packages.

### Linux USB setup

In the GUI, open **Settings → USB access → Install USB access rules**.
Zalivka requests administrator authentication through Polkit (`pkexec`), then
installs the bundled rule and reloads udev. A desktop Polkit authentication agent
must be running; the GUI itself stays under your normal user account.

For a terminal session, or if Polkit is unavailable, install the same rule from
the directory containing the renamed binary:

```sh
sudo ./zalivka drivers install-udev
```

Reconnect the USB cable after installation. The rule grants access to the active
local session. Use `zalivka doctor` to diagnose access or interface claim errors.

For SoC DFU (`1227`), iBoot Recovery (`1280`–`1283`), restored (`12ac`),
Port DFU (`f014`) and KIS (`1881`), the rule also clears usbmuxd's udev activation
and assigns USB access to root/the active local user instead of the usbmux
account. It runs after `39-usbmuxd.rules` and before the seat ACL rule, preventing
usbmuxd from claiming the restore interface while leaving normal iPhone/iPad
IDs alone. Reinstall the rule after updating Zalivka; the installer can upgrade
both previous bundled versions and preserves custom administrator rules. If
usbmuxd already has the Mac open, stop it once and reconnect/re-enter DFU before
retrying. A root-run usbmuxd can bypass device permissions and must be stopped.

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
Proxy selection is shared by firmware/asset downloads, TSS signing requests,
and FDR tunnels. No proxy configuration inside Zalivka is required.

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| System proxy settings and exclusions | libproxy: GNOME, KDE, sysconfig | CFNetwork: active system settings | Current-user Windows settings |
| Automatic proxy configuration (PAC) | Native libproxy PAC engine | Native CFNetwork PAC engine | WinHTTP |
| WPAD | DNS discovery through libproxy | System referrals, cached DHCP option 252, then DNS | WinHTTP discovery |
| Current-user Kerberos / Negotiate | System GSSAPI credential cache | Apple GSS.framework / SSO | SSPI |
| NTLM | GSS NTLM provider, if installed | Requires an available GSS NTLM provider | SSPI |
| Corporate certificate authorities | System certificate store | System certificate store | Windows certificate store |

HTTP CONNECT, TLS to an HTTPS proxy, SOCKS4/4a and SOCKS5/5h are supported.
On macOS, the **Secure Web Proxy (HTTPS)** system setting specifies an HTTP
CONNECT proxy for HTTPS destinations; `https://` in an environment proxy URL
specifies TLS to the proxy itself. Explicit proxy URL credentials support HTTP
Basic and SOCKS authentication.

On Linux and macOS, a nonempty `HTTP_PROXY`/`HTTPS_PROXY` (or lowercase equivalent)
overrides desktop settings for that destination scheme; `ALL_PROXY` is the
fallback. `NO_PROXY`/`no_proxy` supplies exclusions for that environment proxy.
For example:

```sh
HTTPS_PROXY=http://proxy.example:3128 zalivka fetch --ecid 0x123456789ABC
HTTPS_PROXY=socks5h://proxy.example:1080 zalivka fetch --ecid 0x123456789ABC
```

Windows keeps its system-settings-first policy, with environment settings used
when no system policy is configured. PAC route lists on Linux and macOS are
tried in order. A route can fall back to a direct connection only if the native
resolver explicitly returns `DIRECT`. A failed connection can try the next
configured route; a POST already sent to the destination is never replayed by
proxy failover. PAC loading/evaluation and discovery behavior follow the native
resolver, including the installed libproxy version's policy on PAC errors.

Kerberos requires a valid ticket for the current user (domain login/SSO, or
`kinit` on Linux), working realm/DNS configuration, and a registered
`HTTP/proxy-host` service principal. Zalivka uses the existing credential cache;
it does not prompt for a domain password or delegate user credentials. HTTP 407
Negotiate challenges and the server's final mutual-authentication token are
processed before the tunnel becomes usable. Linux NTLM additionally needs a
provider such as `gss-ntlmssp` and credentials available to that provider.

On Debian/Ubuntu, Linux runtime dependencies are `libproxy1v5` and
`libgssapi-krb5-2`, including the distribution's desktop/PAC libproxy modules.
macOS uses built-in CFNetwork, SystemConfiguration and GSS frameworks.

For FDR, the target Mac establishes TLS through Zalivka's tunnel. The network
must allow CONNECT to `tbsc.apple.com:443` without TLS interception; the host's
corporate trust roots do not apply to that connection.

After restoration, connect the Mac itself to Wi-Fi or Ethernet if it displays
an activation screen. A successful restore does not confirm activation.

## Building from source

Requirements: Rust 1.99 or newer and native compiler/linker tools for the chosen
target. Windows MSVC builds need the matching Visual C++ build tools. On Ubuntu,
install the network and GUI development dependencies used by CI:

```sh
sudo apt-get install libxkbcommon-dev libwayland-dev libproxy-dev libkrb5-dev libclang-dev
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

The Linux desktop proxy tests require `gsettings-desktop-schemas` and
`libglib2.0-bin`. They use temporary GNOME/KDE configurations and leave the
user's settings untouched. Two optional integration tests also use disposable
configuration and credentials:

```sh
# Needs krb5-kdc, krb5-admin-server, krb5-user and Python 3.
cargo test --all-features --lib kerberos_authenticates_http_and_fdr_tunnels -- --ignored
# Needs libnss-wrapper and free local TCP port 80.
ZALIVKA_NSS_WRAPPER=/usr/lib/x86_64-linux-gnu/libnss_wrapper.so \
  cargo test --all-features --lib wpad_discovers -- --ignored
```

The Kerberos fixture starts a temporary KDC on a loopback high port and checks
HTTP and FDR authentication with actual tickets. The WPAD fixture maps `wpad`
to loopback only in its child process. Neither changes system DNS, network
settings, Kerberos configuration, or the user's credential cache.

## GitHub Actions and releases

The [Check workflow](.github/workflows/check.yml) runs formatting, Clippy, and
tests on Windows, Linux, and macOS for pushes and pull requests. Linux checks
also exercise a disposable local Kerberos realm. macOS checks compile against
the Apple SDK and exercise native CFNetwork PAC resolution.

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
