# Bundled Apple restore drivers

Original Apple, Inc. USBDevice 538.0.0.0 CAB packages (DriverVer 06/14/2023),
downloaded from Microsoft Update Catalog on 2026-10-23. The packages are unmodified.

| File | Windows architecture | Size | SHA-256 |
| --- | --- | --- | --- |
| apple-usb-x64.cab | AMD64 | 99,260 bytes | `8ae3b3001e3733f24ef0178f149c6534f94e57d16e8a0d75647ab979e03151ca` |
| apple-usb-arm64.cab | ARM64 | 84,538 bytes | `2d7040ff12724ce300534888aa5727b415f6439896916f602d5605d0737192b4` |

Apple KIS 1.1.5.0 (DriverVer 08/02/2023) and Apple RSM 1.1.7.0
(DriverVer 09/19/2023) were downloaded from Microsoft Update Catalog on
2026-10-30. These CABs are also unmodified.

| File | Windows architecture | Size | SHA-256 |
| --- | --- | --- | --- |
| apple-kis-x64.cab | AMD64 | 50,129 bytes | `6639a067886abe2e434b9ce46191f29c9dd7c66659cb5dc6dba8a52ce763ee22` |
| apple-kis-arm64.cab | ARM64 | 50,793 bytes | `92049778c86211c0033be7ac229db4668a033b7ba812ef9a8cc06b5bcd706781` |
| apple-rsm-x64.cab | AMD64 | 56,487 bytes | `79bc94933d2b3b713b08c41a43e9629c2e4ae6004d339f4ca5f43fa630e7544a` |
| apple-rsm-arm64.cab | ARM64 | 50,491 bytes | `98508d33348b9ebeee1d7e06b6174e6f73c42ea1def280b4f66d2114c4bf97d1` |

Official sources:

- [x64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=0bc332b5-0655-4d9f-94a2-c338e31ea4b7).
- [x64: original CAB](https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2023/10/5fb262ea-d52d-46a7-9361-f3260ba57a1a_3e8075a4dded0a795131f82285e2f1a06525ebc2.cab).
- [ARM64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=ec513752-3e72-4ccb-9cb9-c9ab77664300).
- [ARM64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/6b37d68c-8643-4607-ab72-75d9f910a87e_8603ae1d57df15f1f9bb42d3bf9d5c448ef90623.cab).

- [KIS x64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=a164ed48-ad9c-432d-a9a2-613f7b7c64ad).
- [KIS x64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/4af31b21-16f7-4470-918f-b1681cb96989_b535ac7195176213e35b87ee810bfc7a21c2d2f9.cab).
- [KIS ARM64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=eae87d30-0227-43fe-958b-d9e4417735c2).
- [KIS ARM64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/8cd1940e-a919-466d-a57f-3b1859dda730_5abeb2ab64e7af2d0b2fdc4a0fa484505c3189b5.cab).
- [RSM x64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=9f9f0dcf-124f-423b-8132-4fd5a6809dc8).
- [RSM x64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/78bcae93-1a7a-4bad-9d27-dad6770a37f8_6823f134c2ff4561566761c70d8157c52da1dd21.cab).
- [RSM ARM64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=2de59226-152b-479b-b19b-e26d28ba3ad6).
- [RSM ARM64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/ab766df2-534c-40ca-8310-7c3587c031cd_16ffbf749285939e16d3a1e4f61729d829d82334.cab).

Each USB CAB contains `AppleUsb.inf`, `appleusb.cat`, `AppleUsbFilter.dll`,
`AppleKmdfFilter.sys`, and `AppleLowerFilter.sys`. The INF covers DFU PID `1227`,
Port DFU PID `F014`, Recovery PID `1281`, and Restore PID `12AC`, including
`RESTORE_MODE&MI_00`.

Each KIS CAB contains `AppleKIS.inf`, `applekis.cat`, `AppleKIS.sys` and
`AppleKISInterface.dll`. It binds `USB\VID_05AC&PID_1881` in the USBDevice
class and creates KIS portal children. Each RSM CAB contains `AppleRSM.inf`,
`applersm.cat`, `AppleRSM.sys` and `AppleRSMInterface.dll`. RSM binds
`KIS\VID_05AC&PID_0001` in the System class and exposes the recovery interface
GUID `b36f4137-f4ef-4bfc-a25a-c2410768ee37`. Both packages are needed for
Windows Apple KIS recovery. The KIS/RSM AMD64 and ARM64 INFs and PE machine
fields match their respective architectures.

All six CABs are embedded in the Windows executable with `include_bytes!`.
Installation selects the native Windows architecture, including when an x64
executable runs on ARM64. Each CAB is checked against its SHA-256 and extracted
to its own temporary directory with fixed filenames. `DiInstallDriverW` installs
missing USB, KIS and RSM packages with normal signature and ranking enforcement.
No internet download or iTunes installation is needed by Zalivka's installer.

DriverStore checks enumerate both USBDevice and System classes. The status field
`apple_kis_driver_installed` is true only when complete KIS and RSM packages are
present. A missing KIS stack enables the installation button without blocking
an otherwise accessible ordinary DFU device. Package presence does not prove
that a driver is bound to a connected device; diagnostics check actual access.
Reset includes Port DFU and KIS parent devnodes and reinstalls all three packages.
It retains DriverStore packages and Windows' normal driver selection.

Tests compare every extracted file in all six CABs against Windows `expand.exe`,
verify architecture and active hardware-ID declarations, and reject modified
CAB data and filename collisions. On 2026-10-30, Windows PowerShell
`Get-AuthenticodeSignature` reported `Valid` for CAT, SYS and DLL files in all
four added packages: 12 signatures total. CAT signers are Microsoft Windows
Hardware Compatibility Publisher; SYS/DLL signers are Apple Inc., with timestamp
signatures. This uses the local Windows trust configuration; driver loading and
a restore on physical KIS hardware have not been tested here.

Windows verifies the original CAT signature. Installation does not disable
signature checks, self-sign packages, or force replacement of the selected
driver. It does not install iTunes or Apple Mobile Device Service.

Copyright Apple Inc. These drivers are separate proprietary Apple components;
the MIT license for Zalivka's source code does not apply to them. Microsoft's
signature certifies the Windows package without changing its ownership or
licensing terms.
