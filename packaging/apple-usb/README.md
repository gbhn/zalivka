# Bundled Apple USB driver

Original Apple, Inc. USBDevice 538.0.0.0 CAB packages (DriverVer 06/14/2023),
downloaded from Microsoft Update Catalog on 2026-10-23. The packages are unmodified.

| File | Windows architecture | Size | SHA-256 |
| --- | --- | --- | --- |
| apple-usb-x64.cab | AMD64 | 99,260 bytes | `8ae3b3001e3733f24ef0178f149c6534f94e57d16e8a0d75647ab979e03151ca` |
| apple-usb-arm64.cab | ARM64 | 84,538 bytes | `2d7040ff12724ce300534888aa5727b415f6439896916f602d5605d0737192b4` |

Official sources:

- [x64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=0bc332b5-0655-4d9f-94a2-c338e31ea4b7).
- [x64: original CAB](https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2023/10/5fb262ea-d52d-46a7-9361-f3260ba57a1a_3e8075a4dded0a795131f82285e2f1a06525ebc2.cab).
- [ARM64: Microsoft Update Catalog entry](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=ec513752-3e72-4ccb-9cb9-c9ab77664300).
- [ARM64: original CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/6b37d68c-8643-4607-ab72-75d9f910a87e_8603ae1d57df15f1f9bb42d3bf9d5c448ef90623.cab).

Each CAB contains `AppleUsb.inf`, `appleusb.cat`, `AppleUsbFilter.dll`,
`AppleKmdfFilter.sys`, and `AppleLowerFilter.sys`. The INF covers DFU PID `1227`,
Port DFU PID `F014`, Recovery PID `1281`, and Restore PID `12AC`, including
`RESTORE_MODE&MI_00`. It does not include Debug USB / KIS PID `1881`; KIS needs
an appropriate installed Apple KIS driver or a compatible WinUSB binding.

Both CAB files are embedded in the Windows executable with `include_bytes!`.
Installation selects the host Windows architecture, including when an x64
executable runs on ARM64. The package is checked against its SHA-256, extracted
from memory to a temporary directory with the `cab` crate, and installed through
`DiInstallDriverW`. Tests compare all five files for both architectures against
the output of Windows `expand.exe`.

Windows verifies the original CAT signature. Installation does not disable
signature checks, self-sign packages, or force replacement of the driver selected
by Windows. It does not install iTunes or Apple Mobile Device Service.

Copyright Apple Inc. These drivers are separate proprietary Apple components;
the MIT license for Zalivka's source code does not apply to them. Microsoft's
signature certifies the Windows package without changing its ownership or
licensing terms.
