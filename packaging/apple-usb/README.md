# Встроенный драйвер Apple USB

Оригинальные CAB-пакеты Apple, Inc. USBDevice 538.0.0.0 (DriverVer 06/14/2023)
получены из Microsoft Update Catalog 23 октября 2026 года. Пакеты не изменены.

| Файл | Архитектура Windows | Размер | SHA-256 |
| --- | --- | --- | --- |
| apple-usb-x64.cab | AMD64 | 99 260 байт | `8ae3b3001e3733f24ef0178f149c6534f94e57d16e8a0d75647ab979e03151ca` |
| apple-usb-arm64.cab | ARM64 | 84 538 байт | `2d7040ff12724ce300534888aa5727b415f6439896916f602d5605d0737192b4` |

Официальные источники:

- [x64: карточка Microsoft Update Catalog](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=0bc332b5-0655-4d9f-94a2-c338e31ea4b7).
- [x64: исходный CAB](https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2023/10/5fb262ea-d52d-46a7-9361-f3260ba57a1a_3e8075a4dded0a795131f82285e2f1a06525ebc2.cab).
- [ARM64: карточка Microsoft Update Catalog](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=ec513752-3e72-4ccb-9cb9-c9ab77664300).
- [ARM64: исходный CAB](https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2023/10/6b37d68c-8643-4607-ab72-75d9f910a87e_8603ae1d57df15f1f9bb42d3bf9d5c448ef90623.cab).

Каждый CAB содержит AppleUsb.inf, appleusb.cat, AppleUsbFilter.dll,
AppleKmdfFilter.sys и AppleLowerFilter.sys. INF включает DFU PID 1227,
Recovery PID 1281 и Restore PID 12AC, включая RESTORE_MODE&MI_00.

Оба CAB встраиваются в Windows exe через `include_bytes!`. При установке
архитектура выбирается по самой Windows, включая запуск x64 exe на ARM64.
Пакет проверяется по SHA-256, распаковывается из памяти библиотекой `cab` во временную
папку и устанавливается через DiInstallDriverW. Тесты сравнивают все пять файлов
обеих архитектур с результатом системного `expand.exe`. Windows проверяет исходный
CAT; отключение проверки подписей, самоподпись и принудительная замена
выбранного Windows драйвера не применяются. iTunes и AMDS не устанавливаются.

Copyright Apple Inc. Драйверы — отдельные проприетарные компоненты Apple;
лицензия MIT исходников Zalivka на них не распространяется. Подпись Microsoft
подтверждает пакет Windows, но не меняет его владельца или условия лицензии.
