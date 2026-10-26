# Zalivka

Экспериментальный Rust-клиент для восстановления прошивки Apple Silicon и T2 Mac
через DFU. В проект входят CLI и необязательный настольный интерфейс на egui.
Подключение к USB прямое; для обмена с устройством не используется usbmuxd.

## Сборка и запуск

Требуются Rust 1.89 или новее и инструменты компилятора для выбранной платформы.
Подробности Windows-сборки и публикации EXE: [scripts/README.md](scripts/README.md).

```sh
cargo build --locked --features gui
cargo run --locked --features gui -- gui
```

CLI доступен и без feature `gui`:

```sh
cargo run --locked -- --help
cargo run --locked -- detect --json
```

## Работа с локальной прошивкой

```sh
zalivka inspect firmware.ipsw --json
zalivka verify firmware.ipsw
zalivka plan firmware.ipsw --identity 0
```

`inspect` выводит идентификаторы сборки и доступные build identities. `verify`
проверяет ZIP-потоки, CRC и поддерживаемые контрольные суммы компонентов.
Для проверки полного архива передайте `--checksum` с доверенным SHA-1 или SHA-256.
Контрольные суммы расшифрованного содержимого AEA учитываются отдельно в отчёте.

`plan --identity` работает без USB и сети. Для проверки соответствия подключённому
Mac используйте `plan --ecid HEX_ECID`; ECID задаётся шестнадцатеричным числом.
Эти два способа выбора взаимоисключающие. `--revive` выбирает проверку Update identity.
План не подтверждает успешное аппаратное восстановление.

## Команды для подключённого Mac

```text
zalivka doctor
zalivka drivers status
zalivka fetch --ecid HEX_ECID
zalivka revive firmware.ipsw --ecid HEX_ECID --experimental
zalivka restore firmware.ipsw --ecid HEX_ECID --experimental --erase
```

Замените `HEX_ECID` значением из `detect`. Restore стирает данные; Revive требует
Update identity и не переключается на Erase при её отсутствии. Если путь IPSW
не передан, прошивка выбирается из каталога Apple и загружается в кэш.
`--firmware-dir` задаёт каталог автоматической загрузки и не совмещается с локальным IPSW.

В Windows `drivers prepare` устанавливает недостающие драйверы и останавливает
Apple Mobile Device Service. Раздача интернета через USB поддерживается на Windows:

```text
zalivka usb-internet status
zalivka usb-internet share
zalivka usb-internet share --serial SERIAL --seconds 900
```

`usb-internet status` возвращает ошибку доступа отдельно для каждого устройства.
Если дескрипторы прочитать нельзя, номера интерфейсов в JSON имеют значение `null`.

## Проверки

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

Область подтверждённой проверки описана в [docs/validation.md](docs/validation.md).
Результаты комплексного аудита: [50 исправленных замечаний](docs/audit-2026-10-26.md).
