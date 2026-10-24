# Сборка

Для Windows нужны Rust 1.89 или новее и инструменты компилятора для выбранного
Rust target. Команда `cargo` должна быть доступна в `PATH`.

Из корня проекта в PowerShell:

```powershell
.\scripts\build.ps1
```

Если запуск `.ps1` запрещён политикой PowerShell, можно разрешить его только
для этого процесса:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

По умолчанию собирается release-версия с GUI и командами CLI. При обычной
конфигурации Cargo результат находится в `target\release\zalivka.exe`.
Встроенные пакеты драйверов включаются в исполняемый файл при компиляции.

Дополнительные варианты:

```powershell
# Отладочная сборка: target\debug\zalivka.exe
.\scripts\build.ps1 -DebugBuild

# Сборка только CLI
.\scripts\build.ps1 -CliOnly

# Сборка для явно указанного target
.\scripts\build.ps1 -Target aarch64-pc-windows-msvc
```

Для явного target результат находится в `target\<target>\release\zalivka.exe`
(или `debug` с `-DebugBuild`). Target и необходимые инструменты компилятора
должны быть установлены заранее. Настройки Cargo, включая `CARGO_TARGET_DIR`,
продолжают действовать.

Скрипт можно вызывать по полному пути из любой папки. При ошибке сборки он
возвращает код завершения Cargo. Зависимости берутся из `Cargo.lock`.
