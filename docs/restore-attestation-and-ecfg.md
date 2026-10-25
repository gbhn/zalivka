# Аттестация и FDR eCfg в сборке 26A434

Проверено на IPSW из журнала: MacBookAir10,1, j313ap, CPID 0x8103,
BDID 0x26, сборка 26A434. Разобраны MobileDevice 1860.2.5 и
`restored_external` из `043-70833-687.dmg`.

## Аттестация

`Info.RestoreAttestationMode` выбранной identity равен 6.
`AMRestoreAttestationAuthenticate` в MobileDevice (0x143b4c) проверяет:

1. Два полученных сертификата — leaf и intermediate — и фиксированный корень
   BAA System или BAA User в зависимости от `AttestationUseSCRT`.
2. Свойство 1002 в подписанном DeviceIdentifiers
   (`1.2.840.113635.100.8.3`) — SHA-384 персонального ticket.
3. Для уровней 6–8 свойство 1007 — `ibss`.
4. Для уровня 8 свойства 1010/1011: LocalBoot должен быть измерен и сброшен.

Zalivka дополнительно сверяет подписанные chip ID, ECID, security domain и
production/security mode. Ожидаемый хэш фиксируется до передачи iBSS:
смена nonce и переподпись последующих компонентов не должны менять
ожидаемое измерение уже запущенного iBSS.

Для Erase с поддерживаемым режимом аттестация запрашивается автоматически.
Уровни 1–4 соответствуют уровням 5–8 при аутентификации, как в MobileDevice.
Update/Revive не запрашивает DFU restore attestation, как и хост Apple.
Успешный StatusMsg подтверждается протоколу, но не становится успехом
программы, если требуемая аттестация отсутствует или не прошла проверку.

Подписи, время действия, связи issuer/subject, ограничения CA/path,
критические расширения и BAA root проверяются webpki. Ключи и сертификаты
с устройства никогда не становятся доверенными корнями. Корни и первичные
источники перечислены в `certs/README.md`.

## Почему нет eCfg

Сам этап **есть**: `update_fdr_ean` начался в 00:01:04.879 и завершился
в 00:01:04.907 с `result=0`. Отсутствуют данные класса `eCfg`.

В `System/Library/FDR/FDRSealingMap.plist` для MacBookAir10,1 используется
набор `0ef619f96a9e47e660004540c3c54492f2fd0f8d`. У записи eCfg:

```json
{
  "Attributes": ["EarlyAccess", "GeneratedByRestore", "StoreCombined"],
  "DataInstanceIdentifierList": ["ChipID", "UniqueChipID"],
  "Tag": "eCfg"
}
```

Это необязательный класс данных, формируемый устройством. У него нет
`RequiredToSeal` и `EarlyAccessConsistencyRequired`, присутствующих у fCfg.
Это не файл из IPSW и не поле ответа на запрос прошивки EANData.

В `libFDR` функция `_AMFDRSealedDataCreateSealingRequestInternal`
(0x558e8) допускает отсутствие payload для класса, не обязательного для
sealing, и пропускает его при формировании sealing request.
Затем `update_fdr_ean` (0x100050d90) перебирает EarlyAccess-классы.
Когда локальный FDR не возвращает eCfg, код в 0x1000513c0 записывает
предупреждение, удаляет прежнюю запись этого класса из EAN и продолжает.

В журнале `fdr_recover`, `verify_fdr_data` и `fdr_verify_sealed_manifest`
также завершились успешно. До предупреждения нет запросов CONNECT через
FDR: оно не указывает на отказ сетевого прокси Zalivka.

Это подтверждено и исходным `restore-1792899664046367100.jsonl`: Mac
прислал только запрос списка прошивок `EANData/EANImageList`, а предупреждение
eCfg — отдельным завершённым CheckpointMsg. Запроса передать payload eCfg
хосту не было. Такое же предупреждение есть и в предыдущих сохранённых сеансах.

Текстовый журнал не содержит payload локального FDR и подробного журнала
генерации eCfg. По нему нельзя установить, был ли набор eCfg изначально
пустым или отсутствовал уже до этого восстановления. Поэтому предупреждение
сохраняется как WARN; данные eCfg не подменяются выдуманным содержимым.
