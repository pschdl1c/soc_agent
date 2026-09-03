# Кандидаты имён полей

**Модуль:** `app/fields.py`
**Назначение:** списки альтернативных имён полей для извлечения атрибутов из разнородных
источников событий и служебный маркер источника для потокового ingest.

## Область ответственности

- Определение упорядоченных списков имён-кандидатов для host / user / IP / process / time.
- Определение имени служебного поля-маркера источника (`INGEST_SOURCE_FIELD`).
- Функция `first_present` — выбор первого непустого значения по списку имён.

## Списки имён-кандидатов

Порядок в списке = приоритет поиска.

| Константа | Значения |
|---|---|
| `HOST_FIELDS` | `Hostname`, `Computer`, `host`, `ComputerName` |
| `USER_FIELDS` | `TargetUserName`, `SubjectUserName`, `User`, `AccountName` |
| `SRC_IP_FIELDS` | `IpAddress`, `SourceAddress`, `SourceIp`, `src_ip` |
| `DST_IP_FIELDS` | `DestAddress`, `DestinationIp`, `dst_ip` |
| `PROCESS_FIELDS` | `Image`, `NewProcessName`, `CommandLine`, `exe` |
| `TIME_FIELDS` | `SystemTime`, `EventTime`, `@timestamp`, `timestamp`, `EventReceivedTime` |

## `INGEST_SOURCE_FIELD`

Значение: `"SocIngestSourceMarker"`.

Служебный ключ, временно добавляемый в JSON события перед прогоном через движок, чтобы после
объединения нескольких источников в один прогон восстановить исходный `source_batch` каждого
события/алерта.

Ограничения на имя:

- Только символы `[A-Za-z0-9]`. Zircolite при flatten прогоняет имена полей без явного
  маппинга через удаление всех не-alphanumeric символов; подчёркивания и спецсимволы молча
  вырезаются, что нарушило бы обратное сопоставление по имени.
- Длинный отличительный префикс — минимизация коллизии с реальным именем поля.
- Ключ снимается из события (`event.pop(...)`) до записи в БД и до показа: наружу не попадает.

## `first_present(event: dict[str, Any], field_names: list[str]) -> str | None`

Возвращает `str(event[name])` для первого `name` из `field_names`, значение которого истинно
(`if value:`). Если ни одно поле не присутствует с непустым значением — `None`.

## Зависимости

- Импортирует: `typing`.
- Импортируется: `app/detection/normalize.py`, `app/detection/correlation.py`, `app/store.py`,
  `app/main.py` (`INGEST_SOURCE_FIELD`).
