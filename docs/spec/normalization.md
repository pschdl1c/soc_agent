# Нормализация

**Модуль:** `app/detection/normalize.py`
**Назначение:** преобразование сырого результата Zircolite в список объектов `Alert`,
сгруппированных по паре (хост, источник).

## Область ответственности

- Построение `Alert` из каждого сработавшего правила.
- Разбивка событий одного правила на отдельные алерты по (хосту, `source_batch`).
- Извлечение сущностей и сэмпла событий.
- Отсечка уровня `informational`.

## Публичный интерфейс

### `zircolite_results_to_alerts(raw_results: list[dict[str, Any]], default_source_batch: str) -> list[Alert]`

Для каждого элемента `raw_results`:

1. Пропуск, если `matches` пуст.
2. Построение `SigmaRuleRef`:
   - `rule_id` = `rule["id"]` (или `""`);
   - `title` = `rule["title"]` (или `"Unnamed Rule"`);
   - `level` = `Severity.from_zircolite(rule["rule_level"])`;
   - `mitre_techniques` = `[t for t in rule["tags"] if t.startswith("attack.t")]`;
   - `description` = `rule["description"]` (или `""`).
3. Если `level == Severity.informational` — правило пропускается целиком (алерт не создаётся).
4. Группировка `matches` по ключу `(host, source_batch)`:
   - `source_batch` = `event.pop(INGEST_SOURCE_FIELD, default_source_batch)` — маркер снимается
     из события;
   - `host` = `first_present(event, HOST_FIELDS)` или `"unknown-host"`.
5. Для каждой группы:
   - `entities` = `_extract_entities(host_events)`;
   - `main_entity` = `entities.users[0]`, если есть пользователи, иначе `host`;
   - `Alert.dedup_key` = `_dedup_key(rule_id, host, main_entity)`;
   - `event_count` = число событий группы;
   - `sample_events` = `_pick_sample_events(host_events)`.

`engine` алерта — значение по умолчанию `"zircolite"`.

## Вспомогательные функции

### `_dedup_key(rule_id: str, host: str, main_entity: str) -> str`

`sha256(f"{rule_id}:{host}:{main_entity}").hexdigest()[:16]`.

### `_extract_entities(events: list[dict]) -> Entities`

Проход по событиям, для каждой категории — `first_present` по соответствующему списку
(`USER_FIELDS`, `HOST_FIELDS`, `SRC_IP_FIELDS`, `DST_IP_FIELDS`, `PROCESS_FIELDS`). Значения
собираются в множества и возвращаются отсортированными списками.

### `_pick_sample_events(events, limit=_SAMPLE_EVENTS_LIMIT) -> list[dict]`

`_SAMPLE_EVENTS_LIMIT = 10`. При `len(events) <= limit` — все события; иначе первые `limit // 2`
плюс последние `limit // 2`.

## Инварианты

- `INGEST_SOURCE_FIELD` снимается из каждого события до формирования `sample_events` — наружу
  не попадает.
- Отсутствие маркера `INGEST_SOURCE_FIELD` (путь `/ingest/file`, `/ingest/upload`) →
  `source_batch` = `default_source_batch`.
- Уровень `informational` не порождает алертов ни на одном хосте.

## Зависимости

- Импортирует: `hashlib`; `app/fields.py` (`*_FIELDS`, `INGEST_SOURCE_FIELD`, `first_present`);
  `app/models.py` (`Alert`, `Entities`, `Severity`, `SigmaRuleRef`).
- Импортируется: `app/main.py` (`zircolite_results_to_alerts`), `tests/`.
