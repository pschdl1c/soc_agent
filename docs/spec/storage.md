# Хранилище `siem.db`

**Модуль:** `app/store.py`
**Назначение:** доступ к рабочей SQLite-базе `siem.db` — алерты, сырые события, леджер
срабатываний для корреляции, реестр потоковых источников.

## Область ответственности

- Создание схемы при инициализации, поддержка режима WAL.
- Запись алертов (с дедупликацией) и событий батча.
- Чтение и фильтрация алертов / событий / группировок / сводок по батчам.
- Оценка окна корреляции по леджеру `rule_hits`.
- CRUD реестра источников, аутентификация по токену.
- Проверка живости БД для `/health`.

## Модель соединений

Класс `Store` держит два `sqlite3.Connection` к одному файлу с раздельными `threading.Lock`:

| Соединение | Лок | Назначение |
|---|---|---|
| `_conn` | `_lock` | только запись (`INSERT`/`UPDATE`/`DELETE`, DDL) |
| `_read_conn` | `_read_lock` | только чтение; открыто с `PRAGMA query_only=ON` |

При инициализации на `_conn` выставляются `PRAGMA journal_mode=WAL` и `PRAGMA synchronous=NORMAL`,
затем исполняется схема (`executescript(_SCHEMA)`), затем `_migrate(conn)`. WAL позволяет
читателям не блокировать писателя и наоборот; раздельные Python-локи дополняют это, снимая
сериализацию на уровне процесса.

`_migrate(conn)` (Этап A) — аддитивная миграция для БД, созданных до появления ECS-lite
колонок `events`/`group_json` `rule_hits`: `CREATE TABLE IF NOT EXISTS` в `_SCHEMA` не
добавляет новые колонки в уже существующую таблицу (no-op), поэтому недостающие добавляются
через `ALTER TABLE ... ADD COLUMN` (безопасно на живых данных — новые строки `NULL`, без
даунтайма), а зависящие от них индексы создаются ПОСЛЕ добавления колонок (иначе на старой БД
`CREATE INDEX` упал бы на ещё не существующую колонку раньше, чем сработает `ALTER TABLE`).
Выполняется на каждом старте `Store`, механизма версионирования схемы нет — только
идемпотентный `ALTER TABLE ADD COLUMN`/`CREATE INDEX IF NOT EXISTS`/`DROP INDEX IF EXISTS`.

`Store(db_path: str = "siem.db")` — конструктор. `close()` закрывает оба соединения.

## Схема `siem.db`

### Таблица `alerts`

| Колонка | Тип | Ограничения |
|---|---|---|
| `alert_id` | TEXT | PRIMARY KEY |
| `dedup_key` | TEXT | NOT NULL |
| `created_at` | TEXT | NOT NULL, ISO-строка |
| `engine` | TEXT | NOT NULL (`zircolite` / `correlation`) |
| `source_batch` | TEXT | NOT NULL |
| `host` | TEXT | NOT NULL |
| `rule_id` | TEXT | NOT NULL |
| `rule_title` | TEXT | NOT NULL |
| `rule_level` | TEXT | NOT NULL |
| `mitre_techniques` | TEXT | NOT NULL, JSON-массив строк |
| `description` | TEXT | NOT NULL |
| `entities` | TEXT | NOT NULL, JSON-объект (`Entities.model_dump()`) |
| `event_count` | INTEGER | NOT NULL |
| `sample_events` | TEXT | NOT NULL, JSON-массив объектов |
| `status` | TEXT | NOT NULL DEFAULT `'new'` |

Индексы: `idx_alerts_dedup(dedup_key)`, `idx_alerts_status(status)`, `idx_alerts_level(rule_level)`,
`idx_alerts_batch(source_batch)`.

### Таблица `events`

| Колонка | Тип | Ограничения |
|---|---|---|
| `event_id` | TEXT | PRIMARY KEY (`uuid4`) |
| `source_batch` | TEXT | NOT NULL |
| `host` | TEXT | NOT NULL (`first_present(event, HOST_FIELDS)` или `"unknown-host"`) |
| `event_time` | TEXT | NULL; сырой формат источника |
| `ingested_at` | TEXT | NOT NULL, ISO UTC |
| `is_matched` | INTEGER | NOT NULL DEFAULT 0 |
| `matched_rules` | TEXT | NOT NULL DEFAULT `'[]'`, JSON-массив названий правил |
| `raw_json` | TEXT | NOT NULL, полный JSON события после flatten |
| `user_name` | TEXT | NULL, ECS-lite (Этап A) — `first_present(event, USER_FIELDS)` |
| `src_ip` | TEXT | NULL, ECS-lite — `first_present(event, SRC_IP_FIELDS)` |
| `dst_ip` | TEXT | NULL, ECS-lite — `first_present(event, DST_IP_FIELDS)` |
| `process` | TEXT | NULL, ECS-lite — `first_present(event, PROCESS_FIELDS)` |
| `event_code` | TEXT | NULL, ECS-lite — `first_present(event, EVENT_CODE_FIELDS)` (`EventID`/`EventCode`) |

ECS-lite колонки (Этап A дорожной карты) — денормализованный индекс поверх `raw_json` под
группировку Инцидентов по сущности (Этап B) и ручной пивот аналитика; `raw_json` остаётся
источником правды, `filter_lang.py` их не подменяет.

Индексы: `idx_events_batch(source_batch)`, `idx_events_host(host)`, `idx_events_time(event_time)`,
`idx_events_json_eventid` — индекс на выражении `json_extract(raw_json, '$."EventID"')`,
`idx_events_user(user_name)`, `idx_events_src_ip(src_ip)`, `idx_events_ingested(ingested_at)`
(под ретеншн, см. ниже). `idx_events_matched(is_matched)` **убран** (Этап A) — два различимых
значения, планировщик такой индекс практически не выбирал, а стоимость на каждую вставку
платилась.

Выражение индекса на `EventID` должно текстуально совпадать с выражением, которое строит
`resolve_json_path` (`app/filter_lang.py`), иначе планировщик SQLite его не применит.

### Таблица `rule_hits`

Леджер срабатываний, релевантных активным correlation-правилам — включая срабатывания САМИХ
correlation-правил (для цепочек, см. `insert_correlation_hits` ниже и
`app/detection/correlation.py`).

| Колонка | Тип | Ограничения |
|---|---|---|
| `event_id` | TEXT | NOT NULL; логическая ссылка на `events.event_id` (без FOREIGN KEY) для обычных попаданий, либо синтетический `corr:<title>:<dedup_key>:<anchor_time>` для попаданий correlation-правила |
| `rule_title` | TEXT | NOT NULL |
| `source_batch` | TEXT | NOT NULL |
| `event_time` | TEXT | NULL; **нормализованный** вид (`" "` → `"T"`, удалён `"Z"`) |
| `group_json` | TEXT | NULL, JSON-объект `{поле: str(значение)}` — денормализованные значения group-by (∪ `condition.field` у value_count) ЭТОГО попадания |

PRIMARY KEY `(event_id, rule_title)`. Индекс `idx_rule_hits_lookup(rule_title, source_batch, event_time)`.

Строка добавляется только если название правила входит в `hit_spec`, переданный в
`store_events` (см. ниже). `event_time` нормализуется на запись, чтобы запрос окна использовал
простой `BETWEEN` как range-scan по индексу. **Счёт корреляции (Этап A) читает ИСКЛЮЧИТЕЛЬНО
`group_json`, без JOIN к `events`** — стоимость определяется плотностью попаданий в окне, а не
размером `events`/БД в целом (обязательное требование, см. `docs/spec/correlation.md`). `NULL`
у `group_json` — у строк, записанных до появления этого поля (миграция аддитивна, старые
строки не бэкфиллятся); такие строки просто не совпадают ни по одному group-by, что безопасно
(окно корреляции и так смотрит только в недавнее прошлое).

### Таблица `sources`

Реестр потоковых источников.

| Колонка | Тип | Ограничения |
|---|---|---|
| `source_id` | TEXT | PRIMARY KEY (`uuid4`) |
| `name` | TEXT | NOT NULL UNIQUE; служит меткой `source_batch` |
| `description` | TEXT | NOT NULL DEFAULT `''` |
| `token_sha256` | TEXT | NOT NULL; sha256 открытого токена |
| `token_hint` | TEXT | NOT NULL DEFAULT `''`; последние 4 символа токена |
| `enabled` | INTEGER | NOT NULL DEFAULT 1 |
| `created_at` | TEXT | NOT NULL, ISO UTC |
| `last_seen_at` | TEXT | NULL, ISO UTC |

Индекс `idx_sources_token(token_sha256)`.

Таблица аддитивна: метки `source_batch` в `events`/`alerts` от файловых загрузок и старых
стримов с этой таблицей не связаны.

## API `Store` — алерты

### `upsert_alerts(alerts: list[Alert]) -> int`

Для каждого алерта: поиск существующей строки по `dedup_key`. Если найдена — `event_count`
увеличивается на `alert.event_count`, `sample_events` перезаписывается. Если нет — вставка.
Возвращает число обработанных алертов.

### `list_alerts(source_batch=None, status=None, rule_level=None, time_from=None, time_to=None, sort_by=None, sort_dir=None, limit=100, offset=0) -> list[dict]`

Фильтры комбинируются по AND. `time_from`/`time_to` сравниваются строково с `created_at`.
`sort_by` ∈ {`rule` (по рангу severity), `host`, `event_count`, `status`, `created_at`};
неизвестное значение → `ORDER BY created_at DESC`. `sort_dir` — `asc`/`desc` (по умолчанию `desc`).
В строках `mitre_techniques` и `entities` десериализуются из JSON; `sample_events` удаляется.

### `get_alert(alert_id: str) -> dict | None`

Полная строка алерта с десериализованными `mitre_techniques`, `entities`, `sample_events`.
`None`, если алерта нет.

### `update_alert_status(alert_id: str, status: str) -> bool`

`UPDATE alerts SET status`. `True`, если затронута строка.

## API `Store` — события

### `store_events(raw_events, source_batch, matched_row_to_rules, hit_spec=None) -> int`

- `raw_events` — события батча из `ZircoliteCore` (содержат `row_id`).
- `matched_row_to_rules` — `{row_id: [названия правил]}`.
- Для каждого события: `host` = `first_present(event, HOST_FIELDS)` или `"unknown-host"`;
  `event_time` = `first_present(event, TIME_FIELDS)`; `is_matched` = `1`, если список правил
  непуст; `matched_rules` = JSON списка; `raw_json` = JSON события; ECS-lite колонки —
  `first_present` по соответствующим спискам `app/fields.py` (см. схему `events` выше).
- `hit_spec` (Этап A, было `hit_worthy_titles: set[str]`) — `{rule_title: {поля}}` для
  БАЗОВЫХ Sigma-правил, являющихся `base_rule_titles` хотя бы одной активной correlation-записи
  (см. `app/detection/correlation.py:active_hit_spec`). Для события, сматченного таким
  правилом, добавляется строка в `rule_hits` — `group_json` собирается как
  `{поле: str(event[поле])}` по набору полей ИЗ `hit_spec[rule_title]` (пропуская отсутствующие
  в событии), `event_time` нормализуется.
- Вставка через `executemany`, один `commit`. Возвращает число событий.

### `list_events(source_batch=None, only_matched=None, time_from=None, time_to=None, sort_by=None, sort_dir=None, fields=None, query_filter=None, extra_filters=None, limit=100, offset=0) -> list[dict]`

- `fields` — список путей полей `raw_json`; каждый добавляется в SELECT как `extra_i` через
  `resolve_json_path`; в результате собирается в `row["extra"] = {field: value}`.
- `query_filter` — готовый `(sql, params)` из `app/filter_lang.py:compile_filter_query`.
- `extra_filters` — список условий `{field, op, value}` drill-in по группе; всегда добавляются
  по AND (`compile_condition` из `app/filter_lang.py`).
- `time_from`/`time_to` сравниваются с `replace(replace(event_time, ' ', 'T'), 'Z', '')`.
- `sort_by` ∈ {`event_time`, `host`, `is_matched`} или произвольный путь `raw_json`
  (`json_extract`); без `sort_by` → `ORDER BY ingested_at DESC`.
- В строках `matched_rules` десериализуется, `is_matched` приводится к `bool`.

### `count_events(...)  -> int`

Те же фильтры, что у `list_events` (без `fields`/`sort`); `SELECT COUNT(*)`.

### `group_events(group_by, source_batch=None, only_matched=None, time_from=None, time_to=None, query_filter=None, limit=200) -> dict`

Возвращает `{"groups": [{"value", "count"}], "total_groups": int}`.

- `group_by == "is_matched"` → значения `'true'`/`'false'`.
- `group_by == "rule"` → `FROM events e LEFT JOIN json_each(e.matched_rules) mr`, значение
  `mr.value`; событие без правил попадает в группу `NULL` (LEFT JOIN).
- Иначе → `json_extract` по пути (`resolve_json_path`); отсутствие поля — отдельное значение
  `NULL`.
- `total_groups` — `COUNT(*)` по `SELECT DISTINCT` (без `limit`); список — топ `limit` по
  убыванию счётчика.

### `get_event(event_id: str) -> dict | None`

Полная строка события с десериализованными `matched_rules`, `raw_json`, `is_matched`.

## API `Store` — корреляция

Двухфазный счёт (Этап A, см. `docs/spec/correlation.md` за подробным разбором и обоснованием
производительности): `evaluate_correlation_windows` (фаза 1, грубая оценка по объединённому
окну нескольких ключей сразу) → `evaluate_correlation_window` (фаза 2, точная перепроверка
кандидатов в их собственном узком окне). Обе читают счёт ИСКЛЮЧИТЕЛЬНО из `rule_hits.group_json`
(`json_extract`), БЕЗ `JOIN` к `events` — стоимость определяется плотностью попаданий в окне,
не размером `events`/БД в целом. `JOIN` к `events` есть только в `evaluate_correlation_window`
и только ради `sample_events` (реальный контент события для карточки алерта), не влияет на
стоимость счёта.

### `evaluate_correlation_windows(rule_titles, source_batch, time_from, time_to, group_by, mode, distinct_field=None) -> dict[tuple, int]`

Фаза 1 — один `GROUP BY`-запрос по `rule_hits` сразу по ВСЕМ ключам group-by, попавшим в
`[time_from, time_to]` (обычно объединённое окно нескольких кандидатных ключей одного flush'а —
грубая оценка, может завысить счёт отдельных ключей с более ранним anchor, см.
`docs/spec/correlation.md`). `mode`: `"events"` — `COUNT(*)`; `"distinct_values"` —
`COUNT(DISTINCT json_extract(group_json, distinct_field))` (`value_count`); `"distinct_rules"` —
`COUNT(DISTINCT rule_title)` (`temporal`/`temporal_ordered`). Возвращает
`{tuple(значения group_by): count}` — ключи с хотя бы одним `None`-полем в `group_json`
(поле отсутствовало) пропускаются.

### `evaluate_correlation_window(base_rule_titles, group_by, key_values, source_batch, time_from, time_to, mode=None, distinct_field=None, sample_limit=10) -> dict`

Фаза 2 — точная оценка ОДНОГО (correlation-правило, group-by-ключ) сочетания. Возвращает
`{"count": int, "sample_events": list[dict]}`.

- Условия: `rule_title IN (base_rule_titles)`, `source_batch = ?`,
  `event_time BETWEEN time_from AND time_to` (нормализованные строки), и по одному условию
  `json_extract(group_json, <group_by[i]>) = str(key_values[i])`.
- `mode` (как у `evaluate_correlation_windows`, дефолт `"events"`, автоматически
  `"distinct_values"` при заданном `distinct_field` без явного `mode`).
- `sample_events` — до `sample_limit` `e.raw_json` (`JOIN rule_hits h ON events e`), отсортированных
  по `h.event_time ASC`.
- Возвращает нули, если `base_rule_titles` пуст, `group_by` пуст или длины `group_by` и
  `key_values` не совпадают.

### `fetch_correlation_hit_sequence(rule_titles, source_batch, time_from, time_to, group_by, key_values, limit=500) -> list[tuple[str, str]]`

`(rule_title, event_time)` для ОДНОГО group-by-ключа, по возрастанию времени — только для
`temporal_ordered`: реальный порядок появления событий проверяется в Python (жадное
сопоставление подпоследовательности), см. `app/detection/correlation.py:_sequence_matches_order`.

### `insert_correlation_hits(rows: list[tuple[event_id, rule_title, source_batch, event_time, group_json]]) -> None`

Записывает сработавшую корреляцию как обычное попадание в `rule_hits` (`INSERT OR IGNORE`,
идемпотентно) — так родительская корреляция при цепочке (correlation ссылается на другую
correlation) видит потомка тем же запросом, что и обычное базовое правило. `event_id` —
синтетический `corr:<title>:<dedup_key>:<anchor_time>`.

### `delete_events_older_than(cutoff: str, chunk: int = 5000) -> int`

Ретеншн `events` (Этап A) — удаляет строки с `ingested_at < cutoff` (НЕ `event_time`: тот
сырой формат источника, может отсутствовать/быть в прошлом-будущем при replay исторических
датасетов; `ingested_at` — собственное время приёма, монотонно растёт, надёжный ключ
независимо от качества данных источника). Порциями по `chunk` строк, `self._lock` берётся и
отпускается на каждую порцию отдельно (не на весь проход) — не блокирует ingest-воркер надолго
на многомиллионной таблице. Осиротевшие `rule_hits` (`event_id`, которого больше нет в
`events`) чистятся одним проходом в конце. `alerts` не трогает. Вызывается периодически из
`IngestWorker` (см. `app/main.py:_run_retention`, `SIEM_EVENTS_RETENTION_DAYS` в `app/config.py`).

### `upsert_correlation_alerts(alerts: list[Alert]) -> int`

Как `upsert_alerts`, но `event_count`/`sample_events` **перезаписываются**, а не суммируются
(окно пересчитывается на каждый flush).

## API `Store` — батчи

### `list_batches() -> list[dict]`

Группировка `events` по `source_batch`:
`[{source_batch, event_count, matched_event_count, first_ingested_at, last_ingested_at, alert_count}]`,
сортировка по `MAX(ingested_at) DESC`. `alert_count` подмешивается из `alerts`.

### `delete_batch(source_batch: str) -> dict`

Удаляет строки с этой меткой из `events`, `alerts` и `rule_hits`.
Возвращает `{"events_deleted": int, "alerts_deleted": int}`. Реестр `sources` не трогает.

## API `Store` — источники

| Метод | Поведение |
|---|---|
| `create_source(name, description="") -> dict` | Валидирует имя по `_SOURCE_NAME_RE` (`^[\w.\- ]{1,64}$`, UNICODE). Генерирует токен (`secrets.token_urlsafe(32)`), хранит `sha256`. Дубль имени → `ValueError`. Возвращает публичную строку + одноразовое поле `token`. |
| `list_sources() -> list[dict]` | Публичные строки (без `token_sha256`), сортировка по `created_at DESC`. |
| `get_source(source_id) -> dict | None` | Публичная строка или `None`. |
| `rotate_source_token(source_id) -> str | None` | Новый токен, старый sha256 перезаписан. `None`, если источник не найден. |
| `update_source(source_id, enabled=None, description=None) -> dict | None` | Частичное обновление. `None`, если источник не найден. |
| `delete_source(source_id) -> bool` | Удаляет строку реестра. События/алерты не трогает. |
| `authenticate_source(token) -> dict | None` | По `sha256(token)` ищет **активный** (`enabled=1`) источник. `None` при отсутствии токена / несовпадении / выключенном источнике. Обновляет `last_seen_at` не чаще раза в 60 с (`_SOURCE_LAST_SEEN_THROTTLE_S`). |

Публичная строка источника: `{source_id, name, description, token_hint, enabled (bool), created_at, last_seen_at}`.

## API `Store` — health

### `health(detailed: bool = False) -> dict`

`SELECT 1` под `_lock`. Успех → `{"status": "ok", "latency_ms": float, ...}`; исключение →
`{"status": "error", "error": str}`. При `detailed=True` добавляются `alerts` и `events`
(полный `COUNT(*)`) и `size_mb` (размер файла).

## Безопасность

- Все пользовательские значения уходят в SQL как bound-параметры sqlite3.
- Сортировка — только по whitelisted-выражениям (`_ALERT_SORT_COLUMNS`, `_EVENT_SORT_COLUMNS`).
- Путь поля `raw_json` — bound-параметр, кроме whitelist `INDEXED_JSON_FIELDS` (см.
  `app/filter_lang.py`), где путь — литерал из фиксированного словаря.

## Зависимости

- Импортирует: `sqlite3`, `threading`, `hashlib`, `secrets`, `json`, `re`;
  `app/fields.py` (`HOST_FIELDS`, `TIME_FIELDS`, `USER_FIELDS`, `SRC_IP_FIELDS`, `DST_IP_FIELDS`,
  `PROCESS_FIELDS`, `EVENT_CODE_FIELDS`, `first_present`); `app/filter_lang.py` (`FILTER_OPS`,
  `IS_MATCHED_FIELD`, `RULE_FIELD`, `compile_condition`, `resolve_json_path`); `app/models.py`
  (`Alert`, `SOURCE_DESCRIPTION_MAX`).
- Импортируется: `app/detection/correlation.py` (`Store`), `app/main.py`, `tests/`.
