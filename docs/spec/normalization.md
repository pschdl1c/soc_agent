# Нормализация

**Модуль:** `app/detection/normalize.py`
**Назначение:** преобразование сырого результата Zircolite в список объектов `Alert`,
сгруппированных по (хост, источник, [подпись содержимого]).

## Область ответственности

- Построение `Alert` из каждого сработавшего правила.
- Разбивка событий одного правила на отдельные алерты по (хосту, `source_batch`, режиму дедупа).
- Извлечение сущностей и сэмпла событий.

Уровень `informational` НЕ отсекается (было отсечено раньше как «шум» — снято: базовые правила
сценариев/корреляций пишутся именно на этом уровне, их сработки нужны и как обычные алерты, и
как member-алерты инцидента, см. `store.link_alerts_to_incident`). Отдельная, независимая
отсечка `informational` для уровня САМОГО correlation-правила остаётся в `app/detection/
correlation.py:evaluate_batch` — это про другой уровень (correlation, не базового правила) и
её эта отсечка normalize.py не касается.

## Публичный интерфейс

### `zircolite_results_to_alerts(raw_results, default_source_batch, dedup_by_content=True) -> list[Alert]`

Для каждого элемента `raw_results`:

1. Пропуск, если `matches` пуст.
2. Построение `SigmaRuleRef`:
   - `rule_id` = `rule["id"]` (или `""`);
   - `title` = `rule["title"]` (или `"Unnamed Rule"`);
   - `level` = `Severity.from_zircolite(rule["rule_level"])`;
   - `mitre_techniques` = `[t for t in rule["tags"] if t.startswith("attack.t")]`;
   - `description` = `rule["description"]` (или `""`).
3. Группировка `matches` по ключу `(host, source_batch, detail)`:
   - `source_batch` = `event.pop(INGEST_SOURCE_FIELD, default_source_batch)` — маркер снимается
     из события;
   - `host` = `first_present(event, HOST_FIELDS)` или `"unknown-host"`;
   - `detail` = `_content_signature(event)`, если `dedup_by_content=True`, иначе `""` (тогда
     группировка вырождается в `(host, source_batch)` — все события правила на хосте сливаются
     в один алерт, как в built-in-режиме).
4. Для каждой группы:
   - `entities` = `_extract_entities(group_events)`;
   - `Alert.dedup_key` = `_dedup_key(rule_id, host, detail)`;
   - `event_count` = число событий группы;
   - `sample_events` = `_pick_sample_events(group_events)`.

`engine` алерта — значение по умолчанию `"zircolite"`.

## Режимы дедупа (`dedup_by_content`)

Выбирается вызывающей стороной (`app/main.py:_process_batch`) по тому, custom или built-in
`ruleset_path` использовался для батча — сам `normalize.py` про происхождение рулсета не знает.

- **`True` (custom-правила, включая «основной рулсет»** — тот теперь собирается ТОЛЬКО из
  custom, см. `app/rules/main_ruleset.py`**)** — дедуп по хэшу ВСЕГО события за вычетом
  служебных/временных полей. Не привязан к конкретной сущности (юзер/ip/процесс/...) — работает
  для любого правила без знания его семантики: два вхождения считаются «тем же самым» только
  если совпадают все поля, кроме времени. Одинаковых событий будет много отдельных алертов —
  зато каждый строго унифицирован.
- **`False` (built-in-правила,** `Zircolite/rules/*.json`**)** — грубее, просто `(rule_id,
  host)`, без учёта содержимого события и без времени. Built-in используется только для разовых
  batch-прогонов файлов (не для `/ingest/stream` — в основной рулсет built-in не допускается),
  точность на уровне сущности там не нужна, а объём built-in-контента (~4291 правило) сделал бы
  дедуп по содержимому избыточно дробным.

## Вспомогательные функции

### `_content_signature(event: dict) -> str`

Канонический JSON события (`json.dumps(..., sort_keys=True)`) без полей из
`_CONTENT_SIGNATURE_EXCLUDED_FIELDS` = `TIME_FIELDS` (`app/fields.py`) `∪ {"row_id",
"OriginalLogfile"}`:

- `row_id` — Zircolite сам проставляет автоинкрементный номер на каждое событие
  (`Zircolite/zircolite/core.py`);
- `OriginalLogfile` — Zircolite пишет туда имя обрабатываемого файла (`streaming.py`); на
  потоке это СИНТЕТИЧЕСКОЕ имя временного файла, своё на каждый flush `IngestWorker`'а — без
  исключения кросс-батчевый дедуп на стриме никогда бы не совпадал (два идентичных события в
  разных flush'ах получали бы разный хэш только из-за разного tmp-имени).

### `_dedup_key(rule_id: str, host: str, detail: str) -> str`

`sha256(f"{rule_id}:{host}:{detail}").hexdigest()[:16]`. `detail` — либо `_content_signature`
(custom-режим), либо `""` (built-in-режим).

### `_extract_entities(events: list[dict]) -> Entities`

Проход по событиям, для каждой категории — `first_present` по соответствующему списку
(`USER_FIELDS`, `HOST_FIELDS`, `SRC_IP_FIELDS`, `DST_IP_FIELDS`, `PROCESS_FIELDS`). Значения
собираются в множества и возвращаются отсортированными списками. Чисто витрина для UI/агента —
на дедуп больше не влияет (в custom-режиме дедуп идёт по содержимому целиком, в built-in —
вообще без сущности).

### `_pick_sample_events(events, limit=_SAMPLE_EVENTS_LIMIT) -> list[dict]`

`_SAMPLE_EVENTS_LIMIT = 10`. При `len(events) <= limit` — все события; иначе первые `limit // 2`
плюс последние `limit // 2`.

## Инварианты

- `INGEST_SOURCE_FIELD` снимается из каждого события до формирования `sample_events` — наружу
  не попадает.
- Отсутствие маркера `INGEST_SOURCE_FIELD` (путь `/ingest/file`, `/ingest/upload`) →
  `source_batch` = `default_source_batch`.
- Уровень `informational` порождает алерты наравне с остальными.

## Зависимости

- Импортирует: `hashlib`, `json`; `app/fields.py` (`*_FIELDS`, `TIME_FIELDS`,
  `INGEST_SOURCE_FIELD`, `first_present`); `app/models.py` (`Alert`, `Entities`, `Severity`,
  `SigmaRuleRef`).
- Импортируется: `app/main.py` (`zircolite_results_to_alerts`, решает `dedup_by_content` по
  `ruleset_path` в `_process_batch`), `tests/`.
