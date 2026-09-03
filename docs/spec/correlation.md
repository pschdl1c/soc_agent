# Стейтфул-корреляция

**Модуль:** `app/detection/correlation.py`
**Назначение:** оценка Sigma correlation-правил типов `event_count` и `value_count` поверх
постоянных таблиц `events` / `rule_hits`, независимо от размера micro-batch.

## Область ответственности

- Определение активных correlation-правил для рулсета.
- Оценка окна после каждого flush ingest-воркера с коротким замыканием.
- Формирование correlation-алертов (`engine="correlation"`).
- Типы `temporal` и `temporal_ordered` не эвалуируются.

## Причина отдельной реализации

- `ZircoliteCore` создаётся заново на каждый flush с пустой in-memory БД — между вызовами
  состояния нет.
- Пропатченный `pysigma-backend-sqlite==1.2.0` для `event_count`/`value_count` генерирует SQL
  без учёта `timespan`.

Модуль использует собственный компилятор с bound-параметрами и `json_extract` через
`resolve_json_path` (`app/store.py` / `app/filter_lang.py`).

## Публичный интерфейс

### `evaluate_batch(store, ruleset_path, source_batch, matched_events_by_title) -> int`

Точка входа, вызывается из `app/main.py:_process_batch` после каждого `store.store_events(...)`.

- `matched_events_by_title` — `{rule_title: [сырые события, сматченные в этом батче под этим source_batch]}`.
- Возвращает число созданных/обновлённых correlation-алертов.
- Ранний выход `0`, если `ruleset_path` пуст, `matched_events_by_title` пуст или активных
  correlation-правил нет.

Для каждого активного correlation-правила:

1. Пропуск, если `type` не в `{"event_count", "value_count"}`.
2. Пропуск, если уровень `informational`.
3. Пропуск, если `group_by` пуст.
4. `new_matches` — объединение событий по всем `base_rule_titles`; пропуск, если пусто
   (короткое замыкание — базовое правило не срабатывало в этом батче).
5. `timespan_seconds` = `_parse_timespan(timespan)`; пропуск, если `None`.
6. Для `value_count`: `distinct_field` = `condition["field"]`; пропуск, если не задан.
7. Для каждого кандидатного ключа (набор значений полей `group_by`):
   - якорь конца окна = максимальный нормализованный `event_time` среди новых событий с этим
     ключом;
   - `window_start` = якорь − `timespan_seconds`;
   - `count`, `sample_events` = `store.evaluate_correlation_window(...)`;
   - если `_condition_met(condition, count)` — формируется `Alert` через `_build_alert`.
8. `store.upsert_correlation_alerts(alerts)`.

### `active_base_rule_titles(ruleset_path: str | None) -> set[str]`

Множество названий правил, являющихся `base_rule_titles` хотя бы одной активной
correlation-записи. Вызывается `app/main.py` до `store.store_events`, чтобы определить
`hit_worthy_titles`.

## Разбор `timespan`

`_TIMESPAN_RE = ^(\d+)\s*([smhdw])$` (регистронезависимо). Единицы: `s=1`, `m=60`, `h=3600`,
`d=86400`, `w=604800` секунд. `M` (месяц) и `y` (год) не поддержаны. Невалидная строка → `None`.

## Проверка условия (`_condition_met`)

`condition` — словарь вида `{"gte": 10}` (event_count) или `{"field": "Image", "gte": 5}`
(value_count; `field` обрабатывается отдельно в `store`). Операторы: `gte`, `gt`, `lte`, `lt`,
`eq`. Условие без единого распознанного оператора считается **невыполненным**.

## Определение активных правил (`_active_correlation_rules`)

- `ruleset_path` пуст или builtin → `[]`.
- `ruleset_path == "main"` → объединение correlation-правил из всех custom-рулсетов,
  включённых в основной рулсет (`main_ruleset.resolve_with_sources()` +
  `rules_catalog.load_correlation_rules(src)`).
- Обычный custom `ruleset_path` → `rules_catalog.load_correlation_rules(ruleset_path)`.

## Формирование алерта (`_build_alert`)

- `SigmaRuleRef` из полей correlation-правила (`id`, `title`, `level`, `tags` c префиксом
  `attack.t`, `description`).
- `entities` = локальный `_extract_entities(sample_events)`.
- `host` = `first_present(sample_events[0], HOST_FIELDS)`; при отсутствии —
  `"-".join(key)` или `"unknown-host"`.
- `dedup_key` = `sha256(f"{rule_id}:" + ":".join(key_values))[:16]` — семантика ключа —
  набор значений group-by, не (host, main_entity).
- `engine="correlation"`, `event_count = count`.

## Инварианты

- Якорь окна — `event_time` самого позднего нового события с ключом, не `datetime.now()`
  (корректная работа при replay исторических датасетов).
- Нормализация времени (`_normalize_event_time`) дублирует `app/store._normalize_event_time`:
  `" "` → `"T"`, удаление `"Z"`. Форма должна совпадать с `rule_hits.event_time`.
- Корреляция считается в пределах одного `source_batch`.

## Зависимости

- Импортирует: `hashlib`, `re`, `datetime`; `app/rules/{main_ruleset, rules_catalog}`;
  `app/fields.py`; `app/models.py`; `app/store.py` (`Store`).
- Импортируется: `app/main.py` (`evaluate_batch`, `active_base_rule_titles`).
