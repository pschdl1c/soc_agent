# HTTP-API и оркестрация

**Модуль:** `app/main.py`
**Назначение:** FastAPI-приложение — HTTP-эндпоинты, оркестрация прогона батча, аутентификация
потокового ingest, lifespan фонового воркера.

## Область ответственности

- Создание объектов `ZircoliteEngine` и `Store` на реальных путях из `app/config.py`.
- Запуск/остановка `IngestWorker` через lifespan.
- Реализация всех HTTP-эндпоинтов как тонких обёрток над модулями `app/*`.
- Функции оркестрации `_process_batch` / `_process_events`.
- Раздача статики `app/static/index.html`.

## Инициализация

```python
app = FastAPI(title="Mini-SIEM Engine", version=__version__, lifespan=lifespan)
```

`__version__` читается из метаданных установленного пакета
(`importlib.metadata.version("soc-agent")`); при запуске из исходников без установки —
литеральный fallback. Отдаётся в `/openapi.json` и `/docs`.

Глобальные объекты, создаваемые при импорте:

- `engine = ZircoliteEngine(config_path=config.ZIRCOLITE_CONFIG_PATH, default_ruleset_path=config.DEFAULT_RULESET_PATH)`;
- `store = Store(db_path=config.DB_PATH)`;
- `ingest_worker = IngestWorker(process_fn=_process_events)`.

lifespan: `ingest_worker.start()` при старте, `ingest_worker.stop()` при остановке.

`UPLOADS_DIR` (`config.UPLOADS_DIR`) создаётся при импорте (`mkdir(exist_ok=True)`).

## Оркестрация

### `_process_batch(events_path, input_type, ruleset_path, source_label) -> IngestResponse`

1. Выбор способа получения правил по `ruleset_path`:
   - `"main"` → `main_ruleset.resolve()` → `engine.run_batch_with_rules(...)`.
   - `custom_rulesets/*` → `rules_catalog.load_rules(...)` → `engine.run_batch_with_rules(...)`
     (`CatalogError` → HTTP 400).
   - иначе (builtin или `None`) → `engine.run_batch(..., ruleset_path=ruleset_path)`.
2. `_build_matched_row_map(raw_results)` → `{row_id: [названия правил]}`.
3. `hit_titles = correlation.active_base_rule_titles(ruleset_path)` (один раз на батч).
4. `_split_events_by_source(all_events, source_label)` → группы `{label: [events]}`.
5. Для каждой группы: `store.store_events(events, source_batch=label, matched_row_to_rules=..., hit_worthy_titles=hit_titles)`,
   затем `correlation.evaluate_batch(store, ruleset_path, source_batch=label, matched_events_by_title=...)`.
6. `alerts = zircolite_results_to_alerts(raw_results, default_source_batch=source_label)`;
   `created = store.upsert_alerts(alerts)`.
7. Ответ `IngestResponse(source_batch=source_label, events_processed=total_events,
   rules_matched=len(raw_results), alerts_created=created + correlation_created,
   duration_seconds=round(elapsed, 2))`.

### `_process_events(tagged_events, ruleset_path=None) -> IngestResponse`

`tagged_events` — `list[(event, source_label)]`. `ruleset_path` по умолчанию — `"main"`.
Каждое событие пишется во временный `.jsonl` с добавленным ключом `INGEST_SOURCE_FIELD = label`;
`batch_label` — единственный label или `f"mixed:{N}-sources"`. Затем `_process_batch(tmp, "json", ruleset_path, batch_label)`;
временный файл удаляется в `finally`.

### `_split_events_by_source(events, default_label) -> dict[str, list[dict]]`

Для каждого события `label = event.pop(INGEST_SOURCE_FIELD, default_label)`; маркер снимается.

### `_authenticate_ingest(request) -> dict`

Токен из заголовка `Authorization: Bearer <token>` ИЛИ `X-Ingest-Token: <token>` (не из query).
`store.authenticate_source(token)`; `None` → HTTP 401 с заголовком `WWW-Authenticate: Bearer`.
Возвращает публичную строку активного источника (её `name` — метка `source_batch`).
Гейтом закрыты `/ingest/stream` и `/ingest/events`.

## Эндпоинты

### Служебные

| Метод | Путь | Ответ / поведение |
|---|---|---|
| `GET` | `/health` | `{"status": "ok"|"degraded", "checks": {"db", "zircolite", "ingest_queue"}}`. `?detailed=true` добавляет счётчики строк и размер БД |
| `GET` | `/` | `text/html` — `app/static/index.html`, заголовок `Cache-Control: no-store`; 404, если файла нет |

### Ingest

| Метод | Путь | Тело / параметры | Поведение |
|---|---|---|---|
| `POST` | `/ingest/file` | `IngestFileRequest` | прогон файла на диске сервера. Без токена. 404, если файл не найден. `source_label` по умолчанию — `Path(events_path).stem` |
| `POST` | `/ingest/events` | `IngestEventsRequest` | **требует токен источника**. Синхронный прогон. Метка — имя источника (`source_label` из тела игнорируется). Пустой список → 400 |
| `POST` | `/ingest/stream` | NDJSON или JSON-массив | **требует токен источника**. Кладёт события в очередь, отвечает `202 {"queued": N, "source": <name>}`. Неразбираемое тело → 400. `IngestQueueFull`/`RuntimeError` → 503 |
| `POST` | `/ingest/upload` | multipart: `file`, `input_type="auto"`, `ruleset`, `source_label` | загрузка файла из браузера. Без токена. `input_type == "auto"` → определение по расширению (`_guess_input_type`). Файл сохраняется в `UPLOADS_DIR` и не удаляется |

`_parse_stream_body(raw)` — тело, начинающееся с `[`, парсится как JSON-массив; иначе построчно
(NDJSON, пустые строки пропускаются).

`_EXTENSION_TO_INPUT_TYPE`: `.evtx→evtx`, `.json/.jsonl/.ndjson→json`, `.xml→xml`, `.csv→csv`,
`.log→auditd`; иначе `json`.

### Батчи

| Метод | Путь | Поведение |
|---|---|---|
| `GET` | `/batches` | `store.list_batches()` |
| `DELETE` | `/batches/{source_batch}` | `store.delete_batch(...)`; 404, если ничего не удалено. Реестр `sources` не трогает |

### Потоковые источники

| Метод | Путь | Тело | Поведение |
|---|---|---|---|
| `GET` | `/sources` | — | реестр + счётчики `event_count`/`alert_count`/`last_event_at` из `/batches` по `name == source_batch`. Токен не отдаётся |
| `POST` | `/sources` | `SourceCreate` | `201`; ответ несёт одноразовый `token`. Дубль/невалидное имя → 400 |
| `POST` | `/sources/{source_id}/rotate` | — | новый одноразовый `token`; 404, если источник не найден |
| `PATCH` | `/sources/{source_id}` | `SourceUpdate` | смена `enabled`/`description`; 404, если не найден |
| `DELETE` | `/sources/{source_id}` | — | снятие регистрации; события/алерты остаются; 404, если не найден |

### Алерты

| Метод | Путь | Параметры | Поведение |
|---|---|---|---|
| `GET` | `/alerts` | `source_batch`, `status`, `rule_level`, `time_from`, `time_to`, `sort_by`, `sort_dir`, `limit=100`, `offset=0` | `store.list_alerts(...)`. Без ключа `mitre` |
| `GET` | `/alerts/{alert_id}` | — | `store.get_alert(...)`; 404, если нет. Добавляет `alert["mitre"] = kb.enrich_techniques(alert["mitre_techniques"])` |
| `PATCH` | `/alerts/{alert_id}/status` | `AlertStatusUpdate` | `store.update_alert_status(...)`; 404, если не найден |

### События

| Метод | Путь | Параметры | Поведение |
|---|---|---|---|
| `GET` | `/events` | `source_batch`, `only_matched`, `time_from`, `time_to`, `sort_by`, `sort_dir`, `fields` (CSV), `query`, `group_cond`, `limit=100`, `offset=0` | `limit` вне `[1, 500]` → 400. `query` компилируется `_parse_query_filter` (`FilterSyntaxError` → 400). `group_cond` — одиночное условие drill-in (`_parse_filters(f"[{group_cond}]")`). Ответ `{events, total, limit, offset}` |
| `GET` | `/events/group` | `group_by` (обяз.), `source_batch`, `only_matched`, `time_from`, `time_to`, `query`, `limit=200` | `store.group_events(...)` → `{group_by, groups, total_groups}` |
| `GET` | `/events/{event_id}` | — | `store.get_event(...)`; 404, если нет |

`_parse_query_filter(query)` — `compile_filter_query(query)`; `FilterSyntaxError` → HTTP 400 с
текстом. `_parse_filters(filters)` — JSON-массив условий; невалидный JSON / не массив → 400.

### Рулсеты

| Метод | Путь | Параметры / тело | Поведение |
|---|---|---|---|
| `GET` | `/rulesets` | — | `rules_catalog.list_rulesets()` + `main_status` каждому + виртуальная запись `main` |
| `GET` | `/rulesets/rules` | `ruleset` (обяз.), `q`, `sort_by`, `sort_dir="asc"`, `limit=50`, `offset=0`, `only_main=false`, `level` (CSV), `status` (CSV) | `limit` вне `[1, 500]` → 400. `ruleset == "main"` → виртуальный список из `main_ruleset.resolve_with_sources()` (каждая строка несёт `source_ruleset`, `in_main`). Иначе `rules_catalog.search_rules(...)` с `in_main_fn`/`only_ids`. `CatalogError` → 404 |
| `GET` | `/rulesets/rule` | `ruleset`, `rule_id` | `rules_catalog.get_rule(...)`; 404, если нет |
| `POST` | `/rulesets/upload` | multipart: `file` (.yml/.yaml), `ruleset` \| `new_ruleset_name` | `rules_catalog.save_ruleset_yaml(...)`; `CatalogError`/`RuleValidationError`/`ValueListError` → 400. Пересборка зависимых правил (`_recompile_for_value_lists`). Ответ несёт `collisions`, `value_lists_imported`, `recompiled`, `errors` |
| `DELETE` | `/rulesets` | `ruleset` | `rules_catalog.delete_custom_ruleset(...)` (`CatalogError` → 404) + `engine.invalidate(ruleset)` + `main_ruleset.on_ruleset_deleted(ruleset)` |

### Custom-правила

| Метод | Путь | Тело | Поведение |
|---|---|---|---|
| `POST` | `/rules/custom` | `CustomRuleSubmit` | `201`; `rules_catalog.save_custom_rule(...)` (`RuleValidationError`/`CatalogError` → 400) + `engine.invalidate(target_path)`. Ответ несёт `ruleset_path` |
| `PUT` | `/rules/custom/{rule_id}` | query `ruleset` (обяз.), тело `CustomRuleUpdate` | `rules_catalog.update_custom_rule(...)` (`RuleValidationError` → 400, `CatalogError` → 404) + `engine.invalidate(ruleset)` |
| `DELETE` | `/rules/custom/{rule_id}` | query `ruleset` (обяз.) | `rules_catalog.delete_custom_rule(...)` (`CatalogError` → 404) + `engine.invalidate(ruleset)` |

### Основной рулсет

| Метод | Путь | Тело | Поведение |
|---|---|---|---|
| `POST` | `/main-ruleset/rules` | `MainRulesetRuleToggle` | `main_ruleset.toggle_rule(...)` (`CatalogError` → 404) → `{ruleset, rule_id, in_main}` |
| `POST` | `/main-ruleset/rulesets` | `MainRulesetToggle` | `main_ruleset.toggle_ruleset(...)` (`CatalogError` → 404) → `{ruleset, main_status}` |

### Списки значений

| Метод | Путь | Тело / параметры | Поведение |
|---|---|---|---|
| `GET` | `/value-lists` | — | `value_lists.list_lists()` + `used_by_count` (`rules_catalog.value_list_usage_counts()`) |
| `GET` | `/value-lists/{name}` | — | `value_lists.get_list(...)`; 404, если нет. + `used_by` (`rules_catalog.rules_using_value_list(...)`) |
| `POST` | `/value-lists` | `ValueListCreate` | `201`; `value_lists.create_list(...)` (`ValueListError` → 400) |
| `PUT` | `/value-lists/{name}` | `ValueListUpdate` | `value_lists.update_list(...)` (`ValueListError` → 400, `None` → 404). Пересборка зависимых правил; ответ несёт `recompiled`, `errors` |
| `POST` | `/value-lists/upload` | multipart: `file` (.yml/.yaml), `mode="create"` | `value_lists.parse_list_file` + `import_lists(parsed, mode)` (`ValueListError` → 400). Пересборка при `replace`/`merge` |
| `DELETE` | `/value-lists/{name}` | `force=false` | если список используется и `not force` → 409. `value_lists.delete_list(...)`; 404, если нет |

`_recompile_for_value_lists(names)` — для каждого имени `rules_catalog.recompile_rules_for_value_list(name)`,
затем `engine.invalidate(...)` для затронутых рулсетов; возврат `{recompiled, errors}`.

### База знаний

| Метод | Путь | Параметры | Поведение |
|---|---|---|---|
| `GET` | `/kb/mitre/meta` | — | `kb.meta()` (при отсутствии `kb.db` — `{"available": false}`, не 5xx) |
| `GET` | `/kb/mitre/matrix` | — | `kb.matrix()` |
| `GET` | `/kb/mitre/techniques` | `tactic`, `q`, `limit=100`, `offset=0` | `limit` вне `[1, 500]` → 400; `offset < 0` → 400. `kb.list_techniques(...)` |
| `GET` | `/kb/mitre/techniques/{technique_id}` | — | `kb.get_technique(technique_id.upper())`; 404, если техники нет |

## Соответствие исключений и HTTP-кодов

| Исключение | Код |
|---|---|
| `CatalogError` | 400 (создание/загрузка) или 404 (чтение/удаление) |
| `RuleValidationError` | 400 |
| `ValueListError` | 400 (создание/правка), 409 (удаление используемого — через явную проверку) |
| `FilterSyntaxError` | 400 |
| `IngestQueueFull`, `RuntimeError` (воркер) | 503 |
| отсутствие токена источника | 401 |
| ресурс не найден | 404 |

## Запуск

```python
if __name__ == "__main__":
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=True)
```

## Зависимости

- Импортирует: `fastapi`, `json`, `tempfile`, `pathlib`, `uuid`, `importlib.metadata`;
  `app/config.py`, `app/detection/{engine, normalize, correlation}`, `app/fields.py`,
  `app/filter_lang.py`, `app/ingest_queue.py`, `app/models.py`,
  `app/rules/{rules_catalog, main_ruleset, value_lists}`, `app/kb.py`, `app/store.py`.
- Импортируется: точка входа ASGI (`uvicorn app.main:app`).
