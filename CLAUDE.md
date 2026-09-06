# CLAUDE.md

Гайд для Claude Code и разработчиков по проекту **soc_agent** — мини-SIEM на Sigma-правилах
с последующей разработкой AI-агента, который расследует алерты и выносит вердикт.

---

## 1. Что это за проект

**Цель.** Собрать лёгкий SIEM, который:
1. Принимает логи (EVTX / Sysmon / JSON / auditd и т.п.).
2. Прогоняет их через **Sigma-правила** движком **Zircolite** и генерирует алерты.
3. Показывает аналитику алерты и сырые события в веб-консоли.
4. **(следующий этап)** запускает AI-агента, который автоматически расследует каждый
   алерт (обогащение, корреляция, MITRE ATT&CK) и выносит вердикт: `true positive` /
   `false positive` / `needs review` с обоснованием.

**Текущий статус:** работает пайплайн ingest → Sigma-детект → хранение → UI аналитика.
Этап A дорожной карты (§7, движок сценарной корреляции) реализован, проверен на живом сервере
и закоммичен (`45cb331`). Этап 4 (инциденты: сущности `incidents`/`investigations`, блок
`correlation.incident`, ручки `/incidents*`, заглушка джобы вердиктов) реализован —
`docs/spec/incidents.md`. AI-агента расследования ещё нет (см. дорожную карту, этап 5).

---

## 2. Стек и зависимости

- **Python 3.12**, виртуальное окружение в `.venv/`.
- **FastAPI** + **Uvicorn** — API и раздача статики.
- **Pydantic v2** — модели (`Alert`, `Entities`, `SigmaRuleRef`, запросы/ответы).
- **Zircolite** — движок Sigma-детекта. Импортируется НЕ из pip, а из локального клона
  репозитория `./Zircolite` через `sys.path` (см. `app/detection/engine.py`).
- **pySigma** (`sigma`, backend-sqlite, pipeline-windows/sysmon) — компиляция Sigma → SQL.
- **SQLite** — хранилище (`siem.db`), плюс in-memory SQLite внутри Zircolite на каждый батч,
  плюс отдельный read-only `kb.db` (база знаний MITRE ATT&CK, см. `app/kb.py` / §«База знаний»).
- **Frontend** — один статический файл `app/static/index.html` (ванильный JS, без сборки).

> Версии зависимостей зафиксированы в `pyproject.toml` (`[project].dependencies` — прод;
> `[project.optional-dependencies].dev` — pytest/httpx/ruff). `requirements*.txt` из проекта убраны,
> Docker тоже ставит `pip install .`. Конфиг путей/хоста/порта — `.env` (см. `.env.example`,
> читается через `app/config.py`).
>
> **Версия проекта** — `[project].version` в `pyproject.toml` (единственный источник; `app/main.py`
> читает через `importlib.metadata`, отдаёт в `/openapi.json` и `/docs`). SemVer, пока `0.y.z`.
> История и порядок релиза — `CHANGELOG.md` (bump версии → раздел в changelog → коммит →
> `git tag vX.Y.Z` → `git push --tags`). Git-теги — единственный маркер релиза.

---

## 3. Как запускать

```bash
# из корня проекта D:\__projects\soc_agent
.venv\Scripts\activate                    # PowerShell: .venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

- UI аналитика: http://localhost:8000/
- Swagger (все ручки): http://localhost:8000/docs
- Health-check: http://localhost:8000/health (реальные проверки БД/Zircolite-ruleset/очереди
  ingest, не заглушка; `?detailed=true` — счётчики строк/размер БД)

Тестовые данные для прогона лежат в `artifacts/Security-Datasets/` (репозиторий OTRF
Security-Datasets) и в каталоге загрузок `data/uploads/` (`SIEM_UPLOADS_DIR`).

Окружение управляется **uv** (`.venv/` создан `uv venv`, самого `pip` внутри нет — `python -m pip`
там просто не найдётся). Зависимости: `uv pip install -e ".[dev]"`; запуск чего угодно в этом
окружении — `uv run <команда>`. `uv.lock` (его пишет `uv run`) КОММИТИТСЯ — воспроизводимая
сборка поверх пинов `pyproject.toml`; `*.egg-info/` от editable-установки — в `.gitignore`.

Тесты: `uv run pytest` (см. `tests/`, конфиг — `pyproject.toml` `[tool.pytest.ini_options]`).
Линт: `uv run ruff check app tests scripts` — репозиторий пока НЕ ruff-чистый (~108 замечаний,
почти всё однотипное: `B904` raise-from, `UP007` Optional, `UP017` `timezone.utc`), в CI ruff
ещё не поднят; новый код пишем в стиле окружающего, разовую зачистку — отдельной задачей.
HTTP-слой покрыт через `fastapi.testclient` (httpx в dev-зависимостях): starlette при этом
ругается `install httpx2` — это предупреждение, TestClient на httpx 0.28 работает.

База знаний MITRE ATT&CK (вкладка «База знаний»): `python scripts/build_kb.py --out kb/kb.db
--attack-version 15.1` — собирает компактный read-only `kb.db` из STIX-бандла
`mitre-attack/attack-stix-data` (нужна сеть). В Docker собирается автоматически на этапе
`build` и вшивается в образ. Без файла вкладка показывает заглушку, а карточки алертов
матчат MITRE-теги по сырому значению (гибрид, см. `app/kb.py:enrich_techniques`).

---

## 4. Архитектура и поток данных

```
        файл логов / порция событий
                   │
        POST /ingest/{file|events|upload}
                   │
                   ▼
        ┌──────────────────────┐
        │  ZircoliteEngine      │  app/detection/engine.py
        │  • ruleset кэшируется  │  Sigma-правила компилируются в SQL ОДИН раз при старте
        │    один раз (дорого)   │  (RulesetHandler), переиспользуются на каждый батч
        │  • на батч — новый     │  ZircoliteCore с in-memory SQLite
        │    ZircoliteCore       │
        └──────────┬───────────┘
                   │ raw_results (сработавшие правила + row_id),
                   │ all_events (ВСЕ события после flatten)
                   ▼
        ┌──────────────────────┐        ┌──────────────────────┐
        │  normalize.py         │        │  store.py (SQLite)    │
        │  raw_results → Alert  │───────▶│  таблица alerts       │  (дедуп по dedup_key)
        │  (группировка по хосту,│        │  таблица events       │  (все события + метки)
        │   extract entities)    │        └──────────────────────┘
        └──────────────────────┘                   │
                                                    ▼
                             GET /alerts · /events · /batches → UI (index.html)
```

### Ключевые модули (`app/`)

Плоско, кроме двух подпакетов: **`app/detection/`** (`engine.py`, `normalize.py`, `correlation.py` —
путь событие → Sigma-детект → нормализованный `Alert`) и **`app/rules/`** (`rules_catalog.py`,
`main_ruleset.py`, `value_lists.py` — весь Sigma-контент: каталог рулсетов, состав main, value lists;
внутренний DAG `value_lists ← rules_catalog ← main_ruleset`). Остальное — `config.py`, `models.py`,
`fields.py`, `store.py`, `ingest_queue.py`, `filter_lang.py`, `kb.py`, `timespan.py`, `main.py` —
в корне `app/`.

| Файл | Ответственность |
|------|-----------------|
| `config.py` | Конфигурация из окружения/`.env` (`python-dotenv`, см. `.env.example`): `DB_PATH`, `ZIRCOLITE_CONFIG_PATH`, `DEFAULT_RULESET_PATH`, `UPLOADS_DIR` (дефолт `data/uploads`), `KB_DB_PATH`, `LOG_LEVEL`, `HOST`/`PORT`, `INGEST_BATCH_SIZE`/`INGEST_FLUSH_INTERVAL`, `EVENTS_RETENTION_DAYS`, `INCIDENT_VERDICT_ENABLED`/`_INTERVAL`. Явная переменная окружения имеет приоритет над `.env`. Импортируется `main.py` и `ingest_queue.py` — единая точка правды для путей и портов вместо хардкода. |
| `main.py` | FastAPI-приложение, все HTTP-ручки, оркестрация батча (`_process_batch` / `_process_events`), lifespan-хуки воркера. `_process_batch` выбирает как получить правила по `ruleset_path`: `main` → `main_ruleset.resolve()`; `custom_rulesets/*` → `rules_catalog.load_rules()` (скомпилированный `.manifest.json` — там развёрнуты value-list-плейсхолдеры); builtin → `engine.run_batch(ruleset_path)` (кэш `_rulesets_cache`). После каждого `store.store_events(...)` также зовёт `correlation.evaluate_batch(...)` (см. `correlation.py`) — переоценка корреляций для затронутого батчем `source_batch`; `correlation.active_hit_spec(ruleset_path)` считается один раз до цикла и передаётся в `store_events(..., hit_spec=...)` (было `active_base_rule_titles`/`hit_worthy_titles` — переименовано на Этапе A: теперь несёт не только названия правил, но и набор полей на каждое, см. `correlation.py` ниже). Периодический ретеншн `events` (`_run_retention`, `SIEM_EVENTS_RETENTION_DAYS`) зовётся тем же фоновым потоком `IngestWorker`, не отдельным (см. `ingest_queue.py`); туда же (параметр `periodic_tasks`) повешена заглушка вердиктов инцидентов `_run_incident_verdicts` → `incidents.run_pending` (Этап 4). **Инциденты (Этап 4):** `_process_batch` передаёт `evaluate_batch(..., link_specs_out=link_specs)` и ПОСЛЕ `store.upsert_alerts` зовёт `store.link_alerts_to_incident` по каждому `link_spec` с проставленным `incident_id`. Ручки `/incidents`·`/incidents/{id}`·`/incidents/{id}/context`·`PATCH /incidents/{id}/status` — тонкие обёртки над `Store`; `/context` собирает correlation-правило + member-правила (SQL/YAML) + `related_events` через `compile_filter_query(_incident_entity_filter(group_key))` + историю, деградирует (пустые секции + `note`), если правило удалено или `events` вычищены ретеншном. **Аутентификация ingest:** `_authenticate_ingest(request)` — общий гейт для `/ingest/stream` и `/ingest/events`: токен из `Authorization: Bearer` (или `X-Ingest-Token`) → `store.authenticate_source()`; нет/неизвестен/выключен → `401`, события НЕ в очередь. Метку `source_batch` для этих двух путей задаёт ИМЯ источника, привязанного к токену (не `?source=`, не `source_label` из тела — они игнорируются). `/ingest/file`·`/ingest/upload` (их дёргают из локального UI) остаются без токена. Ручки `/sources*` — CRUD реестра источников (`GET` подмешивает счётчики из `/batches` по `name==source_batch`; `POST`/`rotate` отдают ОДНОРАЗОВЫЙ открытый токен; `DELETE` снимает регистрацию, события/алерты не трогает). **База знаний:** `get_alert` дополняет ответ ключом `alert["mitre"] = kb.enrich_techniques(...)` (сырой `mitre_techniques` не трогает — обратная совместимость). Ручки `/kb/mitre/{meta,matrix,techniques,techniques/{id}}` — тонкие обёртки над `app/kb.py`; при отсутствии `kb.db` отдают валидную форму с `available:false` (не 5xx). |
| `detection/engine.py` | Обёртка над Zircolite. **Важно:** `RulesetHandler` создаётся один раз (компиляция правил — самая дорогая операция), `ZircoliteCore` — на каждый батч с in-memory БД. `invalidate(ruleset_path)` сбрасывает кэш по конкретному пути — звать после изменений в `rules_catalog.py` (add/delete кастомного правила или рулсета). `health()` — для `/health` (rules_loaded/cached_rulesets дефолтного рулсета). `_run_core` фильтрует `rule.get("correlation")` перед прогоном — чисто defense-in-depth: correlation-правила в норме сюда и не долетают (см. `rules_catalog.py`/`CORRELATION_EXT` — их вообще не видит `RulesetHandler`), их эвалуацией занимается `correlation.py`. |
| `ingest_queue.py` | Потоковый ingest: очередь + фоновый поток `IngestWorker`, micro-batch flush («N событий ИЛИ T секунд»). Приём событий с форвардеров без блокировки HTTP. **Важно:** флаш отдаёт ВЕСЬ накопленный буфер `process_fn` ОДНИМ вызовом, без группировки по источнику — движок (тысячи скомпилированных правил, ~0.25с фиксированного оверхеда на батч независимо от числа событий) гоняется один раз на весь флаш, даже если в буфере вперемешку события от N разных источников. Разбивка обратно по `source_batch` — дело `main.py`/`normalize.py` (см. `INGEST_SOURCE_FIELD` в `fields.py`), уже ПОСЛЕ прогона движка, дёшево. `IngestWorker(periodic_tasks=[(fn, interval_s), ...])` — произвольные периодические задачи того же потока (Этап 4: заглушка вердиктов инцидентов); `retention_fn`/`retention_interval` — частный случай, внутри складывается в тот же список. |
| `store.py` | SQLite-хранилище. Таблицы: `alerts`, `events`, `rule_hits`, `sources`. Дедуп алертов по `dedup_key`. **`sources`** — реестр потоковых источников (вкладка «Источник данных»): `(source_id, name UNIQUE, description, token_sha256, token_hint, enabled, created_at, last_seen_at)`. Токен ТОЛЬКО хэшем (`_hash_token`=sha256); открытое значение возвращается один раз из `create_source()`/`rotate_source_token()`. `authenticate_source(token)` — по sha256 находит АКТИВНЫЙ источник, `last_seen_at` пишет с троттлингом ~60с (горячий путь `/ingest/stream`). `create_source` валидирует имя (`_SOURCE_NAME_RE`: 1–64, `\w .-`, кириллица ок), дубль имени → `ValueError`. Таблица аддитивна: метки `source_batch` в `events`/`alerts` от файловых загрузок / старых стримов с ней не связаны. `delete_source` снимает только регистрацию (события/алерты — через `delete_batch`). **Два соединения с раздельными локами**: `_conn`/`_lock` — только запись, `_read_conn`/`_read_lock` (с `PRAGMA query_only=ON`) — только чтение; БД в `PRAGMA journal_mode=WAL` (+`synchronous=NORMAL`) — читатели (просмотр/фильтр/группировка Событий) не блокируют писателя (ingest-воркер) и наоборот. Индекс на выражении (`idx_events_json_eventid`) для «горячих» JSON-полей (см. `filter_lang.INDEXED_JSON_FIELDS`) — иначе фильтр/группировка по кастомному полю сканируют всю таблицу. `health()` — для `/health` (`SELECT 1` через `_conn`, опционально счётчики строк/размер БД). `delete_batch(source_batch)` — удаляет из ВСЕХ ТРЁХ таблиц разом (для `DELETE /batches/{source_batch}`), не только events/alerts — иначе `rule_hits` копил бы осиротевшие строки. `rule_hits` — леджер для `correlation.py`: `(event_id, rule_title, source_batch, event_time, group_json)`, PK `(event_id, rule_title)`, индекс `(rule_title, source_batch, event_time)`; заполняется точечно через `store_events(..., hit_spec=...)` — только для полей, реально нужных активным correlation-правилам (group-by ∪ `condition.field`), не для всех сработавших правил и не для всех полей события. `group_json` (Этап A) — денормализованные значения этих полей `{поле: str(значение)}`, записываются ПРЯМО в `rule_hits` на запись; попадания САМИХ correlation-правил (для цепочек) пишутся туда же через `insert_correlation_hits()`. **Счёт корреляции ИСКЛЮЧИТЕЛЬНО по `rule_hits.group_json`, БЕЗ `JOIN` к `events` на счётном пути** (A3): `fetch_correlation_hits()` — один суженный range-scan (по кандидатным ключам за `[min(new) − timespan, max(new) + timespan]`), дальше `correlation.py` считает скользящим окном в памяти; `evaluate_correlation_window()` — авторитетный счёт + `sample_events` по одному найденному окну (`JOIN` к `events` только здесь, ради контента события, не влияет на стоимость счёта). `evaluate_correlation_windows()` (старая «фаза 1», `GROUP BY` по объединённому окну) УДАЛЕНА — после перехода на A3 её не звал ни коррелятор, ни бенчмарк, только собственные тесты. Замерено `scripts/bench_correlation.py`: рост `rule_hits` в 100 раз (10⁵→10⁷) даёт единицы процентов роста времени запроса, не пропорциональный рост. `upsert_correlation_alerts()` — как `upsert_alerts`, но OVERWRITE `event_count`/`sample_events` вместо increment (окно пересчитывается заново на каждый flush, не накапливается). `delete_events_older_than()` — ретеншн `events` по `ingested_at` (не `event_time`: тот про время события У ИСТОЧНИКА, а не приёма — при replay исторических датасетов он весь в прошлом), порциями, лок на каждую порцию отдельно; чистит осиротевшие `rule_hits` одним проходом в конце. **Время:** `event_time` КАНОНИЗИРУЕТСЯ на записи (`app/timeutil.py`), фильтр диапазона сравнивает голую колонку с нормализованной границей (`_events_where`), верхняя граница включающая; строки, накопленные до этого, приводит разовый бэкфилл `_backfill_event_time` (отметка в новой служебной таблице `schema_meta`, второй старт таблицы не перечитывает). `update_incident_status` отклоняет статус вне `models.INCIDENT_STATUSES` (`ValueError`), `_migrate` чинит уже записанный мусор (→`new`). `list_alerts_by_entity(values, ...)` — алерты, где встречается значение сущности (колонка `host` + любое значение внутри `entities` через `json_tree`, регистронезависимо) — история сущности в карточке инцидента, НЕ привязка member-алертов (та по `event_id`). `count_alerts()` — сколько алертов подходит под фильтры (`total` для пейджера вкладки «Алерты», те же фильтры, что у `list_alerts`). `fetch_hit_group_values(event_id, rule_title)` — `group_json` одного попадания леджера, нужен развороту синтетических `corr:`-попаданий цепочек. `_migrate()` — аддитивная миграция схемы (`ALTER TABLE ADD COLUMN`/новые индексы) для БД, созданных до Этапа A — `events` получил ECS-lite колонки (`user_name`/`src_ip`/`dst_ip`/`process`/`event_code`, денормализованный индекс поверх `raw_json` под группировку будущих Инцидентов, Этап B), `idx_events_matched` убран (мёртвый груз — 2 различимых значения). **Этап 4:** новые таблицы `incidents`/`investigations` в `_SCHEMA` (`CREATE TABLE IF NOT EXISTS` отрабатывает и на старой БД); `_migrate` добавил колонку `alerts.incident_id`. Методы: `upsert_incidents()` (insert/update по `dedup_key`-бакету, roll-up severity), `link_alerts_to_incident()` (проставляет `alerts.incident_id` + досчитывает `alert_count`/severity, `events` НЕ трогает), `enqueue_investigation()` (queued-дедуп + ре-энкью терминальных), `list/count/get_incident()`, `update_incident_status()`, `list_pending_investigations()`/`get_investigation()`/`update_investigation()`. `delete_batch()` теперь чистит и `incidents`/`investigations` (5 таблиц). См. `docs/spec/incidents.md`. |
| `detection/normalize.py` | `raw_results` Zircolite → список `Alert`. Уровень `informational` НЕ отсекается (раньше отсекался целиком как «шум» — снято: базовые правила сценариев/корреляций пишутся именно на этом уровне, их сработки нужны и как алерты, и как member-алерты инцидента, см. `store.link_alerts_to_incident`); `correlation.py` при этом сохраняет СВОЮ отдельную отсечку `informational` — та про уровень самого correlation-правила, не про базовое, и её никто не трогал (см. `evaluate_batch`). Один прогон правила разбивается на алерты по **(хосту, источнику, [подписи содержимого])** — источник берётся из `INGEST_SOURCE_FIELD`, временно вписанного в событие перед прогоном движка (см. `ingest_queue.py`/`main.py`), с фолбэком на `default_source_batch`, если маркера нет (одноисточниковые `/ingest/file`·`/ingest/upload`). **Дедуп (`dedup_key`) — два режима** через параметр `dedup_by_content`, выбираемый `main.py:_process_batch` по тому, custom или built-in `ruleset_path` у батча: `True` (custom-правила, включая «основной рулсет» — тот теперь собирается ТОЛЬКО из custom, см. `rules/main_ruleset.py`) — по хэшу ВСЕГО события минус служебные/временные поля (`_content_signature`: `TIME_FIELDS` + `row_id` (автоинкремент Zircolite на каждое событие) + `OriginalLogfile` (Zircolite пишет туда имя файла-источника; на потоке это СИНТЕТИЧЕСКОЕ имя временного файла, своё на каждый flush — без исключения кросс-батчевый дедуп никогда бы не совпадал)); два вхождения одного и того же события (отличаются только временем) — один алерт со счётчиком, любое другое отличие — отдельный алерт. `False` (built-in-рулсеты, `Zircolite/rules/*.json`) — грубее, просто `(rule_id, host)`, без учёта содержимого/времени: built-in используется только для разовых batch-прогонов файлов (в основной рулсет не допускается), точность на уровне сущности там не нужна. Извлекает `entities`, берёт sample-события (первые N + последние N). |
| `models.py` | Pydantic-модели. `Alert`, `Severity`, `Entities`, `SigmaRuleRef` + модели запросов/ответов. |
| `kb.py` | База знаний MITRE ATT&CK — доступ ТОЛЬКО НА ЧТЕНИЕ к отдельному `kb.db` (путь — `config.KB_DB_PATH`, дефолт `kb/kb.db`). Файл собирается `scripts/build_kb.py` на этапе `docker build` и вшивается в образ read-only (volume'ом НЕ монтируется — обновление = пересборка образа). Модуль файл НЕ создаёт и НЕ пишет: ленивое `sqlite3.connect(...?mode=ro)` под `_lock`, один неудачный заход (файла нет) кэшируется. Функции: `available()`, `meta()`, `list_tactics()`, `matrix()` (тактики-колонки с вложенными техниками для UI), `list_techniques(tactic/q/limit/offset)`, `get_technique(id)` (полная карточка: описание, платформы, тактики, митигации, сабтехники + **detection strategies** со вложенными **analytics** (лог-сорс+канал, тюнинг-параметры; ATT&CK v18+) + **procedure examples** (кто из групп/софта и как применял технику) — она же форма будущего агентского tool'а `lookup_mitre`), `enrich_techniques(tags)` — **гибридный матчинг** тегов правила (`attack.t*` → `T1059.001`): найдено в KB → `{name,url,tactics,matched:true}`, не найдено/KB нет → `{matched:false}` (UI покажет сырой тег). O(1) запросов. Зовётся ТОЛЬКО из `main.py:get_alert` (карточка алерта), НЕ в списке `/alerts` и НЕ в поиске по событиям. Если `kb.db` нет — всё деградирует тихо (пустой результат / `available:false`), исключений наружу нет. `configure(path)`/`_reset()` — тест-хуки. Своего класса исключения у модуля нет (`KbError` был объявлен и никогда не поднимался — удалён), отдельного `list_tactics()` тоже (дублировал запрос внутри `matrix()`). |
| `fields.py` | Кандидаты имён полей (host/user/ip/process/time/event-code) для generic-извлечения из разнородных источников (EVTX/Sysmon/auditd называют поля по-разному) — `HOST_FIELDS`/`USER_FIELDS`/`SRC_IP_FIELDS`/`DST_IP_FIELDS`/`PROCESS_FIELDS`/`TIME_FIELDS`/`EVENT_CODE_FIELDS` (последний — Этап A, под ECS-lite колонку `events.event_code`, см. `store.py`). Также `INGEST_SOURCE_FIELD` — служебный маркер источника для слияния нескольких источников в один прогон движка (см. `ingest_queue.py`); ИМЯ ДОЛЖНО быть чисто алфанумерическим — Zircolite при flatten-е вырезает из имён полей без явного маппинга все не-alnum символы (`_NON_ALNUM_RE` в `streaming.py`), подчёркивания молча пропадают. |
| `timespan.py` | Лист-модуль без импортов (Этап A): `parse_timespan("5m") -> 300` — разбор Sigma-таймспана в секунды. Единицы `s`/`m`/`h`/`d`/`w`; `M` (месяц)/`y` (год) намеренно не поддержаны. Общий для `detection/correlation.py` (рантайм-оценка окна) и `rules/rules_catalog.py` (валидация формата при сохранении правила) — отдельный лист вместо импорта между подпакетами `app/rules ↔ app/detection`. |
| `timeutil.py` | Лист-модуль без импортов: `normalize_event_time(...)` — КАНОНИЧЕСКАЯ форма метки времени (наивный ISO по UTC `YYYY-MM-DDTHH:MM:SS[.ffffff]`; смещения `+03:00` конвертируются, `Z`/пробел приводятся; нераспознанный формат — старое правило `" "→"T"`, `"Z"` долой, а не исключение) и `normalize_time_bound(..., upper=)` — та же форма для границы диапазона, у верхней границы хвост-сентинель (`time_to=…T21:01:30` накрывает `…T21:01:30.113`). В этой форме метка ЛОЖИТСЯ НА ДИСК (`store.store_events` пишет ОДНО значение и в `events.event_time`, и в `rule_hits.event_time`), поэтому SQL сравнивает колонку НАПРЯМУЮ — без обёртки `replace(replace(...))`, которая не давала планировщику взять `idx_events_time`. Раньше та однострочная нормализация была продублирована в `store.py`, `detection/correlation.py` и третьей копией в тексте SQL, а граница из параметра не нормализовалась вообще. Сырое значение источника остаётся в `raw_json`. См. `docs/spec/time.md`. |
| `logging_setup.py` | Лист-модуль без импортов проекта: `configure(level)` — переводит в UTF-8 ОБА стандартных потока (stdout — вывод сторонних библиотек, stderr — наш) и вешает ОДИН хендлер на логгер `app` (`propagate=False`, формат `время уровень [модуль] сообщение`). Зовётся один раз из `main.py` ДО создания движка/хранилища. Зачем: `print()` на Windows пишет в кодировке КОНСОЛИ, и при редиректе вывода в файл русские сообщения (в т.ч. `ошибка обработки батча...`, на котором держится диагностика потери событий) становились нечитаемы. Модули логируют штатным `logging.getLogger(__name__)` — имена начинаются с `app.`, поэтому наследуют этот хендлер и не дублируются хендлерами uvicorn. Второй поток (stdout) — не косметика: `rich`-спиннер Zircolite (`⠋`) на cp1251-потоке роняет компиляцию правил и весь флаш ingest, см. §8. Уровень — `SIEM_LOG_LEVEL`. |
| `filter_lang.py` | Мини-язык фильтра Событий (строка ввода в UI, в духе MaxPatrol query bar): токенайзер + recursive-descent парсер + компилятор условий в parametrized SQL (`json_extract` — инъекция исключена). Поддерживает произвольную вложенность `and`/`or`/`not` через скобки; спецполя результата детекта `rule` и `is_matched` (не часть raw_json — отдельные колонки `matched_rules`/`is_matched` в `events`). У `rule` операторы `=`/`!=`/`contains`/`in`/`is null` — сравнение по НАЗВАНИЮ правила, а `>`/`<`/`>=`/`<=` — отдельная семантика: сравнение КОЛИЧЕСТВА сработавших правил (`json_array_length(matched_rules)`), напр. `rule > 1`. `ENTITY_COLUMNS` (Этап рефакторинга) — ECS-lite колонки события как ИМЕНА ПОЛЕЙ фильтра: `user_name`/`src_ip`/`dst_ip`/`process`/`event_code` резолвятся в настоящие колонки `events` (заполняются на записи по кандидатам из `fields.py`), а не в `json_extract` — одно имя сущности поверх разнобоя имён у источников (EVTX/Sysmon/auditd) плюс работающие индексы `idx_events_user`/`idx_events_src_ip`. `resolve_field()` возвращает третьим элементом признак «это настоящая TEXT-колонка» — для неё `compile_condition` НЕ оборачивает выражение в `CAST(... AS TEXT)` (с `CAST` планировщик индекс не берёт, и колонки не окупались бы). `INDEXED_JSON_FIELDS`/`resolve_json_path()` — узкий whitelist «горячих» полей raw_json (сейчас только `EventID`), для которых JSON-путь подставляется ЛИТЕРАЛОМ в текст SQL (не bound-параметром) — нужно, чтобы совпасть с expression-индексом `idx_events_json_eventid` в `store.py` (SQLite матчит индекс на выражении только по текстовому совпадению, bound-параметр для этого не годится); безопасность не страдает — литерал всегда один из фиксированных значений словаря по ключу, как у `_ALERT_SORT_COLUMNS`/`_EVENT_SORT_COLUMNS` в `store.py`. |
| `rules/rules_catalog.py` | Каталог Sigma-рулсетов/правил для вкладки «Sigma-правила»: built-in (`Zircolite/rules/*.json`, read-only) и любое число ИМЕНОВАННЫХ custom-рулсетов (`custom_rulesets/<id>/` — `meta.json` + `*.yml` на обычное правило, source of truth, + `.manifest.json` — кэш скомпилированных метаданных для быстрого браузинга). Просмотр builtin/custom — обычный `json.load()` с кэшем по mtime (без pySigma); компиляция через `zircolite.rules.RulesetHandler` нужна только при добавлении нового custom-правила/рулсета (`save_custom_rule`/`save_ruleset_yaml`, оба принимают `ruleset` — существующий, ИЛИ `new_ruleset_name` — создать новый; builtin как цель отклоняется). **Correlation-правила (`type: event_count`/`value_count`/`temporal`/`temporal_ordered`) хранятся ОТДЕЛЬНО** — файлом `<rule_id>{CORRELATION_EXT}` (`.sigmacorr`, НЕ `.yml`/`.yaml`) в той же директории рулсета: `RulesetHandler` глобит только `*.yml`/`*.yaml`, значит их вообще не видит при компиляции — это НЕ побочный эффект, а осознанный обход реального бага **стокового** (не пропатченного — сверено по sha256 файла против RECORD в dist-info) `pysigma-backend-sqlite==1.2.0` (воспроизведено и на 1.2.4): `finalize_correlation_subqueries = False` (`pysigma/conversion/base.py`, не переопределён sqlite-бэкендом) отключает финализацию для правила с backreference из `correlation.rules` в том же `SigmaCollection` — без `correlation.generate:` оно молча выпадает из скомпилированного рулсета, с `generate: true` наружу уходит сырая SQL-строка вместо dict и валит компиляцию всего файла целиком. Благодаря физической изоляции правило, на которое ссылается корреляция, компилируется как совершенно обычное правило под своим настоящим именем — никаких «правил-двойников» в контенте заводить не нужно. `compile_custom_rule`/`compile_ruleset_yaml` сами решают (по ключу `correlation:` в документе) — отдать документ в `RulesetHandler` или в свою лёгкую валидацию без pySigma (`_validate_correlation_doc`/`_compile_correlation_doc`, дают «псевдо-скомпилированную» запись для `.manifest.json`: id/title/level/tags/description, без `rule`-SQL). `_validate_correlation_doc` (Этап A) дополнительно требует непустой `group-by`, проверяет формат `timespan` через `app/timespan.parse_timespan` и явно отклоняет «расширенные» condition-выражения — раньше эти три ошибки молча проходили валидацию и потом никогда не срабатывали. `load_correlation_rules(ruleset_path)` — структурные поля correlation-правила (`type`/`group-by`/`timespan`/`condition`/`rules`) читаются заново из raw `.sigmacorr` при каждом использовании, с кэшем по сигнатуре директории (число файлов + макс. mtime среди `*.yml`/`*.yaml`/`*.sigmacorr`); `correlation.rules` (ссылки по Sigma `name`/`id`) резолвится по общему индексу, построенному И по `*.yml`/`*.yaml` (`kind="base"`), И по `*.sigmacorr` (`kind="correlation"`, Этап A — раньше индекс строился только по первым, из-за чего ссылка correlation→correlation (цепочки) никогда не резолвилась, и вся зависимая correlation-запись молча пропадала целиком) — в настоящий `title` соседнего правила, это и есть значение, которое реально попадёт в `events.matched_rules`/`rule_hits.rule_title`. Результат несёт и `base_rule_titles` (плоский список), и `base_rule_refs` (с `kind`, нужен `correlation.py:active_hit_spec`); `id` берётся из YAML, а при отсутствии — из ИМЕНИ ФАЙЛА (по нему запись сопоставляется с манифестом в `_active_correlation_rules` для main, см. §8). **Этап 4:** необязательный блок `correlation.incident` (`{type, severity?, title?}`) валидируется в `_validate_correlation_doc` (громко: `type` обязателен и slug `^[a-z0-9][a-z0-9_]{0,63}$`, `severity` из набора `Severity`), доезжает как ключ `incident` в `load_correlation_rules` (через `_parse_incident_spec`) и булев бейдж `incident: true` в `.manifest.json`. `build_ref_index(target_dir)` — ОДИН на два пути индекс Sigma `name`/`id` → `{title, kind}` по всем файлам рулсета: по нему и резолвятся `correlation.rules` в рантайме, и проверяются на СОХРАНЕНИИ (`_validate_correlation_doc(doc, ref_index=...)`) — неразрешимая ссылка теперь `RuleValidationError`/400, а не 201 с правилом, которое молча выпадает из `load_correlation_rules` и никогда не срабатывает; ссылки резолвятся только внутри своего рулсета (межрулсетные не поддержаны — сообщение об этом в тексте ошибки), при загрузке пака в индекс добавляются и документы самого файла. `compile_custom_rule` разбирает YAML ОДИН раз в самом начале и проверяет структуру уже по разобранным документам (`_docs_look_like_sigma_rule`) — иначе синтаксическая ошибка YAML маскировалась общим «должен содержать title, logsource и detection», а ветка с позицией ошибки парсера была недостижима. `save_ruleset_yaml` создаёт НОВЫЙ рулсет только когда известно, что в него ляжет хотя бы одно правило (`_resolve_existing_target` вместо `_resolve_target_ruleset`) — полностью коллизионный пак больше не оставляет пустую директорию с `rule_count: 0`. `_find_rule_file()` — ищет файл правила по `rule_id` независимо от расширения (обычное/correlation), нужен `get_rule`/`update_custom_rule`/`delete_custom_rule` (тип правила может смениться при редактировании — файл переписывается под новым расширением). Ничего не знает про «основной рулсет» (main) — однонаправленная зависимость `main_ruleset.py → rules_catalog.py`. **Value lists:** `compile_custom_rule`/`compile_ruleset_yaml` зовут `value_lists.expand_placeholders()` (разворот `%name%`/`\|expand`) до `RulesetHandler`, `ValueListError` транслируется в `RuleValidationError`; соседи в scratch-каталоге тоже разворачиваются. `rules_using_value_list(name)`/`value_list_usage_counts()` — скан custom-правил на ссылки-плейсхолдеры; `recompile_rules_for_value_list(name)` — пересобирает зависимые правила и переписывает их `.manifest.json` (зовётся из `main.py:PUT /value-lists/{name}`, `engine.invalidate` затронутых рулсетов — там же). |
| `rules/main_ruleset.py` | Состав «основного рулсета» (виртуальная композиция правил ТОЛЬКО из custom-рулсетов — `toggle_rule`/`toggle_ruleset` отклоняют built-in `ruleset_path`, `CatalogError`; built-in не пишется с расчётом на сценарии/инциденты, его место — разовые batch-прогоны файлов через явный `ruleset=`) — файл `custom_rulesets/main_ruleset.json`: список целиком добавленных рулсетов + точечные исключения/добавления отдельных правил (`resolve()` собирает плоский список для движка). Используется по умолчанию `/ingest/stream` и `/ingest/events` (там нет параметра `ruleset` — раньше молча падали на `engine.default_ruleset_path`, теперь на main). `resolve()` дешёвый — читает уже скомпилированные правила через кэш `rules_catalog`, без pySigma. `resolve_with_sources()` дополнительно переиспользует `correlation.py` — чтобы найти, какие custom-рулсеты реально дают активные correlation-правила для main. |
| `detection/correlation.py` | Стейтфул-корреляция — `event_count`/`value_count`/`temporal`/`temporal_ordered`, включая ЦЕПОЧКИ (correlation ссылается на другую correlation), поверх постоянной таблицы `events`/`rule_hits`, а не через `pysigma-backend-sqlite`/`pysigma-backend-clickhouse` (оба генерируют SQL БЕЗ учёта `timespan` у `event_count`/`value_count`, а `temporal_ordered` считают, но никогда не сравнивают реальный порядок — см. §8/`docs/spec/correlation.md`, плюс у Zircolite нет state между batch'ами). Вызывается из `main.py:_process_batch` ПОСЛЕ каждого `store.store_events(...)`, т.е. после каждого flush ingest-воркера — с коротким замыканием: если ни одно активное correlation-правило (и ни одна корреляция, сработавшая ВЫШЕ по цепочке в ЭТОМ ЖЕ проходе) не даёт новых попаданий, до БД дело не доходит. Значения ключа group-by приводятся к строкам (`str(v)`) — `rule_hits.group_json` хранит их строками, рассогласование типов (Python `int` из числового поля вроде `EventID` против строки) раньше давало ложноотрицательный результат. Счёт — **A3-оценка** (`_evaluate_correlation_rule` + `_best_anchor`): один суженный range-scan `store.fetch_correlation_hits()` (по кандидатным ключам за `[min(new) − timespan, max(new) + timespan]`) → проход СКОЛЬЗЯЩИМ окном в памяти по ВСЕМ точкам-якорям конца окна (`O(H)` от плотности попаданий, не размер БД) → `store.evaluate_correlation_window()` за авторитетным счётом + `sample_events` по найденному окну. Перебор всех точек-якорей (а не одна на `max(event_time)` новых событий, как раньше — то `datetime.now()` не используем, replay сломался бы) закрывает краевой эффект при перемешанном порядке прихода: «позднее» событие со старой меткой больше не «прячет» окно. Обязательное требование производительности — независимость от размера БД, замерено `scripts/bench_correlation.py`. Старая «фаза 1» (`store.evaluate_correlation_windows`) удалена вместе с методом. `_topo_order()` — корреляции-потомки (на них ссылаются другие активные корреляции) обрабатываются раньше родителей; сработавшая корреляция пишется в `rule_hits` СРАЗУ (`store.insert_correlation_hits`, не батчится до конца прохода) — родитель, обрабатываемый ниже по порядку в этом же вызове, считает свой счёт запросом к БД, а не по внутрипроцессным данным. `_sequence_matches_order()` — жадное сопоставление подпоследовательности для `temporal_ordered` (реальная проверка порядка, которой нет у апстрим Sigma-бэкендов). `_expand_synthetic_samples()`/`_merge_samples()` — синтетическому `event_id` попадания цепочки (`corr:{dedup}:{title}:{anchor}`) в `events` не соответствует НИЧЕГО, и `JOIN` за `sample_events` его молча пропускал: у корреляции НАД корреляцией сэмплы (а с ними и `entities`, они извлекаются из сэмплов) приходили ПУСТЫМИ. Теперь по синтетическому id находится окно и group-ключ предка (`store.fetch_hit_group_values`) и берутся сэмплы ЕГО окна, рекурсивно (глубина ≤ `_MAX_EXPAND_DEPTH`), результат сводится в один хронологический список без повторов (≤ `_MAX_SAMPLE_EVENTS`). Стоимость платится только в момент реального срабатывания цепочки и только на контент событий — счётный путь не затрагивается. `active_hit_spec(ruleset_path)` (было `active_base_rule_titles`) — `{rule_title: {поля}}` для БАЗОВЫХ правил, что писать в `rule_hits.group_json` (зовётся `main.py` ДО `store_events`); ссылки на другие correlation-правила сюда не попадают — их `rule_hits` пишет сама `evaluate_batch`. Correlation-правило уровня `informational` пропускается (см. `normalize.py`) — до расчёта окна дело не доходит. «Расширенные» condition-выражения не эвалуируются (отклоняются раньше, при валидации в `rules_catalog.py`). Результат — обычный `Alert` в таблице `alerts` (переиспользует dedup-паттерн), помечен `engine="correlation"` (без миграции модели). **Этап 4:** если у correlation-правила есть блок `correlation.incident` (`_active_correlation_rules` теперь прокидывает и `ruleset_path`), при срабатывании строится `Incident` (`_build_incident`) и пишется в `incidents` ВМЕСТО `Alert` — обычного `engine="correlation"` алерта по такому правилу НЕ будет. Помеченное правило пробивает отсечку `informational`. Идентичность инцидента — ИСТОЧНИК + фиксированный бакет по `timespan` (`dedup_key = sha256(source_batch:incident_type:group_values:window_bucket)`), повтор в том же бакете и источнике → UPDATE строки. Необязательный `link_specs_out` — список, куда `evaluate_batch` дописывает по записи на инцидент (`main.py:_process_batch` по ним после `upsert_alerts` зовёт `store.link_alerts_to_incident`). См. `docs/spec/incidents.md`. |
| `incidents.py` | Фоновая обработка расследований инцидентов (таблица `investigations`). **Этап 4 — ЗАГЛУШКА:** `run_pending(store, batch=20)` берёт `queued`-строки (FIFO), переводит `queued → running → done` с вердиктом `needs-review` и placeholder-обоснованием, без анализа; ошибка на строке → её статус `error`, проход не падает. Настоящий агент (`app/agent/`, LangGraph + OpenAI-совместимый провайдер) — Этап 5, он заменит тело `run_pending`. Вызывается периодически тем же потоком `IngestWorker`, что и ретеншн `events` (новый параметр `IngestWorker(periodic_tasks=[(fn, interval), ...])`; `retention_fn` — частный случай, внутри складывается в тот же список). Конфиг — `SIEM_INCIDENT_VERDICT_ENABLED`/`_INTERVAL` (дефолт вкл, 30с). |
| `rules/value_lists.py` | Именованные списки значений для Sigma-плейсхолдеров `%name%` + модификатора `\|expand` (вкладка «Списки»). Файл `data/value_lists/<name>.yml` (`name` = имя плейсхолдера, `[A-Za-z0-9_]{1,64}`, оно же id — отдельного индекса нет), `{name, description, values, created_at, updated_at}`. `expand_placeholders(yaml_text) -> yaml_text` — обходит `detection:`, для ключей с сегментом `expand` в `\|`-цепочке заменяет записи вида `%name%` на значения списка (OR), убирает `expand` из цепочки; неизвестный/пустой список → `ValueListError`. **Разворот делается САМИ ДО компиляции** (в `rules_catalog.compile_custom_rule`/`compile_ruleset_yaml`), НЕ через `pysigma ValuePlaceholderTransformation` — Zircolite `RulesetHandler` жёстко собирает pipeline из имён плагинов, свой `ProcessingPipeline` воткнуть нельзя без форка. На диск правило пишется с `%name%` (source of truth) — списки живые. Быстрый путь: если подстроки `expand` в тексте нет — возвращает текст как есть (не пересериализует, комментарии правила целы). Только кастомные правила (builtin приходят уже в SQL). Correlation-правила (`.sigmacorr`) не трогаются — у них нет `detection`. Модуль НЕ импортирует `rules_catalog` (цикла нет); `rules_using_value_list`/`value_list_usage_counts`/`recompile_rules_for_value_list` живут в `rules_catalog.py`, оркестрируются из `main.py`. Пустой список (`values: []`, либо всё схлопнулось при trim/дедупе) отклоняется на записи — `create_list`/`update_list`/импорт: правило с плейсхолдером на пустой список всё равно не компилируется, то есть создать такой список было можно, а пользоваться им нельзя. **Загрузка файлом:** `parse_list_file(text)` понимает Sigma processing-pipeline YAML (`transformations` с `type: value_placeholders`/`query_expansion_placeholders` + `mapping: {имя: [значения]}` — один файл → много списков), наш `{name, description?, values}` (multi-doc) и «голый» `{имя: [значения]}`; `import_lists(parsed, mode)` (`create`/`replace`/`merge`) пишет их и возвращает `recompile_needed`. `is_list_document(doc)` — СТРОГАЯ проверка (только pipeline `value_placeholders` или `{name, values}`, без «голого» mapping) для `rules_catalog._peel_value_list_docs` — тот вынимает документы-списки из multi-doc `+ Загрузить рулсет` ПЕРЕД компиляцией правил пака. |

### Модель данных (SQLite, `siem.db`)

- **`alerts`** — нормализованные алерты для аналитика и будущего агента. Дедуп — два режима
  (см. `detection/normalize.py`): для custom-правил `dedup_key` — хэш содержимого события
  (минус время/служебные поля), для built-in — грубее, `(rule_id, host)`; повторное
  срабатывание инкрементит `event_count`. Поля: `rule_*`, `mitre_techniques`, `entities`,
  `sample_events`. Колонки `status` у алерта НЕТ (была `new → investigating → closed`, убрана
  из `_SCHEMA`; ручки `PATCH /alerts/{id}/status` тоже нет) — триаж-статус только у инцидентов,
  см. `incidents.status` ниже. БД, созданные до её удаления, не мигрируются — `siem.db`
  одноразовая dev-БД, пересоздаётся с нуля.
- **`events`** — снимок ВСЕХ событий батча (в т.ч. не вызвавших правил), с флагом
  `is_matched` и списком `matched_rules`. Нужны для ручного пивота аналитиком и RAG агента.
- **`rule_hits`** — леджер срабатываний, "интересных" для correlation-правил (`app/detection/correlation.py`):
  `(event_id, rule_title, source_batch, event_time)`, заполняется точечно (не на каждое
  сработавшее правило — только на те, что реально base_rule активной корреляции). Даёт индекс
  `(rule_title, source_batch, event_time)`, которого нет и не должно быть на `events` под
  произвольные Sigma-поля.
- **`sources`** — реестр потоковых источников: `(source_id, name UNIQUE, description,
  token_sha256, token_hint, enabled, created_at, last_seen_at)`. `name` обязателен и уникален,
  он же метка `source_batch` всех событий/алертов источника. Токен хранится только хэшем;
  `/ingest/stream` и `/ingest/events` без валидного токена активного источника → `401`. Никак
  не связана с уже накопленными `source_batch` в `events`/`alerts` — чисто аддитивная.
- **`incidents`** (Этап 4) — агрегат срабатываний, будущая единица работы агента. Заводится
  ТОЛЬКО помеченным `correlation.incident` correlation-правилом (вместо `engine="correlation"`
  алерта). Дедуп по `dedup_key = sha256(source_batch:incident_type:group_values:window_bucket)[:16]`
  — источник + фиксированный бакет по `timespan` правила: повтор в бакете → UPDATE, разрыв больше
  `timespan` → новый инцидент, ДРУГОЙ источник → всегда другой инцидент (см. §8). Поля: `incident_type`/`title`/`severity`/`status` (`new → investigating →
  closed`)/`source_batch`/`ruleset_path`/`correlation_rule_*`/`group_key`/`member_rule_titles`/
  `window_*`/`alert_count`/`mitre_techniques`/`entities`/`sample_events`. Обратная ссылка —
  `alerts.incident_id`. Привязан к одному `source_batch` → чистится `delete_batch`. Переживает
  свои `events` (ретеншн их не трогает). Catch-all прохода по `alerts` НЕТ (см.
  `docs/spec/incidents.md`).
- **`investigations`** (Этап 4) — очередь и результат расследования: `(investigation_id,
  incident_id, status [`queued → running → done → error`], verdict [`TP`/`FP`/`needs-review`],
  rationale, confidence, steps, error, timestamps)`. На Этапе 4 обработка — заглушка
  (`app/incidents.py:run_pending`), настоящий агент — Этап 5.

### API (обзор)

| Метод | Путь | Назначение |
|-------|------|-----------|
| POST | `/ingest/stream` | **Потоковый приём с форвардеров** (NDJSON/JSON-массив), 202 Accepted → очередь → micro-batch. **Требует токен** зарегистрированного источника: `Authorization: Bearer <token>` или `X-Ingest-Token` (иначе `401`, события не приняты). Метку `source_batch` задаёт ИМЯ источника по токену — `?source=` больше нет. Ruleset не выбирается per-request — всегда «основной рулсет» (`app/rules/main_ruleset.py`). См. `docs/guide/forwarder.md`. |
| POST | `/ingest/file` | Прогон файла, уже лежащего на диске сервера (batch/тесты). Без токена (локальный путь). `ruleset` — путь из `/rulesets` (в т.ч. `"main"` — основной рулсет) или пусто (движковый дефолт `rules_windows_merged.json`). |
| POST | `/ingest/events` | Приём порции сырых событий в теле запроса (синхронный прогон). **Требует токен источника** (как `/ingest/stream`); `source_label` в теле игнорируется — метка из имени источника. Ruleset не выбирается — всегда основной рулсет. |
| POST | `/ingest/upload` | Загрузка файла из браузера (multipart), автоопределение типа по расширению. Без токена (локальный путь). `ruleset` — как у `/ingest/file`. |
| GET · POST | `/sources` | Реестр потоковых источников (вкладка «Источник данных»). `GET` → `[{source_id, name, description, token_hint, enabled, created_at, last_seen_at, event_count, alert_count, last_event_at}]` (счётчики сведены с `/batches` по `name==source_batch`), токен НЕ отдаётся. `POST {name, description?}` → `201 {…, token}` — открытый токен ОДИН раз (в БД sha256). Имя обязательно/уникально/неизменяемо. |
| POST · PATCH · DELETE | `/sources/{id}` … | `POST /sources/{id}/rotate` → `{token}` (новый одноразовый, старый мёртв сразу). `PATCH {enabled?, description?}` — вкл/выкл приём по токену, сменить описание. `DELETE` — снять регистрацию (токен отозван); события/алерты остаются, их чистит `DELETE /batches/{name}`. |
| GET | `/batches` | Сводка по загруженным источникам-меткам (стримы, файлы, вставки) — для селектора в UI. |
| DELETE | `/batches/{source_batch}` | Удаление источника-метки целиком: все его `events` И `alerts` (плюс `rule_hits`, `incidents`, `investigations`). Ответ несёт `incidents_deleted`. `404`, если ничего не удалено. Регистрацию в `sources` (если есть) не трогает. |
| GET | `/alerts` · `/alerts/{id}` | Список / карточка алерта. Список — обёртка `{alerts, total, limit, offset}` (как у `/events`·`/incidents`; голым массивом был до появления пейджера в UI — без `total` вкладка молча показывала только первую страницу). Фильтры: `source_batch`, `rule_level`, `time_from/to` (фильтра по `status` НЕТ — у алерта нет статуса); сортировка `sort_by` (`rule`=severity/`host`/`event_count`/`created_at`) + `sort_dir`. Карточка (`/alerts/{id}`) дополнительно несёт `mitre` — обогащение тегов через `app/kb.py` (`[{tag, technique_id, name?, url?, tactics?, matched}]`), список `/alerts` — нет. Ручки на смену статуса алерта нет — триаж-статус только у инцидентов. |
| GET | `/incidents` · `/incidents/{id}` | **Инциденты (Этап 4).** Список — обёртка `{incidents, total, limit, offset}`, фильтры `status`/`incident_type`/`source_batch`/`severity`/`time_from/to`, сортировка `sort_by` (`created_at`\|`updated_at`\|`alert_count`\|`status`\|`severity`)/`sort_dir`, `limit` 1..500; каждая строка несёт `investigation_status`. Карточка — `+ member_alerts`, `investigation`, `mitre` (обогащение тегов правила + member-алертов). |
| GET | `/incidents/{id}/context` | Полный контекст под агента/триаж: `correlation_rule` (структурные поля), `member_rules` (`+ yaml_text`/SQL), `sample_events`, `related_events` (события по сущности через `compile_filter_query(_incident_entity_filter(group_key))`), `entity_history` — алерты, в которых РЕАЛЬНО встречаются значения `group_key` (`store.list_alerts_by_entity`, `scope: "entity"`); при пустом `group_key` — фолбэк на последние алерты источника с `scope: "source"` и `note` (раньше секция ВСЕГДА отдавала последние 50 алертов источника без привязки к сущности). Удалённое правило / вычищенные ретеншном `events` → пустые секции + `note`, не 5xx. |
| PATCH | `/incidents/{id}/status` | Смена статуса инцидента. Тело типизировано `Literal["new", "investigating", "closed"]` (`models.IncidentStatus`/`INCIDENT_STATUSES`) — произвольная строка теперь 422 от FastAPI, а не 200 с мусором в БД (после такого инцидент не находился ни одним фильтром `?status=`); `store.update_incident_status` проверяет то же самое для вызовов мимо HTTP. |
| GET | `/events` · `/events/{id}` | Список / карточка сырого события. Фильтры: `source_batch`, `only_matched`, `time_from/to`; `query` — строка мини-языка фильтра (`app/filter_lang.py`: and/or/not, скобки, спецполя `rule`/`is_matched`), при синтаксической ошибке `400` с текстом и позицией; `group_cond` — drill-in по группе (всегда AND, отдельно от `query`; неизвестный оператор/пустое поле → `400`, а не молчаливый пропуск условия — фильтр обязан только сужать); `time_from`/`time_to` приводятся к канонической форме (`app/timeutil.py`), верхняя граница ВКЛЮЧАЮЩАЯ (`time_to=…T21:01:30` накрывает `…T21:01:30.113`); сортировка `sort_by`/`sort_dir` (в т.ч. по любому полю raw_json); `fields=A,B` — кастом-колонки. Отдельного параметра фильтра по хосту нет — выражается через `query` (напр. `Hostname contains "..."`). |
| GET | `/events/group` | Агрегаторы для панели группировки: `group_by=<field>` (включая спецполя `rule`/`is_matched`) + те же фильтры (`query` и т.п.) → `[{value, count}]` по убыванию (фильтр применяется до группировки; `rule` — многозначное поле, разворачивается через `LEFT JOIN json_each`). |
| GET | `/rulesets` | Каталог рулсетов (builtin + все именованные custom + одна виртуальная запись «main», основной рулсет) — `[{path, category, name, rule_count, size_bytes, deletable, main_status}]`. `main_status` — `full`\|`partial`\|`none`, состав основного рулсета внутри ЭТОГО рулсета (см. `app/rules/main_ruleset.py`). `path` — то же значение, что подставляется в `ruleset` у `/ingest/file`·`/ingest/upload` (в т.ч. `"main"`). |
| GET | `/rulesets/rules` · `/rulesets/rule` | Список правил рулсета (`ruleset=<path>`, поиск `q` по title/description, `only_main=true` — только правила, входящие в основной рулсет, сортировка `sort_by=level`\|`title`\|`author`\|`status`, пагинация; каждая строка списка несёт `in_main`) / карточка одного правила. Для custom-рулсета карточка дополнительно содержит `yaml_text` (исходный Sigma YAML) — у builtin его нет и не было никогда, хранится только уже скомпилированный SQL. |
| POST | `/rulesets/upload` | Загрузка рулсета — сырой Sigma YAML (`.yml`/`.yaml`, можно multi-document — несколько правил в одном файле). Тело — multipart: `file` + (`ruleset` — существующий свой рулсет, ИЛИ `new_ruleset_name` — создать новый; ровно один из двух). Встроенные рулсеты как цель отклоняются (`400`). |
| DELETE | `/rulesets` | Удаление именованного custom-рулсета целиком (`?ruleset=<path>`); встроенные рулсеты не удаляются (`404`). Чистит ссылки на него в основном рулсете (`main_ruleset.on_ruleset_deleted`). |
| POST | `/rules/custom` | Компиляция и сохранение НОВОГО своего правила: тело `{yaml_text, ruleset?, new_ruleset_name?}` — сырой Sigma YAML одного правила + существующий/новый целевой custom-рулсет (ровно один из двух), валидируется и компилируется через `RulesetHandler` (`400` с текстом ошибки, ничего не пишется на диск). Ответ дополнительно содержит `ruleset_path` — куда правило попало. |
| PUT | `/rules/custom/{rule_id}` | Пересборка СУЩЕСТВУЮЩЕГО своего правила на месте: query `ruleset` (обязателен) + тело `{yaml_text}`. `id` правила остаётся исходным (из URL): отсутствующий/пустой `id:` в новом YAML подставляется автоматически, а ДРУГОЙ `id:` — ошибка `400` (не тихая подмена: переименование = удалить старое правило и создать новое явно). Редактирование не переименовывает файл/manifest-запись. |
| DELETE | `/rules/custom/{rule_id}` | Удаление своего правила (обязательный query-параметр `ruleset` — из какого именованного custom-рулсета). |
| POST | `/main-ruleset/rules` | Включить/выключить ОДНО правило в основном рулсете: тело `{ruleset, rule_id, include}`. |
| POST | `/main-ruleset/rulesets` | Добавить/убрать рулсет ЦЕЛИКОМ в основной рулсет: тело `{ruleset, include}` (сбрасывает точечные исключения/добавления по этому рулсету). |
| GET | `/value-lists` · `/value-lists/{name}` | Именованные списки значений (плейсхолдеры `%name%`/`\|expand` для Sigma-правил, см. `app/rules/value_lists.py`). Список — `[{name, description, value_count, updated_at, used_by_count}]`; карточка — `+ values`, `used_by: [{ruleset, rule_id, title}]`. |
| POST · PUT · DELETE | `/value-lists` · `/value-lists/{name}` | `POST {name, description, values}` (201, `name` потом неизменяемо). `PUT {description, values}` → СРАЗУ пересобирает зависимые правила, ответ `+ {recompiled, errors}`. `DELETE` → `409`, если список используется; `?force=true` — удалить всё равно (эти правила перестанут компилироваться). Всё — только для кастомных правил. |
| POST | `/value-lists/upload` | Загрузка списков файлом (multipart `file` + `mode` = `create`\|`replace`\|`merge`). Форматы — Sigma pipeline с `value_placeholders.mapping` (один файл → много списков), наш `{name, values}`, «голый» `{имя: [значения]}` (см. `value_lists.parse_list_file`). `replace`/`merge` пересобирают зависимые правила. |
| GET | `/kb/mitre/meta` · `/kb/mitre/matrix` | База знаний MITRE (вкладка «База знаний»), read-only, `app/kb.py`. `meta` → строки `mitre_meta` (`attack_version`/`built_at`/counts) + `available`. `matrix` → тактики-колонки в порядке kill-chain с вложенными техниками/сабтехниками. Нет `kb.db` → `{"available": false, ...}` (не 5xx). |
| GET | `/kb/mitre/techniques` · `/kb/mitre/techniques/{id}` | Плоский список техник (`tactic`, `q`, `limit` 1..500, `offset`) / полная карточка техники (описание, detection, платформы, data sources, тактики, митигации, сабтехники). Неизвестный id → `404`. |
| POST | `/rulesets/upload` | *(дополнено)* Multi-document файл может кроме правил нести документы-определения списков (Sigma pipeline `value_placeholders` или `{name, values}`) — они вынимаются и пишутся ПЕРВЫМИ (`mode=replace`), потом компилируются правила. Ответ `+ {value_lists_imported, recompiled, errors}`; если в файле ТОЛЬКО списки — рулсет не создаётся (`name`/`path` в ответе нет). |

---

## 5. Sigma-правила и датасеты

- Скомпилированные рулсеты Zircolite — `Zircolite/rules/*.json`
  (windows/linux, срезы generic/merged/high/medium). По умолчанию используется
  `rules_windows_merged.json` (см. `DEFAULT_RULESET_PATH` в `app/main.py`).
- Конфиг field-mappings и transforms — `Zircolite/config/`.
- Тестовые логи атак — `artifacts/Security-Datasets/datasets/` (OTRF), напр.
  PurpleSharp AD playbook в каталоге загрузок (`SIEM_UPLOADS_DIR`, по умолчанию `data/uploads/`).
- **`custom_rulesets/`** (создаётся автоматически, сюда попадают только пользовательские
  данные из вкладки «Sigma-правила», `Zircolite/` не трогаем):
  - `<ruleset_id>/` — один именованный custom-рулсет (id = `uuid4().hex`, кроме `my_rules` —
    зарезервированный id для рулсета, созданного до введения именованных рулсетов, см. миграцию
    ниже). Внутри: `meta.json` (`{id, name, created_at}`), `<rule_id>.yml` на правило (raw Sigma
    YAML, source of truth), `.manifest.json` (кэш скомпилированных метаданных всех правил папки,
    для быстрого браузинга И для детекта). `custom_rulesets/<ruleset_id>` как `ruleset_path` для
    `/ingest/file`·`/ingest/upload` гоняется по УЖЕ скомпилированному `.manifest.json`
    (`main.py:_process_batch` → `rules_catalog.load_rules` → `engine.run_batch_with_rules`), НЕ
    пересборкой сырых `*.yml` через `RulesetHandler`: только в манифесте развёрнуты плейсхолдеры
    value lists (`%name%`/`|expand`, `app/rules/value_lists.py`) — `RulesetHandler`, глядя на сырой
    `.yml` с `%name%`, молча уронил бы такое правило. Freshness манифеста держит mtime-кэш
    `rules_catalog` (не `engine._rulesets_cache` — для custom-путей он больше не используется,
    как и для `main`). Правило/рулсет можно добавить только в существующий именованный
    custom-рулсет или создать новый (`ruleset`/`new_ruleset_name` — ровно один из двух в
    `POST /rules/custom` и `POST /rulesets/upload`); встроенные рулсеты как цель — `400`.
  - `main_ruleset.json` — состав «основного рулсета» (см. `app/rules/main_ruleset.py` в таблице
    модулей выше): `included_rulesets` (целиком добавленные рулсеты) + `excluded_rules`/
    `included_rules` (точечные исключения/добавления по конкретным правилам). Управляется из
    вкладки «Sigma-правила» — кнопка у каждого правила (колонка в таблице) и кнопка «добавить
    рулсет целиком» рядом с селектором рулсета; toggle switch «Только основной рулсет»
    фильтрует уже открытый список правил текущего рулсета до входящих в main. Сам «Основной
    рулсет» также выбирается пунктом в том же селекторе рулсета — просмотр его состава как
    отдельного виртуального рулсета (`GET /rulesets/rules?ruleset=main`, каждая строка несёт
    `source_ruleset` — настоящий рулсет-источник, по нему бьют клик/кнопка снятия с main).
    Основной рулсет — то, что по умолчанию обрабатывает `/ingest/stream` и
    `/ingest/events` (там нет параметра `ruleset`).
  - Раскладка до появления именованных custom-рулсетов была `my_rules/*.yml` (одна безымянная
    папка) + `uploaded/*.json` (загрузка уже скомпилированного JSON, без сырого YAML) —
    `rules_catalog.py` при импорте один раз (идемпотентно) дописывает `meta.json` в `my_rules/`,
    если его там ещё нет, ничего не перемещая; `uploaded/` (если пустая) просто перестаёт
    использоваться.
- **`data/value_lists/`** (создаётся автоматически, вкладка «Списки», `app/rules/value_lists.py`) —
  `<name>.yml` на список (`name` = имя плейсхолдера `%name%`, `[A-Za-z0-9_]{1,64}`),
  `{name, description, values, created_at, updated_at}`. Разворачиваются в кастом-правила при
  компиляции (`Field|...|expand: ['%name%']`), builtin не поддержаны. Под Docker — отдельный
  named volume `siem_value_lists` (см. `docker-compose.yml`).
- **`kb/kb.db`** — база знаний MITRE ATT&CK (Enterprise), read-only SQLite. Собирается
  `scripts/build_kb.py` из STIX-бандла `mitre-attack/attack-stix-data`; в Docker — на этапе
  `build` (`ARG ATTACK_STIX_REF`/`ATTACK_STIX_VERSION`; по умолчанию `master` = актуальная ATT&CK,
  v18+), вшивается в образ, **volume'ом НЕ монтируется** (обновление = пересборка). Таблицы:
  `mitre_meta`, `mitre_tactic`, `mitre_technique`, `mitre_technique_tactic`, `mitre_mitigation`,
  `mitre_technique_mitigation`, `mitre_detection_strategy` + `mitre_analytic` (структурный детект
  v18+: стратегия→техника через `detects`, аналитика несёт `log_sources`/`mutable_elements`),
  `mitre_procedure` (`uses`: группа/софт→техника + текст). **NB:** в ATT&CK v18 переработана модель —
  свободный `x_mitre_detection`, плоский `x_mitre_data_sources`, `x_mitre_permissions_required`
  из бандла УБРАНЫ (колонки `detection`/`data_sources` в схеме остались, но на v18+ пустые); детект
  теперь только структурный (strategy/analytic). Путь — `SIEM_KB_DB_PATH` (`app/config.py`).
  Читается только `app/kb.py`, никем не пишется в рантайме. Нет файла → вкладка «База знаний» и
  MITRE-обогащение карточки деградируют тихо.
- **`scripts/`** — вспомогательные скрипты для ручного тестирования (не часть приложения).
  Исключение — `build_kb.py`: он часть сборки (COPY в builder-стадию Dockerfile), автономен
  (stdlib + `requests`, без `import app.*`), логика разбита на `parse_bundle()`/`write_kb_db()`
  для тестов (`tests/test_kb.py`).
  Все, кто шлёт в `/ingest/stream` (`fake_forwarder.py`, `stream_main_ruleset_test.py`,
  `stream_correlation_test.py`, `send_value_list_test_events.py`), теперь требуют токен
  источника: флаг `--token` или переменная окружения `SIEM_INGEST_TOKEN` — сначала создайте
  источник во вкладке «Источник данных» (по умолчанию с именем `SOURCE_LABEL` скрипта, иначе
  `--source`), т.к. под этим именем скрипты потом поллят `/alerts?source_batch=...`. Прогоны
  изолируются рандомизацией host/ip/user (а не суффиксом в имени источника, как раньше).
  - `fake_forwarder.py` — синтетический форвардер для `/ingest/stream`, режимы `burst`
    (много событий разом — проверка size-trigger флаша) и `drip` (медленно и долго —
    проверка time-trigger); печатает состояние очереди из `/health?detailed=true`.
  - `send_rule_test_events.py` — тестовое Sigma-правило (в докстринге, вставить во вкладку
    «Sigma-правила» → «Написать своё правило») + набор событий (часть под правило, часть
    контрольных, специально ломающих ровно один из селекторов) через `/ingest/file` с
    `ruleset=custom_rulesets/my_rules`.
  - `stream_main_ruleset_test.py` — проверка «Основного рулсета» (`app/rules/main_ruleset.py`) именно
    через `/ingest/stream` (единственный путь, где ruleset вообще нельзя выбрать per-request —
    всегда main). Докстринг содержит своё тестовое Sigma-правило (LOLBIN-детект `certutil
    -urlcache`, независимое от правила в `send_rule_test_events.py`) — вставить во вкладку
    «Sigma-правила», добавить в основной рулсет вместе с любым built-in рулсетом (напр.
    `rules_windows_merged.json`) кнопками `+`/«добавить рулсет целиком». Скрипт шлёт NDJSON
    через `/ingest/stream`, ждёт флаша `IngestWorker` (поллит `/health?detailed=true` →
    `queue_size`), затем поллит `/alerts?source_batch=...` и печатает сработавшие правила —
    ожидается и builtin-алерт (напр. «HackTool - Mimikatz Execution - Sysmon»), и кастомный.
  - `stream_correlation_test.py` — проверка стейтфул-корреляции (`app/detection/correlation.py`) именно
    через `/ingest/stream`: **только форвард событий**, правило (`artifacts/content/
    windows_bruteforce.yml`) нужно загрузить и добавить в основной рулсет САМОСТОЯТЕЛЬНО через
    вкладку «Sigma-правила» ДО запуска — скрипт ничего не пишет в `custom_rulesets`. Шлёт 10
    событий `EventID=4625` ТРЕМЯ отдельными HTTP-запросами с паузой дольше `flush_interval`
    (гарантированно разные flush'и — то, что раньше не работало) и ждёт алерт
    `event_count=10, engine=correlation`. Флаг `--negative` — контрольный прогон с событиями за
    пределами 5-минутного `timespan` (алерт НЕ должен появиться).
  - `bench_correlation.py` (Этап A) — бенчмарк масштабируемости коррелятора, только stdlib +
    `app.store`, без HTTP-слоя и без новых зависимостей. Наполняет временную БД синтетическими
    строками `rule_hits` (10⁵/10⁶/10⁷ по умолчанию) при фиксированной плотности попаданий
    внутри окна и замеряет `store.fetch_correlation_hits` (A3-счётный путь) — прямая проверка требования
    «скорость коррелятора не зависит от размера БД» (см. `docs/spec/correlation.md`). Отдельно
    — замер зависимости от ПЛОТНОСТИ окна при фиксированном размере БД (там линейный рост
    ожидаем и нормален, `O(H)`). Наполнение — чанками через `store.insert_correlation_hits`
    (генератор, не список в памяти) — 10⁷ строк голым списком кортежей исчерпывало бы память
    неприемлемо долго.

---

## 6. Соглашения по коду

- Комментарии и docstring-и — **на русском** (так уже написан весь код, держим единый стиль).
- `from __future__ import annotations` в начале модулей; современные type hints (`str | None`).
- Модели данных — только Pydantic; не тащить сырые dict-и в бизнес-логику UI/агента.
- Новые имена полей источников добавлять в `app/fields.py`, не хардкодить в normalize.
- Работа с БД — только через `Store` под соответствующим локом (`_lock` для записи, `_read_lock`
  для чтения — см. `store.py`); не открывать sqlite-конекты мимо него.

---

## 7. Дорожная карта (поэтапный план)

Легенда: ✅ готово · 🟡 частично · ⬜ не начато

### Этап 0 — Гигиена проекта ✅
- ✅ `pyproject.toml` — единственный манифест зависимостей (`[project].dependencies` — прод,
  `[project.optional-dependencies].dev` — pytest/httpx/ruff, `[tool.pytest.ini_options]`,
  `[tool.ruff]`); `requirements*.txt` и `pytest.ini` удалены, Docker ставит `pip install .`;
  `.venv` из репо убран (`.gitignore`).
- ✅ `.gitignore` (`*.db`, `.venv/`, `uploads/`, `custom_rulesets/`, `__pycache__/`, `Zircolite/`,
  `artifacts/` — последние два внешние клоны со своим `.git`, см. §1/§6); git-репозиторий
  инициализирован.
- ✅ Мини-набор тестов на `engine`/`normalize`/`store` (`tests/`, pytest, конфиг `pytest.ini`)
  + один e2e-прогон (события → `ZircoliteEngine` → `normalize` → `Store`, полный цикл
  ingest→alert/event на временных `tmp_path`-фикстурах, без побочных эффектов на реальную
  `siem.db`). Не импортируют `app.main` напрямую (тот на импорте создаёт глобальные
  `engine`/`store` поверх РЕАЛЬНЫХ путей из `app/config.py`) — собирают `ZircoliteEngine`/
  `Store` вручную через фикстуры `tests/conftest.py`. Не покрыты: `rules_catalog.py`,
  `main_ruleset.py`, `filter_lang.py`, HTTP-слой `main.py`.
- ✅ `.env`-конфиг вместо хардкод-путей (`app/config.py`, читает `.env` через `python-dotenv`,
  см. `.env.example`): `DB_PATH`, `ZIRCOLITE_CONFIG_PATH`, `DEFAULT_RULESET_PATH`,
  `UPLOADS_DIR` (по умолчанию `data/uploads`), `KB_DB_PATH`, `LOG_LEVEL`, `HOST`/`PORT`,
  `INGEST_BATCH_SIZE`/`INGEST_FLUSH_INTERVAL`, `EVENTS_RETENTION_DAYS`, `INCIDENT_VERDICT_*`.

### Этап 1 — Архитектура SIEM 🟡 (ядро есть, укрепляем)
- ✅ Пайплайн ingest → Sigma-детект (Zircolite) → нормализация → хранение.
- ✅ Дедупликация алертов, хранение всех событий, кэш скомпилированных правил.
- ✅ **Потоковый ingest с форвардеров**: `POST /ingest/stream` → очередь → фоновый воркер
  (`app/ingest_queue.py`), micro-batch flush по «N событий ИЛИ T секунд». `docs/guide/forwarder.md`.
- ✅ **Аутентификация форвардеров по токену источника**: каждый поток (`/ingest/stream`,
  `/ingest/events`) требует bearer-токен зарегистрированного источника (таблица `sources`,
  токен хранится sha256, отдаётся один раз, есть перевыпуск/выключение). Регистрация и токен —
  вкладка «Источник данных» → «Создать источник». Имя источника обязательно и уникально, оно
  же метка `source_batch`. `/ingest/file`·`/ingest/upload` (локальный UI) — без токена.
- ✅ **`/health` отражает реальное состояние**, не заглушку: `SELECT 1` по БД (`Store.health`),
  жив ли фоновый поток `IngestWorker` (`IngestWorker.health`), загружен ли Zircolite-ruleset
  (`ZircoliteEngine.health`); `?detailed=true` добавляет счётчики строк/размер БД. UI (светофор
  в шапке) опрашивает каждые 20с, а не разово при загрузке страницы; клик — попап с разбивкой
  по подсистемам.
- ⬜ **Точная привязка entity**: маппинг полей под конкретный источник (EVTX Security /
  Sysmon / Auditd) вместо общих кандидатов из `fields.py`.
- 🟡 **Обогащение MITRE ATT&CK**: ✅ база знаний MITRE (Enterprise) в отдельном read-only
  `kb.db` (`app/kb.py`, `scripts/build_kb.py`, собирается в `docker build`), вкладка «База
  знаний» с матрицей тактик/техник; карточка техники несёт detection strategies + analytics
  (лог-сорс/канал/тюнинг) и procedure examples (кто применял); карточка алерта достраивает
  tactic/technique/ссылку по тегам (гибрид: нет в KB → сырой тег). ⬜ Осталось: MITRE-обогащение
  в списке алертов/дашборде, tool `lookup_mitre` для агента поверх `app/kb.py` (Этап 4).
- ✅ **Стейтфул-корреляция** Sigma-правил — все четыре эвалуируемых типа
  (`event_count`/`value_count`/`temporal`/`temporal_ordered`, включая ЦЕПОЧКИ —
  correlation-правило ссылается на другую correlation) поверх постоянной таблицы
  `events`/`rule_hits` (`app/detection/correlation.py`) — независимо от micro-batch flush'а
  ingest-воркера (окно реального времени `timespan`, не размера батча) И независимо от размера
  БД (двухфазный счёт по `rule_hits.group_json`, без `JOIN` к `events` на счётном пути; замерено
  `scripts/bench_correlation.py` — рост `rule_hits` в 100 раз даёт единицы процентов роста
  времени). Не через `pysigma-backend-sqlite`/`pysigma-backend-clickhouse` — ни один SQL-бэкенд
  Sigma не считает корректный скользящий `event_count`/`value_count` (`timespan` выбрасывается
  `str.format`) и не проверяет реальный порядок `temporal_ordered` (см. §8, `docs/spec/
  correlation.md`). «Расширенные» condition-выражения (`temporal_extended`/
  `temporal_ordered_extended`) — ⬜ не поддержаны, отклоняются явной ошибкой при сохранении
  правила, не тихой инертностью. Агрегация алертов в **инциденты** (`incidents` — единица
  работы агента, склейка нескольких алертов) — ⬜, вынесена в Этап 4.
- 🟡 Ретеншн `events` — ✅ `app/store.py:delete_events_older_than`, вызывается фоново из
  `IngestWorker` (`SIEM_EVENTS_RETENTION_DAYS`, дефолт 14д, `0` — выключено); архивация/переезд
  на Postgres/Elastic при дальнейшем росте — ⬜.

### Этап 2 — UI SIEM 🟡 (одна страница есть, расширяем)
- ✅ Вкладки: Источник данных / Алерты / События / Sigma-правила / Списки / База знаний; карточки алерта и события; смена статуса.
- ✅ **Вкладка «База знаний»** (`app/kb.py`, `/kb/mitre/*`) — подвкладки MITRE ATT&CK (матрица
  тактик-колонок с техниками/сабтехниками, клиентский фильтр по ID/названию, resizable
  детейл-панель техники: описание/detection/платформы/data sources/тактики/митигации/сабтехники)
  и Playbooks (заглушка). Карточка алерта показывает названия сматчившихся техник (ссылки на
  attack.mitre.org) + чипы тактик; несматчившийся тег остаётся сырым (`renderMitreChips`).
- ✅ Сортировка по клику на заголовок (Алерты: Правило=severity/Хост/События/Статус/Создан;
  События: Время/Хост), серверная — корректна с пагинацией.
- ✅ Колонки в Событиях: кастомные из сырого JSON (`json_extract`, пусто если поля нет) +
  базовые (Время/Хост/Правила) — единый перетаскиваемый порядок (`columnOrder`, включает и
  базовые, и кастомные id), базовые не удаляются, только переставляются; кнопка «Сбросить
  fieldset» возвращает к дефолтному набору колонок, не трогая сохранённые именованные
  **fieldset-ы** (`{fields, order}` в localStorage, с обратной совместимостью со старым
  форматом-массивом).
- ✅ **Фильтр** Событий — строка ввода с мини-языком (в духе MaxPatrol query bar,
  `app/filter_lang.py`): `поле оператор значение`, логика `and`/`or`/`not` с приоритетом как
  в SQL и произвольной вложенностью через скобки (замена старого конструктора с одним общим
  AND/OR на весь список условий — там нельзя было выразить смешанную логику). Операторы
  `=`/`!=`/`>`/`<`/`>=`/`<=`/`contains`/`in(...)`/`is null`/`is not null`; спецполя результата
  детекта `rule` (название сработавшего правила, `EXISTS` по `json_each(matched_rules)` — поле
  многозначное) и `is_matched` (`true`/`false`, только `=`/`!=`). Разбор — токенайзер +
  recursive-descent парсер → AST → parametrized SQL (поле/значение всегда bound-параметры,
  инъекция исключена); синтаксическая ошибка → `400` с текстом и позицией под строкой фильтра
  (устаревшие ответы игнорируются по счётчику `eventsRequestSeq` — иначе гонка старого/нового
  запроса могла показать чужую ошибку). Разворачиваемая справка по кнопке «Подробнее».
  Отдельного фильтра по хосту нет — выражается тем же языком (`Hostname contains "..."`).
  Пайплайн: фильтр → потом группировка.
- ✅ **Группировка** как в MaxPatrol: панель агрегаторов слева (значение+счётчик), клик = drill-in в события группы (условие всегда AND); заголовок показывает общее число уникальных значений (`total_groups` от `/events/group`, независимо от лимита выдачи); панель группировки и панель деталей — resizable (тянуть за край, кнопка сброса ширины).
- ✅ Колонки в таблице Событий — resizable по ширине через отдельную строку-«линейку» под заголовками (имена полей → строка регулировки ширины → события), тонкие вертикальные разделители между колонками; ширины сохраняются в localStorage per-колонка.
- ✅ Главный контейнер использует всю ширину окна (без фиксированного `max-width`).
- ✅ Панель группировки — **две вложенные коробки**: `.group-panel-wrap` (грид-item, sticky, держит ширину/высоту, хостит resize-handle, который торчит за правый край через `right:-14px` — сама `overflow: visible`, иначе обрезала бы свою же ручку) и `.group-panel` внутри неё (100% размера родителя, `overflow: hidden` **безусловно по обеим осям**). Разделение специально ради этого `overflow: hidden` — раньше пытались сдержать переполнение только через `min-height: 0` на грид-элементе (у грид/флекс-элементов по умолчанию «automatic minimum size» = min-content содержимого, который побеждает явный `height`), но на практике список групп всё равно иногда вылезал за пределы блока по вертикали; `overflow: hidden` не зависит от этой эвристики вообще и клипает контент engine-native, гарантированно. Внутри — `.group-scroll` (`flex: 1 1 auto; min-height: 0; max-height: 100%; overflow-y: auto; overflow-x: hidden`) — тот же scroll-wrapper паттерн, что у `.detail-panel`/`.detail-body`.
  Колонка «значение» внутри группировки — resizable (отдельная строка-линейка над списком + вертикальный разделитель значение/счётчик через общую CSS-переменную `--group-value-w`), при создании новой группировки её ширина и ширина всей панели (`computeOptimalGroupPanelWidth`) подбираются автоматически под самые длинные реально пришедшие значения (`computeOptimalGroupWidth`, зажато в [70, 380]px / [200, 640]px), дальше можно доресайзить вручную. Длинные значения обрезаются эллипсисом (как в основной таблице Событий, полный текст — в `title`), а не индивидуальным scrollbar-ом на поле. При сужении панели ужимается **только** колонка значения (`.gv { flex: 0 1 var(--group-value-w) }`) — колонка счётчика (`.gc { flex: 0 0 auto }`) никогда не сжимается и не уезжает за пределы видимости.
- ✅ Временной интервал (пресеты 15м/1ч/24ч/7д + кастомный from–to, с секундами): События по
  `event_time`, Алерты по `created_at`. Границы сравниваются как «наивные» строки без часового
  пояса (без `Z`/offset) — ровно в том виде, в каком время хранится в БД (`event_time` у разных
  источников то `"YYYY-MM-DD HH:MM:SS"`, то ISO с `Z`/мс — нормализуется на лету при сравнении
  в SQL); свой интервал берёт значение picker-а буквально, без пересчёта через локальный
  часовой пояс браузера (раньше `Date.toISOString()` сдвигал диапазон на офсет, и фильтр
  «ничего не находил»). Колонка «Время» в таблице Событий отображается в едином виде
  `YYYY-MM-DD HH:MM:SS` независимо от формата источника (только отображение, хранение не трогает).
- ✅ Светофор статуса сервиса в шапке — реальная проверка, не заглушка (см. `/health` в Этапе 1),
  опрашивается каждые 20с (пауза при неактивной вкладке); клик — попап с разбивкой по
  БД/Zircolite/очереди ingest.
- ✅ **Вкладка «Sigma-правила»** (`app/rules/rules_catalog.py`, `app/rules/main_ruleset.py`, `/rulesets*`,
  `/rules/custom*`, `/main-ruleset/*`) — просмотр built-in + любого числа именованных custom
  рулсетов, поиск, серверная сортировка (в т.ч. `level` по рангу серьёзности, не алфавиту),
  resizable детейл-панель правила (1-в-1 паттерн Alerts: `PANEL_RESIZE_CONFIG` + переиспользование
  `--alert-detail-w`, дефолтная ширина увеличена до 700px/maxWidth 900px специально для этой
  панели — читать YAML+SQL одновременно в исходных 380px было тесно); блок «Sigma YAML» внутри
  (`pre.json-block.yaml-block`) — `max-height: 70vh` (был 280px общий для всех `.json-block`,
  включая этот — тесно было не только ширине, но и высоте при резайзе через нативный `resize:
  vertical`). **Важно (грабли, уже словили дважды):** начальная ширина resizable-панели при
  ПЕРВОЙ ЗАГРУЗКЕ страницы берётся НЕ из `PANEL_RESIZE_CONFIG.defaultWidth` (тот применяется
  только по клику «Сбросить ширину»/явному `resetPanelWidth(...)`), а из CSS grid-переменной
  трека (`var(--alert-detail-w, 380px)` и т.п., с фолбэком 380px) — если у панели дефолт
  ОТЛИЧАЕТСЯ от 380px (как у rule-detail=700px, editor-reference-pane=480px), она рендерится
  шире СВОЕГО грид-трека и визуально наезжает на соседнюю колонку (ловили: ~300px таблицы правил
  перекрывались панелью просмотра, пока не заметили). Фикс — явный `resetPanelWidth(panelId)`
  один раз при инициализации скрипта (см. вызовы рядом с `makeResizable(...)` в конце файла) для
  КАЖДОЙ панели, чей `defaultWidth` ≠ 380px. Если добавляешь новую resizable-панель с нестандартным
  дефолтом — не забудь этот вызов, иначе баг повторится молча (визуально, без ошибок в консоли).
  **Создание/редактирование правила** — отдельный ПОЛНОЭКРАННЫЙ вид (`#sigma-editor-panel`),
  подменяющий содержимое вкладки целиком (не модалка, не глобальная вкладка в шапке —
  `openRuleEditor()`/`closeRuleEditor()` просто переключают `display` между `#sigma-browse-panel`
  и `#sigma-editor-panel` внутри `#view-sigma`; `switchTab`/`activeTab`/`RELOAD_FNS` не трогают,
  переключение на другую вкладку и обратно состояние редактора не сбрасывает). Раскладка —
  СЕТКА 4×2 через `grid-template-areas` на `.editor-grid` (не последовательные строки/флекс-блоки
  друг под другом — начальный вариант через простые блоки не давал одноимённым элементам встать
  вровень по вертикали, пока не переехали на явные area):
  ```
  "header reftoolbar"
  "header refpicker"
  ".      yamllabel"
  "editor refyaml"
  ```
  Первые два ряда (высота `auto`) — **слева** ОДНА ячейка `.editor-header-col`, спанящая оба ряда,
  внутри неё две горизонтальные части: `.editor-header-buttons` (тулбар «← Назад к списку правил»,
  заголовок `#rule-editor-title`, «Сохранить» — кластером слева, `margin-left:auto` НЕ используется
  на кнопке; плюс `#rule-editor-target-row`/`#rule-editor-static-target` — выбор целевого рулсета)
  и `.editor-vl-pane` — мини-браузер именованных списков значений (`%name%`/`\|expand`, фильтр
  сверху, список слева, значения выбранного списка справа), чтобы не переключаться на вкладку
  «Списки», пока пишешь правило. **Справа** — референс-браузер уже существующих правил, РАЗБИТЫЙ
  НА ДВА РЯДА: `#rule-editor-ref-toolbar` (`grid-area: reftoolbar` — селектор рулсета + поиск) и
  `#editor-reference-pane` (`grid-area: refpicker` — сам список, `#rule-editor-ref-list-body`/
  `.ref-rule-list`). Спан левой ячейки на оба ряда — ровно ради того, чтобы верх левого блока и
  селектор рулсета справа начинались на ОДНОМ уровне (раньше тулбар жил снаружи грида, в общей
  строке «Источник:», и весь левый блок висел на ряд ниже него; сама строка `#source-select-row`
  на вкладке Sigma-правил теперь прячется целиком — в ней больше нечего показывать).
  Третий ряд — подписи колонок: «Editor» (`grid-area: editorlabel`) над самим редактором и
  «Sigma YAML» (`grid-area: yamllabel`) над просмотрщиком, СВОИМ рядом, а не внутри самих панелей:
  иначе подпись добавляла бы высоту только одной колонке и её содержимое начиналось бы ниже
  соседней.
  Нижний ряд (`1fr`, съедает весь остаток высоты экрана) — **слева** `.code-editor-wrap`
  (`grid-area: editor`) — сам редактор (`#rule-editor-yaml`) с ЖИВОЙ подсветкой синтаксиса:
  overlay-приём без внешних библиотек (прозрачный `<textarea>` с видимой только кареткой поверх
  `<pre id="rule-editor-highlight">`, куда на каждый `input` пишется тот же `highlightYaml()`,
  что и для read-only показа; `.code-editor-highlight`/`.code-editor-input` ОБЯЗАНЫ совпадать по
  font/line-height/padding/box-sizing, иначе слои разъедутся при скролле). Tab вставляет 2
  пробела вместо перевода фокуса (YAML чувствителен к отступам). **Справа** `.editor-reference-yaml`
  (`grid-area: refyaml`) — YAML (или SQL с пометкой, если у правила нет исходного YAML, т.е.
  builtin) выбранного в списке правила; `pre.json-block.yaml-block` внутри без max-height,
  растягивается на весь флекс-родитель.
  Поскольку `editor` и `refyaml` — это ОДИН И ТОТ ЖЕ ряд грида, они автоматически начинаются
  РОВНО на одном уровне по вертикали (та же логика для `header`/`reftoolbar` в первом ряду) —
  именно ради этого выбрана raw grid-template-areas раскладка, а не last-min flex-подгонка отступов.
  **Грабли, уже словили:** `#editor-reference-pane` должен иметь ЯВНУЮ `height` (не `min-height`!)
  — без неё грид-ряд "auto" считает intrinsic-высотой контента ВЕСЬ нескролленный список правил
  (`.ref-rule-list` с `overflow-y:auto` включает скролл только когда у родителя УЖЕ есть
  зафиксированная высота), из-за чего ряд разъезжался на тысячи пикселей и второй ряд грида
  (сам редактор) уезжал далеко за пределы экрана. Обе референс-панели (`refpicker`/`refyaml`) НЕ
  связаны с тем, что печатается слева — чисто browse-панель для подглядывания в уже существующие
  правила. Вся правая колонка (`.editor-grid` column 2, driven by `--editor-ref-w`) — resizable
  тем же паттерном, что и детейл-панели (`PANEL_RESIZE_CONFIG`, defaultWidth 600/min 320/max 780,
  `gridEl` — сам `#editor-grid`; drag-хэндлов ДВА — в `refpicker` и в `refyaml`, оба двигают одну
  CSS-переменную колонки, значит синхронно тянут и `reftoolbar` тоже, без доп. кода); тянет левую колонку у́же/шире, т.к. она `1fr` в том же
  grid-е.
  Кнопка «Редактор правил» (вкладка, слева от «+ Загрузить рулсет») открывает `create` (пустой
  редактор + выбор целевого рулсета, `readSigmaTarget()`), кнопка «Редактировать» в детейл-панели
  custom-правила — `edit` (YAML предзаполнен из `r.yaml_text`, целевой рулсет зафиксирован,
  меняться не может, `PUT /rules/custom/{rule_id}`). Загрузка ЦЕЛОГО рулсета (файл, не текст)
  осталась отдельной раскрывающейся панелью «+ Загрузить рулсет» — её теснота не мешает (выбор
  файла, а не печать YAML). И создание, и редактирование, и загрузка ТРЕБУЮТ указать целевой
  custom-рулсет (radio «существующий» + селектор / «новый» + поле имени — `readSigmaTarget()`,
  общая для `sigma-upload`/`rule-editor` префиксов) — встроенные рулсеты как цель недоступны в UI.
  Кнопка «Редактировать» ссылается на предзаполненные данные ЧЕРЕЗ ГЛОБАЛЬНУЮ ПЕРЕМЕННУЮ
  (`currentSigmaRule`, выставляется в `selectSigmaRule` при открытии детейл-панели), а не
  встраивает YAML-текст прямо в HTML `onclick`-атрибут — сырой Sigma YAML почти всегда содержит
  и `'...'`, и `"..."` одновременно, и `JSON.stringify` НЕ экранирует `'` (не служебный символ в
  JSON), поэтому `onclick='...(${JSON.stringify(yaml)})'` ломается на первой же одинарной
  кавычке внутри YAML — ловили `SyntaxError: Invalid or unexpected token` именно на этом.
  Удаление — для custom-рулсетов и своих правил (встроенные — read-only). Списки `ruleset` в формах ingest
  («Источник данных») и сам селектор рулсета вкладки Sigma-правила заполняются из одного
  каталога, плюс пункт «⭐ Основной рулсет» первым во ВСЕХ трёх (`rulesetOptionsHtml(catalog,
  {includeMain:true})` теперь без исключения для sigma-select).
  **Основной рулсет** (main, см. `app/rules/main_ruleset.py` выше) собирается прямо тут: отдельная
  колонка в таблице правил с кнопкой `+`/`✓` на каждую строку (`toggleRuleInMain`, работает для
  ЛЮБОГО открытого рулсета — builtin или custom), кнопка «добавить рулсет целиком» рядом с
  селектором (`toggleCurrentRulesetInMain`, статус из `entry.main_status`), toggle switch
  «Только основной рулсет» (`#sigma-only-main-toggle`) фильтрует уже открытый список до
  входящих в main (`only_main=true` у `/rulesets/rules`; выключен и снят, когда сам main выбран
  в селекторе — там и так только он). Выбор «⭐ Основной рулсет» в селекторе — такой же пункт,
  как любой другой: показывает виртуальный список, собранный сразу из НЕСКОЛЬКИХ реальных
  рулсетов (`GET /rulesets/rules?ruleset=main` → `main_ruleset.resolve_with_sources()`); каждая
  строка несёт `source_ruleset` — по нему (не по значению селектора) идут клик по правилу и
  кнопка `+`/`✓` (`selectSigmaRule(ruleId, ruleset)` принимает ruleset построчно, не читает
  селектор напрямую).
  В детейл-панели правила — блок «Sigma YAML» **выше** блока «SQL»: YAML показывается только
  у своих правил (у built-in исходного YAML нет и не было, только скомпилированный SQL),
  подсветка синтаксиса — свой лёгкий построчный regex-highlighter (`highlightYaml`,
  без внешних библиотек); первым шагом обязательно `escapeHtml`, потом раскраска (YAML
  своего правила — untrusted-текст, экранировать нужно до, не после разметки).
- ✅ **Удаление источника** (`DELETE /batches/{source_batch}`) — таблица источников во
  вкладке «Источник данных» (переиспользует уже загружаемый `/batches`), кнопка «Удалить» с
  `confirm()`-предупреждением перед необратимым действием; удаляет и `events`, и `alerts`.
- ✅ **Регистрация потоковых источников + токен** (`/sources*`, таблица `sources`) — во вкладке
  «Источник данных» блок «Потоковые источники»: «Создать источник» (имя обязательно/уникально +
  описание) → одноразовый показ токена, curl-сниппет показывается ТОЛЬКО при создании (при
  перевыпуске — только новый токен). Таблица с перевыпуском/вкл-выкл/снятием регистрации.
  Форма «вставить события напрямую» теперь тоже требует источник+токен (свежий токен сессии
  подставляется сам). Отдельно от таблицы «все загруженные метки `source_batch`».
- ⬜ Дашборд: счётчики по severity, топ правил/хостов/MITRE, таймлайн.
- ⬜ Полноценный **триаж-воркфлоу**: назначение аналитика, комментарии, метки TP/FP.
- ⬜ Поиск/фильтры по событиям (полнотекст, по полям), пивот из алерта в связанные события.
- ⬜ Живое обновление (SSE/WebSocket) при поступлении новых алертов.
- ⬜ Аутентификация/роли (аналитик vs админ) — перед выходом за пределы localhost.
- ✅ **Пагинация в «Алертах» и «Инцидентах»** — тот же пейджер, что у Событий/Sigma-правил
  (`renderPager(prefix, offset, limit, total)` + `alertsOffset`/`incidentsOffset`); `/alerts`
  ради этого стал отдавать обёртку с `total` (см. §4 API). Колонка «Сущность» (`group_key`)
  в списке инцидентов и строка `group_key` в шапке карточки; бейджи «корреляция»/«инцидент»
  в списке Sigma-правил (`ruleKindBadges`); после сохранения из редактора правил детейл-панель
  показывает только что сохранённое правило, а не прежнее из другого рулсета.

### Этап 3 — Ingest коннекторы и нормализация 🟡
- Поддержка потоковых источников (Winlogbeat/NXLog/syslog forwarder → `/ingest/events`).
- Стабильная схема нормализованного события (ECS-подобная) на входе в хранилище.
- 🟡 Управление рулсетами: ✅ именованные custom-рулсеты, загрузка Sigma YAML (в т.ч.
  multi-document) + написание своих правил, обязательный выбор целевого рулсета — см. вкладку
  «Sigma-правила» (Этап 2), `app/rules/rules_catalog.py`. ⬜ Осталось: версионирование, включение/
  выключение по тегам.
- ✅ **Именованные списки значений** (`%name%` + `|expand`, `app/rules/value_lists.py`, вкладка
  «Списки», `/value-lists*`) — длинные перечни (recon-утилиты, LOLBIN и т.п.) выносятся в
  отдельный файл `data/value_lists/<name>.yml` и подставляются в кастом-правило плейсхолдером
  при компиляции; правка списка сразу пересобирает зависимые правила. Только кастомные правила
  (builtin приходят уже в SQL). v1: запись целиком `%name%`, без встроенных `foo%name%bar`.
- ✅ **`ruleset` для `/ingest/stream`/`/ingest/events`** — оба теперь используют «основной
  рулсет» (`app/rules/main_ruleset.py`, `MAIN_RULESET_ID = "main"`) вместо жёсткого дефолта движка:
  `_process_events` в `app/main.py` подставляет `ruleset_path = ruleset_path or
  main_ruleset.MAIN_RULESET_ID`, дальше `_process_batch` резолвит `main_ruleset.resolve()` в
  плоский список правил и зовёт `engine.run_batch_with_rules(...)` (кэш `_rulesets_cache` тут
  не участвует — `resolve()` и так дешёвый, читает уже скомпилированные правила через кэш
  `rules_catalog`). Состав основного рулсета собирается во вкладке «Sigma-правила» (кнопки на
  правилах/рулсетах, см. Этап 2) — теперь свои правила ИЗ ЛЮБОГО custom-рулсета можно
  протестировать через потоковый ingest, для этого достаточно добавить их в main.

### Этап 4 — Инциденты и подготовка контекста для агента 🟡 (ядро есть, tool'ы агента — Этап 5)
- ✅ **Таблица `incidents`** — агрегат срабатываний, единица работы агента. Заводится НЕ
  проходом-агрегатором по `alerts` (как планировалось изначально), а **сценарно**: срабатывание
  correlation-правила (`app/detection/correlation.py`), помеченного блоком `correlation.incident`
  (`{type, severity?, title?}`), создаёт инцидент ВМЕСТО `engine="correlation"` алерта. Логика
  сценария — Sigma-правилом (`temporal`/`temporal_ordered`/цепочки). Идентичность —
  источник + фиксированный бакет по `timespan`
  (`dedup_key = sha256(source_batch:incident_type:group_values:window_bucket)`),
  повтор в том же бакете обновляет строку. Тип инцидента параметризуемый (`incident.type` — slug).
  **Catch-all прохода по `alerts` намеренно НЕТ** — одиночный critical-алерт без покрывающего
  сценария инцидентом не станет (осознанное ограничение, `docs/spec/incidents.md`).
- ✅ **Хранилище вердиктов** — таблица `investigations` (`incident_id`, `status` `queued → running
  → done → error`, `verdict` `TP`/`FP`/`needs-review`, `rationale`, `confidence`, `steps`,
  timestamps). Заполняется фоновой джобой (`app/incidents.py:run_pending`, на треде `IngestWorker`,
  `SIEM_INCIDENT_VERDICT_*`). На Этапе 4 — **заглушка** (`queued → done` с `needs-review` и
  placeholder-обоснованием); настоящий LLM — Этап 5.
- ✅ **`GET /incidents/{id}/context`** — полный контекст одним ответом: correlation-правило + member-
  правила (Sigma SQL/YAML), sample-события, связанные события по entity
  (`compile_filter_query(_incident_entity_filter(group_key))`), история сущности
  (`store.list_alerts_by_entity` по значениям `group_key`, а не последние алерты источника). Переживает вычищенные
  ретеншном `events` (пустой `related_events` + `note`).
- ⬜ **Инструменты (tools)** — stack-agnostic обёртки `search_events`, `get_incident_context`,
  `pivot_by_entity`, `lookup_mitre` (`app/kb.py:get_technique`/`enrich_techniques` — осталось
  обернуть) — пишутся вместе с агентом на Этапе 5.

### Этап 5 — AI-агент расследования 🎯 главная цель ⬜
- **Стек:** агент на **LangGraph**; «мозги» — любой **OpenAI-совместимый** провайдер через
  `langchain-openai.ChatOpenAI`. Провайдер/модель/ключ — из `.env`: `SOC_AGENT_API_BASE`,
  `SOC_AGENT_API_KEY`, `SOC_AGENT_MODEL`, опц. `SOC_AGENT_TEMPERATURE` (добавить в
  `app/config.py`, `.env.example`). **НЕ Anthropic SDK; skill `claude-api` не используется.**
- **Размещение:** подпакет `app/agent/`; зависимости (`langgraph`, `langchain-openai`) — в
  `[project.optional-dependencies].agent`, в базовый прод не тянутся. Запуск — фоновая джоба/
  воркер (как `IngestWorker`): создан инцидент → в очередь расследования → `investigations.status`.
- **Граф:** триаж → tool-use цикл (события/пивот/MITRE) → гипотеза → вердикт
  `TP`/`FP`/`needs-review` + обоснование + confidence → запись в `investigations`, показ в
  карточке инцидента (Этап 2).
- **Контент правил — отдельный трек:** N типов инцидентов, старт с brute-force и простых
  сценариев; базовый `main`-рулсет (curated-срез, не весь `rules_windows_merged.json`) + листы
  значений.
- **Оценка качества — живой adversarial-контур** (не replay датасетов): опенсорсный
  pentest-agent на ВМ с настроенным аудитом, подключённой в SIEM через форвардер
  (`POST /ingest/stream`, см. `docs/guide/forwarder.md`). pentest-agent генерит атаки →
  инциденты → soc-agent выносит вердикты → сверка. OTRF Security-Datasets остаются только для
  ОФЛАЙН-разработки корреляции/правил, НЕ для прогона агента.
- **Human-in-the-loop:** аналитик подтверждает/отклоняет вердикт → данные для дообучения промптов.

### Этап 6 — Продакшн-готовность ⬜
- Метрики (Prometheus), логирование, обработка ошибок ingest, бэкапы БД.
- Контейнеризация (Dockerfile/compose), CI (линт + тесты).

---

## 8. Что важно помнить при доработке

- **Не пересоздавай `RulesetHandler` на каждый запрос** — это секунды на тысячах правил.
  Кэш живёт в `ZircoliteEngine._rulesets_cache` (ключ — путь к рулсету, никогда сам не
  инвалидируется). После add/delete кастомного правила или удаления загруженного рулсета —
  обязательно `engine.invalidate(ruleset_path)`, иначе `/ingest/*` с этим `ruleset_path`
  продолжит использовать старую скомпилированную версию до рестарта процесса (уже ловили:
  правило удалено, а детект по нему всё ещё срабатывал).
- **Редактирование (`PUT /rules/custom/{rule_id}`) уже включённого в основной рулсет правила
  НЕ требует повторного тоггла** — членство в main хранится по `(ruleset_path, rule_id)`
  (`custom_rulesets/main_ruleset.json`), а `id` при редактировании остаётся исходным - другой
  `id:` в YAML отклоняется с 400 (см. `rules_catalog.update_custom_rule`), поэтому ссылка не рвётся. Новая версия
  SQL подхватывается СРАЗУ на следующем батче: `update_custom_rule` инвалидирует mtime-кэш
  `.manifest.json` (`_write_manifest` → `_invalidate_cache`), а `main_ruleset.resolve()`
  каждый раз заново вызывает `rules_catalog.load_rules()` — так что никакого отдельного кэша
  на уровне main нет и обновлять вручную нечего. Если тот же custom-рулсет раньше гоняли
  НАПРЯМУЮ (`ruleset=custom_rulesets/<id>` у `/ingest/file`/`/ingest/upload`, не через main) -
  там свой кэш в `ZircoliteEngine._rulesets_cache`, но роут `PUT` и его тоже инвалидирует
  (`engine.invalidate(ruleset)`). Уже созданные алерты по старой версии правила не
  пересчитываются - изменения касаются только будущих детектов; если отредактированное
  правило сработает повторно на том же хосте/сущности - это инкремент `event_count` у
  существующего алерта (тот же `dedup_key`, см. ниже), не новый алерт.
- **У built-in скомпилированных рулсетов (напр. `rules_windows_merged.json`) один Sigma-`id`
  легитимно встречается НЕСКОЛЬКО раз** — одно исходное правило превращается в несколько
  записей с разным SQL под разные pipeline/источники (напр. «... - Generic» на Security/4688 и
  «... - Sysmon» на Sysmon/EventID=1, оба с одним `id`; в `rules_windows_merged.json` так у
  1611 из 4291 записей). `app/rules/main_ruleset.py:resolve_with_sources()` **не дедуплицирует по
  id** — раньше дедуплицировал по `(ruleset_path, id)` и это молча теряло ~37% правил при
  добавлении рулсета целиком в main; см. докстринг функции, если тянет добавить обратно.
  Точечный toggle одного правила по `rule_id` (`toggle_rule`) при этом всё равно затрагивает
  ВСЕ записи с этим id сразу (это ожидаемо — они представляют одно логическое правило).
- **При ручном тестировании alert-дедупликации** (два режима дедупа, см. `detection/
  normalize.py` и §4) осторожно с фиксированными `id` в тестовых Sigma-правилах — для
  custom-правил (обычный случай) повторный прогон СОВПАДАЮЩЕГО по содержимому события (то же
  самое, только другое время) не создаёт новый алерт, а инкрементит `event_count` у уже
  существующего (и `source_batch` у него остаётся от
  ПЕРВОГО батча, где он появился) — со стороны выглядит как «алертов 0» в новом батче, хотя
  события реально сматчились. Через `DELETE /batches/{source_batch}` можно почистить старые
  тестовые батчи, если это создаёт путаницу.
- **У correlation-правила `id` берётся из YAML, а при его отсутствии — из ИМЕНИ ФАЙЛА**
  (`<rule_id>.sigmacorr`, `load_correlation_rules`). Sigma не требует `id:`, и мы его в файл не
  дописываем, а `correlation._active_correlation_rules` для «основного рулсета» сопоставляет
  correlation-запись с `.manifest.json` именно по `id` — с `id=None` правило молча выпадало из
  main: сохранено, видно в UI, никогда не срабатывает (ловили вживую). Не «упрощай» обратно до
  `doc.get("id")`.
- **Ссылки `correlation.rules` проверяются на СОХРАНЕНИИ и резолвятся только внутри своего
  рулсета.** Опечатка в ссылке или ссылка на правило из ДРУГОГО рулсета — `400`, а не тихо
  сохранённое правило, которое `load_correlation_rules` потом целиком пропускает (правило
  выглядело сохранённым и никогда не срабатывало). Индекс ссылок один на оба пути —
  `rules_catalog.build_ref_index`: если добавляешь новый источник имён (например поддержку
  межрулсетных ссылок), правь его, а не два места по отдельности, иначе валидация и рантайм
  снова разъедутся. Базовое правило и корреляцию держи в одном рулсете (для пака — можно в
  одном multi-document файле: документы файла тоже попадают в индекс).
- **ECS-lite колонки `events` (`user_name`/`src_ip`/`dst_ip`/`process`/`event_code`) теперь
  ЧИТАЮТСЯ** — это имена полей фильтра/группировки/сортировки (`filter_lang.ENTITY_COLUMNS`),
  единые для всех источников. Не удаляй их и не оборачивай в `CAST(... AS TEXT)` в новом коде:
  с `CAST` планировщик не берёт `idx_events_user`/`idx_events_src_ip` (проверка —
  `EXPLAIN QUERY PLAN`, должно быть `SEARCH events USING INDEX idx_events_src_ip`, тест
  `tests/test_store.py::test_entity_columns_are_filterable_and_indexed`).
- **В `app/` не пишем `print()` — только `logging.getLogger(__name__)`** (настройка —
  `app/logging_setup.py`, зовётся из `main.py`). `print` на Windows берёт кодировку консоли:
  при `uvicorn ... > server.log` русские сообщения превращались в мусор ровно там, где они
  нужнее всего (ошибка обработки батча = потерянные события).
- **`logging_setup.configure()` переводит в UTF-8 ОБА потока (`stdout` И `stderr`) — не убирай
  stdout «за ненадобностью».** Zircolite рисует прогресс компиляции правил через `rich`
  (спиннер `⠋`, U+280B) в stdout. На cp1251-потоке (перенаправление в файл, служба, обычная
  консоль Windows) запись этого символа бросает `UnicodeEncodeError` ВНУТРИ конвертации,
  Zircolite ловит её как «Cannot convert» и отдаёт ПУСТОЙ рулсет. Симптомы обманчивы:
  «Правило не скомпилировалось в SQL — проверь detection/logsource» на заведомо корректном
  правиле и потеря ЦЕЛОГО флаша ingest. Ловили вживую; тест — `tests/test_logging_setup.py`.
  Поэтому же `configure()` зовётся ДО создания `ZircoliteEngine`.
- **`siem.db` большой** (десятки МБ) и растёт с каждым ingest — не коммить, чистить при тестах.
- **`Zircolite/` и `artifacts/Security-Datasets/` — внешние клоны** (со своими `.git`),
  не редактируй их код; всё своё держи в `app/`.
- **AI-агент (`app/agent/`, Этап 5) — на LangGraph + OpenAI-совместимом API** (провайдер/модель/
  ключ из `.env`, префикс `SOC_AGENT_*`), НЕ на Anthropic SDK; skill `claude-api` не используется.
  Зависимости агента (`langgraph`, `langchain-openai`) — в extra `[project.optional-dependencies].agent`,
  в базовый прод не тянутся. Единица работы агента — **инцидент** (агрегат алертов, таблица
  `incidents`), не сырое срабатывание правила. Оценка качества — живой контур с pentest-agent на
  ВМ (форвардер → `/ingest/stream`), не replay датасетов.
- **Фильтр Событий (`app/filter_lang.py`) — никогда не подставляй пользовательский текст
  в SQL напрямую.** Значение условия всегда уходит как bound-параметр sqlite3 через
  `compile_condition`/`_compile_node` — при добавлении новых операторов или спецполей (по
  образцу `rule`/`is_matched`) сохраняй этот паттерн. Путь поля - тоже bound-параметр, КРОМЕ
  узкого whitelist `INDEXED_JSON_FIELDS` (сейчас только `EventID`) - для них путь литерал в
  тексте SQL, чтобы сработал expression-индекс `idx_events_json_eventid` (см. `store.py`); это
  по-прежнему безопасно (литерал всегда фиксированное значение словаря по ключу, не производная
  от сырого текста), но если добавляешь новое "горячее" поле в этот словарь - парный индекс в
  `store.py`/`_SCHEMA` должен ТЕКСТУАЛЬНО совпадать с выражением, иначе SQLite его не подхватит
  (проверяй `EXPLAIN QUERY PLAN` - должно быть `USING COVERING INDEX idx_events_json_...`, а не
  `SCAN events` без индекса).
- **Ingest нескольких источников сливается в ОДИН прогон движка за флаш** (`app/ingest_queue.py`
  → `app/main.py:_process_events`) - фиксированный оверхед Zircolite на батч (~0.25с у нас на
  ~4300 правилах, не зависит от числа событий) раньше платился ОТДЕЛЬНО за каждый источник
  внутри одного флаша (`IngestWorker._flush` группировал буфер по `source_label` до прогона
  движка) - при большом числе источников это было главным узким местом стабильности (см. §7,
  оценка ~15-20 источников на 5-секундное окно флаша при старой схеме). Теперь источник каждого
  события временно кодируется в САМОМ событии (`INGEST_SOURCE_FIELD` из `app/fields.py`) перед
  прогоном и снимается после (`_split_events_by_source` для events, `normalize.py` для alerts) -
  если добавляешь новый ingest-путь, который тоже должен уметь мешать источники, следуй этому
  же паттерну, а не возвращай группировку по source_label ДО движка.
- **Correlation-правила (`app/rules/rules_catalog.py`) хранятся под `CORRELATION_EXT` (`.sigmacorr`),
  НЕ `.yml`/`.yaml` — не переименовывай/не "исправляй" эту раскладку.** Причина не косметика:
  установленный сток (не пропатченный — сверено по sha256 файла против RECORD в dist-info)
  `pysigma-backend-sqlite==1.2.0` (воспроизведено и на 1.2.4, актуальной опубликованной) не
  может скомпилировать правило для независимого вывода, если оно ЕЩЁ И referenced корреляцией
  из ТОГО ЖЕ `SigmaCollection`. Механизм — `finalize_correlation_subqueries = False`
  (`pysigma/conversion/base.py`, не переопределён sqlite-бэкендом) отключает `finalize_query`
  для правила с backreference. Без `correlation.generate:` referenced-правило получает
  `_output = False` и молча выпадает из скомпилированного рулсета (перестаёт детектить само по
  себе). С `generate: true` `_output` остаётся `True`, и наружу уходит НЕ финализированная
  сырая SQL-строка вместо dict, что валит компиляцию ВСЕГО файла (`'str' object has no
  attribute 'get'` в Zircolite при попытке отсортировать результат). Решение — не патчить
  Zircolite/pySigma (нельзя, внешние зависимости) и не заводить "правила-двойники" в контенте
  (был первый, отброшенный вариант), а физически развести правило-корреляцию и правило-
  селектор по разным расширениям, чтобы `RulesetHandler` (глобит только `*.yml`/`*.yaml`)
  никогда не видел их вместе. Если когда-нибудь апстрим починит баг — можно будет вернуть
  единое `.yml`-хранение, но проверяй эмпирически (compile_ruleset_yaml на файле с корреляцией
  + referenced-правилом в одном документе), не полагайся на changelog.
- **Ни один SQL-совместимый Sigma-бэкенд не годится для скользящей корреляции — это не повод
  переезжать на другой движок хранения.** Проверены `pysigma-backend-sqlite==1.2.0` (сток,
  единственный SQL-бэкенд в официальном реестре плагинов, кроме clickhouse) и
  `pysigma-backend-clickhouse` (`clicksiem/pySigma-backend-clickhouse`) — построчный порт тех
  же трёх дефектов: у `event_count`/`value_count` шаблон не содержит `{timespan}` (значение
  вычисляется и выбрасывается `str.format`), `temporal` считает окно как «весь срок жизни
  группы уложился в timespan» (не скользящее), `temporal_ordered` считает
  `GROUP_CONCAT(sigma_rule_id ORDER BY timestamp)` и НИКОГДА её не сравнивает — реальный
  порядок не проверяется. DuckDB-бэкенда для Sigma не существует вовсе. Это не баг одного
  бэкенда: Sigma-бэкенд генерирует один SQL statement, а скользящее окно с анкером и
  переоценкой на каждый flush — свойство движка исполнения, которого у Sigma-бэкендов нет в
  принципе. Полный разбор альтернатив (форк бэкенда, DuckDB, ClickHouse — все отклонены) и
  экономика решения — `docs/spec/correlation.md`, план в истории git (`Этап A`).
- **Счёт корреляции (`app/detection/correlation.py`) должен оставаться независимым от размера БД —
  это не пожелание, а проверяемое требование.** Счётный путь (A3: `store.fetch_correlation_hits`
  → скользящее окно в `_best_anchor` → `store.evaluate_correlation_window` за авторитетным
  счётом) читает ИСКЛЮЧИТЕЛЬНО `rule_hits.group_json` (денормализованные значения полей,
  записанные ПРЯМО в леджер на `store_events`/`insert_correlation_hits`), БЕЗ `JOIN` к `events` —
  не возвращай `JOIN`/`json_extract(raw_json, ...)` на счётном пути, даже «ради простоты», это
  снова сделает скорость зависимой от размера `events`. `fetch_correlation_hits` ОБЯЗАН быть
  сужен и по кандидатным ключам (`new_spans.keys()`), и по диапазону `~2×timespan` — без обоих
  фильтров это скан по всем ключам/всей истории. Проверяй `scripts/bench_correlation.py` при
  любой правке счётного пути — рост `rule_hits` в 100 раз должен давать единицы процентов роста
  времени, не пропорциональный.
- **A3 закрыл краевой эффект при перемешанном порядке прихода** (`_best_anchor` перебирает ВСЕ
  точки-якоря в `[min(new), max(new) + timespan]`, а не одну на `max(event_time)` новых
  событий). Не возвращай «якорь = max(new)» — «позднее» событие со старой меткой (форвардер
  выгрузил буфер, разъехались часы, replay) снова начнёт «прятать» окно, и правило будет молча
  не взводиться. `datetime.now()` как якорь по-прежнему нельзя (сломает replay — см. ниже).
- **`correlation.timespan` длиннее `SIEM_EVENTS_RETENTION_DAYS` отклоняется на сохранении**
  (`rules_catalog._validate_correlation_doc`, `RuleValidationError`): ретеншн удаляет `events` и
  осиротевшие `rule_hits`, окно длиннее ретеншна недосчитывало бы. `0` — ретеншн выключен,
  проверки нет. `rules_catalog` из-за этого импортирует `app.config` (цикла нет).
- **У `Store` теперь есть механизм аддитивной миграции схемы (`app/store.py:_migrate`,
  введён на Этапе A) — новые колонки/индексы добавляй через него, а не только в `_SCHEMA`.**
  `_SCHEMA` — это `CREATE TABLE IF NOT EXISTS`, no-op на уже существующей таблице: новая
  колонка, вписанная только туда, не появится у пользователей с уже накопленной `siem.db`.
  `_migrate(conn)` вызывается на каждом старте `Store` ПОСЛЕ `executescript(_SCHEMA)`:
  `PRAGMA table_info(...)` → `ALTER TABLE ... ADD COLUMN` для недостающих, затем — только
  ПОСЛЕ добавления колонок — `CREATE INDEX IF NOT EXISTS`/`DROP INDEX IF EXISTS` (иначе на
  старой БД индекс на новой колонке упал бы раньше, чем колонка появится). Версионирования
  схемы нет — только идемпотентные операции, безопасно звать на каждом старте.
- **Окно корреляции (`app/detection/correlation.py`) анкерится на `event_time` сохранённых
  попаданий (A3 перебирает точки-якоря в `[min(new), max(new) + timespan]`), не на
  `datetime.now()`.** `datetime.now()` сломал бы replay исторических датасетов (напр. OTRF
  Security-Datasets, где все `event_time` в прошлом) и бэкфилл: событие с меткой старше
  `now − timespan` не попало бы ни в одно окно (разбор — история обсуждения A3).
  `DELETE /batches/{source_batch}` чистит и
  `rule_hits`, не только `events`/`alerts` - если добавляешь ЕЩЁ одну таблицу, привязанную к
  `source_batch`, не забудь то же самое в `Store.delete_batch`. **Таблица `sources` под это
  правило НЕ подпадает намеренно**: `delete_batch` удаляет накопленные данные, но НЕ снимает
  регистрацию источника (его токен продолжает работать) - это разные действия (`DELETE
  /sources/{id}` vs `DELETE /batches/{name}`), и в UI это две разные таблицы/кнопки.
- **`/ingest/stream` и `/ingest/events` теперь за токеном источника** (`_authenticate_ingest`
  в `app/main.py`, таблица `sources` в `app/store.py`). Токен только из заголовка
  (`Authorization: Bearer` / `X-Ingest-Token`), НЕ из query - query светится в логах прокси
  (правило про секреты в URL). Токен в БД только sha256, открытый отдаётся один раз из
  `create_source`/`rotate_source_token`. Схема `sources` - обычный `CREATE TABLE IF NOT
  EXISTS` в `_SCHEMA`, миграции не нужно: существующая `siem.db` получает таблицу на старте,
  уже накопленные метки `source_batch` с ней никак не связаны. UI держит свежий токен в
  памяти сессии (`sessionSourceTokens`) - хэш из БД повторно не показать.
- **Метка времени события КАНОНИЗИРУЕТСЯ на записи (`app/timeutil.py`), а не нормализуется в
  SQL на каждое чтение - не возвращай `replace(replace(event_time, ' ', 'T'), 'Z', '')` в
  запросы.** `store.store_events` пишет ОДНО каноническое значение (наивный ISO по UTC) и в
  `events.event_time`, и в `rule_hits.event_time`; сырой формат источника остаётся в `raw_json`.
  Три следствия старой схемы, которые этим закрыты: граница из параметра не нормализовалась
  вовсе (`time_from=2026-09-05 09:00:00` с пробелом отдавал 0 строк), событие ровно на `time_to`
  с дробной частью выпадало (`…T21:01:30.113` > `…T21:01:30`), смещения не конвертировались
  (`21:00:00+03:00` и `18:00:00Z` - один момент, сортировались на три часа врозь). Границы
  приводит `normalize_time_bound` в ЕДИНСТВЕННОЙ точке (`store._events_where`), верхняя -
  включающая (хвост-сентинель). Побочный выигрыш: сравнение идёт с голой колонкой, и
  `idx_events_time` наконец работает как range-scan (`EXPLAIN QUERY PLAN` - должно быть
  `SEARCH events USING INDEX idx_events_time`, а не `SCAN events`). БД, накопленные до этого,
  приводит разовый бэкфилл `store._backfill_event_time` под отметкой в служебной таблице
  `schema_meta` - **это не версия схемы**: `_migrate` по-прежнему только идемпотентные операции,
  `schema_meta` нужна ровно чтобы не перечитывать всю `events` на каждом старте.
- **Ошибки каталога правил делятся на «нет объекта» и «нельзя»: `CatalogNotFound` (подкласс
  `CatalogError`) → 404, остальные `CatalogError` → 400** (`app/main.py:_catalog_http` -
  единственная точка трансляции, не пиши `raise HTTPException(404, str(exc))` по месту).
  Раньше все ручки каталога отдавали 404 на любую `CatalogError`: попытка добавить встроенный
  рулсет в main отвечала «не найден» про существующий файл, а несуществующий кастомный путь -
  сообщением про встроенность. Путь с префиксом `CUSTOM_PREFIX` (`custom_rulesets/`) теперь
  разбирается ТОЛЬКО как кастомный, даже если такого рулсета нет - иначе он снова провалится в
  builtin-ветку и получит «недопустимый путь» вместо «не найден». Наследование
  `CatalogNotFound` от `CatalogError` намеренное: `except CatalogError` в
  `main_ruleset.resolve_with_sources` (осиротевшая ссылка молча пропускается) продолжает
  ловить оба вида.
- **`group_cond` (drill-in по группе) fail-closed: нераспознанное условие - ошибка, а не
  пропуск.** `store._build_extra_filter_clause` бросает `FilterSyntaxError`, `main._parse_filters`
  отдаёт 400 раньше. Раньше условие с неизвестным `op` молча выбрасывалось, и drill-in вместо
  сужения возвращал ВСЮ выборку - в UI это не видно (он шлёт корректный `eq`), а через API
  выглядело как успешный ответ с неверными данными. Добавляешь новый оператор - добавляй его
  в `filter_lang.FILTER_OPS`, а не «мягкий» обход проверки.
- **Инциденты (`app/detection/correlation.py` + `incidents`/`investigations`, Этап 4) - грабли:**
  - Correlation-правило с блоком `correlation.incident` при срабатывании создаёт ИНЦИДЕНТ, а НЕ
    `engine="correlation"` алерт. Если ждёшь алерт от такого правила в тесте/на живом сервере -
    его не будет, смотри `GET /incidents`. Помеченное правило ещё и пробивает отсечку
    `level: informational` (severity инцидента - из `incident.severity`).
  - `incidents.dedup_key` - ИСТОЧНИК + фиксированный бакет по `timespan` (`source_batch:
    incident_type:group_values:window_bucket`). Повтор ключа в том же бакете = UPDATE строки
    (окно расширяется, severity пересчитывается), НЕ новый инцидент. Разрыв больше `timespan` =
    новый бакет = новый инцидент. **`source_batch` из ключа не убирать**: всё остальное в
    инциденте живёт в рамках одного источника (счёт корреляции сужен по `source_batch`, колонка
    `incidents.source_batch` одна, `delete_batch` чистит по ней), и без него два источника с
    одной сущностью в одном бакете схлопывались в ОДНУ строку - `UPDATE` перезаписывал окно/
    сэмплы/сущности данными второго, метка оставалась от первого, member-алерты приезжали из
    обоих, а `/incidents/{id}/context` собирал `related_events` по источнику из колонки, где
    показанных сэмплов уже не было. Настоящая КРОСС-источниковая корреляция - отдельная задача
    (нужен и счётный путь без сужения по `source_batch`, и модель "инцидент - много источников"),
    полумерой через ключ она не получается.
  - `store.delete_batch` теперь чистит ПЯТЬ таблиц (`events`/`alerts`/`rule_hits`/`incidents`/
    `investigations`). Добавляешь ещё одну таблицу с `source_batch` - не забудь её сюда же.
  - Инцидент ПЕРЕЖИВАЕТ свои `events` (ретеншн `events` не трогает `alerts`/`incidents`).
    `GET /incidents/{id}/context` обязан работать при пустом `related_events` - не полагайся на
    наличие событий.
  - `app/incidents.py:run_pending` - ЗАГЛУШКА Этапа 4 (ставит `verdict="needs-review"` без
    анализа). Настоящий агент - Этап 5, он заменит тело функции; жизненный цикл статуса
    `queued → running → done → error` и точка вызова из `IngestWorker` (`periodic_tasks`) -
    остаются.
  - Привязка member-алертов (`store.link_alerts_to_incident`) - цепочкой `event_id` (реальный
    `events.event_id` через колонку `events.alert_id`, ЛИБО синтетический `"corr:{dedup}:
    {title}:{anchor_time}"` через прямой поиск `alerts.dedup_key`, `dedup_key` - ВСЕГДА второй
    `":"`-сегмент), а НЕ по значению "сущности" (host/entities LIKE - так было раньше, молча не
    находило алерты, если group-by correlation-правила был не по хосту/известной категории
    сущности, напр. DNS `QueryName`/путь ключа реестра). См. `docs/spec/incidents.md`. БЕЗ
    временнóго сужения по `created_at` по-прежнему (наивный wall-clock приёма ≠ `event_time`
    источника при replay) - но `event_id`, а не значение, снимает практическую остроту:
    привязать может только событие, РЕАЛЬНО вошедшее в окно корреляции, не любое совпадение по
    значению. `events` (кроме колонки `alert_id`) на этом пути не трогается (то же требование
    производительности, что у счёта корреляции). **Правило дизайна контента:**
    `correlation.incident` ставь только на ПОСЛЕДНЕМ звене цепочки - если A ссылается на B, а B
    сам инцидентный, получится два инцидента на одну историю вместо одного финального (см.
    `docs/spec/incidents.md`).
