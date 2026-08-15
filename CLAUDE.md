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
AI-агента ещё нет (см. дорожную карту, этап 5).

---

## 2. Стек и зависимости

- **Python 3.12**, виртуальное окружение в `.venv/`.
- **FastAPI** + **Uvicorn** — API и раздача статики.
- **Pydantic v2** — модели (`Alert`, `Entities`, `SigmaRuleRef`, запросы/ответы).
- **Zircolite** — движок Sigma-детекта. Импортируется НЕ из pip, а из локального клона
  репозитория `./Zircolite` через `sys.path` (см. `app/engine.py`).
- **pySigma** (`sigma`, backend-sqlite, pipeline-windows/sysmon) — компиляция Sigma → SQL.
- **SQLite** — хранилище (`siem.db`), плюс in-memory SQLite внутри Zircolite на каждый батч.
- **Frontend** — один статический файл `app/static/index.html` (ванильный JS, без сборки).

> Версии зафиксированы в `requirements.txt` (прод) / `requirements-dev.txt` (+ pytest). Конфиг
> путей/хоста/порта — `.env` (см. `.env.example`, читается через `app/config.py`).

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
Security-Datasets) и в `uploads/`.

Тесты: `pip install -r requirements-dev.txt && pytest` (см. `tests/`, конфиг — `pytest.ini`).

---

## 4. Архитектура и поток данных

```
        файл логов / порция событий
                   │
        POST /ingest/{file|events|upload}
                   │
                   ▼
        ┌──────────────────────┐
        │  ZircoliteEngine      │  app/engine.py
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

| Файл | Ответственность |
|------|-----------------|
| `config.py` | Конфигурация из окружения/`.env` (`python-dotenv`, см. `.env.example`): `DB_PATH`, `ZIRCOLITE_CONFIG_PATH`, `DEFAULT_RULESET_PATH`, `UPLOADS_DIR`, `HOST`/`PORT`, `INGEST_BATCH_SIZE`/`INGEST_FLUSH_INTERVAL`. Явная переменная окружения имеет приоритет над `.env`. Импортируется `main.py` и `ingest_queue.py` — единая точка правды для путей и портов вместо хардкода. |
| `main.py` | FastAPI-приложение, все HTTP-ручки, оркестрация батча (`_process_batch` / `_process_events`), lifespan-хуки воркера. `_process_batch` после каждого `store.store_events(...)` также зовёт `correlation.evaluate_batch(...)` (см. `correlation.py`) — переоценка корреляций для затронутого батчем `source_batch`; `correlation.active_base_rule_titles(ruleset_path)` считается один раз до цикла и передаётся в `store_events(..., hit_worthy_titles=...)`. |
| `engine.py` | Обёртка над Zircolite. **Важно:** `RulesetHandler` создаётся один раз (компиляция правил — самая дорогая операция), `ZircoliteCore` — на каждый батч с in-memory БД. `invalidate(ruleset_path)` сбрасывает кэш по конкретному пути — звать после изменений в `rules_catalog.py` (add/delete кастомного правила или рулсета). `health()` — для `/health` (rules_loaded/cached_rulesets дефолтного рулсета). `_run_core` фильтрует `rule.get("correlation")` перед прогоном — чисто defense-in-depth: correlation-правила в норме сюда и не долетают (см. `rules_catalog.py`/`CORRELATION_EXT` — их вообще не видит `RulesetHandler`), их эвалуацией занимается `correlation.py`. |
| `ingest_queue.py` | Потоковый ingest: очередь + фоновый поток `IngestWorker`, micro-batch flush («N событий ИЛИ T секунд»). Приём событий с форвардеров без блокировки HTTP. **Важно:** флаш отдаёт ВЕСЬ накопленный буфер `process_fn` ОДНИМ вызовом, без группировки по источнику — движок (тысячи скомпилированных правил, ~0.25с фиксированного оверхеда на батч независимо от числа событий) гоняется один раз на весь флаш, даже если в буфере вперемешку события от N разных источников. Разбивка обратно по `source_batch` — дело `main.py`/`normalize.py` (см. `INGEST_SOURCE_FIELD` в `fields.py`), уже ПОСЛЕ прогона движка, дёшево. |
| `store.py` | SQLite-хранилище. Три логически независимые таблицы: `alerts`, `events`, `rule_hits`. Дедуп алертов по `dedup_key`. **Два соединения с раздельными локами**: `_conn`/`_lock` — только запись, `_read_conn`/`_read_lock` (с `PRAGMA query_only=ON`) — только чтение; БД в `PRAGMA journal_mode=WAL` (+`synchronous=NORMAL`) — читатели (просмотр/фильтр/группировка Событий) не блокируют писателя (ingest-воркер) и наоборот. Индекс на выражении (`idx_events_json_eventid`) для «горячих» JSON-полей (см. `filter_lang.INDEXED_JSON_FIELDS`) — иначе фильтр/группировка по кастомному полю сканируют всю таблицу. `health()` — для `/health` (`SELECT 1` через `_conn`, опционально счётчики строк/размер БД). `delete_batch(source_batch)` — удаляет из ВСЕХ ТРЁХ таблиц разом (для `DELETE /batches/{source_batch}`), не только events/alerts — иначе `rule_hits` копил бы осиротевшие строки. `rule_hits` — леджер для `correlation.py`: `(event_id, rule_title, source_batch, event_time)`, PK `(event_id, rule_title)`, индекс `(rule_title, source_batch, event_time)`; заполняется точечно через `store_events(..., hit_worthy_titles=...)` — только для правил, реально нужных активным correlation-правилам, не для всех сработавших. `evaluate_correlation_window()` — JOIN `rule_hits`↔`events` по индексу + `json_extract` по group-by полям, COUNT(*)/COUNT(DISTINCT ...). `upsert_correlation_alerts()` — как `upsert_alerts`, но OVERWRITE `event_count`/`sample_events` вместо increment (окно пересчитывается заново на каждый flush, не накапливается). |
| `normalize.py` | `raw_results` Zircolite → список `Alert`. Правила уровня `informational` пропускаются целиком (не заводят алерт ни на одном хосте) — этот уровень чисто шумовой, во вкладке «Алерты» его быть не должно; та же отсечка продублирована в `correlation.py` для correlation-алертов (единой точки для обоих движков нет — см. `evaluate_batch`). Один прогон правила разбивается на алерты по **(хосту, источнику)** — источник берётся из `INGEST_SOURCE_FIELD`, временно вписанного в событие перед прогоном движка (см. `ingest_queue.py`/`main.py`), с фолбэком на `default_source_batch`, если маркера нет (одноисточниковые `/ingest/file`·`/ingest/upload`). Извлекает `entities`, берёт sample-события (первые N + последние N). |
| `models.py` | Pydantic-модели. `Alert`, `Severity`, `Entities`, `SigmaRuleRef` + модели запросов/ответов. |
| `fields.py` | Кандидаты имён полей (host/user/ip/process/time) для generic-извлечения из разнородных источников (EVTX/Sysmon/auditd называют поля по-разному). Также `INGEST_SOURCE_FIELD` — служебный маркер источника для слияния нескольких источников в один прогон движка (см. `ingest_queue.py`); ИМЯ ДОЛЖНО быть чисто алфанумерическим — Zircolite при flatten-е вырезает из имён полей без явного маппинга все не-alnum символы (`_NON_ALNUM_RE` в `streaming.py`), подчёркивания молча пропадают. |
| `filter_lang.py` | Мини-язык фильтра Событий (строка ввода в UI, в духе MaxPatrol query bar): токенайзер + recursive-descent парсер + компилятор условий в parametrized SQL (`json_extract` — инъекция исключена). Поддерживает произвольную вложенность `and`/`or`/`not` через скобки; спецполя результата детекта `rule` и `is_matched` (не часть raw_json — отдельные колонки `matched_rules`/`is_matched` в `events`). У `rule` операторы `=`/`!=`/`contains`/`in`/`is null` — сравнение по НАЗВАНИЮ правила, а `>`/`<`/`>=`/`<=` — отдельная семантика: сравнение КОЛИЧЕСТВА сработавших правил (`json_array_length(matched_rules)`), напр. `rule > 1`. `INDEXED_JSON_FIELDS`/`resolve_json_path()` — узкий whitelist «горячих» полей (сейчас только `EventID`), для которых JSON-путь подставляется ЛИТЕРАЛОМ в текст SQL (не bound-параметром) — нужно, чтобы совпасть с expression-индексом `idx_events_json_eventid` в `store.py` (SQLite матчит индекс на выражении только по текстовому совпадению, bound-параметр для этого не годится); безопасность не страдает — литерал всегда один из фиксированных значений словаря по ключу, как у `_ALERT_SORT_COLUMNS`/`_EVENT_SORT_COLUMNS` в `store.py`. |
| `rules_catalog.py` | Каталог Sigma-рулсетов/правил для вкладки «Sigma-правила»: built-in (`Zircolite/rules/*.json`, read-only) и любое число ИМЕНОВАННЫХ custom-рулсетов (`custom_rulesets/<id>/` — `meta.json` + `*.yml` на обычное правило, source of truth, + `.manifest.json` — кэш скомпилированных метаданных для быстрого браузинга). Просмотр builtin/custom — обычный `json.load()` с кэшем по mtime (без pySigma); компиляция через `zircolite.rules.RulesetHandler` нужна только при добавлении нового custom-правила/рулсета (`save_custom_rule`/`save_ruleset_yaml`, оба принимают `ruleset` — существующий, ИЛИ `new_ruleset_name` — создать новый; builtin как цель отклоняется). **Correlation-правила (`type: event_count`/`value_count`/`temporal`/`temporal_ordered`) хранятся ОТДЕЛЬНО** — файлом `<rule_id>{CORRELATION_EXT}` (`.sigmacorr`, НЕ `.yml`/`.yaml`) в той же директории рулсета: `RulesetHandler` глобит только `*.yml`/`*.yaml`, значит их вообще не видит при компиляции — это НЕ побочный эффект, а осознанный обход реального бага пинченного `pysigma-backend-sqlite` (правило, referenced корреляцией из ТОГО ЖЕ `SigmaCollection`, при компиляции возвращает сырую SQL-строку вместо dict и валит компиляцию всего файла целиком; воспроизведено эмпирически вплоть до последней опубликованной версии 1.2.4). Благодаря физической изоляции правило, на которое ссылается корреляция, компилируется как совершенно обычное правило под своим настоящим именем — никаких «правил-двойников» в контенте заводить не нужно. `compile_custom_rule`/`compile_ruleset_yaml` сами решают (по ключу `correlation:` в документе) — отдать документ в `RulesetHandler` или в свою лёгкую валидацию без pySigma (`_validate_correlation_doc`/`_compile_correlation_doc`, дают «псевдо-скомпилированную» запись для `.manifest.json`: id/title/level/tags/description, без `rule`-SQL). `load_correlation_rules(ruleset_path)` — структурные поля correlation-правила (`type`/`group-by`/`timespan`/`condition`/`rules`) читаются заново из raw `.sigmacorr` при каждом использовании (дёшево, файлов единицы), `correlation.rules` (ссылки по Sigma `name`/`id`) резолвится в настоящий `title` соседнего `*.yml`-правила — это и есть значение, которое реально попадёт в `events.matched_rules`/`rule_hits.rule_title`. `_find_rule_file()` — ищет файл правила по `rule_id` независимо от расширения (обычное/correlation), нужен `get_rule`/`update_custom_rule`/`delete_custom_rule` (тип правила может смениться при редактировании — файл переписывается под новым расширением). Ничего не знает про «основной рулсет» (main) — однонаправленная зависимость `main_ruleset.py → rules_catalog.py`. |
| `main_ruleset.py` | Состав «основного рулсета» (виртуальная композиция правил из ЛЮБЫХ других рулсетов) — файл `custom_rulesets/main_ruleset.json`: список целиком добавленных рулсетов + точечные исключения/добавления отдельных правил (`resolve()` собирает плоский список для движка). Используется по умолчанию `/ingest/stream` и `/ingest/events` (там нет параметра `ruleset` — раньше молча падали на `engine.default_ruleset_path`, теперь на main). `resolve()` дешёвый — читает уже скомпилированные правила через кэш `rules_catalog`, без pySigma. `resolve_with_sources()` дополнительно переиспользует `correlation.py` — чтобы найти, какие custom-рулсеты реально дают активные correlation-правила для main. |
| `correlation.py` | Стейтфул-корреляция (`event_count`/`value_count`; `temporal`/`temporal_ordered` — намеренно НЕ эвалуируются, следующая задача) поверх постоянной таблицы `events`/`rule_hits`, а не через `pysigma-backend-sqlite` (тот для этих типов генерирует SQL вовсе БЕЗ учёта `timespan`, плюс у Zircolite нет state между batch'ами — см. §8). Вызывается из `main.py:_process_batch` ПОСЛЕ каждого `store.store_events(...)`, т.е. после каждого flush ingest-воркера — с коротким замыканием: если ни одно активное correlation-правило не ссылается на правило, сработавшее В ЭТОМ батче, до БД дело не доходит. Окно `[anchor - timespan, anchor]` считается от `event_time` САМОГО ПОЗДНЕГО из новых событий (НЕ `datetime.now()` — иначе корреляции не срабатывали бы на replay исторических датасетов вроде OTRF Security-Datasets). `active_base_rule_titles(ruleset_path)` — какие названия правил стоит писать в `rule_hits` (зовётся `main.py` ДО `store_events`). Correlation-правило уровня `informational` пропускается (см. `normalize.py`) — до расчёта окна дело не доходит. Результат — обычный `Alert` в таблице `alerts` (переиспользует dedup-паттерн), помечен `engine="correlation"` (без миграции модели). |

### Модель данных (SQLite, `siem.db`)

- **`alerts`** — нормализованные алерты для аналитика и будущего агента. Дедуп по
  `dedup_key = sha256(rule_id:host:main_entity)[:16]`; повторное срабатывание
  инкрементит `event_count`. Поля: `rule_*`, `mitre_techniques`, `entities`,
  `sample_events`, `status` (`new → investigating → closed`).
- **`events`** — снимок ВСЕХ событий батча (в т.ч. не вызвавших правил), с флагом
  `is_matched` и списком `matched_rules`. Нужны для ручного пивота аналитиком и RAG агента.
- **`rule_hits`** — леджер срабатываний, "интересных" для correlation-правил (`app/correlation.py`):
  `(event_id, rule_title, source_batch, event_time)`, заполняется точечно (не на каждое
  сработавшее правило — только на те, что реально base_rule активной корреляции). Даёт индекс
  `(rule_title, source_batch, event_time)`, которого нет и не должно быть на `events` под
  произвольные Sigma-поля.

### API (обзор)

| Метод | Путь | Назначение |
|-------|------|-----------|
| POST | `/ingest/stream` | **Потоковый приём с форвардеров** (NDJSON/JSON-массив, `?source=`), 202 Accepted → очередь → micro-batch. Ruleset не выбирается per-request — всегда «основной рулсет» (`app/main_ruleset.py`). См. `docs/forwarder.md`. |
| POST | `/ingest/file` | Прогон файла, уже лежащего на диске сервера (batch/тесты). `ruleset` — путь из `/rulesets` (в т.ч. `"main"` — основной рулсет) или пусто (движковый дефолт `rules_windows_merged.json`). |
| POST | `/ingest/events` | Приём порции сырых событий в теле запроса (синхронный прогон). Ruleset не выбирается — всегда основной рулсет (как и `/ingest/stream`). |
| POST | `/ingest/upload` | Загрузка файла из браузера (multipart), автоопределение типа по расширению. `ruleset` — как у `/ingest/file`. |
| GET | `/batches` | Сводка по загруженным источникам (для селектора в UI). |
| DELETE | `/batches/{source_batch}` | Удаление источника целиком: все его `events` И `alerts` (`source_batch` — не отдельная сущность, просто общая метка на обеих таблицах). `404`, если ничего не удалено. |
| GET | `/alerts` · `/alerts/{id}` | Список / карточка алерта. Фильтры: `source_batch`, `status`, `rule_level`, `time_from/to`; сортировка `sort_by` (`rule`=severity/`host`/`event_count`/`status`/`created_at`) + `sort_dir`. |
| PATCH | `/alerts/{id}/status` | Смена статуса алерта. |
| GET | `/events` · `/events/{id}` | Список / карточка сырого события. Фильтры: `source_batch`, `only_matched`, `time_from/to`; `query` — строка мини-языка фильтра (`app/filter_lang.py`: and/or/not, скобки, спецполя `rule`/`is_matched`), при синтаксической ошибке `400` с текстом и позицией; `group_cond` — drill-in по группе (всегда AND, отдельно от `query`); сортировка `sort_by`/`sort_dir` (в т.ч. по любому полю raw_json); `fields=A,B` — кастом-колонки. Отдельного параметра фильтра по хосту нет — выражается через `query` (напр. `Hostname contains "..."`). |
| GET | `/events/group` | Агрегаторы для панели группировки: `group_by=<field>` (включая спецполя `rule`/`is_matched`) + те же фильтры (`query` и т.п.) → `[{value, count}]` по убыванию (фильтр применяется до группировки; `rule` — многозначное поле, разворачивается через `LEFT JOIN json_each`). |
| GET | `/rulesets` | Каталог рулсетов (builtin + все именованные custom + одна виртуальная запись «main», основной рулсет) — `[{path, category, name, rule_count, size_bytes, deletable, main_status}]`. `main_status` — `full`\|`partial`\|`none`, состав основного рулсета внутри ЭТОГО рулсета (см. `app/main_ruleset.py`). `path` — то же значение, что подставляется в `ruleset` у `/ingest/file`·`/ingest/upload` (в т.ч. `"main"`). |
| GET | `/rulesets/rules` · `/rulesets/rule` | Список правил рулсета (`ruleset=<path>`, поиск `q` по title/description, `only_main=true` — только правила, входящие в основной рулсет, сортировка `sort_by=level`\|`title`\|`author`\|`status`, пагинация; каждая строка списка несёт `in_main`) / карточка одного правила. Для custom-рулсета карточка дополнительно содержит `yaml_text` (исходный Sigma YAML) — у builtin его нет и не было никогда, хранится только уже скомпилированный SQL. |
| POST | `/rulesets/upload` | Загрузка рулсета — сырой Sigma YAML (`.yml`/`.yaml`, можно multi-document — несколько правил в одном файле). Тело — multipart: `file` + (`ruleset` — существующий свой рулсет, ИЛИ `new_ruleset_name` — создать новый; ровно один из двух). Встроенные рулсеты как цель отклоняются (`400`). |
| DELETE | `/rulesets` | Удаление именованного custom-рулсета целиком (`?ruleset=<path>`); встроенные рулсеты не удаляются (`404`). Чистит ссылки на него в основном рулсете (`main_ruleset.on_ruleset_deleted`). |
| POST | `/rules/custom` | Компиляция и сохранение НОВОГО своего правила: тело `{yaml_text, ruleset?, new_ruleset_name?}` — сырой Sigma YAML одного правила + существующий/новый целевой custom-рулсет (ровно один из двух), валидируется и компилируется через `RulesetHandler` (`400` с текстом ошибки, ничего не пишется на диск). Ответ дополнительно содержит `ruleset_path` — куда правило попало. |
| PUT | `/rules/custom/{rule_id}` | Пересборка СУЩЕСТВУЮЩЕГО своего правила на месте: query `ruleset` (обязателен) + тело `{yaml_text}`. `id` правила всегда остаётся исходным (из URL), даже если в новом YAML указан другой/отсутствует `id:` — редактирование не переименовывает файл/manifest-запись. |
| DELETE | `/rules/custom/{rule_id}` | Удаление своего правила (обязательный query-параметр `ruleset` — из какого именованного custom-рулсета). |
| POST | `/main-ruleset/rules` | Включить/выключить ОДНО правило в основном рулсете: тело `{ruleset, rule_id, include}`. |
| POST | `/main-ruleset/rulesets` | Добавить/убрать рулсет ЦЕЛИКОМ в основной рулсет: тело `{ruleset, include}` (сбрасывает точечные исключения/добавления по этому рулсету). |

---

## 5. Sigma-правила и датасеты

- Скомпилированные рулсеты Zircolite — `Zircolite/rules/*.json`
  (windows/linux, срезы generic/merged/high/medium). По умолчанию используется
  `rules_windows_merged.json` (см. `DEFAULT_RULESET_PATH` в `app/main.py`).
- Конфиг field-mappings и transforms — `Zircolite/config/`.
- Тестовые логи атак — `artifacts/Security-Datasets/datasets/` (OTRF), напр.
  PurpleSharp AD playbook в `uploads/`.
- **`custom_rulesets/`** (создаётся автоматически, сюда попадают только пользовательские
  данные из вкладки «Sigma-правила», `Zircolite/` не трогаем):
  - `<ruleset_id>/` — один именованный custom-рулсет (id = `uuid4().hex`, кроме `my_rules` —
    зарезервированный id для рулсета, созданного до введения именованных рулсетов, см. миграцию
    ниже). Внутри: `meta.json` (`{id, name, created_at}`), `<rule_id>.yml` на правило (raw Sigma
    YAML, source of truth), `.manifest.json` (кэш скомпилированных метаданных всех правил папки,
    для быстрого браузинга). `custom_rulesets/<ruleset_id>` работает как `ruleset_path` для
    `/ingest/file`·`/ingest/upload` «из коробки» — `RulesetHandler` для директории глобит
    `*.yml`/`*.yaml`, `.json` внутри директории игнорирует, поэтому `.manifest.json`/`meta.json`
    в детект не попадают. Правило/рулсет можно добавить только в существующий именованный
    custom-рулсет или создать новый (`ruleset`/`new_ruleset_name` — ровно один из двух в
    `POST /rules/custom` и `POST /rulesets/upload`); встроенные рулсеты как цель — `400`.
  - `main_ruleset.json` — состав «основного рулсета» (см. `app/main_ruleset.py` в таблице
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
- **`scripts/`** — вспомогательные скрипты для ручного тестирования (не часть приложения):
  - `fake_forwarder.py` — синтетический форвардер для `/ingest/stream`, режимы `burst`
    (много событий разом — проверка size-trigger флаша) и `drip` (медленно и долго —
    проверка time-trigger); печатает состояние очереди из `/health?detailed=true`.
  - `send_rule_test_events.py` — тестовое Sigma-правило (в докстринге, вставить во вкладку
    «Sigma-правила» → «Написать своё правило») + набор событий (часть под правило, часть
    контрольных, специально ломающих ровно один из селекторов) через `/ingest/file` с
    `ruleset=custom_rulesets/my_rules`.
  - `stream_main_ruleset_test.py` — проверка «Основного рулсета» (`app/main_ruleset.py`) именно
    через `/ingest/stream` (единственный путь, где ruleset вообще нельзя выбрать per-request —
    всегда main). Докстринг содержит своё тестовое Sigma-правило (LOLBIN-детект `certutil
    -urlcache`, независимое от правила в `send_rule_test_events.py`) — вставить во вкладку
    «Sigma-правила», добавить в основной рулсет вместе с любым built-in рулсетом (напр.
    `rules_windows_merged.json`) кнопками `+`/«добавить рулсет целиком». Скрипт шлёт NDJSON
    через `/ingest/stream`, ждёт флаша `IngestWorker` (поллит `/health?detailed=true` →
    `queue_size`), затем поллит `/alerts?source_batch=...` и печатает сработавшие правила —
    ожидается и builtin-алерт (напр. «HackTool - Mimikatz Execution - Sysmon»), и кастомный.
  - `stream_correlation_test.py` — проверка стейтфул-корреляции (`app/correlation.py`) именно
    через `/ingest/stream`: **только форвард событий**, правило (`artifacts/content/
    windows_bruteforce.yml`) нужно загрузить и добавить в основной рулсет САМОСТОЯТЕЛЬНО через
    вкладку «Sigma-правила» ДО запуска — скрипт ничего не пишет в `custom_rulesets`. Шлёт 10
    событий `EventID=4625` ТРЕМЯ отдельными HTTP-запросами с паузой дольше `flush_interval`
    (гарантированно разные flush'и — то, что раньше не работало) и ждёт алерт
    `event_count=10, engine=correlation`. Флаг `--negative` — контрольный прогон с событиями за
    пределами 5-минутного `timespan` (алерт НЕ должен появиться).

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
- ✅ `requirements.txt` (прод) / `requirements-dev.txt` (+ pytest) c фиксацией версий; `.venv`
  из репо убран (`.gitignore`).
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
  `UPLOADS_DIR`, `HOST`/`PORT`, `INGEST_BATCH_SIZE`/`INGEST_FLUSH_INTERVAL`.

### Этап 1 — Архитектура SIEM 🟡 (ядро есть, укрепляем)
- ✅ Пайплайн ingest → Sigma-детект (Zircolite) → нормализация → хранение.
- ✅ Дедупликация алертов, хранение всех событий, кэш скомпилированных правил.
- ✅ **Потоковый ingest с форвардеров**: `POST /ingest/stream` → очередь → фоновый воркер
  (`app/ingest_queue.py`), micro-batch flush по «N событий ИЛИ T секунд». `docs/forwarder.md`.
- ✅ **`/health` отражает реальное состояние**, не заглушку: `SELECT 1` по БД (`Store.health`),
  жив ли фоновый поток `IngestWorker` (`IngestWorker.health`), загружен ли Zircolite-ruleset
  (`ZircoliteEngine.health`); `?detailed=true` добавляет счётчики строк/размер БД. UI (светофор
  в шапке) опрашивает каждые 20с, а не разово при загрузке страницы; клик — попап с разбивкой
  по подсистемам.
- ⬜ **Точная привязка entity**: маппинг полей под конкретный источник (EVTX Security /
  Sysmon / Auditd) вместо общих кандидатов из `fields.py`.
- ⬜ **Обогащение MITRE ATT&CK**: из тегов Sigma достраивать tactic/technique в удобный вид.
- 🟡 **Стейтфул-корреляция** Sigma-правил (`event_count`/`value_count`) поверх постоянной
  таблицы `events`/`rule_hits` (`app/correlation.py`) — независимо от micro-batch flush'а
  ingest-воркера, окно реального времени (`timespan`), не размера батча. Не через
  `pysigma-backend-sqlite` (у него для этих типов нет ни `timespan` в SQL, ни state между
  батчами — см. §8). `temporal`/`temporal_ordered` (в т.ч. цепочки корреляция-над-корреляцией)
  — ⬜ не эвалуируются, следующая задача. Корреляция алертов в **инциденты** (склейка
  нескольких алертов в один инцидент, не просто «алерт от correlation-правила») — тоже ⬜.
- ⬜ Ретеншн/архивация `siem.db`, при росте — рассмотреть Postgres/Elastic.

### Этап 2 — UI SIEM 🟡 (одна страница есть, расширяем)
- ✅ Вкладки: Источник данных / Алерты / События; карточки алерта и события; смена статуса.
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
- ✅ **Вкладка «Sigma-правила»** (`app/rules_catalog.py`, `app/main_ruleset.py`, `/rulesets*`,
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
  СЕТКА 2×2 через `grid-template-areas` на `.editor-grid` (не последовательные строки/флекс-блоки
  друг под другом — начальный вариант через простые блоки не давал одноимённым элементам встать
  вровень по вертикали, пока не переехали на явные area):
  ```
  "header refpicker"
  "editor refyaml"
  ```
  Верхний ряд (высота `auto`, реально задаётся высотой `refpicker`, см. ниже) — **слева**
  `.editor-header-col`: тулбар («← Назад к списку правил», заголовок `#rule-editor-title`,
  «Сохранить» — все три кластером слева, `margin-left:auto` больше НЕ используется на кнопке)
  и `#rule-editor-target-row`/`#rule-editor-static-target` (выбор целевого рулсета для
  создаваемого/редактируемого правила); **справа** `#editor-reference-pane` (`grid-area:
  refpicker`) — селектор рулсета + поиск + сам список правил (`#rule-editor-ref-list-body`/
  `.ref-rule-list`) для просмотра уже существующих правил, ВСЁ вместе, единым блоком.
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
  Поскольку `editor` и `refyaml` — это ВТОРОЙ ряд грида, они автоматически начинаются РОВНО на
  одном уровне по вертикали (та же логика для `header`/`refpicker` в первом ряду) — именно ради
  этого выбрана raw grid-template-areas раскладка, а не last-min flex-подгонка отступов.
  **Грабли, уже словили:** `#editor-reference-pane` должен иметь ЯВНУЮ `height` (не `min-height`!)
  — без неё грид-ряд "auto" считает intrinsic-высотой контента ВЕСЬ нескролленный список правил
  (`.ref-rule-list` с `overflow-y:auto` включает скролл только когда у родителя УЖЕ есть
  зафиксированная высота), из-за чего ряд разъезжался на тысячи пикселей и второй ряд грида
  (сам редактор) уезжал далеко за пределы экрана. Обе референс-панели (`refpicker`/`refyaml`) НЕ
  связаны с тем, что печатается слева — чисто browse-панель для подглядывания в уже существующие
  правила. Вся правая колонка (`.editor-grid` column 2, driven by `--editor-ref-w`) — resizable
  тем же паттерном, что и детейл-панели (`PANEL_RESIZE_CONFIG`, defaultWidth 480/min 320/max 700,
  drag-хэндл живёт внутри `refpicker`, но двигает CSS-переменную колонки — значит синхронно
  тянет и `refyaml` тоже, без доп. кода); тянет левую колонку у́же/шире, т.к. она `1fr` в том же
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
  **Основной рулсет** (main, см. `app/main_ruleset.py` выше) собирается прямо тут: отдельная
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
- ⬜ Дашборд: счётчики по severity, топ правил/хостов/MITRE, таймлайн.
- ⬜ Полноценный **триаж-воркфлоу**: назначение аналитика, комментарии, метки TP/FP.
- ⬜ Поиск/фильтры по событиям (полнотекст, по полям), пивот из алерта в связанные события.
- ⬜ Живое обновление (SSE/WebSocket) при поступлении новых алертов.
- ⬜ Аутентификация/роли (аналитик vs админ) — перед выходом за пределы localhost.
- 🔎 Черновики в `index_v1.html` / `index_vX.html` — консолидировать, лишнее удалить.

### Этап 3 — Ingest коннекторы и нормализация 🟡
- Поддержка потоковых источников (Winlogbeat/NXLog/syslog forwarder → `/ingest/events`).
- Стабильная схема нормализованного события (ECS-подобная) на входе в хранилище.
- 🟡 Управление рулсетами: ✅ именованные custom-рулсеты, загрузка Sigma YAML (в т.ч.
  multi-document) + написание своих правил, обязательный выбор целевого рулсета — см. вкладку
  «Sigma-правила» (Этап 2), `app/rules_catalog.py`. ⬜ Осталось: версионирование, включение/
  выключение по тегам.
- ✅ **`ruleset` для `/ingest/stream`/`/ingest/events`** — оба теперь используют «основной
  рулсет» (`app/main_ruleset.py`, `MAIN_RULESET_ID = "main"`) вместо жёсткого дефолта движка:
  `_process_events` в `app/main.py` подставляет `ruleset_path = ruleset_path or
  main_ruleset.MAIN_RULESET_ID`, дальше `_process_batch` резолвит `main_ruleset.resolve()` в
  плоский список правил и зовёт `engine.run_batch_with_rules(...)` (кэш `_rulesets_cache` тут
  не участвует — `resolve()` и так дешёвый, читает уже скомпилированные правила через кэш
  `rules_catalog`). Состав основного рулсета собирается во вкладке «Sigma-правила» (кнопки на
  правилах/рулсетах, см. Этап 2) — теперь свои правила ИЗ ЛЮБОГО custom-рулсета можно
  протестировать через потоковый ingest, для этого достаточно добавить их в main.

### Этап 4 — Подготовка к AI-агенту (данные и контекст) ⬜
- API отдачи полного контекста алерта агенту: правило + Sigma-логика, sample-события,
  связанные события по entity, история по хосту/пользователю.
- Хранилище **вердиктов и обоснований** (таблица `investigations`): вход, шаги, вывод, confidence.
- Инструменты (tools) для агента: `search_events`, `get_alert_context`, `pivot_by_entity`,
  `lookup_mitre`, (позже) threat-intel обогащение.

### Этап 5 — AI-агент расследования 🎯 главная цель ⬜
- Агент на **Claude** (Anthropic SDK; по умолчанию Opus 4.8 для расследования,
  Haiku 4.5 для дешёвой предобработки). Загрузить skill `claude-api` перед реализацией.
- **Tool-use цикл**: агент берёт алерт → дёргает инструменты (события/пивот/MITRE) →
  строит гипотезу → выносит вердикт `TP / FP / needs-review` + обоснование + confidence.
- Запись расследования в `investigations`, отображение вердикта в карточке алерта (Этап 2).
- Оценка качества: набор размеченных алертов из Security-Datasets как бенчмарк точности.
- Human-in-the-loop: аналитик подтверждает/отклоняет вердикт → данные для дообучения промптов.

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
  (`custom_rulesets/main_ruleset.json`), а `id` при редактировании принудительно остаётся
  исходным (см. `rules_catalog.update_custom_rule`), поэтому ссылка не рвётся. Новая версия
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
  1611 из 4291 записей). `app/main_ruleset.py:resolve_with_sources()` **не дедуплицирует по
  id** — раньше дедуплицировал по `(ruleset_path, id)` и это молча теряло ~37% правил при
  добавлении рулсета целиком в main; см. докстринг функции, если тянет добавить обратно.
  Точечный toggle одного правила по `rule_id` (`toggle_rule`) при этом всё равно затрагивает
  ВСЕ записи с этим id сразу (это ожидаемо — они представляют одно логическое правило).
- **При ручном тестировании alert-дедупликации** (`dedup_key = sha256(rule_id:host:main_entity)`,
  см. §4) осторожно с фиксированными `id` в тестовых Sigma-правилах и фиксированными именами
  хостов в тестовых скриптах — повторный прогон с теми же id+host+entity не создаёт новый
  алерт, а инкрементит `event_count` у уже существующего (и `source_batch` у него остаётся от
  ПЕРВОГО батча, где он появился) — со стороны выглядит как «алертов 0» в новом батче, хотя
  события реально сматчились. Через `DELETE /batches/{source_batch}` можно почистить старые
  тестовые батчи, если это создаёт путаницу.
- **`siem.db` большой** (десятки МБ) и растёт с каждым ingest — не коммить, чистить при тестах.
- **`Zircolite/` и `artifacts/Security-Datasets/` — внешние клоны** (со своими `.git`),
  не редактируй их код; всё своё держи в `app/`.
- AI-агент по умолчанию строится на **Claude** (см. этап 5) — при работе с LLM-частью
  сначала грузи skill `claude-api`, не полагайся на память о моделях/API.
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
- **Correlation-правила (`app/rules_catalog.py`) хранятся под `CORRELATION_EXT` (`.sigmacorr`),
  НЕ `.yml`/`.yaml` — не переименовывай/не "исправляй" эту раскладку.** Причина не косметика:
  пинченный `pysigma-backend-sqlite` (проверено вплоть до последней опубликованной версии
  1.2.4) не может скомпилировать правило для независимого вывода, если оно ЕЩЁ И referenced
  корреляцией из ТОГО ЖЕ `SigmaCollection` — возвращает сырую SQL-строку вместо dict, и это
  валит компиляцию ВСЕГО файла (`'str' object has no attribute 'get'` в Zircolite). Решение —
  не патчить Zircolite/pySigma (нельзя, внешние зависимости) и не заводить "правила-двойники"
  в контенте (был первый, отброшенный вариант), а физически развести правило-корреляцию и
  правило-селектор по разным расширениям, чтобы `RulesetHandler` (глобит только `*.yml`/
  `*.yaml`) никогда не видел их вместе. Если когда-нибудь апстрим починит баг — можно будет
  вернуть единое `.yml`-хранение, но проверяй эмпирически (compile_ruleset_yaml на файле с
  корреляцией + referenced-правилом в одном документе), не полагайся на changelog.
- **Окно корреляции (`app/correlation.py`) анкерится на `event_time` САМОГО ПОЗДНЕГО из новых
  событий батча, не на `datetime.now()`.** Иначе корреляции никогда не срабатывали бы при
  replay исторических датасетов (напр. OTRF Security-Datasets, где все `event_time` уже в
  прошлом) - потоковый ingest живых логов при этом работает так же корректно, `event_time`
  свежих событий и так близок к текущему моменту. `DELETE /batches/{source_batch}` чистит и
  `rule_hits`, не только `events`/`alerts` - если добавляешь ЕЩЁ одну таблицу, привязанную к
  `source_batch`, не забудь то же самое в `Store.delete_batch`.
