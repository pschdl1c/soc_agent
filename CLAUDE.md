# CLAUDE.md

Гайд для Claude Code и разработчиков по проекту **soc_agent** — мини-SIEM на Sigma-правилах
с последующей разработкой AI-агента, который расследует алерты и выносит вердикт.

> **Этот файл — навигация и грабли, а не спецификация.** Точные интерфейсы, схемы данных,
> форматы и инварианты — в `docs/spec/` (один файл на модуль, карта — `docs/spec/README.md`),
> руководства и ранбуки — в `docs/guide/`. Сюда попадает только то, что меняет ПОВЕДЕНИЕ при
> доработке (§8) и при написании детект-контента (§9). Факт, уже описанный в спеке, здесь не
> дублируем — даём ссылку.

---

## 1. Что это за проект

**Цель.** Собрать лёгкий SIEM, который:
1. Принимает логи (EVTX / Sysmon / JSON / auditd и т.п.).
2. Прогоняет их через **Sigma-правила** движком **Zircolite** и генерирует алерты.
3. Показывает аналитику алерты и сырые события в веб-консоли.
4. **(следующий этап)** запускает AI-агента, который автоматически расследует каждый
   инцидент (обогащение, корреляция, MITRE ATT&CK) и выносит вердикт: `true positive` /
   `false positive` / `needs review` с обоснованием.

**Текущий статус:** работает пайплайн ingest → Sigma-детект → корреляция → инциденты → UI.
Этап 4 (инциденты, `docs/spec/incidents.md`) и Этап 4.5 (детект-контент) закрыты: контент
`artifacts/content/` покрыт фикстурами на 100% базовых правил, живой прогон на win10-lab
(2026-09-19, Hyper-V) подтвердил 49 из 53 сценариев и 10 из 11 доменов; `lateral` ждёт второй
хост (`docs/guide/windows-vm-lab.md` §5). AI-агента расследования ещё нет — Этап 5.

---

## 2. Стек и зависимости

- **Python 3.12**, окружение `.venv/` под управлением **uv**.
- **FastAPI** + **Uvicorn** — API и раздача статики; **Pydantic v2** — модели.
- **Zircolite** — движок Sigma-детекта, импортируется НЕ из pip, а из локального клона
  `./Zircolite` через `sys.path` (`app/detection/engine.py`).
- **pySigma** (`sigma`, backend-sqlite, pipeline-windows/sysmon) — компиляция Sigma → SQL.
- **SQLite** — `siem.db` (хранилище) + in-memory БД Zircolite на батч + read-only `kb.db`
  (MITRE ATT&CK, `app/kb.py`).
- **Frontend** — один статический файл `app/static/index.html` (ванильный JS, без сборки).

Версии зафиксированы в `pyproject.toml` (`dependencies` — прод, `optional-dependencies.dev` —
pytest/httpx/ruff, `.agent` — LangGraph для Этапа 5). `requirements*.txt` нет, Docker ставит
`pip install .`. Конфиг — `.env` (`.env.example`, читается `app/config.py`, спека `docs/spec/config.md`).

**Версия проекта** — `[project].version` в `pyproject.toml` (единственный источник; `app/main.py`
читает через `importlib.metadata`). SemVer, пока `0.y.z`. Порядок релиза: bump → раздел в
`CHANGELOG.md` → коммит → `git tag vX.Y.Z` → `git push --tags`. Git-теги — единственный маркер релиза.

---

## 3. Как запускать

```bash
# из корня проекта D:\__projects\soc_agent
.venv\Scripts\activate                    # PowerShell: .venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

- UI: http://localhost:8000/ · Swagger: `/docs` · Health: `/health` (`?detailed=true` — счётчики).
- Тестовые данные — `artifacts/Security-Datasets/` (клон OTRF) и `data/uploads/` (`SIEM_UPLOADS_DIR`).

Окружение — **uv** (`pip` внутри `.venv` нет): зависимости `uv pip install -e ".[dev]"`, запуск
чего угодно — `uv run <команда>`. `uv.lock` КОММИТИТСЯ, `*.egg-info/` — в `.gitignore`.

- Тесты: `uv run pytest` (конфиг — `pyproject.toml`). HTTP-слой — через `fastapi.testclient`;
  предупреждение starlette «install httpx2» игнорируем, на httpx 0.28 работает.
- Линт: `uv run ruff check app tests scripts` — репозиторий пока НЕ ruff-чистый (~113 замечаний,
  почти всё однотипное: `B904`, `UP007`, `UP017`), в CI ruff не поднят. Новый код пишем в стиле
  окружающего, разовую зачистку — отдельной задачей.
- База знаний MITRE: `python scripts/build_kb.py --out kb/kb.db --attack-version 15.1` (нужна сеть).
  В Docker собирается на этапе `build` и вшивается в образ. Без файла вкладка «База знаний»
  показывает заглушку, карточки алертов матчат MITRE-теги по сырому значению.

---

## 4. Архитектура и поток данных

```
        файл логов / порция событий
                   │
        POST /ingest/{file|events|upload|stream}
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
        │  raw_results → Alert  │───────▶│  alerts / events /    │
        │  (группировка по хосту,│        │  rule_hits / sources  │
        │   extract entities)    │        └──────────┬───────────┘
        └──────────────────────┘                    │
                   │                                 ▼
                   │                     correlation.py → incidents
                   ▼
              GET /alerts · /events · /incidents · /batches → UI (index.html)
```

### Карта модулей

Плоско, кроме двух подпакетов: **`app/detection/`** (`engine.py`, `normalize.py`,
`correlation.py` — путь событие → детект → `Alert`/`Incident`) и **`app/rules/`**
(`rules_catalog.py`, `main_ruleset.py`, `value_lists.py` — весь Sigma-контент; внутренний DAG
`value_lists ← rules_catalog ← main_ruleset`).

| Модуль | Ответственность | Спека `docs/spec/` |
|---|---|---|
| `config.py` | Конфиг из окружения/`.env`, единая точка правды для путей и портов | `config.md` |
| `main.py` | FastAPI-приложение, все ручки, оркестрация батча (`_process_batch`/`_process_events`), lifespan воркера, аутентификация ingest | `http-api.md` |
| `models.py` | Pydantic-модели (`Alert`, `Severity`, `Entities`, `SigmaRuleRef`, запросы/ответы) | `models.md` |
| `store.py` | SQLite `siem.db`: схема, аддитивные миграции, два соединения (запись/чтение) под раздельными локами, WAL | `storage.md` |
| `ingest_queue.py` | Очередь потокового ingest, фоновый `IngestWorker`, micro-batch flush, периодические задачи | `ingest-queue.md` |
| `fields.py` | Кандидаты имён полей (host/user/ip/process/time/event-code), маркер источника `INGEST_SOURCE_FIELD` | `fields.md` |
| `filter_lang.py` | Мини-язык фильтра Событий → parametrized SQL, спецполя `rule`/`is_matched`, ECS-lite колонки | `filter-language.md` |
| `timeutil.py` | Каноническая форма метки времени и границ диапазона (лист-модуль без импортов) | `time.md` |
| `timespan.py` | `parse_timespan("5m") -> 300` — общий лист для `detection/correlation.py` и `rules/rules_catalog.py` | — |
| `logging_setup.py` | `configure(level)`: UTF-8 на ОБА потока + один хендлер на логгер `app` | `logging.md` |
| `updates.py` | In-memory счётчики изменений списков для автообновления UI (`GET /updates`) | `updates.md` |
| `kb.py` | Read-only доступ к `kb.db` (MITRE ATT&CK), `enrich_techniques` — гибридный матчинг тегов | `knowledge-base.md` |
| `incidents.py` | Фоновая обработка `investigations`; на Этапе 4 `run_pending` — ЗАГЛУШКА (`needs-review` без анализа) | `incidents.md` |
| `detection/engine.py` | Обёртка Zircolite: кэш `RulesetHandler`, `_SiemCore` (NULL-колонки полей правил, лог ошибок SQL), `invalidate()`, `health()` | `detection-engine.md` |
| `detection/normalize.py` | `raw_results` → `Alert`, два режима `dedup_key`, извлечение entities, sample-события | `normalization.md` |
| `detection/correlation.py` | Стейтфул-корреляция (`event_count`/`value_count`/`temporal`/`temporal_ordered` + цепочки), A3-счёт по `rule_hits`, построение инцидентов | `correlation.md` |
| `rules/rules_catalog.py` | Каталог рулсетов и правил, компиляция, `.sigmacorr`-корреляции, индекс ссылок, межрулсетные зависимости | `rules-catalog.md` |
| `rules/main_ruleset.py` | Состав «основного рулсета», `resolve_for()` — единая точка «что исполняется» | `main-ruleset.md` |
| `rules/value_lists.py` | Списки значений для `%name%` / `\|expand`, разворот ДО компиляции | `value-lists.md` |

### Модель данных (`siem.db`)

- **`alerts`** — нормализованные алерты. Дедуп по `dedup_key` (два режима, см.
  `normalization.md`); повтор инкрементит `event_count`. Колонки `status` НЕТ — триаж-статус
  только у инцидентов.
- **`events`** — снимок ВСЕХ событий батча (включая не сработавшие) + `is_matched`/`matched_rules`
  + ECS-lite колонки (`user_name`/`src_ip`/`dst_ip`/`process`/`event_code`). Чистится ретеншном
  по `ingested_at`.
- **`rule_hits`** — леджер срабатываний, «интересных» активным корреляциям:
  `(event_id, rule_title, source_batch, event_time, group_json)`. Заполняется ТОЧЕЧНО через
  `store_events(..., hit_spec=...)` — только нужные корреляциям правила и поля.
- **`sources`** — реестр потоковых источников (`name` UNIQUE = метка `source_batch`, токен только
  sha256, открытый отдаётся один раз). С уже накопленными метками `source_batch` не связана.
- **`incidents`** / **`investigations`** / **`incident_alerts`** — Этап 4, `docs/spec/incidents.md`.
  Инцидент заводится ТОЛЬКО correlation-правилом с блоком `correlation.incident`; catch-all
  прохода по `alerts` намеренно нет. Member-алерты — many-to-many.

### API (карта; детали — `docs/spec/http-api.md`)

| Группа | Ручки | Что помнить |
|---|---|---|
| Ingest | `POST /ingest/{stream,events,file,upload}` | `stream`/`events` — **только с токеном источника** (`Authorization: Bearer` или `X-Ingest-Token`), метка `source_batch` = имя источника, рулсет всегда `main`. `file`/`upload` — локальный UI, без токена, `ruleset` выбирается. |
| Источники | `GET·POST /sources`, `POST /sources/{id}/rotate`, `PATCH·DELETE /sources/{id}` | Токен открытым текстом — один раз при создании/ротации. `DELETE` снимает регистрацию, данные не трогает. |
| Данные | `GET /batches`, `DELETE /batches/{source_batch}` | `DELETE` чистит ШЕСТЬ таблиц, регистрацию в `sources` не трогает. |
| Алерты | `GET /alerts`, `/alerts/groups`, `/alerts/{id}` | Список — обёртка с `total`; фильтры `source_batch`/`rule_level`/`time_*`/`incident`/`q`/`rule_title`. Карточка несёт `incidents` и `mitre`, список — нет. Ручки смены статуса нет. |
| Инциденты | `GET /incidents`, `/incidents/{id}`, `/incidents/{id}/context`, `PATCH /incidents/{id}/status` | `/context` — полный контекст под агента, деградирует до пустых секций + `note` при удалённом правиле / вычищенных событиях. Статус типизирован `Literal`. |
| События | `GET /events`, `/events/{id}`, `/events/group` | `query` — мини-язык фильтра (400 с позицией при ошибке), `group_cond` — drill-in (fail-closed), `fields=A,B` — кастом-колонки. Верхняя граница `time_to` включающая. |
| Правила | `GET /rulesets`, `/rulesets/rules`, `/rulesets/rule`, `POST /rulesets/upload`, `DELETE /rulesets`, `POST·PUT·DELETE /rules/custom*`, `POST /main-ruleset/{rules,rulesets}` | Цель всегда свой рулсет (`ruleset` ИЛИ `new_ruleset_name`), builtin как цель — 400. Удаление/переименование под ссылкой корреляции — 409 + `force=true`. |
| Списки | `GET·POST·PUT·DELETE /value-lists*`, `POST /value-lists/upload` | `PUT`/импорт сразу пересобирают зависимые правила. |
| KB | `GET /kb/mitre/{meta,matrix,techniques,techniques/{id}}` | Без `kb.db` — валидная форма с `available:false`, не 5xx. |
| Служебное | `GET /health`, `GET /updates` | `/updates` считается в памяти, БЕЗ похода в БД — его поллит каждая открытая вкладка раз в 7с. |

---

## 5. Контент, правила и данные на диске

- **`Zircolite/rules/*.json`** — скомпилированные built-in рулсеты (read-only, по умолчанию
  `rules_windows_merged.json`); `Zircolite/config/` — field-mappings и transforms.
- **`data/custom_rulesets/`** (`SIEM_CUSTOM_RULESETS_DIR`) — пользовательские рулсеты, в API
  адресуются как `custom_rulesets/<ruleset_id>`. Внутри: `meta.json`, `<rule_id>.yml` (raw Sigma,
  source of truth), `<rule_id>.sigmacorr` (correlation-правила, §8), `.manifest.json` (кэш
  скомпилированных метаданных — по нему И браузинг, И детект: только в манифесте развёрнуты
  плейсхолдеры value lists). Плюс `main_ruleset.json` — состав основного рулсета.
- **`data/value_lists/`** — `<name>.yml` на список (`name` = имя плейсхолдера, `[A-Za-z0-9_]{1,64}`).
- **`data/uploads/`** — каталог загрузок; **`kb/kb.db`** — read-only база MITRE (в Docker вшита
  в образ, volume'ом не монтируется, обновление = пересборка).
- **`artifacts/content/`** — детект-контент в git, ИСТОЧНИК ПРАВДЫ (в SIEM попадает только через
  `scripts/deploy_content.py`): `<domain>/rules/*.yml`, `<domain>/correlations/*.yml`,
  `<domain>/tests/<SCE_имя>.yml` (фикстуры), `value_lists/`, `telemetry/` (конфиг Sysmon стенда и
  схема полей событий; в SIEM не грузятся). Имя каталога домена = имя custom-рулсета. Соглашения — §9.
- **`artifacts/Security-Datasets/`** и **`Zircolite/`** — внешние клоны со своим `.git`, не трогаем.

### Скрипты (`scripts/`, не часть приложения)

Исключение — `build_kb.py`: он часть сборки (COPY в builder-стадию Dockerfile), автономен
(stdlib + `requests`, без `import app.*`).

| Скрипт | Назначение |
|---|---|
| `deploy_content.py` · `test_content.py` · `content_lib.py` | Деплой контента из git через HTTP API (идемпотентно, `--prune`) и прогон фикстур; `--coverage` — правила, не сработавшие ни в одном кейсе (код выхода 2 при дырах). Гонять на изолированном экземпляре (`SIEM_DB_PATH`/`SIEM_CUSTOM_RULESETS_DIR`/`SIEM_VALUE_LISTS_DIR`, свой порт). `docs/spec/content-pipeline.md` |
| `deploy_content.ps1` · `.sh` | Тот же деплой без Python на хосте — одноразовый контейнер из `soc_agent:latest`. |
| `content/sigma_find.py` · `adapt_sigma.py` · `new_correlation.py` | Инструменты автора контента: поиск кандидатов в клоне SigmaHQ, черновик адаптации по §9, заготовка корреляции. |
| `build_agent_installer.py` · `build_lab_runner.py` | Сборка `dist/install-soc-agent.ps1` (аудит + Sysmon + Vector службой) и `dist/run-lab-scenarios.ps1` (гид по `lab:`-секциям фикстур на самой ВМ). **`dist/`** — единая папка: шаблоны (`*.template.ps1`) и собранные файлы рядом под РАЗНЫМИ именами. Раннер ASCII-only, план встроен base64-строками — устойчивость к порче при ручном переносе на ВМ. |
| `export_event_fields.py` | Выгрузка реального набора полей по `Channel\|EventID` в `telemetry/event_fields.json`. Берёт только события ТЕКУЩЕЙ БД — выгрузку сливать, а не перезаписывать. |
| `bench_correlation.py` | Бенчмарк масштабируемости коррелятора (только stdlib + `app.store`): 10⁵/10⁶/10⁷ строк `rule_hits` — проверка требования «скорость не зависит от размера БД» (§8). |
| `fake_forwarder.py` · `stream_main_ruleset_test.py` · `stream_correlation_test.py` · `send_rule_test_events.py` · `send_value_list_test_events.py` | Ручные проверки через живой сервер. Все, кто шлёт в `/ingest/stream`, требуют токен (`--token` или `SIEM_INGEST_TOKEN`) — сначала создайте источник во вкладке «Источник данных». Прогоны изолируются рандомизацией host/ip/user. |

---

## 6. Соглашения по коду

- Комментарии и docstring-и — **на русском** (так написан весь код, держим единый стиль).
- `from __future__ import annotations` в начале модулей; современные type hints (`str | None`).
- Модели данных — только Pydantic; не тащить сырые dict-ы в бизнес-логику UI/агента.
- Новые имена полей источников — в `app/fields.py`, не хардкодить в normalize.
- Работа с БД — только через `Store` под соответствующим локом (`_lock` запись, `_read_lock`
  чтение); не открывать sqlite-конекты мимо него.
- В `app/` не пишем `print()` — только `logging.getLogger(__name__)` (§8).
- Пишешь не код, а детект-КОНТЕНТ — §9 (§8 про движок, §9 про то, что в него кладут).

---

## 7. Дорожная карта

Легенда: ✅ готово · 🟡 частично · ⬜ не начато

### Этап 0 — Гигиена проекта ✅
`pyproject.toml` как единственный манифест, `.gitignore`, `.env`-конфиг (`app/config.py`),
мини-набор тестов (`tests/`, не импортируют `app.main` — собирают `ZircoliteEngine`/`Store` через
фикстуры `conftest.py`). Не покрыты тестами: `rules_catalog.py`, `main_ruleset.py`, `filter_lang.py`.

### Этап 1 — Архитектура SIEM 🟡
- ✅ Пайплайн ingest → детект → нормализация → хранение, дедуп алертов, кэш правил.
- ✅ Потоковый ingest (`POST /ingest/stream` → очередь → micro-batch, `docs/guide/forwarder.md`)
  с аутентификацией по токену источника (таблица `sources`).
- ✅ Реальный `/health` (БД, поток воркера, загруженность ruleset), светофор в UI раз в 20с.
- ✅ Стейтфул-корреляция всех четырёх типов + цепочки, независимо от флаша и от размера БД
  (`docs/spec/correlation.md`). ⬜ «Расширенные» condition (`temporal_extended`) — не поддержаны,
  отклоняются явной ошибкой при сохранении.
- 🟡 MITRE ATT&CK: ✅ `kb.db` + вкладка «База знаний» + обогащение карточки алерта.
  ⬜ Обогащение в списке алертов/дашборде, tool `lookup_mitre` для агента.
- 🟡 Ретеншн `events` (`delete_events_older_than` из `IngestWorker`); ⬜ архивация / переезд на
  Postgres/Elastic при росте.

### Этап 2 — UI 🟡
- ✅ Вкладки Источник данных / Алерты / Инциденты / События / Sigma-правила / Списки / База знаний;
  карточки алерта, инцидента, события, правила.
- ✅ События: мини-язык фильтра со скобками и `and/or/not`, панель группировки с drill-in,
  кастомные колонки из raw JSON + именованные fieldset-ы, resizable-панели и колонки,
  серверная сортировка, временной интервал (пресеты + кастомный, без пересчёта через таймзону).
- ✅ Sigma-правила: просмотр builtin и своих рулсетов, поиск, сортировка, полноэкранный редактор
  правила с живой подсветкой YAML, сборка «основного рулсета» кнопками, загрузка рулсета файлом.
- ✅ Алерты/Инциденты: пагинация, группировка по правилу, фильтр «в инцидентах / вне»,
  живое обновление через `GET /updates` (бейдж «↑ N новых», тихая перезагрузка когда можно).
  События намеренно не покрыты автообновлением.
- ⬜ Дашборд (severity, топ правил/хостов/MITRE, таймлайн).
- ⬜ Триаж-воркфлоу (назначение аналитика, комментарии, метки TP/FP).
- ⬜ Push-транспорт (SSE/WebSocket) вместо поллинга `/updates` и общее (не in-process) состояние
  счётчиков, если поедем на несколько воркеров.
- ⬜ Аутентификация/роли — перед выходом за пределы localhost.

### Этап 3 — Ingest-коннекторы и нормализация 🟡
- ✅ Потоковые источники (Vector → `/ingest/stream`), «основной рулсет» по умолчанию для
  `/ingest/stream` и `/ingest/events`, именованные списки значений (`%name%` / `\|expand`).
- 🟡 Управление рулсетами: есть именованные рулсеты и загрузка Sigma YAML; ⬜ версионирование,
  включение/выключение по тегам.
- ⬜ Стабильная ECS-подобная схема нормализованного события на входе в хранилище.

### Этап 4 — Инциденты и контекст для агента 🟡
- ✅ Таблицы `incidents`/`investigations`/`incident_alerts`, сценарное заведение инцидента
  correlation-правилом с `correlation.incident`, `GET /incidents/{id}/context`.
- ✅ Фоновая джоба вердиктов — пока ЗАГЛУШКА (`app/incidents.py:run_pending`).
- ⬜ Tools агента: `search_events`, `get_incident_context`, `pivot_by_entity`, `lookup_mitre` —
  пишутся вместе с агентом на Этапе 5.

### Этап 4.5 — Детект-контент ✅
Соглашения — §9 (читать целиком перед первым правилом), стенд — `docs/guide/windows-vm-lab.md`,
агент — `docs/guide/windows-agent.md`, пайплайн — `docs/spec/content-pipeline.md`.

- ✅ 11 доменов-рулсетов (`auth`, `recon`, `execution`, `persistence`, `privesc`, `credaccess`,
  `evasion`, `lateral`, `exfil`, `impact`, `killchain`): 49 сценариев с инцидентом (14 `SCE_TH_`),
  131 базовое правило, 71 корреляция (22 тихих звена), 46 value lists; 221/221 кейс зелёный,
  `--coverage` — 0 непокрытых правил (2026-09-16).
- ✅ Движок под контент: межрулсетные ссылки и зависимости, тихие informational-звенья,
  `TimeCreated` как время события, NULL-колонки полей правил, лог ошибок SQL правил,
  member-алерты many-to-many, резолв правил один раз на флаш.
- ✅ Телеметрия по эталонам: Sysmon — sysmon-modular balanced с ProcessCreate в exclude-режиме,
  аудит — базовая линия Microsoft, 4103 выключен. Простой стенда ~1500 событий/ч без алертов,
  фильтрация шума не нужна. Подробности и таблица «что приезжает» — `windows-vm-lab.md` §4.
- ✅ Агент Vector вместо Fluent Bit, подключение хоста одним скриптом (`dist/`).
- ✅ Живой прогон (2026-09-19, Hyper-V): 49 из 53 сценариев, 10 из 11 доменов; починены 5 фикстур
  и раннер. **Не проверено:** `lateral` (нужен второй хост), `SCE_Exec_Office_Child_Network`
  (нужен Office), Sysmon 17/18 и 19–21 (правил под них в контенте нет), `_legacy_keys` в
  `event_fields.json`.
- ✅ Решено НЕ делать: близнецы правил на System 7045 (двойной счёт с 4697); корреляция учётки
  4720 `TargetSid` ↔ 4732 `MemberSid` (алиасов полей в движке нет); исключения под FP — разбор
  TP/FP это задача агента Этапа 5 (§9).

### Этап 5 — AI-агент расследования 🎯 главная цель ⬜
- **Стек:** **LangGraph**; «мозги» — любой **OpenAI-совместимый** провайдер через
  `langchain-openai.ChatOpenAI`. Провайдер/модель/ключ из `.env`: `SOC_AGENT_API_BASE`,
  `SOC_AGENT_API_KEY`, `SOC_AGENT_MODEL`, опц. `SOC_AGENT_TEMPERATURE` (добавить в `app/config.py`
  и `.env.example`). **НЕ Anthropic SDK; skill `claude-api` не используется.**
- **Размещение:** подпакет `app/agent/`; зависимости — в `[project.optional-dependencies].agent`,
  в базовый прод не тянутся. Запуск — фоновая джоба (как `IngestWorker`): инцидент → очередь
  расследования → `investigations.status`.
- **Граф:** триаж → tool-use цикл (события / пивот / MITRE) → гипотеза → вердикт `TP`/`FP`/
  `needs-review` + обоснование + confidence → запись в `investigations` → карточка инцидента.
- **Единица работы — инцидент**, не сырое срабатывание правила.
- **Оценка качества — живой adversarial-контур**, не replay датасетов: опенсорсный pentest-agent
  на ВМ с форвардером в SIEM генерит атаки → инциденты → soc-agent выносит вердикты → сверка.
  OTRF Security-Datasets остаются только для ОФЛАЙН-разработки правил и корреляций.
- **Human-in-the-loop:** аналитик подтверждает/отклоняет вердикт → данные для дообучения промптов.

### Этап 6 — Продакшн-готовность ⬜
Метрики (Prometheus), обработка ошибок ingest, бэкапы БД, CI (линт + тесты).

---

## 8. Что важно помнить при доработке

Грабли, пойманные вживую. Подробный разбор каждой — в соответствующей спеке `docs/spec/`.

### Правила и каталог

- **Не пересоздавай `RulesetHandler` на каждый запрос** — это секунды на тысячах правил. Кэш —
  `ZircoliteEngine._rulesets_cache`, сам не инвалидируется. После add/delete кастомного правила
  или рулсета обязательно `engine.invalidate(ruleset_path)`, иначе детект идёт по старой
  скомпилированной версии до рестарта (ловили: правило удалено, а детект работает).
- **Редактирование правила, уже включённого в main, НЕ требует повторного тоггла** — членство
  хранится по `(ruleset_path, rule_id)`, `id` при `PUT` остаётся исходным (другой `id:` в YAML —
  400). Новая версия SQL подхватывается на следующем батче. Уже созданные алерты не
  пересчитываются; повторное срабатывание = инкремент `event_count` существующего алерта.
- **В built-in рулсетах один Sigma-`id` легитимно встречается НЕСКОЛЬКО раз** (одно правило →
  несколько записей под разные pipeline; 1611 из 4291 в `rules_windows_merged.json`).
  `main_ruleset.resolve_with_sources()` **не дедуплицирует по id** — дедуп молча терял ~37% правил
  при добавлении рулсета целиком. Точечный toggle по `rule_id` затрагивает все записи с этим id —
  это ожидаемо.
- **У correlation-правила `id` берётся из YAML, а при его отсутствии — из ИМЕНИ ФАЙЛА**
  (`<rule_id>.sigmacorr`). С `id=None` правило молча выпадало из main: сохранено, видно в UI,
  никогда не срабатывает. Не «упрощай» обратно до `doc.get("id")`.
- **Correlation-правила хранятся под `.sigmacorr`, НЕ `.yml`** — это обход бага стокового
  `pysigma-backend-sqlite` (`finalize_correlation_subqueries = False`): referenced-правило в том
  же `SigmaCollection` либо молча выпадает из рулсета, либо валит компиляцию всего файла сырой
  SQL-строкой. `RulesetHandler` глобит только `*.yml`/`*.yaml` и потому их не видит. Не
  «исправляй» раскладку; если апстрим починит — проверяй эмпирически, не по changelog.
  Разбор — `docs/spec/rules-catalog.md`.
- **Ссылки `correlation.rules` проверяются на СОХРАНЕНИИ и резолвятся по ВСЕМ custom-рулсетам**
  (`rules_catalog.build_ref_index` — один индекс на валидацию и рантайм; новый источник имён правь
  там). Опечатка — 400, а не тихо сохранённое неработающее правило. Цена глобального резолва —
  глобальная уникальность `title` (ключ `rule_hits`) и `name` (ключ ссылки). Исполнение
  подтягивает зависимости (`with_dependencies`); удаление/переименование под ссылкой — 409 +
  `force=true`.
- **Скан файлов правил кэшируется с перепроверкой раз в 2 секунды** (`_SCAN_RECHECK_SECONDS`);
  запись через API сбрасывает кэш сразу. Не убирай паузу: резолв main зовётся на каждом источнике
  каждого флаша, без неё стоил ~0.5 с на 197 правилах. Файлы, правленые мимо API, подхватываются
  с этой задержкой.
- **Ошибки каталога: `CatalogNotFound` → 404, остальные `CatalogError` → 400**
  (`main._catalog_http` — единственная точка трансляции, не пиши `HTTPException` по месту).
  Путь с префиксом `custom_rulesets/` разбирается ТОЛЬКО как кастомный, даже если такого рулсета нет.

### Детект и корреляция

- **Correlation-правило уровня `informational` без `incident` — ТИХОЕ звено**: считается и пишет
  попадание в `rule_hits`, но алерта не создаёт. На этом держатся промежуточные звенья и
  агрегаторы тактик (§9). Раньше пропускалось целиком, и цепочка молча не срабатывала.
- **Счёт корреляции ОБЯЗАН оставаться независимым от размера БД** — это проверяемое требование,
  не пожелание. Счётный путь (A3: `fetch_correlation_hits` → скользящее окно в `_best_anchor` →
  `evaluate_correlation_window`) читает ИСКЛЮЧИТЕЛЬНО `rule_hits.group_json`, БЕЗ `JOIN` к
  `events`. Не возвращай `JOIN`/`json_extract(raw_json, ...)` на счётный путь «ради простоты».
  `fetch_correlation_hits` сужен и по кандидатным ключам, и по диапазону `~2×timespan` — без
  обоих фильтров это скан всей истории. Правишь счётный путь — гоняй `scripts/bench_correlation.py`.
- **Окно анкерится на `event_time`, `_best_anchor` перебирает ВСЕ точки-якоря** в
  `[min(new), max(new) + timespan]`. Не возвращай «якорь = max(new)» (позднее событие со старой
  меткой снова начнёт «прятать» окно) и тем более `datetime.now()` (сломает replay исторических
  датасетов, где все метки в прошлом).
- **Ни один SQL-совместимый Sigma-бэкенд не годится для скользящей корреляции** — проверены
  `pysigma-backend-sqlite` и `pysigma-backend-clickhouse`: у `event_count`/`value_count` шаблон не
  содержит `{timespan}`, `temporal` считает «весь срок жизни группы», `temporal_ordered` собирает
  порядок и НИКОГДА его не сравнивает. Это не баг одного бэкенда, а свойство «один SQL statement».
  Полный разбор альтернатив — `docs/spec/correlation.md`. Не повод переезжать на другой движок.
- **`correlation.timespan` длиннее `SIEM_EVENTS_RETENTION_DAYS` отклоняется на сохранении** —
  ретеншн удалил бы `events` и осиротевшие `rule_hits`, окно недосчитывало бы. `0` — ретеншн
  выключен, проверки нет.
- **Время события — `TimeCreated`, `EventTime` — только фолбэк.** `EventTime` (время чтения
  журнала форвардером) отставал на 1–2 с и путал порядок в `temporal_ordered`.
  `_sequence_matches_order` считает попадания с равной меткой одной ступенью — не возвращай
  строгий построчный проход. У Sysmon 3 `TimeCreated` отстаёт от `UtcTime` самого события, поэтому
  агент для канала Sysmon кладёт в `TimeCreated` именно `UtcTime` (VRL `dist/vector.toml`);
  сервер про `UtcTime` не знает — **не ставь его в `TIME_FIELDS`** (синтетика дополняет
  отсутствующие поля заглушкой `"-"`, и она стала бы временем события).
- **Поля, упомянутые правилами, но не пришедшие в событиях флаша, движок досоздаёт NULL-колонками**
  (`RuleColumnIndex` + `_SiemCore.add_missing_rule_columns`) — раньше такое правило падало с
  «no such column» и молча не срабатывало. Список колонок выясняется у САМОГО SQLite (`EXPLAIN`),
  не регэкспом (литералы с `=` и `LIKE` дают ложные колонки), и кэшируется по тексту SQL.
  Остаётся семантика NULL: `NOT (поле LIKE ...)` на отсутствующем поле — ложь, поэтому синтетика
  `test_content.py` дополняет события реальным набором полей стенда.
- **Ошибки SQL правил видны в логе** — `_SiemCore.execute_select_query` пишет WARNING с названием
  правила, не чаще раза в 600 с на правило. Сток Zircolite глушит их в debug и возвращает тот же
  `[]`, что и «не сработало», поэтому метод переопределён целиком.

### Хранилище и время

- **Новые колонки/индексы добавляй через `store._migrate`, а не только в `_SCHEMA`.** `_SCHEMA` —
  это `CREATE TABLE IF NOT EXISTS`, no-op на существующей таблице. `_migrate` зовётся на каждом
  старте: `PRAGMA table_info` → `ALTER TABLE ADD COLUMN`, и только ПОСЛЕ этого — индексы.
  Версионирования схемы нет, только идемпотентные операции.
- **Метка времени КАНОНИЗИРУЕТСЯ на записи (`app/timeutil.py`)** — не возвращай
  `replace(replace(event_time, ' ', 'T'), 'Z', '')` в запросы. `store_events` пишет ОДНО
  каноническое значение и в `events.event_time`, и в `rule_hits.event_time`; сырое остаётся в
  `raw_json`. Границы приводит `normalize_time_bound` в ЕДИНСТВЕННОЙ точке (`_events_where`),
  верхняя — включающая. Побочный выигрыш: `idx_events_time` работает как range-scan.
- **ECS-lite колонки `events` ЧИТАЮТСЯ** — это имена полей фильтра/группировки/сортировки
  (`filter_lang.ENTITY_COLUMNS`). Не удаляй их и не оборачивай в `CAST(... AS TEXT)`: с `CAST`
  планировщик не берёт `idx_events_user`/`idx_events_src_ip` (тест
  `tests/test_store.py::test_entity_columns_are_filterable_and_indexed`).
- **`delete_batch` чистит ШЕСТЬ таблиц** (`events`/`alerts`/`rule_hits`/`incidents`/
  `investigations`/`incident_alerts`). Добавляешь ещё одну таблицу с `source_batch` — не забудь её
  сюда же. Таблица `sources` под это правило НЕ подпадает намеренно: удаление данных и снятие
  регистрации — разные действия.
- **`siem.db` большой** (десятки МБ) и растёт с каждым ingest — не коммить, чистить при тестах.

### HTTP, фильтры, ingest

- **`app/filter_lang.py` — никогда не подставляй пользовательский текст в SQL напрямую.** Значение
  всегда bound-параметр; путь поля — тоже, КРОМЕ узкого whitelist `INDEXED_JSON_FIELDS` (сейчас
  только `EventID`), где путь литерал ради expression-индекса. Добавляешь «горячее» поле — парный
  индекс в `store._SCHEMA` должен ТЕКСТУАЛЬНО совпасть с выражением (проверь `EXPLAIN QUERY PLAN`).
- **`group_cond` (drill-in) fail-closed**: нераспознанное условие — 400, а не молчаливый пропуск.
  Раньше drill-in вместо сужения возвращал ВСЮ выборку. Новый оператор — в `filter_lang.FILTER_OPS`,
  а не «мягкий» обход проверки.
- **Ingest нескольких источников сливается в ОДИН прогон движка за флаш** — фиксированный оверхед
  Zircolite (~0.25 с на ~4300 правилах, не зависит от числа событий) раньше платился за каждый
  источник отдельно. Источник кодируется в САМОМ событии (`INGEST_SOURCE_FIELD`) перед прогоном и
  снимается после. Новый ingest-путь, умеющий мешать источники, следует этому же паттерну —
  не возвращай группировку по `source_label` ДО движка.
- **Токен ingest берётся ТОЛЬКО из заголовка** (`Authorization: Bearer` / `X-Ingest-Token`), не из
  query — query светится в логах прокси. В БД только sha256, открытый отдаётся один раз.
- **Автообновление (`app/updates.py`) — не поллить сам список и не считать «новых» по `created_at`.**
  У канала ДВА счётчика: `version` (любое изменение, включая инкремент `event_count`) и `created`
  (реально созданные строки) — у `alerts` нет `updated_at`, по максимуму `created_at` инкремент не
  виден вовсе. Число новых считается по `dedup_key` ДО записи (`get_alert_ids_by_dedup_keys`):
  `upsert_alerts` возвращает число ОБРАБОТАННЫХ строк, не созданных. Схема верна, пока процесс
  ОДИН (uvicorn без `--workers`).

### Инциденты

- **Правило с `correlation.incident` создаёт ИНЦИДЕНТ, а НЕ `engine="correlation"` алерт.** Ждёшь
  алерт в тесте — его не будет, смотри `GET /incidents`. Помеченное правило пробивает отсечку
  `level: informational`.
- **`incidents.dedup_key` = `source_batch:incident_type:group_values:window_bucket`.** Повтор в том
  же бакете = UPDATE строки, разрыв больше `timespan` = новый инцидент. **`source_batch` из ключа
  не убирать**: без него два источника с одной сущностью схлопывались в одну строку с
  перезаписанным окном и сэмплами. Настоящая кросс-источниковая корреляция — отдельная задача,
  полумерой через ключ не получается.
- **Привязка member-алертов — цепочкой `event_id`** (реальный `events.event_id` через
  `events.alert_id`, либо синтетический `corr:{dedup}:{title}:{anchor}` через поиск по
  `alerts.dedup_key`), а НЕ по значению сущности (так было раньше — молча не находило алерты, если
  group-by был не по хосту). Связи в `incident_alerts` (many-to-many) — не возвращай одну колонку
  `alerts.incident_id`: при двух сценариях на одних событиях второй инцидент оставался пустым.
- **Инцидент ПЕРЕЖИВАЕТ свои `events`** — `GET /incidents/{id}/context` обязан работать при пустом
  `related_events`.
- **`correlation.incident` ставь только на ПОСЛЕДНЕМ звене цепочки** — иначе на одну историю
  получится два инцидента вместо одного финального.
- **`app/incidents.py:run_pending` — заглушка Этапа 4.** Настоящий агент (Этап 5) заменит тело
  функции; жизненный цикл `queued → running → done → error` и точка вызова из `IngestWorker`
  остаются.

### Окружение и вывод

- **`logging_setup.configure()` переводит в UTF-8 ОБА потока (`stdout` И `stderr`) — не убирай
  stdout «за ненадобностью».** Zircolite рисует прогресс компиляции через `rich` (спиннер `⠋`); на
  cp1251-потоке запись падает с `UnicodeEncodeError` ВНУТРИ конвертации, Zircolite ловит её как
  «Cannot convert» и отдаёт ПУСТОЙ рулсет. Симптомы обманчивы: «правило не скомпилировалось» на
  заведомо корректном правиле и потеря ЦЕЛОГО флаша. Поэтому же `configure()` зовётся ДО создания
  движка. Тест — `tests/test_logging_setup.py`.
- **Формат событий Windows задаёт агент, а не сервер** (`dist/vector.toml`, VRL `sigma_fields`):
  `EventData`/`UserData` — на верхний уровень под именами `<Data Name>`, системные — в именах
  Fluent Bit, КРОМЕ `ExecutionProcessID`/`ExecutionThreadID` (иначе перетирали `ProcessId` Sysmon —
  колонки SQLite регистронезависимы). Поле данных, совпавшее с системным, получает префикс
  (`UserDataChannel` у System 104). Вложенный `UserData` разбирается парсингом XML
  (`include_xml = true`) — не выключай, иначе 104/1102 приедут без данных. Меняешь набор полей —
  перегенерируй `event_fields.json`.
- **AI-агент (`app/agent/`, Этап 5) — LangGraph + OpenAI-совместимый API** (`SOC_AGENT_*` в
  `.env`), НЕ Anthropic SDK; skill `claude-api` не используется. Зависимости — в extra `agent`.
  Единица работы — инцидент. Оценка — живой контур с pentest-agent, не replay датасетов.
- **При ручном тестировании дедупа алертов** осторожно с фиксированными `id` в тестовых правилах:
  повторный прогон совпадающего по содержимому события не создаёт новый алерт, а инкрементит
  `event_count` у существующего (и `source_batch` у него остаётся от ПЕРВОГО батча) — со стороны
  выглядит как «алертов 0». Чистить — `DELETE /batches/{source_batch}`.

---

## 9. Соглашения по контенту (Sigma-правила и корреляции)

Раздел про НАПИСАНИЕ детект-контента, а не про код движка (тот — §8). Правила выведены эмпирически
на стенде `win10-lab` (`docs/guide/windows-vm-lab.md`).

### Где живёт контент и как он проверяется

Источник правды — git: `artifacts/content/<domain>/rules/*.yml` (одно базовое правило на файл),
`<domain>/correlations/*.yml`, `<domain>/tests/<SCE_имя>.yml` (фикстуры), `value_lists/`,
`telemetry/`. В SIEM — только через `scripts/deploy_content.py` (value lists → базовые правила →
корреляции в топологическом порядке → `--prune` → включение в main). Правка через UI-редактор —
песочница, следующий деплой её перезапишет.

Проверка: изолированный экземпляр (`SIEM_DB_PATH`, `SIEM_CUSTOM_RULESETS_DIR`,
`SIEM_VALUE_LISTS_DIR`, свой порт) → деплой → `scripts/test_content.py`. Ожидание в фикстуре
ТОЧНОЕ: лишний инцидент — такой же FAIL, как недостающий. Каждое базовое правило обязано сработать
хотя бы в одном кейсе (`--coverage`, 0 непокрытых — условие готовности). Кандидаты из SigmaHQ —
`scripts/content/sigma_find.py` + `adapt_sigma.py`, заготовка корреляции — `new_correlation.py`.

### Исключения под ложные срабатывания не пишем

Фильтр в правиле — только исправление ЛОГИКИ (правило не сработает на реальном формате поля, одно
событие засчитывается сценарию дважды, неполный уже существующий фильтр). Легитимную активность,
которая выглядит как атака — установку агента (`wevtutil sl`, `sysmon -c`, `auditpol`), процессы
AV, администраторские действия — **в контенте не вырезаем**: она должна доходить до инцидента,
TP/FP разбирает агент расследования (Этап 5). Решено пользователем 2026-09-16.

### Именование и авторство

- Корреляция, взводящая инцидент: `title: SCE_<Domain>_<Scenario>`; threat hunting —
  `SCE_TH_<Domain>_<Scenario>` с `incident.severity: low` и префиксом `th_` в `incident.type`.
  Сквозные сценарии — `SCE_KC_*`. Остальные правила — обычные названия.
- Правило SigmaHQ без правок — авторы как есть. Доработанное (включая guard) —
  `author: '<оригинал>, ET, Claude'`, новый UUID, `related: [{id: <оригинальный>, type: derived}]`,
  `modified`. Своё — `author: ET, Claude`. `name` задаётся всегда явно, `id` — фиксированный UUID.
- Описания и `falsepositives` — по-английски (как в SigmaHQ), комментарии в YAML — по-русски.

### Адаптация правил SigmaHQ под этот SIEM

Компиляция идёт БЕЗ Sigma-пайплайна: `logsource` игнорируется, имена полей берутся буквально.

- Каждому правилу — guard `guard_logsource: {Channel, EventID}` и
  `condition: guard_logsource and (...)` (имя блока не должно попадать под `selection*`/`filter*`
  оригинального condition).
- Process-правила — ТОЛЬКО Sysmon EID 1 (поле `Image`). Близнецы под 4688 не заводим: один запуск
  даёт два события, `event_count` удваивается, `value_count` по `Image` 4688 не видит.
- Установка службы — правила ТОЛЬКО на Security 4697 (есть `SubjectUserName`). Близнецов на
  System 7045 нет по той же причине: одна установка пишет оба события.
- `Provider_Name` не доезжает (агент шлёт `ProviderName`, `_` режется flatten-ом) — писать
  `ProviderName`, если провайдер реально сужает детект, иначе убирать (роль играет guard).
- `Initiated`/`DestinationIsIpv6` — числа (`Initiated: 1`, не `'true'`).
- System 7045 (`ServiceName`/`ImagePath`/`StartType`/`AccountName`) и System 104 / Security 1102
  (`SubjectUserName`, канал очищенного журнала — `UserDataChannel`) приходят с именованными полями.
  Поле `Channel` у 104 — канал самой записи (`System`), не очищенного журнала.
- Реестр: запись в `HKCU\Software\Classes` Sysmon показывает как `HKU\<SID>_Classes\...` — суффикс
  в правиле начинать с `Classes\`, иначе правило мёртвое.
- Отсутствие поля — `Field: null` (→ `Field IS NULL`), а НЕ `Field|exists: false` (→
  `NOT Field = Field`, на NULL не истина — ветка никогда не срабатывает). `Field|exists: true`
  работает правильно. Windows пишет «пусто» как `'-'` — чаще нужен фильтр по значению.
- Группы «любое из» в одном сценарии: одно событие не должно матчиться двумя правилами группы
  (общий `Company` у продуктов одного вендора, подстрока одного шаблона внутри другого) — иначе
  `temporal gte: 2` взводится одним событием. Проверяется негативным кейсом.
- Связка по полям с разными именами (4720 `TargetSid` ↔ 4732 `MemberSid`) не выражается: алиасов
  полей в движке нет и не будет — ключуй по общему полю (`Computer`).
- Системный PID записи — `ExecutionProcessID`; `ProcessId` в правиле — поле события.
- Стенд на русской Windows: SID вместо имён групп (`S-1-5-32-544`),
  `User|contains: [AUTHORI, AUTORI]` для SYSTEM, локализованные имена — вторым значением.
- Поле, которого стек не доставляет, делает правило мёртвым молча (§8) — сверять с
  `telemetry/event_fields.json`.

### Рулсет = ДОМЕН; сценарий может опираться на другие домены

`correlation.rules` резолвятся по всем своим рулсетам (§8), поэтому базовое правило живёт в ОДНОМ
домене, а корреляции других доменов на него ссылаются (`lateral` → сетевой вход из `auth`,
`killchain` → агрегаторы всех доменов). Копировать базовые правила между рулсетами нельзя: копия —
другой `title`, то есть лишний алерт и лишние строки леджера на то же событие (и глобальная
уникальность `title` это запрещает). «Всё в одном рулсете» — плохо: рулсет это единица включения в
main, удаления и изолированного прогона.

### Промежуточные звенья и агрегаторы

`temporal_ordered` требует КАЖДУЮ ссылку, а сценарию обычно нужно «любое из A1..A3, потом любое из
B1..B3». Такие группы собираются тихими корреляциями: `level: informational`, без `incident`,
`event_count gte: 1` поверх нескольких базовых правил с тем же `group-by`. Они же гасят двойной
счёт одного приёма, видимого в двух телеметриях (удаление теневых копий в Sysmon 1 и в 4104).
Агрегаторы тактик (`Host <Tactic> Activity`, `[Computer]`) лежат в своих доменах и кормят
`killchain`.

### Базовых правил столько, сколько РАЗЛИЧНЫХ selection — не сколько корреляций

`correlation.active_hit_spec` собирает ОБЪЕДИНЕНИЕ полей всех корреляций, ссылающихся на правило.
Одно базовое правило, на которое ссылаются три корреляции с разным `group-by`, получит в
`group_json` все их поля разом, а каждая корреляция вытащит свой срез. **Отдельное базовое правило
под каждую комбинацию group-by заводить НЕ НУЖНО** — это была главная ошибка тестового контента.
Одиннадцать корреляций поверх трёх базовых правил — норма.

### Guard на мусорные значения ключа ОБЯЗАТЕЛЕН

`store.store_events` пишет в `group_json` всё, что не `None`, а `fetch_correlation_hits` отбрасывает
строку, только если поля НЕТ вовсе. Значения `'-'` и `''` — полноправные значения ключа: у 4625 при
локальном входе `IpAddress` равен именно `'-'`. Правило, чей `group-by` идёт по такому полю, ОБЯЗАНО
отфильтровать мусор само — иначе корреляция отрапортует «20 неудач с IP `-`». Канонический вид:

```yaml
detection:
  selection:
    EventID: 4625
    IpAddress|exists: true
  filter_invalid_ip:
    IpAddress: ['-', '']
  filter_machine:
    TargetUserName|endswith: '$'
  condition: selection and not 1 of filter_*
```

### Базовое правило даёт СВОЙ алерт — держи его узким

Отсечка `informational` снята намеренно: сработки базовых правил нужны и как алерты (видимость,
отладка сценария), и как member-алерты инцидента. Следствие: широкое базовое правило = мусор во
вкладке «Алерты» + строки в леджере. Ловили: `SELECT * FROM logs WHERE EventID=4624` без фильтров
дал 71 алерт, все — `LogonType=5` от `NT AUTHORITY\СИСТЕМА` (SCM поднимает службы).

Для auth-правил обязательны **белый список `LogonType`** (`2` интерактивный, `3` сетевой,
`7` разблокировка, `10` RDP, `11` кэшированные) и отсечка машинных учёток
(`TargetUserName|endswith: '$'`).

### `title` — ключ в `rule_hits`, `name` — ключ ссылки

Ссылки `correlation.rules` резолвятся по Sigma `name`, а в леджер пишется `title`. Переименование
`title` базового правила НЕ рвёт ссылку, но осиротит накопленные строки леджера — корреляция
ослепнет на свой `timespan` (для `1d` это сутки), и молча. `title` базового правила считать
стабильным идентификатором; менять — только с осознанным принятием слепого окна.

### Value lists — для перечислений, но без значимых пробелов

Перечни от ~8 значений (или переиспользуемые) выносятся в value list `<префикс домена>_<смысл>`
(`cred_lsass_read_access_masks`, не `..._grantedaccess2`) с русским описанием, в котором указано,
как список применяется (`|endswith по Image`). Автоимена `adapt_sigma.py --auto-vl` переименовать
до коммита. Пространство имён ГЛОБАЛЬНОЕ и плоское — префикс домена обязателен.

**Сервер обрезает пробелы по краям значений** — значение вроде `' -nop '`, `'cmd '`, `' JAB'` в
списке молча расширит правило; такие перечни остаются inline (`content_lib.py` отказывается
деплоить список с краевыми пробелами).

### Прочее

- `correlation.incident` — только на ПОСЛЕДНЕМ звене цепочки (§8); внутри домена помеченным должен
  быть ровно один файл на сценарий.
- `timespan` не длиннее `SIEM_EVENTS_RETENTION_DAYS` — иначе 400 на сохранении.
- **Порядок миграции контента: сначала переставить ссылки в корреляциях, ПОТОМ удалять базовые
  правила.** Удалишь первым — `load_correlation_rules` начнёт молча пропускать корреляцию с
  неразрешимой ссылкой, правило будет видно в UI и никогда не сработает.

### Что реально доступно на стенде

Стенд `win10-lab`: агент Vector, `telemetry/sysmonconfig.xml` (ProcessCreate в exclude-режиме),
аудит по базовой линии Microsoft, каналы Security, System, Sysmon/Operational,
PowerShell/Operational, Defender, WMI-Activity, TaskScheduler, Bits-Client. Простой — ~1500
событий/ч без алертов, фильтрация шума не нужна.

Пиши контент на process / PowerShell / auth / registry / services / log clearing. **Таблица «какой
EventID реально приезжает и сколько правил на него смотрит» — `docs/guide/windows-vm-lab.md` §4**
(там же: 4657 не приезжает без SACL, 4673/4674/5379 отфильтрованы в агенте, 4689 выключен).

**Телеметрия берётся из эталонов, контент следует за ней, а не наоборот** (решено 2026-09-15):
Sysmon — sysmon-modular balanced с ProcessCreate в exclude-режиме (не добавляй
`ProcessCreate onmatch="include"` — это вернёт режим «только перечисленное»); аудит — базовая линия
Microsoft без Sensitive Privilege Use и Process Termination; PowerShell — только ScriptBlock (4104).
Правило на событие, которое эталон не пишет, — осознанное дополнение конфига, а не молчаливая надежда.
