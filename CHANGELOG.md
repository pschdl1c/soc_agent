# Changelog

Все заметные изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [SemVer](https://semver.org/lang/ru/) (пока `0.y.z` — публичного API нет, ломающие
изменения бампают MINOR).

Источник правды для номера версии — `[project].version` в `pyproject.toml`; `app/main.py`
читает его через `importlib.metadata` и отдаёт в `/docs` и `/openapi.json`.

Релиз: поднять версию в `pyproject.toml` (и совпадающий фолбэк `__version__` в `app/main.py`) →
дописать раздел сюда → коммит → `git tag vX.Y.Z` → `git push --tags`.

## [Unreleased]

### Added
- Стейтфул-корреляция (`app/detection/correlation.py`) теперь эвалуирует все четыре
  Sigma-типа: `event_count`/`value_count` (было раньше) плюс `temporal`/`temporal_ordered`,
  включая ЦЕПОЧКИ (correlation-правило ссылается на другую correlation, форма
  `artifacts/content/auth_after_brutforce.yml` — теперь реально срабатывает).
  `temporal_ordered` проверяет РЕАЛЬНЫЙ порядок появления событий (жадное сопоставление
  подпоследовательности) — ни один апстрим Sigma-бэкенд (pysigma-backend-sqlite/-clickhouse)
  этого не делает.
- Двухфазный счёт корреляции (`rule_hits.group_json` + `store.evaluate_correlation_windows`/
  `evaluate_correlation_window`) — скорость коррелятора больше не зависит от размера БД
  (замерено `scripts/bench_correlation.py`: рост `rule_hits` в 100 раз даёт единицы процентов
  роста времени запроса). Счёт больше не делает `JOIN` к `events` вовсе.
- ECS-lite колонки `events.user_name`/`src_ip`/`dst_ip`/`process`/`event_code` — денормализованный
  индекс поверх `raw_json`, фундамент будущей группировки Инцидентов по сущности (Этап B).
- Ретеншн `events` (`SIEM_EVENTS_RETENTION_DAYS`, дефолт 14 дней, `0` — выключено) —
  `store.delete_events_older_than`, вызывается фоново тем же потоком `IngestWorker`.
- `app/timespan.py` — разбор Sigma-таймспана (`"5m"` → `300`), общий для рантайма корреляции и
  валидации при сохранении правила.
- `scripts/bench_correlation.py` — бенчмарк масштабируемости коррелятора.
- Валидация correlation-правил при сохранении (`rules_catalog._validate_correlation_doc`)
  теперь требует непустой `group-by`, проверяет формат `timespan` и явно отклоняет
  "расширенные" condition-выражения — раньше такие правила молча сохранялись и никогда
  не срабатывали.

### Fixed
- Резолв ссылок `correlation.rules` теперь видит и другие correlation-правила (не только
  обычные), что чинит цепочки — раньше ссылка correlation → correlation никогда не
  резолвилась, и вся зависимая запись пропадала целиком.
- Group-by по ЧИСЛОВОМУ полю (напр. `EventID`) в correlation-правиле раньше всегда считал 0
  (несовпадение типов INTEGER/TEXT в SQLite) — теперь все значения в `rule_hits.group_json`
  хранятся и сравниваются строками.

### Changed
- `store.store_events(..., hit_worthy_titles=...)` → `store.store_events(..., hit_spec=...)`
  (теперь несёт не только названия правил, но и набор нужных полей на каждое).
  `correlation.active_base_rule_titles` → `correlation.active_hit_spec`.
- `docs/spec/correlation.md`, `docs/spec/storage.md`, `docs/spec/rules-catalog.md`,
  `docs/spec/ingest-queue.md`, `docs/spec/config.md`, `CLAUDE.md` — обновлены под все
  изменения выше; поправлена неточность "пропатченный `pysigma-backend-sqlite`" (сток, не
  пропатчен — сверено по sha256 файла) и разобраны причины отказа от переезда на
  DuckDB/ClickHouse.

## [0.4.0] — 2026-09-03

### Changed
- Реструктуризация пакета `app/`: выделены подпакеты
  - `app/detection/` — `engine.py`, `normalize.py`, `correlation.py` (путь событие → Sigma-детект → `Alert`);
  - `app/rules/` — `rules_catalog.py`, `main_ruleset.py`, `value_lists.py` (весь Sigma-контент).
  Остальные модули остались в корне `app/`. Изменения только внутренние — HTTP-API, схемы БД
  и формат данных не затронуты.
- Реструктуризация `docs/`: разделение на `docs/spec/` (строгие технические спецификации) и
  `docs/guide/` (гайды/туториалы); существующие `forwarder.md` и `sigma-rules-guide.md`
  перемещены в `guide/`.
- Версия приложения больше не хардкодится в `app/main.py` — читается из метаданных пакета
  (единственный источник — `pyproject.toml`).

### Added
- База знаний MITRE ATT&CK, Tier 1/2: карточка техники теперь несёт **detection strategies**
  со вложенными **analytics** (лог-сорс + канал, тюнинг-параметры / mutable elements; ATT&CK v18+)
  и **procedure examples** (какие группы/софт применяли технику + текст). `scripts/build_kb.py`
  парсит `x-mitre-detection-strategy` / `x-mitre-analytic` / `intrusion-set` / `malware` / `tool`
  и relationship'ы `detects` / `uses`; схема `kb.db` расширена таблицами `mitre_detection_strategy`,
  `mitre_analytic`, `mitre_procedure`.
- `docs/guide/mitre-attack-guide.md` — подробный гайд по MITRE ATT&CK (модель, идентификаторы,
  тактики Enterprise v19.2, STIX-формат, версии ATT&CK, как это используется во вкладке «База знаний»).
- `docs/README.md` — как устроена документация (`spec/` vs `guide/`).
- `CHANGELOG.md` (этот файл).

## [0.3.0] — 2026-09-03

### Added
- **Аутентификация потоковых источников по токену.** Реестр источников (таблица `sources`,
  вкладка «Источник данных», ручки `/sources*`): имя уникально и становится меткой `source_batch`,
  токен хранится только `sha256`, отдаётся один раз, есть перевыпуск/выключение. `/ingest/stream`
  и `/ingest/events` теперь требуют `Authorization: Bearer <token>` активного источника (иначе `401`).
- **Именованные списки значений** (value lists, `app/value_lists.py`, вкладка «Списки»,
  ручки `/value-lists*`): Sigma-плейсхолдеры `%name%` + модификатор `|expand`, разворачиваются
  в кастом-правила при компиляции; правка списка сразу пересобирает зависимые правила.
  Поддержана загрузка файлом (Sigma processing-pipeline / `{name, values}` / «голый» mapping).
- **База знаний MITRE ATT&CK** (`app/kb.py`, `scripts/build_kb.py`, ручки `/kb/mitre/*`,
  вкладка «База знаний»): компактный read-only `kb/kb.db` из STIX-бандла `mitre-attack/attack-stix-data`,
  собирается на этапе `docker build`. Матрица тактик/техник в UI; карточка алерта достраивает
  tactic/technique/ссылку по MITRE-тегам правила (гибрид: нет в KB → сырой тег).

### Changed
- Единственный манифест зависимостей — `pyproject.toml` (`[project].dependencies` — прод,
  `[project.optional-dependencies].dev` — pytest/httpx/ruff). Удалены `requirements.txt`,
  `requirements-dev.txt`, `pytest.ini`; Docker ставит `pip install .`.
- `/ingest/stream` и `/ingest/events` по умолчанию гоняют «Основной рулсет» (`app/main_ruleset.py`)
  вместо жёсткого дефолта движка.
- Оптимизация `Dockerfile`: корректное кэширование слоёв (зависимости/Zircolite/`kb.db` не
  пересобираются при правках `app/`).
- Веб-консоль: вкладки «Источник данных / Алерты / События / Sigma-правила / Списки / База знаний»,
  resizable-панели, фильтр и группировка Событий, временные интервалы, светофор `/health`.

## [0.2.0] — 2026-08-15


### Added
- **Стейтфул-корреляция Sigma-правил** (`app/correlation.py`): `event_count` / `value_count`
  поверх постоянной таблицы `events` / `rule_hits`, окно реального времени (`timespan`),
  независимо от размера micro-batch. Correlation-правила хранятся отдельным файлом `.sigmacorr`
  (обход бага компиляции в `pysigma-backend-sqlite`). Результат — обычный `Alert` с `engine="correlation"`.
- Инфраструктура именованных custom-рулсетов, «Основной рулсет» как виртуальная композиция правил.

## [0.1.0] — 2026-07

### Added
- Базовый пайплайн: ingest (EVTX/Sysmon/JSON/auditd) → Sigma-детект движком Zircolite →
  нормализация в `Alert` → SQLite (`siem.db`) → одностраничная веб-консоль.
- Потоковый ingest с форвардеров (`POST /ingest/stream` → очередь → фоновый воркер, micro-batch).
- Дедупликация алертов, хранение всех событий, кэш скомпилированных правил.
- `/health` с реальными проверками БД / Zircolite / очереди ingest.
- Конфигурация через `.env` (`app/config.py`), Docker-развёртывание (`Dockerfile`, `docker-compose.yml`),
  мини-набор тестов (`tests/`), гайд по Sigma-правилам.

[Unreleased]: https://github.com/pschdl1c/soc_agent/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pschdl1c/soc_agent/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pschdl1c/soc_agent/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pschdl1c/soc_agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pschdl1c/soc_agent/releases/tag/v0.1.0
