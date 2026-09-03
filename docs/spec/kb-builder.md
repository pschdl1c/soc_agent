# Сборщик базы знаний

**Скрипт:** `scripts/build_kb.py`
**Назначение:** сборка компактного read-only SQLite-файла `kb.db` из STIX-бандла
MITRE ATT&CK Enterprise. Часть процесса `docker build` (builder-стадия) и локальной разработки.

## Область ответственности

- Загрузка STIX-бандла (сеть или локальный файл).
- Разбор нужных типов объектов и relationship'ов в плоское представление.
- Запись `kb.db` по фиксированной схеме с атомарной подменой файла.
- Проверка целостности перед записью.

Зависимости — только стандартная библиотека + `requests`. Модуль не импортирует `app.*`.
`requests` импортируется внутри `fetch_bundle`, чтобы модуль оставался импортируемым в тестах
без установленного `requests`.

## CLI

```
python scripts/build_kb.py [--out PATH] [--attack-version VER] [--ref REF] [--source URL] [--from-file PATH]
```

| Флаг | По умолчанию | Смысл |
|---|---|---|
| `--out` | `kb/kb.db` | путь результирующего файла |
| `--attack-version` | — | версия ATT&CK (напр. `15.1`); без флага — `enterprise-attack.json` (latest) |
| `--ref` | `master` | git ref репозитория `attack-stix-data` |
| `--source` | — | полный URL бандла (перекрывает `--ref`/`--attack-version`) |
| `--from-file` | — | локальный STIX JSON, без сети |

URL по умолчанию:
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ref}/enterprise-attack/{filename}`.

`main(argv=None) -> int` — точка входа; `0` при успехе.

## Разбор (`parse_bundle(objects: list[dict]) -> ParsedKb`)

Отбрасываются объекты с `revoked` или `x_mitre_deprecated` (`_is_dead`). Отбрасывается всё вне
Enterprise-таксономии (id не матчит регэксп типа).

| Регэксп | Тип id |
|---|---|
| `_TECHNIQUE_ID_RE` | `^T\d{4}(?:\.\d{3})?$` |
| `_TACTIC_ID_RE` | `^TA\d{4}$` |
| `_MITIGATION_ID_RE` | `^M\d{4}$` |
| `_GROUP_ID_RE` | `^G\d{4}$` |
| `_SOFTWARE_ID_RE` | `^S\d{4}$` |

### Первый проход (по типам объектов)

| STIX type | Действие |
|---|---|
| `x-mitre-collection` | `x_mitre_version` → `attack_version` |
| `x-mitre-matrix` | `tactic_refs` → порядок колонок |
| `x-mitre-tactic` | `tactic_id`, `shortname` (`x_mitre_shortname`), `name`, `description`, `url` |
| `attack-pattern` | техника: `technique_id`, `name`, `is_subtechnique`, `parent_id` (по `.`), `description`, `detection` (`x_mitre_detection`), `platforms` (`x_mitre_platforms`), `data_sources` (`x_mitre_data_sources`), `url`; `kill_chain_phases[].phase_name` (для `kill_chain_name == "mitre-attack"`) → связи техника↔тактика |
| `course-of-action` (id `M####`) | митигация: `mitigation_id`, `name`, `description`, `url` |
| `intrusion-set` (id `G####`) | источник procedure: `{id, name, type: "group"}` |
| `malware` / `tool` (id `S####`) | источник procedure: `{id, name, type: "malware"|"tool"}` |
| `x-mitre-detection-strategy` | сырой объект по STIX-id |
| `x-mitre-analytic` | `analytic_id` (external_id или STIX-id), `name`, `description`, `platforms`, `log_sources` (`x_mitre_log_source_references` → `{name, channel}`), `mutable_elements` (`x_mitre_mutable_elements` → `{field, description}`) |

`_mitre_ref(obj)` — `(external_id, url)` из первой `external_references` с `source_name == "mitre-attack"`.

### Второй проход (relationship'ы)

| `relationship_type` | Действие |
|---|---|
| `mitigates` (`course-of-action` → `attack-pattern`) | связь техника↔митигация |
| `detects` (стратегия → `attack-pattern`) | привязка стратегии к технике |
| `uses` (group/malware/tool → `attack-pattern`) | procedure example: `{technique_id, source_id, source_name, source_type, description}` |

После этого: для каждой привязанной стратегии формируется запись `mitre_detection_strategy`
(`strategy_id` = external_id или STIX-id) и её аналитики (`x_mitre_analytic_refs`) с полем
`strategy_id`.

### Постобработка

- `sort_order` тактик — индекс `shortname` в `x-mitre-matrix.tactic_refs` (иначе `999`);
  тактики сортируются по `(sort_order, tactic_id)`.
- Связи техника↔тактика и техника↔митигация дедуплицируются и сортируются.
- `meta` заполняется: `attack_version` (или `unknown`), `built_at` (ISO, сек),
  `*_count` по числу собранных записей.

`main()` дополнительно кладёт в `meta`: `attack_version` из `--attack-version` (если задан) и
`source` (URL или путь файла).

## `ParsedKb` (dataclass)

| Поле | Тип |
|---|---|
| `meta` | `dict[str, str]` |
| `tactics` | `list[dict]` |
| `techniques` | `list[dict]` |
| `technique_tactic` | `list[tuple[str, str]]` |
| `mitigations` | `list[dict]` |
| `technique_mitigation` | `list[tuple[str, str]]` |
| `detection_strategies` | `list[dict]` (`strategy_id, name, technique_id`) |
| `analytics` | `list[dict]` (`analytic_id, strategy_id, name, description, platforms, log_sources, mutable_elements`) |
| `procedures` | `list[dict]` (`technique_id, source_id, source_name, source_type, description`) |

## Схема `kb.db`

```sql
CREATE TABLE mitre_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE mitre_tactic (
    tactic_id   TEXT PRIMARY KEY,
    shortname   TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    sort_order  INTEGER NOT NULL
);

CREATE TABLE mitre_technique (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    description     TEXT NOT NULL DEFAULT '',
    detection       TEXT NOT NULL DEFAULT '',
    platforms       TEXT NOT NULL DEFAULT '[]',   -- JSON []
    data_sources    TEXT NOT NULL DEFAULT '[]',   -- JSON []
    url             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_mitre_tech_parent ON mitre_technique(parent_id);

CREATE TABLE mitre_technique_tactic (
    technique_id     TEXT NOT NULL,
    tactic_shortname TEXT NOT NULL,
    PRIMARY KEY (technique_id, tactic_shortname)
);
CREATE INDEX idx_mitre_tt_tactic ON mitre_technique_tactic(tactic_shortname);

CREATE TABLE mitre_mitigation (
    mitigation_id TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE mitre_technique_mitigation (
    technique_id  TEXT NOT NULL,
    mitigation_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, mitigation_id)
);

CREATE TABLE mitre_detection_strategy (
    strategy_id  TEXT PRIMARY KEY,     -- DET#### или STIX-id
    name         TEXT NOT NULL,
    technique_id TEXT NOT NULL
);
CREATE INDEX idx_mitre_ds_tech ON mitre_detection_strategy(technique_id);

CREATE TABLE mitre_analytic (
    analytic_id      TEXT PRIMARY KEY, -- AN####
    strategy_id      TEXT NOT NULL,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    platforms        TEXT NOT NULL DEFAULT '[]',   -- JSON []
    log_sources      TEXT NOT NULL DEFAULT '[]',   -- JSON [{"name","channel"}]
    mutable_elements TEXT NOT NULL DEFAULT '[]'    -- JSON [{"field","description"}]
);
CREATE INDEX idx_mitre_analytic_strategy ON mitre_analytic(strategy_id);

CREATE TABLE mitre_procedure (
    technique_id TEXT NOT NULL,
    source_id    TEXT NOT NULL,       -- G#### / S####
    source_name  TEXT NOT NULL,
    source_type  TEXT NOT NULL,       -- 'group' | 'malware' | 'tool'
    description  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (technique_id, source_id)
);
CREATE INDEX idx_mitre_proc_tech ON mitre_procedure(technique_id);
```

### Замечание о версиях ATT&CK

В ATT&CK v18 из бандла удалены `x_mitre_detection`, плоский `x_mitre_data_sources`,
`x_mitre_permissions_required`. На версиях ≥ v18 колонки `detection` и `data_sources` пусты;
детект представлен структурно через `mitre_detection_strategy` + `mitre_analytic`. Объекты
`x-mitre-detection-strategy` / `x-mitre-analytic` существуют только на версиях ≥ v18.

## Запись (`write_kb_db(path: str, kb: ParsedKb) -> None`)

Создаёт `<path>.tmp`, исполняет схему, вставляет все таблицы через `executemany`
(связи — `INSERT OR IGNORE`), `commit`, `VACUUM`, затем `os.replace(tmp, path)` (атомарная
подмена). Родительский каталог создаётся при необходимости.

## Проверка целостности (`_sanity_check`)

Вызывается перед записью. `SystemExit` (ненулевой код), если:

- число тактик вне `[12, 16]`;
- число техник `< 500`;
- нет ни одной связи техника↔тактика.

Битая выгрузка роняет `docker build`, а не попадает в образ.

## Зависимости

- Импортирует: `argparse`, `json`, `os`, `re`, `sqlite3`, `sys`, `dataclasses`, `datetime`;
  `requests` (внутри `fetch_bundle`).
- Импортируется: `tests/test_kb.py` (`parse_bundle`, `write_kb_db`).
- Runtime-чтение результата: `app/kb.py` (см. [`knowledge-base.md`](knowledge-base.md)).
