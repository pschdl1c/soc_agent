# База знаний (доступ)

**Модуль:** `app/kb.py`
**Назначение:** доступ только на чтение к базе знаний MITRE ATT&CK в отдельном SQLite-файле
`kb.db`.

## Область ответственности

- Ленивое открытие read-only соединения к `kb.db`.
- Запросы матрицы тактик/техник, карточки техники, метаданных.
- Гибридное обогащение MITRE-тегов алерта.
- Тихая деградация при отсутствии файла.

Модуль не создаёт и не пишет `kb.db`. Файл собирается `scripts/build_kb.py` (см.
`kb-builder.md`), путь — `config.KB_DB_PATH` (по умолчанию `<BASE_DIR>/kb/kb.db`).

## Соединение

`_ensure_conn_locked()` (под `_lock`): `sqlite3.connect(f"file:{_kb_path}?mode=ro", uri=True, check_same_thread=False)`,
`row_factory=sqlite3.Row`, проверочный `SELECT 1 FROM mitre_meta LIMIT 1`. Любая
`sqlite3.Error` → соединение `None`, флаг `_open_attempted=True` (повторные попытки открытия
не выполняются до сброса).

`configure(path: str | None)` — подмена пути и переоткрытие (тестовый хук; `None` → значение
из `config`). `_reset()` — сброс кэша соединения без смены пути.

## Исключение

`KbError(Exception)` — объявлено для трансляции в HTTP; штатные пути его не поднимают
(при отсутствии `kb.db` возвращается пустой результат / `available: false`).

## Публичный интерфейс

### `available() -> bool`

`True`, если соединение открыто успешно.

### `meta() -> dict`

Строки `mitre_meta` как плоский словарь `{key: value}` + `"available": True`. При отсутствии
файла — `{"available": False}`.

Ожидаемые ключи `mitre_meta`: `attack_version`, `built_at`, `source`, `tactic_count`,
`technique_count`, `mitigation_count`, `detection_strategy_count`, `analytic_count`,
`procedure_count`.

### `list_tactics() -> list[dict]`

`[{tactic_id, shortname, name, description, url, sort_order}]`, `ORDER BY sort_order, tactic_id`.
Нет файла → `[]`.

### `matrix() -> dict`

```
{
  "available": bool,
  "tactics": [
    { ...tactic, "techniques": [{technique_id, name, is_subtechnique, parent_id}, ...] }
  ]
}
```

Тактики — в порядке kill-chain (`sort_order`). Техники внутри тактики упорядочены по
`technique_id` (сабтехники следуют за базовой лексикографически). Нет файла →
`{"available": False, "tactics": []}`.

### `list_techniques(tactic=None, q=None, limit=100, offset=0) -> dict`

```
{"available": bool, "total": int, "techniques": [{technique_id, name, is_subtechnique, parent_id, url}, ...]}
```

- `tactic` — фильтр по `shortname` (JOIN `mitre_technique_tactic`).
- `q` — подстрока по `technique_id` ИЛИ `name` (`LIKE`, bound-параметр).
- Сортировка по `technique_id`, срез `LIMIT/OFFSET`.
- Нет файла → `{"available": False, "techniques": [], "total": 0}`.

### `get_technique(technique_id: str) -> dict | None`

Полная карточка техники или `None` (нет файла / нет техники). Поля:

| Поле | Тип | Источник |
|---|---|---|
| `technique_id`, `name`, `parent_id`, `url`, `description` | — | `mitre_technique` |
| `is_subtechnique` | `bool` | — |
| `detection` | `str` | `mitre_technique.detection` (пусто на ATT&CK ≥ v18) |
| `platforms` | `list[str]` | JSON `mitre_technique.platforms` |
| `data_sources` | `list[str]` | JSON `mitre_technique.data_sources` (пусто на ≥ v18) |
| `tactics` | `list[{tactic_id, shortname, name}]` | JOIN `mitre_technique_tactic` / `mitre_tactic`, `ORDER BY sort_order` |
| `mitigations` | `list[{mitigation_id, name, url}]` | JOIN `mitre_technique_mitigation` / `mitre_mitigation` |
| `subtechniques` | `list[{technique_id, name, url}]` | `mitre_technique WHERE parent_id = ?` |
| `detection_strategies` | `list[{strategy_id, name, analytics: [...]}]` | `mitre_detection_strategy` + вложенные `mitre_analytic` |
| `procedures` | `list[{source_id, source_name, source_type, description}]` | `mitre_procedure`, `ORDER BY source_type, source_id` |

Элемент `analytics`: `{analytic_id, name, description, platforms (list), log_sources (list[{name, channel}]), mutable_elements (list[{field, description}])}` —
JSON-поля декодируются.

### `enrich_techniques(tags: list[str] | None) -> list[dict]`

Гибридный матчинг MITRE-тегов правила. Нормализация: `attack.t1059.001` → `T1059.001`
(`_normalize_tags`: срез `attack.`, `.split(".", 1)[1].upper()`); не-`attack.t*` игнорируется.

На каждый нормализованный тег:

- Найдено в `mitre_technique` →
  `{tag, technique_id, name, url, is_subtechnique, parent_id, tactics: [{tactic_id, shortname, name}], matched: True}`.
- Не найдено или `kb.db` недоступна → `{tag, technique_id, matched: False}`.

Число SQL-запросов не зависит от числа тегов (один `WHERE technique_id IN (...)` + один JOIN
по тактикам). Пустой вход → `[]`.

## Конкурентность

Все запросы — под модульным `threading.Lock` (`_lock`). Соединение переиспользуется между
запросами (`check_same_thread=False`).

## Зависимости

- Импортирует: `json`, `sqlite3`, `threading`; `app/config.py` (`KB_DB_PATH`).
- Импортируется: `app/main.py` (эндпоинты `/kb/mitre/*`, обогащение `GET /alerts/{id}`), `tests/`.

## Связанная схема

Таблицы `kb.db` (`mitre_meta`, `mitre_tactic`, `mitre_technique`, `mitre_technique_tactic`,
`mitre_mitigation`, `mitre_technique_mitigation`, `mitre_detection_strategy`, `mitre_analytic`,
`mitre_procedure`) описаны в [`kb-builder.md`](kb-builder.md).
