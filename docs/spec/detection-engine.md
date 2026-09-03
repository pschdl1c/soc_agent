# Движок детекта

**Модуль:** `app/detection/engine.py`
**Назначение:** обёртка над библиотечным API Zircolite для компиляции Sigma-правил в SQL и
прогона батчей событий.

## Область ответственности

- Компиляция рулсета через `RulesetHandler` и кэширование по пути к файлу.
- Прогон одного файла событий через in-memory SQLite Zircolite.
- Предоставление статуса для `/health`.
- Не занимается correlation-правилами (`event_count`/`value_count`/`temporal`/`temporal_ordered`) —
  они отфильтровываются перед прогоном.

## Подключение Zircolite

Zircolite импортируется не из pip, а из локального клона. При импорте модуля в `sys.path`
добавляется `ZIRCOLITE_REPO_PATH = <корень проекта>/Zircolite` (файл модуля лежит в
`app/detection/`, поэтому три уровня вверх). Затем импортируются
`zircolite.config.{ProcessingConfig, RulesetConfig}`, `zircolite.rules.RulesetHandler`,
`zircolite.core.ZircoliteCore`.

## Класс `ZircoliteEngine`

### `__init__(config_path: str, default_ruleset_path: str, time_field: str = "SystemTime")`

Сохраняет параметры, создаёт пустой кэш `_rulesets_cache: dict[str, RulesetHandler]` и
синхронно компилирует `default_ruleset_path` (прогрев). Ошибка компиляции рулсета по
умолчанию роняет старт сервиса.

### `run_batch(events_path, input_type="json", ruleset_path=None) -> tuple[list[dict], list[dict], int, float]`

Компилирует (или берёт из кэша) `ruleset_path` (или `default_ruleset_path`), прогоняет файл.
Возвращает кортеж `(raw_results, all_events, total_events, elapsed)`.

### `run_batch_with_rules(events_path, rules, input_type="json") -> tuple[list[dict], list[dict], int, float]`

Прогон по заранее собранному списку скомпилированных правил (для «основного рулсета», который
собирается на каждый батч и не кэшируется по одному пути). Компиляция не выполняется.

### `invalidate(ruleset_path: str) -> bool`

Удаляет запись `ruleset_path` из `_rulesets_cache`. Возвращает `True`, если запись была.
Вызывается после изменения/удаления кастомных правил и рулсетов.

### `health() -> dict`

`{"status": "ok"|"error", "ruleset": <default>, "rules_loaded": int, "cached_rulesets": int}`.
`status == "error"`, если в кэше нет рулсета по умолчанию или в нём 0 правил.

## Формат возвращаемого кортежа

| Элемент | Тип | Содержание |
|---|---|---|
| `raw_results` | `list[dict]` | сработавшие правила в сыром формате Zircolite; ключ `matches` содержит события с `row_id` |
| `all_events` | `list[dict]` | все события, попавшие в in-memory БД после flatten, включая не сматченные |
| `total_events` | `int` | число обработанных событий |
| `elapsed` | `float` | длительность прогона, секунды |

## Внутренний прогон (`_run_core`)

1. Из списка правил удаляются записи с истинным ключом `correlation` (defense-in-depth; в
   норме такие правила сюда не доходят).
2. Создаётся `ZircoliteCore(config_path, ProcessingConfig(db_location=":memory:", disable_progress=True, no_output=True))`.
3. `core.load_ruleset_from_var(rules, None)`.
4. `core.run_streaming([events_path], input_type=input_type)` → `total_events`.
5. `core.execute_ruleset("unused.json", keep_results=True, show_table=False, disable_progress=True)`;
   результаты — `core.full_results`.
6. `all_events` = `core.execute_select_query("SELECT * FROM logs")`.
7. `core.close()` в `finally`.

## Кэш рулсетов

`_rulesets_cache` — `{ruleset_path: RulesetHandler}`. Никогда не инвалидируется автоматически;
явный сброс — `invalidate(...)`. Компиляция `RulesetHandler` — самая дорогая операция
(секунды на тысячи правил), поэтому выполняется один раз за жизнь пути.

`input_type` — один из `json`, `evtx`, `auditd`, `sysmon_linux`, `xml`, `csv`.

## Зависимости

- Импортирует: `sys`, `time`, `pathlib`, `zircolite.*` (из локального клона).
- Импортируется: `app/main.py` (`ZircoliteEngine`), `tests/`.
