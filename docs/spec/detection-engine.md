# Движок детекта

**Модуль:** `app/detection/engine.py`
**Назначение:** обёртка над библиотечным API Zircolite для компиляции Sigma-правил в SQL и
прогона батчей событий.

## Область ответственности

- Компиляция рулсета через `RulesetHandler` и кэширование по пути к файлу.
- Прогон одного файла событий через in-memory SQLite Zircolite.
- Предоставление статуса для `/health`.
- Досоздание колонок полей, упомянутых правилами, но не пришедших ни в одном событии батча, и
  логирование ошибок SQL правил (`_SiemCore`, см. ниже) — без этого мёртвые правила не видны.
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

Сохраняет параметры, создаёт пустой кэш `_rulesets_cache: dict[str, RulesetHandler]`, общий
`RuleColumnIndex` (`_column_index`) и состояние троттлинга лога ошибок SQL
(`_sql_error_log_state`), затем синхронно компилирует `default_ruleset_path` (прогрев). Ошибка
компиляции рулсета по умолчанию роняет старт сервиса.

`logging_setup.configure()` обязан быть вызван ДО создания движка: Zircolite рисует прогресс
компиляции правил через `rich`, и на потоке в кодировке консоли Windows это роняет компиляцию
с пустым рулсетом (см. `docs/spec/logging.md`).

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
   норме такие правила сюда не доходят — они хранятся под `CORRELATION_EXT` и `RulesetHandler`
   их не компилирует, см. `docs/spec/rules-catalog.md`).
2. Создаётся `_SiemCore(config_path, ProcessingConfig(db_location=":memory:", disable_progress=True, no_output=True), error_log_state=...)` — подкласс `ZircoliteCore`, см. ниже.
3. `core.load_ruleset_from_var(rules, None)`.
4. `core.run_streaming([events_path], input_type=input_type)` → `total_events`.
5. `core.add_missing_rule_columns(self._column_index)` — **между загрузкой событий и прогоном
   правил**, иначе правило с полем, отсутствующим во флаше, молча не сработает (см. ниже).
6. `core.execute_ruleset("unused.json", keep_results=True, show_table=False, disable_progress=True)`;
   результаты — `core.full_results`.
7. `all_events` = `core.execute_select_query("SELECT * FROM logs")`.
8. `core.close()` в `finally`.

## `_SiemCore` — подкласс `ZircoliteCore`

Две доработки поверх стокового ядра, без правки внешнего клона Zircolite.

### Досоздание колонок полей правил (`add_missing_rule_columns`)

Zircolite строит таблицу `logs` из полей **пришедших** событий. Правило, упоминающее поле,
которого нет ни в одном событии флаша, падает с `no such column`; штатный Zircolite глушит
ошибку и возвращает тот же пустой результат, что и на «не сработало» — правило молча мёртвое.
Это бьёт и по правилам, где редкое поле стоит под `OR` или под отрицанием: флаш из одних
PowerShell 4104 гасил бы `NOT (ParentImage LIKE ...)`.

Метод берёт колонки, нужные правилам (`RuleColumnIndex.missing_columns`, сравнение имён без
учёта регистра — как у колонок SQLite), и добавляет недостающие через `ALTER TABLE logs ADD
COLUMN` с типом `TEXT COLLATE NOCASE` — тем же, что Zircolite ставит полям событий, иначе
сравнения в SQL правил вели бы себя иначе. Возвращает число добавленных колонок.

Остаётся семантика NULL: `NOT (поле LIKE ...)` на отсутствующем поле — ложь. Правило, чей
фильтр опирается на поле, которого стек не доставляет, по-прежнему не сработает — колонка
появится, но со значением NULL. Поэтому синтетика фикстур дополняет события реальным набором
полей стенда (`docs/spec/content-pipeline.md`).

### `RuleColumnIndex` — какие колонки нужны SQL правила

Набор колонок выясняется у САМОГО SQLite, а не регэкспом по тексту SQL: запрос готовится
(`EXPLAIN`) на пустой таблице `logs(row_id INTEGER PRIMARY KEY AUTOINCREMENT)`, имя из ошибки
`no such column` добавляется колонкой, подготовка повторяется — и так до успеха либо до
`_MAX_COLUMN_PROBES` (512, страховка от зацикливания). На соединение регистрируется заглушка
функции `regexp`, иначе подготовка упала бы на `no such function` раньше, чем дойдёт до колонок.

Разбор регэкспом заменять нельзя: литералы с `=`, `LIKE`-шаблоны и вызовы функций дают ложные
колонки. Две ловушки SQLite, из-за которых наивный разбор не работает: неизвестный идентификатор
в **двойных** кавычках трактуется как строковый литерал (ошибки нет вообще), а имена с пробелами
pySigma пишет в обратных кавычках.

Результат кэшируется по тексту SQL (`columns_for`, под `threading.Lock` с двойной проверкой) —
разбор делается один раз на правило за жизнь процесса: ~1.9 с единожды на 4291 правило
встроенного рулсета, далее миллисекунды. Кэш живёт в `ZircoliteEngine._column_index`, то есть
общий на все прогоны и все рулсеты.

### Логирование ошибок SQL правил

`execute_select_query` переопределён **целиком** (а не обёрнут): родительский метод возвращает
на ошибку тот же `[]`, что и на пустой результат, и пишет её на уровне debug — мёртвые правила
не видны. Переопределённый пишет `WARNING` с названием правила, текстом ошибки и первыми 500
символами запроса.

Название текущего правила известно из `execute_rule`, который сохраняет `rule["title"]` на время
вызова. Троттлинг — не чаще раза в `SQL_ERROR_LOG_INTERVAL` (600 с) **на правило**; состояние
(`{title: время последней записи}`) принадлежит `ZircoliteEngine`, а не ядру, иначе счётчик
жил бы один флаш.

## Кэш рулсетов

`_rulesets_cache` — `{ruleset_path: RulesetHandler}`. Никогда не инвалидируется автоматически;
явный сброс — `invalidate(...)`. Компиляция `RulesetHandler` — самая дорогая операция
(секунды на тысячи правил), поэтому выполняется один раз за жизнь пути.

`input_type` — один из `json`, `evtx`, `auditd`, `sysmon_linux`, `xml`, `csv`.

## Зависимости

- Импортирует: `logging`, `re`, `sqlite3`, `sys`, `threading`, `time`, `pathlib`, `zircolite.*`
  (из локального клона).
- Импортируется: `app/main.py` (`ZircoliteEngine`), `tests/`.
