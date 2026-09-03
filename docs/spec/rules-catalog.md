# Каталог Sigma-рулсетов и правил

**Модуль:** `app/rules/rules_catalog.py`
**Назначение:** каталогизация builtin и custom рулсетов, чтение и пагинация правил, компиляция
пользовательского Sigma YAML, хранение custom-рулсетов на диске, интеграция со списками значений.

## Область ответственности

- Перечисление рулсетов (builtin `Zircolite/rules/*.json` + custom `data/custom_rulesets/<id>/`).
- Кэшированное чтение JSON-рулсетов и манифестов по mtime.
- Компиляция одного правила и целого рулсета через `RulesetHandler` (только при сохранении).
- Отдельная лёгкая валидация correlation-документов без pySigma.
- CRUD custom-правил и custom-рулсетов.
- Связь «список значений ↔ правила» (поиск использований, пересборка).

## Хранение custom-рулсета

`data/custom_rulesets/<ruleset_id>/`:

| Файл | Содержание |
|---|---|
| `meta.json` | `{id, name, created_at}` |
| `<rule_id>.yml` | сырой Sigma YAML обычного правила (source of truth) |
| `<rule_id>.sigmacorr` | сырой Sigma YAML correlation-правила (`CORRELATION_EXT`) |
| `.manifest.json` | кэш скомпилированных метаданных всех правил каталога |

`ruleset_id` — `uuid4().hex`, кроме зарезервированного `my_rules` (миграция старой раскладки).

`CUSTOM_ROOT = <BASE_DIR>/data/custom_rulesets` (в Docker — `/app/data/custom_rulesets`).

### Расширение correlation-правил

`CORRELATION_EXT = ".sigmacorr"`. `RulesetHandler` глобит только `*.yml`/`*.yaml`, поэтому
correlation-файлы не попадают в компиляцию вместе с правилом, на которое они ссылаются. Это
обходит баг `pysigma-backend-sqlite` (проверено до версии 1.2.4): правило, referenced из
`correlation.rules` в том же `SigmaCollection`, компилируется в сырую SQL-строку вместо dict
и роняет компиляцию файла.

`_CORR_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}`.

## Исключения

| Класс | Смысл | HTTP |
|---|---|---|
| `CatalogError` | рулсет/правило не найдено, невалиден путь | 400 / 404 |
| `RuleValidationError` | пользовательский YAML не прошёл валидацию/компиляцию | 400 |

## Кэш чтения

`_load_json_rules(path)` — `json.load` с кэшем `{abs_path: (mtime, list)}` под `_cache_lock`.
Список рулсета должен быть JSON-массивом, иначе `CatalogError`. `_invalidate_cache(path)`
сбрасывает запись. `_write_manifest` пишет манифест и инвалидирует его кэш.

## Резолв путей

### `_safe_resolve(ruleset_path) -> Path`

Для builtin: `(BASE_DIR / ruleset_path).resolve()`, проверка `is_relative_to(Zircolite/rules)`.
Выход за пределы → `CatalogError` (защита от path traversal).

### `_custom_ruleset_dir(ruleset_path) -> Path`

Требует префикс `custom_rulesets/`, id по `_SAFE_ID_RE = ^[A-Za-z0-9_-]{1,128}$`, существующий
`meta.json`. Иначе `CatalogError`.

### `_find_rule_file(target_dir, rule_id) -> Path | None`

Ищет `<rule_id>.yml`, затем `<rule_id>.sigmacorr`.

## Чтение правил

### `load_rules(ruleset_path) -> list[dict]`

- custom → содержимое `.manifest.json` (через кэш).
- builtin → `_load_json_rules(_safe_resolve(ruleset_path))`.

### `paginate_rules(rules, q, sort_by, sort_dir, limit, offset, only_ids=None, in_main_fn=None, level=None, status=None) -> dict`

Над готовым списком: подстрочный поиск `q` по `title`/`description`; фильтр `level`/`status`
(мультиселект, регистронезависимо); фильтр `only_ids`; сортировка (`level` — по `LEVEL_ORDER`,
`title`/`author`/`status` — по строке); срез `[offset:offset+limit]`. При `in_main_fn` — в
каждую строку добавляется `in_main: bool`.
Возврат: `{"rules": [...], "total": int, "limit": int, "offset": int}`.

`LEVEL_ORDER = {critical: 0, high: 1, medium: 2, low: 3, informational: 4}`.

### `search_rules(ruleset_path, ...)` — `paginate_rules(load_rules(ruleset_path), ...)`.

### `get_rule(ruleset_path, rule_id) -> dict | None`

Правило по `id`. Для custom-рулсета добавляет `yaml_text` — содержимое `<rule_id>.yml`
или `<rule_id>.sigmacorr` (dict копируется перед мутацией). У builtin `yaml_text` отсутствует.

### `load_correlation_rules(ruleset_path) -> list[dict]`

Только для custom. Читает `*.sigmacorr` напрямую (`yaml.safe_load_all`, без pySigma).
Строит индекс `name`/`id` → `title` по всем `*.yml`/`*.yaml` рулсета. Для каждого
correlation-документа с `title` и словарём `correlation`:

```
{
  "id": <str|None>, "title": <str>, "level": <str>, "description": <str>, "tags": <list>,
  "type": <str>, "group_by": <list>, "timespan": <str>, "condition": <dict>,
  "base_rule_titles": [<title соседнего правила>, ...]
}
```

Правило с неразрешённой ссылкой `correlation.rules` пропускается.

## Рулсеты: список / создание / удаление

| Функция | Возврат | Поведение |
|---|---|---|
| `list_rulesets()` | `list[dict]` | builtin (`deletable=False`) + custom (`deletable=True`); запись `main` не входит |
| `create_custom_ruleset(name)` | `str` (ruleset_path) | новый пустой каталог с `meta.json` |
| `delete_custom_ruleset(ruleset_path)` | `None` | `shutil.rmtree`; инвалидация кэша файлов |

Строка рулсета: `{path, category, name, rule_count, size_bytes, deletable}`.

`_resolve_target_ruleset(ruleset, new_ruleset_name)` — ровно один из двух; builtin как
existing-цель отклоняется.

## Компиляция

### `compile_custom_rule(yaml_text, *, target_dir=None, exclude_filename=None) -> dict`

Валидация + компиляция одного правила без записи на диск.

1. Пустой YAML → `RuleValidationError`.
2. Структурная пре-проверка `_looks_like_sigma_rule` (title+logsource+detection ЛИБО
   title+correlation) → иначе `RuleValidationError`.
3. Если первый документ — correlation (`_looks_like_correlation_doc`): `_validate_correlation_doc`
   + возврат `_compile_correlation_doc` (без обращения к pySigma).
4. Иначе: `value_lists.expand_placeholders(yaml_text)`; `ValueListError` → `RuleValidationError`.
5. `target_dir is None` → компиляция во временном одиночном файле; берётся `handler.rulesets[0]`.
6. `target_dir` задан → соседние `*.yml`/`*.yaml` (кроме `exclude_filename`) с раскрытыми
   плейсхолдерами копируются в scratch-каталог вместе с новым правилом; компиляция каталога;
   среди результатов выбирается запись с совпадающим `title`. Более одного кандидата →
   `RuleValidationError` (коллизия title внутри рулсета).
7. Пустой `handler.rulesets` → `RuleValidationError`.

### `compile_ruleset_yaml(yaml_text) -> list[dict]`

Компиляция всех документов multi-document YAML. Correlation-документы валидируются отдельно
(`_validate_correlation_doc` + `_compile_correlation_doc`), обычные — разворачиваются
(`expand_placeholders`) и компилируются одним файлом **без** correlation-документов. Пустой
результат обоих видов → `RuleValidationError`. Возврат — `compiled_plain + corr_results`.

## Сохранение custom-правил

### `save_custom_rule(yaml_text, ruleset=None, new_ruleset_name=None) -> tuple[dict, str]`

`_resolve_target_ruleset` → `compile_custom_rule(..., target_dir=...)`. `rule_id` — валидный
Sigma `id:` (`_SAFE_ID_RE`) или новый `uuid4().hex`. Явный `id`, занятый в любом рулсете
(`_find_rule_id_owner`) → `RuleValidationError`. Запись `<rule_id>{.yml|.sigmacorr}`; запись в
`.manifest.json` под `_manifest_lock`. Возврат `(скомпилированное правило, ruleset_path)`.

### `save_ruleset_yaml(yaml_text, ruleset=None, new_ruleset_name=None) -> tuple[dict|None, str|None, list, dict]`

Возврат `(сводка рулсета|None, ruleset_path|None, collisions, value_lists_imported)`.

- `_peel_value_list_docs` извлекает документы-определения списков (строго — `is_list_document`),
  импортирует их `mode="replace"` первыми.
- Если после извлечения правил не осталось → `(None, None, [], imported)`.
- `compile_ruleset_yaml` + сопоставление исходных YAML-документов с правилами по `title`
  (`_match_yaml_by_title`; дубль title — документ исключается).
- Правило с занятым явным `id` (в этом рулсете, в другом рулсете или дубль в файле) не
  добавляется; запись — в `collisions` (`{title, id, conflict_ruleset, conflict_title}`).
  Остальные правила сохраняются (частичный успех).

### `update_custom_rule(ruleset_path, rule_id, yaml_text) -> dict`

`id` всегда остаётся исходным (`rule_id` из URL). Явный другой `id` в новом YAML →
`RuleValidationError`. Тип правила (обычное ↔ correlation) может смениться — файл
переписывается под новым расширением, старый удаляется. Обновление `.manifest.json`.

### `delete_custom_rule(ruleset_path, rule_id) -> None`

Удаляет запись из `.manifest.json` и файл правила. Отсутствие правила → `CatalogError`.

## Списки значений ↔ правила

| Функция | Возврат | Поведение |
|---|---|---|
| `rules_using_value_list(list_name)` | `list[{ruleset, rule_id, title}]` | правила, чей `detection` ссылается на `%list_name%` через `|expand` |
| `value_list_usage_counts()` | `dict[str, int]` | `{имя списка: число правил}` одним проходом |
| `recompile_rules_for_value_list(list_name)` | `dict` | пересобирает зависимые правила, переписывает их `.manifest.json`; возврат `{recompiled, errors, affected_rulesets}` |

`engine.invalidate(...)` для `affected_rulesets` выполняет `app/main.py`.

## Компиляция и Zircolite

При импорте модуля в `sys.path` добавляется `<BASE_DIR>/Zircolite`; импортируются
`zircolite.config.RulesetConfig`, `zircolite.rules.RulesetHandler`. `RulesetHandler`
глотает ошибки конвертации отдельных правил — после конструктора отдельно проверяется
непустой `handler.rulesets`.

## Миграция

`_migrate_legacy_layout()` (вызывается при импорте): если `custom_rulesets/my_rules/` содержит
`*.yml`/`.manifest.json`, но нет `meta.json` — дописывает `meta.json` (`id="my_rules"`,
`name="Мои правила"`). Идемпотентно.

## Зависимости

- Импортирует: `json`, `re`, `shutil`, `sys`, `tempfile`, `threading`, `datetime`, `pathlib`,
  `uuid`, `yaml`; `app/rules/value_lists.py`; `zircolite.*`.
- Импортируется: `app/rules/main_ruleset.py`, `app/detection/correlation.py`, `app/main.py`.
- Не импортирует `main_ruleset` (однонаправленная зависимость).
