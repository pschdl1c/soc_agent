# Основной рулсет

**Модуль:** `app/rules/main_ruleset.py`
**Назначение:** хранение и разрешение состава «основного рулсета» — виртуальной композиции
правил из произвольных других рулсетов, используемой по умолчанию для `/ingest/stream` и
`/ingest/events`.

## Область ответственности

- Персистентное состояние состава в файле `data/custom_rulesets/main_ruleset.json`.
- Разрешение состава в плоский список скомпилированных правил.
- Переключение отдельных правил и рулсетов целиком.
- Очистка ссылок на удалённый рулсет.

## Константы

| Имя | Значение |
|---|---|
| `MAIN_RULESET_ID` | `"main"` |
| `STATE_PATH` | `rules_catalog.CUSTOM_ROOT / "main_ruleset.json"` |

## Формат состояния

```json
{
  "included_rulesets": ["<ruleset_path>", ...],
  "excluded_rules":  {"<ruleset_path>": ["<rule_id>", ...]},
  "included_rules":  {"<ruleset_path>": ["<rule_id>", ...]}
}
```

- `included_rulesets` — рулсеты, добавленные целиком.
- `excluded_rules` — точечные исключения внутри целиком добавленных рулсетов.
- `included_rules` — точечные добавления правил из рулсетов, не добавленных целиком.

Отсутствующий или нечитаемый файл эквивалентен `{"included_rulesets": [], "excluded_rules": {}, "included_rules": {}}`.

## Публичный интерфейс

### `load_state() -> dict`

Чтение файла состояния. При `JSONDecodeError`/`OSError` — состояние по умолчанию. Возвращаются
только известные ключи.

### `is_rule_included(state, ruleset_path, rule_id) -> bool`

- Рулсет в `included_rulesets` → `rule_id not in excluded_rules[ruleset_path]`.
- Иначе → `rule_id in included_rules[ruleset_path]`.

### `ruleset_status(state, ruleset_path) -> str`

| Значение | Условие |
|---|---|
| `"full"` | рулсет в `included_rulesets`, исключений нет |
| `"partial"` | рулсет в `included_rulesets` с исключениями, ЛИБО не добавлен, но есть `included_rules` |
| `"none"` | рулсет не участвует |

### `resolve_with_sources() -> list[tuple[str, dict]]`

Список `(ruleset_path, скомпилированное правило)`:

1. Для каждого `ruleset_path` из `included_rulesets` — все правила `rules_catalog.load_rules(ruleset_path)`,
   кроме `excluded_rules[ruleset_path]`.
2. Для каждого `(ruleset_path, rule_ids)` из `included_rules`, если рулсет не в `included_rulesets`
   и `rule_ids` непуст — правила с `id` из `rule_ids`.

Отсутствующий на диске рулсет (`CatalogError`) пропускается без ошибки.

**Дедупликация по `id` не выполняется:** у скомпилированных Zircolite-рулсетов один Sigma-`id`
легитимно даёт несколько записей с разным SQL под разные pipeline/источники.

### `resolve() -> list[dict]`

`[rule for _src, rule in resolve_with_sources()]` — плоский список для `engine.run_batch_with_rules`.

### `rule_count() -> int`

`len(resolve_with_sources())`.

### `toggle_rule(ruleset_path, rule_id, include) -> bool`

Валидирует существование через `rules_catalog.load_rules(ruleset_path)` (`CatalogError` при
отсутствии). Обновляет `excluded_rules` (если рулсет добавлен целиком) или `included_rules`.
Пустые множества удаляются из словарей. Возвращает итоговое `is_rule_included`.

### `toggle_ruleset(ruleset_path, include) -> str`

Добавляет/удаляет `ruleset_path` в `included_rulesets`; сбрасывает `excluded_rules[ruleset_path]`
и `included_rules[ruleset_path]`. Возвращает `ruleset_status`.

### `on_ruleset_deleted(ruleset_path) -> None`

Удаляет `ruleset_path` из `included_rulesets`, `excluded_rules`, `included_rules`. Файл
переписывается, только если что-то изменилось.

## Конкурентность

Все мутирующие операции выполняются под модульным `threading.Lock` (`_lock`). Запись файла —
`json.dumps(state, indent=2, ensure_ascii=False)`.

## Зависимости

- Импортирует: `json`, `threading`; `app/rules/rules_catalog.py`.
- Импортируется: `app/main.py`, `app/detection/correlation.py`.
- Зависимость однонаправленная: `main_ruleset → rules_catalog`.

## Инварианты

- `resolve()` дёшев (читает скомпилированные правила через mtime-кэш `rules_catalog`), поэтому
  вызывается на каждый батч без отдельного кэша.
- `"main"` не является валидным `ruleset_path` для `rules_catalog` — разрешение в реальные
  рулсеты происходит только в этом модуле.
