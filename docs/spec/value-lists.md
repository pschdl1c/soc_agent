# Именованные списки значений

**Модуль:** `app/rules/value_lists.py`
**Назначение:** реализация Sigma-плейсхолдера `%name%` с модификатором `|expand` — хранение
именованных списков и их разворот в правило перед компиляцией.

## Область ответственности

- Файловое хранилище списков (`data/value_lists/<name>.yml`).
- CRUD списков.
- Разворот `%name%` под ключами с `|expand` в `detection` перед компиляцией.
- Определение плейсхолдеров, используемых правилом.
- Разбор файлов импорта (Sigma pipeline / нативный формат / «голый» mapping).

Модуль не импортирует `rules_catalog` (запрет цикла). Fan-out на пересборку зависимых правил
делает `app/rules/rules_catalog.py`, оркеструет `app/main.py`.

## Формат файла списка

`data/value_lists/<name>.yml`:

```yaml
name: <name>
description: <str>
created_at: <ISO>
updated_at: <ISO>
values:
  - <str>
  - ...
```

`name` = имя плейсхолдера = имя файла. Регэксп имени `_NAME_RE = ^[A-Za-z0-9_]{1,64}$`.
Ограничения: `_MAX_VALUES = 20000`, `_MAX_DESCRIPTION = 2000`.

## Исключение

`ValueListError(Exception)` — не найден / пуст / недопустимое имя / уже существует.
`app/main.py` транслирует в HTTP 400 / 404 / 409; `rules_catalog` — в `RuleValidationError`.

## CRUD

| Функция | Возврат | Поведение |
|---|---|---|
| `list_lists()` | `list[dict]` | `{name, description, value_count, updated_at}` по всем `*.yml`; повреждённый файл пропускается |
| `get_list(name)` | `dict \| None` | `{name, description, created_at, updated_at, values}` |
| `create_list(name, description, values)` | `dict` | валидирует имя; `ValueListError`, если файл уже есть |
| `update_list(name, description, values)` | `dict \| None` | `None`, если списка нет; `name` неизменяем; `created_at` сохраняется |
| `delete_list(name)` | `bool` | `False`, если файла не было; проверку использования делает вызывающая сторона |

`_normalize_values` — trim, отброс пустых, дедуп с сохранением порядка; `> _MAX_VALUES` →
`ValueListError`.

## Разворот плейсхолдеров

### `expand_placeholders(yaml_text: str) -> str`

Разворачивает `%name%` под ключами с сегментом `expand` в `|`-цепочке модификаторов, внутри
всех `detection`-мап всех YAML-документов.

- Быстрый путь: если подстроки `"expand"` в тексте нет — исходный текст возвращается без
  изменений (форматирование и комментарии сохраняются).
- Невалидный YAML — исходный текст возвращается как есть (ошибку поднимет компилятор).
- Для ключа с `|expand`: значения-строки вида `%name%` заменяются на значения списка
  (`_resolve_placeholder_values`), прочие значения сохраняются; результат дедуплицируется;
  сегмент `expand` удаляется из ключа; при совпадении нового ключа с существующим значения
  объединяются.
- Результат пересериализуется (`yaml.safe_dump_all`, `width=4096`). На диск не пишется —
  только для компилятора.
- Неизвестный или пустой список → `ValueListError`.

Поддержана только запись-значение, **целиком** равная `%name%` (встроенные `foo%name%bar` не
разворачиваются).

### `placeholders_used(yaml_text: str) -> set[str]`

Имена плейсхолдеров, на которые ссылается `detection` через ключи с `|expand`. При невалидном
YAML — fallback на regex `%([A-Za-z0-9_]+)%` по всему тексту.

## Импорт файлом

### `parse_list_file(text: str) -> list[ParsedList]`

`ParsedList = NamedTuple(name: str, description: str, values: list[str])`.

Распознаёт три формата (multi-document):

1. **Sigma processing-pipeline** — документ с `transformations`, где `type` ∈
   `{value_placeholders, query_expansion_placeholders}` и `mapping: {имя: [значения]}`.
2. **Нативный** — `{name: str, description?: str, values: list}` без ключей-маркеров правила
   (`logsource`, `detection`, `correlation`, `title`).
3. **«Голый» mapping** — `{имя: [значения], ...}` без ключей-маркеров и `transformations`,
   все значения — `list`/`str`/`int`/`float`.

Имена валидируются `_NAME_RE`, значения — `_normalize_values`. Дубль имени в файле —
объединение значений. Нераспознанный документ → `ValueListError`.

### `is_list_document(doc: dict) -> bool`

Строгая проверка (только Sigma pipeline с `value_placeholders` ИЛИ нативный `{name, values}`).
«Голый» mapping не распознаётся. Используется `rules_catalog._peel_value_list_docs`.

### `import_lists(parsed: list[ParsedList], mode: str) -> dict[str, list[str]]`

`mode` ∈ `{create, replace, merge}` (иначе `ValueListError`).

Возврат: `{"created": [...], "replaced": [...], "merged": [...], "skipped": [...], "recompile_needed": [...]}`.

| `mode` | Существующий список |
|---|---|
| `create` | не трогается → `skipped` |
| `replace` | перезапись целиком → `replaced` + `recompile_needed` |
| `merge` | объединение значений → `merged` + `recompile_needed` |

Несуществующий список создаётся всегда → `created`.

## Зависимости

- Импортирует: `re`, `threading`, `datetime`, `pathlib`, `yaml`.
- Импортируется: `app/rules/rules_catalog.py`, `app/main.py` (`ValueListError` и функции CRUD/импорта).
