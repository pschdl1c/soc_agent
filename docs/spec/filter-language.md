# Мини-язык фильтра событий

**Модуль:** `app/filter_lang.py`
**Назначение:** разбор пользовательской строки фильтра вкладки «События» в AST и компиляция
AST в параметризованный SQL WHERE-фрагмент по `raw_json`.

## Область ответственности

- Токенизация и рекурсивный спуск (парсер) строки фильтра.
- Компиляция AST и отдельных условий в `(sql, params)`.
- Резолв пути JSON-поля с учётом whitelist индексируемых полей.
- Специальная семантика псевдополей результата детекта `rule` и `is_matched`.

## Грамматика (EBNF)

Ключевые слова регистронезависимы.

```
or_expr    = and_expr { OR and_expr }
and_expr   = not_expr { AND not_expr }
not_expr   = [ NOT ] primary
primary    = '(' or_expr ')' | condition
condition  = field ( is_clause | in_clause | cmp_clause )
is_clause  = IS [ NOT ] NULL
in_clause  = IN '(' value { ',' value } ')'
cmp_clause = ( '=' | '!=' | '<>' | '>=' | '<=' | '>' | '<' | CONTAINS ) value
field      = WORD
value      = STRING | WORD
```

- `STRING` — литерал в `"..."` или `'...'`, экранирование `\"`, `\'`, `\\`.
- `WORD` — последовательность символов вне `\s()=<>!,"'`; для значений с пробелами/операторами
  требуются кавычки.
- Приоритет: `NOT` > `AND` > `OR`. Произвольная вложенность через скобки.

## Публичный интерфейс

### `compile_filter_query(text: str) -> tuple[str, list[Any]]`

Разбирает и компилирует строку. Пустая/пробельная строка → `("", [])`. Любая синтаксическая
ошибка → `FilterSyntaxError` с человекочитаемым текстом и позицией.

### `compile_condition(field: str, op: str, value: Any) -> tuple[str, list[Any]]`

Компилирует одно условие. `op` ∈ `FILTER_OPS`. Используется и парсером, и `app/store.py` для
drill-in по группе. Правила приведения типов:

- `eq`/`neq`/`contains`/`in` — обе стороны приводятся к TEXT (`CAST(... AS TEXT)`), сравнение
  по отображаемому значению независимо от JSON-типа.
- `gt`/`lt`/`gte`/`lte` — если значение похоже на число, `CAST(... AS REAL)`, иначе TEXT.
- `neq` для обычного поля: `(<col> IS NULL OR <col> <> ?)` — событие без поля проходит `!=`.

### `resolve_json_path(field: str) -> tuple[str, list[Any]]`

- Поле из `INDEXED_JSON_FIELDS` (ключ в нижнем регистре) → `("json_extract(raw_json, '<литерал>')", [])`.
- Иначе → `("json_extract(raw_json, ?)", ['$."<field без кавычек>"'])`.

Литеральный путь для индексируемых полей нужен, чтобы SQLite применил индекс на выражении
(`app/store.py:idx_events_json_eventid`) — bound-параметр для этого не подходит.

## Константы

| Константа | Значение |
|---|---|
| `FILTER_OPS` | `{eq, neq, contains, in, gt, lt, gte, lte, isnull, notnull}` |
| `INDEXED_JSON_FIELDS` | `{"eventid": '$."EventID"'}` |
| `RULE_FIELD` | `"rule"` |
| `IS_MATCHED_FIELD` | `"is_matched"` |

## Псевдополе `is_matched`

Не часть `raw_json` — колонка `events.is_matched`.

- Операторы: только `=` и `!=`.
- Значение: `true`/`1`/`yes`/`да` → `1`; `false`/`0`/`no`/`нет` → `0`; иначе `FilterSyntaxError`.

## Псевдополе `rule`

Не часть `raw_json` — колонка `events.matched_rules` (JSON-массив названий правил).

| Оператор | Семантика | SQL |
|---|---|---|
| `= X` | среди сработавших есть правило `X` | `EXISTS (SELECT 1 FROM json_each(matched_rules) WHERE value = ?)` |
| `!= X` | правила `X` среди сработавших нет | `NOT EXISTS (...)` |
| `contains X` | подстрока в названии | `EXISTS (... WHERE value LIKE ? ESCAPE '\')` |
| `in (A, B)` | одно из перечисленных | `EXISTS (... WHERE value IN (...))`; пустой список → `0` |
| `is null` | ничего не сработало | `is_matched = 0` |
| `is not null` | сработало хоть что-то | `is_matched = 1` |
| `> N` / `< N` / `>= N` / `<= N` | сравнение **количества** сработавших правил | `json_array_length(matched_rules) <op> ?` |

`>`/`<`/`>=`/`<=` требуют числового значения, иначе `FilterSyntaxError`.

## Исключения

`FilterSyntaxError(ValueError)` — единственное исключение, выходящее за границу модуля. Текст
сообщения предназначен для показа пользователю; `app/main.py` оборачивает его в HTTP 400.

## Безопасность

- AST — кортежи (`("and", …)`, `("cond", field, op, value)`), не исполняемый код; `eval` не
  используется.
- Значение условия всегда bound-параметр.
- Путь поля — bound-параметр, кроме `INDEXED_JSON_FIELDS`, где путь — литерал из фиксированного
  словаря по ключу, не производная от сырого текста.

## Зависимости

- Импортирует: `re`, `typing`.
- Импортируется: `app/store.py`, `app/main.py` (`FilterSyntaxError`, `compile_filter_query`),
  `app/detection/correlation.py` (косвенно — `resolve_json_path` через `app/store.py`).
