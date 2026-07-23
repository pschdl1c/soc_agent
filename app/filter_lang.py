"""
Мини-язык фильтров для Событий (в духе строки поиска MaxPatrol): пользователь пишет строку вида

    hostname contains "local" and eventid = 4688

которая разбирается в AST и компилируется в parametrized SQL WHERE-фрагмент по raw_json
событий (см. store.py). Поддерживает произвольную вложенность and/or/not через скобки -
в отличие от старого конструктора с одним общим AND/OR на весь список условий, здесь можно
явно выразить смешанную логику: (a or b) and c.

Грамматика (EBNF, ключевые слова регистронезависимы):
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

Значение можно писать в кавычках ("..." или '...', с \\-экранированием) или голым словом без
пробелов (числа, простые идентификаторы, хосты вида a.b.local) - голое слово не может содержать
пробелы/скобки/кавычки/операторы, для этого нужны кавычки.

Безопасность: результат разбора - это AST из простых кортежей (никогда не исполняемый код,
никакого eval). compile_filter_query() транслирует AST в SQL, где значение условия ВСЕГДА
идёт как bound-параметр sqlite3. JSON-путь поля тоже bound-параметр (через
json_extract(raw_json, ?)) для подавляющего большинства полей - ЗА ИСКЛЮЧЕНИЕМ узкого whitelist
"горячих" полей из INDEXED_JSON_FIELDS (сейчас только EventID), где путь - литерал в тексте SQL
(нужно для expression-индекса, см. resolve_json_path). Это не ослабляет безопасность: литерал
всегда один из фиксированных значений словаря по ключу, никогда не производная от сырого
пользовательского текста - тот же паттерн, что и у whitelisted sort-колонок в store.py.
Пользовательский текст сам по себе никогда не подставляется в SQL-строку - инъекция
синтаксически невозможна.
"""
from __future__ import annotations

import re
from typing import Any, NamedTuple

# Публичный список поддерживаемых операторов - используется и здесь, и в store.py для
# валидации group_cond (drill-in по группе), который тем же способом компилируется в SQL.
FILTER_OPS = {"eq", "neq", "contains", "in", "gt", "lt", "gte", "lte", "isnull", "notnull"}

_CMP_OPS = {"=": "eq", "!=": "neq", "<>": "neq", ">": "gt", "<": "lt", ">=": "gte", "<=": "lte"}


class FilterSyntaxError(ValueError):
    """Ошибка разбора строки фильтра - текст сообщения уже готов для показа пользователю."""


class Token(NamedTuple):
    type: str  # LPAREN, RPAREN, COMMA, OP, STRING, WORD, EOF
    value: str
    pos: int  # 1-based позиция в исходной строке - для сообщений об ошибках


_TOKEN_RE = re.compile(r"""
    (?P<SKIP>\s+)
  | (?P<OP>!=|<>|>=|<=|=|>|<)
  | (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<COMMA>,)
  | (?P<STRING>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<WORD>[^\s()=<>!,"']+)
""", re.VERBOSE)


def _unescape(raw: str) -> str:
    """Снимает кавычки строкового литерала и разворачивает \\" \\' \\\\."""
    quote = raw[0]
    body = raw[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body) and body[i + 1] in (quote, "\\"):
            out.append(body[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    length = len(text)
    while pos < length:
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise FilterSyntaxError(f"неожиданный символ '{text[pos]}' в позиции {pos + 1}")
        kind = m.lastgroup
        raw = m.group()
        if kind != "SKIP":
            value = _unescape(raw) if kind == "STRING" else raw
            tokens.append(Token(kind, value, pos + 1))
        pos = m.end()
    tokens.append(Token("EOF", "", length + 1))
    return tokens


class _Parser:
    def __init__(self, tokens: list[Token]):
        self._tokens = tokens
        self._i = 0

    def _cur(self) -> Token:
        return self._tokens[self._i]

    def _advance(self) -> Token:
        tok = self._tokens[self._i]
        if tok.type != "EOF":
            self._i += 1
        return tok

    def _match_word(self, *words: str) -> bool:
        tok = self._cur()
        if tok.type == "WORD" and tok.value.lower() in words:
            self._advance()
            return True
        return False

    def _expect_word(self, word: str) -> None:
        if not self._match_word(word):
            tok = self._cur()
            raise FilterSyntaxError(
                f"ожидалось '{word}' в позиции {tok.pos}, получено '{tok.value or 'конец строки'}'"
            )

    def parse(self):
        node = self._parse_or()
        tok = self._cur()
        if tok.type != "EOF":
            raise FilterSyntaxError(f"неожиданный текст '{tok.value}' в позиции {tok.pos}")
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._match_word("or"):
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._match_word("and"):
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self):
        if self._match_word("not"):
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self):
        tok = self._cur()
        if tok.type == "LPAREN":
            self._advance()
            node = self._parse_or()
            if self._cur().type != "RPAREN":
                raise FilterSyntaxError(f"не хватает закрывающей ')' (открыта в позиции {tok.pos})")
            self._advance()
            return node
        return self._parse_condition()

    def _parse_condition(self):
        tok = self._cur()
        if tok.type != "WORD" or tok.value.lower() in ("and", "or", "not"):
            raise FilterSyntaxError(
                f"ожидалось имя поля в позиции {tok.pos}, получено '{tok.value or 'конец строки'}'"
            )
        field = self._advance().value

        if self._match_word("is"):
            negate = self._match_word("not")
            self._expect_word("null")
            return ("cond", field, "notnull" if negate else "isnull", None)

        if self._match_word("in"):
            open_tok = self._cur()
            if open_tok.type != "LPAREN":
                raise FilterSyntaxError(f"после 'in' ожидается '(' в позиции {open_tok.pos}")
            self._advance()
            values = [self._parse_value()]
            while self._cur().type == "COMMA":
                self._advance()
                values.append(self._parse_value())
            if self._cur().type != "RPAREN":
                raise FilterSyntaxError(f"не хватает закрывающей ')' у 'in(...)' (открыта в позиции {open_tok.pos})")
            self._advance()
            return ("cond", field, "in", values)

        if self._match_word("contains"):
            return ("cond", field, "contains", self._parse_value())

        if self._cur().type == "OP":
            op = _CMP_OPS[self._advance().value]
            return ("cond", field, op, self._parse_value())

        bad = self._cur()
        raise FilterSyntaxError(
            f"ожидался оператор (=, !=, >, <, >=, <=, contains, in, is null) после поля '{field}' "
            f"в позиции {bad.pos}, получено '{bad.value or 'конец строки'}'"
        )

    def _parse_value(self):
        tok = self._cur()
        if tok.type in ("STRING", "WORD"):
            self._advance()
            return tok.value
        raise FilterSyntaxError(f"ожидалось значение в позиции {tok.pos}, получено '{tok.value or 'конец строки'}'")


def _json_path(field: str) -> str:
    """Безопасный JSON-путь верхнего уровня для json_extract; всегда идёт как bound-параметр."""
    return f'$."{str(field).replace(chr(34), "")}"'


# Горячие поля raw_json, под которые в store.py заведён индекс НА ВЫРАЖЕНИИ
# (idx_events_json_hot, CREATE INDEX ... ON events(json_extract(raw_json, '$."EventID"'))).
# SQLite подхватывает expression-индекс, только если выражение в запросе ТЕКСТУАЛЬНО совпадает
# с выражением индекса - подставить путь через bound-параметр (?), как для обычных полей, для
# этого не годится: с точки зрения планировщика json_extract(raw_json, ?) и
# json_extract(raw_json, '$."EventID"') - разные выражения, даже если параметр в рантайме
# получит то же значение. Поэтому для полей из этого словаря путь идёт литералом ПРЯМО В ТЕКСТЕ
# SQL - это по-прежнему безопасно (CLAUDE.md требует не подставлять пользовательский текст в
# SQL напрямую): литерал всегда один из фиксированных значений словаря, выбранный по ключу,
# никогда не производная от сырого текста поля/значения из фильтра (тот же паттерн, что и
# _ALERT_SORT_COLUMNS/_EVENT_SORT_COLUMNS в store.py - whitelist ключ -> безопасное SQL-выражение).
# Список короткий и добавляется вручную: Hostname/event_time уже вынесены в отдельные
# проиндексированные колонки events.host/events.event_time при записи (см. store.py), это не
# нужно дублировать здесь - EventID остаётся единственным по-настоящему универсальным "горячим"
# полем для Windows-ориентированных источников проекта (Security/Sysmon/System channels).
INDEXED_JSON_FIELDS: dict[str, str] = {
    "eventid": '$."EventID"',
}


def resolve_json_path(field: str) -> tuple[str, list[Any]]:
    """Возвращает (SQL-выражение json_extract(...), доп.bound-параметры для него) - для полей
    из INDEXED_JSON_FIELDS путь литерал в тексте (чтобы сработал expression index), для всех
    остальных - как раньше, обычный bound-параметр (медленнее, но без индекса и не нужно)."""
    key = str(field).strip().lower()
    if key in INDEXED_JSON_FIELDS:
        return f"json_extract(raw_json, '{INDEXED_JSON_FIELDS[key]}')", []
    return "json_extract(raw_json, ?)", [_json_path(field)]


def _like_escape(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _as_number(value: Any) -> float | None:
    """Пытается привести значение к числу (для корректного >/</>=/<= по числовым полям)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# "Правила" (какие Sigma-правила сработали на событии) - это НЕ поле исходного события,
# а результат работы движка: отдельные колонки events.is_matched (0/1) и events.matched_rules
# (JSON-массив названий правил), не часть raw_json. Обычный json_extract(raw_json, ...) их не
# видит, поэтому у этих двух имён - свои правила компиляции (см. compile_condition ниже) и
# свой SQL для группировки (store.py/group_events, т.к. matched_rules - массив: у события может
# быть 0 или несколько сработавших правил, группировка "разворачивает" каждое в отдельный счётчик
# через json_each, как обычно делают для многозначных полей вроде тегов/техник MITRE).
RULE_FIELD = "rule"
IS_MATCHED_FIELD = "is_matched"

_TRUE_WORDS = {"true", "1", "yes", "да"}
_FALSE_WORDS = {"false", "0", "no", "нет"}


def _coerce_bool(value: Any) -> int:
    text = str(value).strip().lower()
    if text in _TRUE_WORDS:
        return 1
    if text in _FALSE_WORDS:
        return 0
    raise FilterSyntaxError(
        f"поле 'is_matched' ожидает true/false (или 1/0), получено '{value}'"
    )


def _compile_is_matched(op: str, value: Any) -> tuple[str, list[Any]]:
    if op == "eq":
        return "is_matched = ?", [_coerce_bool(value)]
    if op == "neq":
        return "is_matched != ?", [_coerce_bool(value)]
    raise FilterSyntaxError(
        f"поле 'is_matched' поддерживает только = и != (значение true/false) - получен оператор '{op}'"
    )


def _compile_rule(op: str, value: Any) -> tuple[str, list[Any]]:
    """
    matched_rules - JSON-массив названий правил, поэтому сравнение по имени идёт через EXISTS
    по json_each(matched_rules), а не напрямую по колонке (у события может быть несколько
    сработавших правил сразу - "rule = X" должно значить "среди сработавших есть X", а не
    "весь список равен X"). isnull/notnull трактуем как "ничего не сработало"/"хоть что-то
    сработало" - это ровно то же самое, что is_matched = false/true.

    >/</>=/<= у "rule" - намеренно другая семантика: не сравнение имени (там оно бы не имело
    смысла - какое правило "больше" другого?), а сравнение КОЛИЧЕСТВА сработавших правил через
    json_array_length. Так "сколько правил сработало" (rule > 1) и "какое именно правило"
    (rule = "X" / contains / in) - два ортогональных вопроса без конфликта операторов.
    """
    if op == "isnull":
        return "is_matched = 0", []
    if op == "notnull":
        return "is_matched = 1", []
    if op == "eq":
        return "EXISTS (SELECT 1 FROM json_each(matched_rules) WHERE value = ?)", [str(value)]
    if op == "neq":
        return "NOT EXISTS (SELECT 1 FROM json_each(matched_rules) WHERE value = ?)", [str(value)]
    if op == "contains":
        return (
            "EXISTS (SELECT 1 FROM json_each(matched_rules) WHERE value LIKE ? ESCAPE '\\')",
            [f"%{_like_escape(value)}%"],
        )
    if op == "in":
        items = value if isinstance(value, list) else [v.strip() for v in str(value).split(",") if v.strip()]
        if not items:
            return "0", []  # пустой in(...) никогда не совпадает
        placeholders = ",".join("?" * len(items))
        return (
            f"EXISTS (SELECT 1 FROM json_each(matched_rules) WHERE value IN ({placeholders}))",
            [str(v) for v in items],
        )
    if op in ("gt", "lt", "gte", "lte"):
        num = _as_number(value)
        if num is None:
            raise FilterSyntaxError(f"поле 'rule' с оператором '{op}' ожидает число, получено '{value}'")
        cmp_op = {"gt": ">", "lt": "<", "gte": ">=", "lte": "<="}[op]
        return f"json_array_length(matched_rules) {cmp_op} ?", [num]
    raise FilterSyntaxError(
        f"поле 'rule' поддерживает =, !=, contains, in(...), is null, is not null, "
        f">/</>=/<= (по количеству сработавших правил) - получен оператор '{op}'"
    )


def compile_condition(field: str, op: str, value: Any) -> tuple[str, list[Any]]:
    """
    Компилирует одно условие (field, op, value) в parametrized SQL-фрагмент по raw_json.
    Значение ВСЕГДА уходит как bound-параметр; путь поля - тоже, кроме узкого whitelist
    "горячих" полей (см. resolve_json_path/INDEXED_JSON_FIELDS) - инъекция всё равно исключена.

    Значения приходят как TEXT (из строки фильтра или обычного <input>), а json_extract на
    числовом поле (EventID и т.п.) возвращает INTEGER/REAL. В SQLite INTEGER и TEXT НИКОГДА
    не считаются равными при сравнении - из-за этого "eq" ложно ничего не находил бы, а "neq"
    ложно совпадал бы со всеми строками. Поэтому для eq/neq/contains/in обе стороны приводим
    к TEXT явным CAST - сравнение идёт по отображаемому значению независимо от исходного
    JSON-типа. Для gt/lt/gte/lte приводим к REAL, если значение похоже на число (иначе
    сравниваем как TEXT).

    Два имени поля - специальные псевдонимы результата детекта (is_matched/rule), не часть
    raw_json - см. комментарий у RULE_FIELD/IS_MATCHED_FIELD выше.
    """
    key = str(field).strip().lower()
    if key == IS_MATCHED_FIELD:
        return _compile_is_matched(op, value)
    if key == RULE_FIELD:
        return _compile_rule(op, value)

    col, path_params = resolve_json_path(field)
    text_col = f"CAST({col} AS TEXT)"
    if op == "isnull":
        return f"{col} IS NULL", [*path_params]
    if op == "notnull":
        return f"{col} IS NOT NULL", [*path_params]
    if op == "eq":
        return f"{text_col} = ?", [*path_params, str(value)]
    if op == "neq":
        return f"({text_col} IS NULL OR {text_col} <> ?)", [*path_params, *path_params, str(value)]
    if op == "contains":
        return f"{text_col} LIKE ? ESCAPE '\\'", [*path_params, f"%{_like_escape(value)}%"]
    if op == "in":
        items = value if isinstance(value, list) else [v.strip() for v in str(value).split(",") if v.strip()]
        if not items:
            return "0", []  # пустой in(...) никогда не совпадает
        placeholders = ",".join("?" * len(items))
        return f"{text_col} IN ({placeholders})", [*path_params, *[str(v) for v in items]]
    if op in ("gt", "lt", "gte", "lte"):
        cmp_op = {"gt": ">", "lt": "<", "gte": ">=", "lte": "<="}[op]
        num = _as_number(value)
        if num is not None:
            return f"CAST({col} AS REAL) {cmp_op} ?", [*path_params, num]
        return f"{text_col} {cmp_op} ?", [*path_params, str(value)]
    raise FilterSyntaxError(f"неизвестный оператор '{op}'")


def _compile_node(node: tuple) -> tuple[str, list[Any]]:
    kind = node[0]
    if kind in ("and", "or"):
        _, left, right = node
        lsql, lparams = _compile_node(left)
        rsql, rparams = _compile_node(right)
        joiner = " AND " if kind == "and" else " OR "
        return f"({lsql}{joiner}{rsql})", [*lparams, *rparams]
    if kind == "not":
        _, inner = node
        isql, iparams = _compile_node(inner)
        return f"(NOT {isql})", iparams
    if kind == "cond":
        _, field, op, value = node
        return compile_condition(field, op, value)
    raise FilterSyntaxError(f"неизвестный узел выражения '{kind}'")


def compile_filter_query(text: str) -> tuple[str, list[Any]]:
    """
    Разбирает строку фильтра и сразу компилирует в (sql, params) для подстановки в WHERE.
    Пустая/пробельная строка -> ("", []) (фильтр не задан). При любой синтаксической проблеме
    бросает FilterSyntaxError с человекочитаемым сообщением - вызывающая сторона (main.py)
    оборачивает это в HTTP 400, чтобы UI показал текст ошибки пользователю.
    """
    if not text or not text.strip():
        return "", []
    tokens = _tokenize(text)
    node = _Parser(tokens).parse()
    return _compile_node(node)
