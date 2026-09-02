"""
Хранилище на SQLite: алерты (для анализа/агента) и сырые события (для просмотра
аналитиком, включая те, что не вызвали ни одного правила).

Обе таблицы живут в одном файле БД, но логически независимы - события просто
хранят JSON-снимок того, что попало в движок, плюс список названий правил,
которые на этом событии сработали (может быть пустым).
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.fields import HOST_FIELDS, TIME_FIELDS, first_present
from app.filter_lang import FILTER_OPS, IS_MATCHED_FIELD, RULE_FIELD, compile_condition, resolve_json_path
from app.models import SOURCE_DESCRIPTION_MAX, Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    engine TEXT NOT NULL,
    source_batch TEXT NOT NULL,
    host TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    rule_level TEXT NOT NULL,
    mitre_techniques TEXT NOT NULL,
    description TEXT NOT NULL,
    entities TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    sample_events TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(rule_level);
CREATE INDEX IF NOT EXISTS idx_alerts_batch ON alerts(source_batch);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    source_batch TEXT NOT NULL,
    host TEXT NOT NULL,
    event_time TEXT,
    ingested_at TEXT NOT NULL,
    is_matched INTEGER NOT NULL DEFAULT 0,
    matched_rules TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_batch ON events(source_batch);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_matched ON events(is_matched);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);

-- Индекс НА ВЫРАЖЕНИИ для "горячих" полей внутри raw_json (см. filter_lang.INDEXED_JSON_FIELDS
-- /resolve_json_path) - без него фильтр/группировка по EventID сканируют всю таблицу целиком
-- (json_extract на каждой строке). Выражение здесь должно ТЕКСТУАЛЬНО совпадать с тем, что
-- строит resolve_json_path, иначе планировщик SQLite индекс не подхватит.
CREATE INDEX IF NOT EXISTS idx_events_json_eventid ON events(json_extract(raw_json, '$."EventID"'));

-- Леджер срабатываний, "интересных" для корреляционных правил (app/correlation.py) - НЕ для
-- всех сработавших правил, только для тех, что являются base_rule_titles хотя бы одной
-- активной correlation-записи (см. hit_worthy_titles у store_events) - иначе таблица росла бы
-- на каждое срабатывание любого из тысяч built-in-правил. event_id логически ссылается на
-- events.event_id (без FOREIGN KEY - проект их нигде не использует), raw_json НЕ дублируется -
-- достаётся через JOIN. event_time здесь уже НОРМАЛИЗОВАННЫЙ (см. _normalize_event_time) вид,
-- не сырой формат источника - тогда evaluate_correlation_window может делать простой BETWEEN
-- без обёртки replace(...) в SQL и реально использовать индекс как range-scan (колонка,
-- обёрнутая в функцию, индекс так не использует).
CREATE TABLE IF NOT EXISTS rule_hits (
    event_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    source_batch TEXT NOT NULL,
    event_time TEXT,
    PRIMARY KEY (event_id, rule_title)
);
CREATE INDEX IF NOT EXISTS idx_rule_hits_lookup ON rule_hits(rule_title, source_batch, event_time);

-- Зарегистрированные потоковые источники (вкладка «Источник данных» -> «Создать источник»).
-- Каждый источник ОБЯЗАН иметь имя (name): оно уникально и служит меткой source_batch для всех
-- его событий/алертов. Токен хранится ТОЛЬКО хэшем (sha256) - открытое значение отдаётся один
-- раз в ответе на создание/перевыпуск (token_hint = последние 4 символа, чисто для UI). Приём
-- по /ingest/stream и /ingest/events без валидного токена активного источника отклоняется 401,
-- события в очередь не попадают (см. app/main.py:_authenticate_ingest). Таблица чисто аддитивна:
-- уже накопленные в events/alerts метки source_batch (файловые загрузки, старые стримы) с ней
-- никак не связаны и продолжают показываться в /batches как раньше.
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    token_sha256 TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sources_token ON sources(token_sha256);
"""

# Имя источника: 1..64 символов, буквы (в т.ч. кириллица - re.UNICODE у \w), цифры, пробел, . _ -
# Ведущие/хвостовые пробелы отсекаются до проверки. Имя уходит в URL (DELETE /batches/{name}),
# поэтому без слэшей/двоеточий/спецсимволов - те же ограничения, что у "тихих" меток батчей.
_SOURCE_NAME_RE = re.compile(r"^[\w.\- ]{1,64}$", re.UNICODE)

# Порог троттлинга записи last_seen_at на горячем ingest-пути (см. authenticate_source).
_SOURCE_LAST_SEEN_THROTTLE_S = 60.0


def _new_source_token() -> str:
    """Криптостойкий токен источника (~43 символа, URL-safe base64). В БД не хранится - только
    его sha256; открытое значение живёт лишь в ответе создающего/перевыпускающего запроса."""
    return secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_event_time(event_time: str | None) -> str | None:
    """Нормализует event_time в вид "YYYY-MM-DDTHH:MM:SS[...]" (без пробела и без 'Z') -
    та же логика, что сейчас инлайнится в SQL в _events_where на КАЖДОЕ чтение (replace/replace);
    для rule_hits нормализуем один раз на запись, чтобы запрос к нему был простым BETWEEN и
    реально использовал idx_rule_hits_lookup как range-scan (см. докстринг схемы выше)."""
    if event_time is None:
        return None
    return event_time.replace(" ", "T").replace("Z", "")

# Ранг severity для сортировки колонки "Правило" (critical - самый высокий).
_SEVERITY_RANK_SQL = (
    "CASE rule_level "
    "WHEN 'critical' THEN 5 "
    "WHEN 'high' THEN 4 "
    "WHEN 'medium' THEN 3 "
    "WHEN 'low' THEN 2 "
    "ELSE 1 END"
)

# Белые списки сортируемых полей: ключ из UI -> безопасное SQL-выражение.
# Ввод пользователя никогда не подставляется в SQL напрямую.
_ALERT_SORT_COLUMNS = {
    "rule": _SEVERITY_RANK_SQL,  # сортировка по рангу severity
    "host": "host",
    "event_count": "event_count",
    "status": "status",
    "created_at": "created_at",
}
_EVENT_SORT_COLUMNS = {
    "event_time": "event_time",
    "host": "host",
    "is_matched": "is_matched",
}


def _order_clause(sort_by: str | None, sort_dir: str | None, columns: dict[str, str], default: str) -> str:
    """Строит безопасный ORDER BY только из whitelisted-выражений (для алертов)."""
    expr = columns.get(sort_by or "", None)
    if expr is None:
        return default
    direction = "ASC" if (sort_dir or "").lower() == "asc" else "DESC"
    return f"ORDER BY {expr} {direction}"


def _event_order(sort_by: str | None, sort_dir: str | None) -> tuple[str, list[Any]]:
    """ORDER BY для событий: фикс-колонка из whitelist ИЛИ произвольное поле raw_json (json_extract,
    для "горячих" полей - литерал-путь с индексом, см. resolve_json_path)."""
    direction = "ASC" if (sort_dir or "").lower() == "asc" else "DESC"
    if not sort_by:
        return "ORDER BY ingested_at DESC", []
    if sort_by in _EVENT_SORT_COLUMNS:
        return f"ORDER BY {_EVENT_SORT_COLUMNS[sort_by]} {direction}", []
    col_expr, col_params = resolve_json_path(sort_by)
    return f"ORDER BY {col_expr} {direction}", col_params


def _build_extra_filter_clause(filters: list[dict] | None) -> tuple[str, list[Any]]:
    """
    Собирает WHERE-фрагмент AND-ом из простых условий {field, op, value} - используется только
    для group_cond (drill-in по выбранной группе в панели группировки), который всегда сужает
    выборку. Свободный текстовый язык фильтра (app/filter_lang.py, поддерживает произвольную
    вложенность and/or/not) компилируется отдельно в main.py/_parse_query_filter и приходит
    сюда уже готовым SQL-фрагментом (см. _events_where/query_filter) - здесь его трогать не надо.

    Компиляция каждого условия делегирована filter_lang.compile_condition - тот же движок,
    что и у текстового языка фильтра, поэтому оба пути (свободный текст и drill-in по группе)
    гарантированно ведут себя одинаково. Путь поля и значение уходят как bound-параметры.
    """
    if not filters:
        return "", []
    parts: list[str] = []
    params: list[Any] = []
    for f in filters:
        field = str(f.get("field") or "").strip()
        op = str(f.get("op") or "eq").lower()
        value = f.get("value")
        if not field or op not in FILTER_OPS:
            continue
        sql, p = compile_condition(field, op, value)
        parts.append(sql)
        params += p
    if not parts:
        return "", []
    return "(" + " AND ".join(parts) + ")", params


class Store:
    """Два SQLite-соединения на один файл, с раздельными локами:
    - self._conn / self._lock       - ТОЛЬКО запись (INSERT/UPDATE/DELETE, upsert_alerts,
      store_events, схема при старте).
    - self._read_conn / self._read_lock - ТОЛЬКО чтение (список/карточка алертов и событий,
      группировка, /batches).

    Раньше и то, и другое шло через одно соединение под одним общим локом - любой тяжёлый
    запрос аналитика во вкладке "События" (группировка/фильтр по кастомному полю - full table
    scan по json_extract, см. filter_lang.py) блокировал запись новых событий из ingest-воркера
    на всё время своего выполнения, и наоборот. WAL-режим (включается ниже) позволяет читателям
    не блокировать писателя и наоборот (писатели друг друга по-прежнему блокируют, но пишет
    всегда один и тот же ingest-воркер последовательно - это не новое ограничение). Раздельные
    соединения нужны ДОПОЛНИТЕЛЬНО к WAL, а не вместо него - одно соединение и один Lock всё
    равно сериализовали бы всё на уровне Python, независимо от возможностей самого WAL."""

    def __init__(self, db_path: str = "siem.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            # WAL: читатели не блокируют писателя и наоборот (в отличие от дефолтного
            # rollback-журнала). synchronous=NORMAL - стандартная пара к WAL: fsync на checkpoint,
            # а не на каждый commit - заметно быстрее запись при том же практическом уровне
            # надёжности (риск потери самых последних транзакций остаётся только при падении ОС/
            # железа, не при падении процесса приложения - для ingest-пайплайна это приемлемо).
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        self._read_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._read_conn.row_factory = sqlite3.Row
        # query_only - страховка на уровне соединения: даже случайная попытка написать через
        # read_conn упадёт явной ошибкой, а не тихо проскочит мимо self._lock.
        self._read_conn.execute("PRAGMA query_only=ON")

    # ------------------------------------------------------------------ Alerts

    def upsert_alerts(self, alerts: list[Alert]) -> int:
        """Дедуплицирует по dedup_key: повторное срабатывание того же правила на
        том же хосте/сущности увеличивает счётчик существующего алерта."""
        count = 0
        with self._lock:
            cur = self._conn.cursor()
            for alert in alerts:
                cur.execute("SELECT alert_id, event_count FROM alerts WHERE dedup_key = ?", (alert.dedup_key,))
                existing = cur.fetchone()
                if existing:
                    cur.execute(
                        "UPDATE alerts SET event_count = ?, sample_events = ? WHERE dedup_key = ?",
                        (
                            existing["event_count"] + alert.event_count,
                            json.dumps(alert.sample_events, default=str),
                            alert.dedup_key,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO alerts (
                            alert_id, dedup_key, created_at, engine, source_batch, host,
                            rule_id, rule_title, rule_level, mitre_techniques, description,
                            entities, event_count, sample_events, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert.alert_id, alert.dedup_key, alert.created_at.isoformat(),
                            alert.engine, alert.source_batch, alert.host,
                            alert.rule.rule_id, alert.rule.title, alert.rule.level.value,
                            json.dumps(alert.rule.mitre_techniques), alert.rule.description,
                            json.dumps(alert.entities.model_dump()), alert.event_count,
                            json.dumps(alert.sample_events, default=str), alert.status,
                        ),
                    )
                count += 1
            self._conn.commit()
        return count

    def list_alerts(
        self,
        source_batch: str | None = None,
        status: str | None = None,
        rule_level: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        sort_by: str | None = None,
        sort_dir: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if source_batch:
            query += " AND source_batch = ?"
            params.append(source_batch)
        if status:
            query += " AND status = ?"
            params.append(status)
        if rule_level:
            query += " AND rule_level = ?"
            params.append(rule_level)
        if time_from:
            query += " AND created_at >= ?"
            params.append(time_from)
        if time_to:
            query += " AND created_at <= ?"
            params.append(time_to)
        order = _order_clause(sort_by, sort_dir, _ALERT_SORT_COLUMNS, "ORDER BY created_at DESC")
        query += f" {order} LIMIT ? OFFSET ?"
        params += [limit, offset]

        with self._read_lock:
            rows = [dict(r) for r in self._read_conn.execute(query, params).fetchall()]
        for row in rows:
            row["mitre_techniques"] = json.loads(row["mitre_techniques"])
            row["entities"] = json.loads(row["entities"])
            row.pop("sample_events", None)
        return rows

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._read_lock:
            row = self._read_conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["mitre_techniques"] = json.loads(result["mitre_techniques"])
        result["entities"] = json.loads(result["entities"])
        result["sample_events"] = json.loads(result["sample_events"])
        return result

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------ Events

    def store_events(
        self,
        raw_events: list[dict[str, Any]],
        source_batch: str,
        matched_row_to_rules: dict[Any, list[str]],
        hit_worthy_titles: set[str] | None = None,
    ) -> int:
        """
        raw_events            - все события батча, как вернул ZircoliteCore (включают row_id)
        matched_row_to_rules  - {row_id: [названия сработавших правил]} для этого же батча
        hit_worthy_titles     - названия правил, которые являются base_rule_titles хотя бы
                                 одной АКТИВНОЙ correlation-записи (см. app/correlation.py) -
                                 для событий, сматченных ЭТИМИ правилами, дополнительно пишется
                                 строка в rule_hits (леджер для correlation-движка, см. схему
                                 выше). None/пусто (обычный ingest без активных корреляций) -
                                 rule_hits не трогается вообще.
        """
        ingested_at = datetime.now(timezone.utc).isoformat()
        rows = []
        hit_rows = []
        for event in raw_events:
            row_id = event.get("row_id")
            matched = matched_row_to_rules.get(row_id, [])
            host = first_present(event, HOST_FIELDS) or "unknown-host"
            event_time = first_present(event, TIME_FIELDS)
            event_id = str(uuid4())
            rows.append((
                event_id,
                source_batch,
                host,
                event_time,
                ingested_at,
                1 if matched else 0,
                json.dumps(matched),
                json.dumps(event, default=str),
            ))
            if hit_worthy_titles:
                normalized_time = _normalize_event_time(event_time)
                for title in matched:
                    if title in hit_worthy_titles:
                        hit_rows.append((event_id, title, source_batch, normalized_time))

        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO events (
                    event_id, source_batch, host, event_time, ingested_at,
                    is_matched, matched_rules, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            if hit_rows:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO rule_hits (event_id, rule_title, source_batch, event_time)
                    VALUES (?, ?, ?, ?)
                    """,
                    hit_rows,
                )
            self._conn.commit()
        return len(rows)

    def _events_where(
        self,
        source_batch: str | None,
        only_matched: bool | None,
        time_from: str | None,
        time_to: str | None,
        query_filter: tuple[str, list[Any]] | None = None,
        extra_filters: list[dict] | None = None,
    ) -> tuple[str, list[Any]]:
        """Общий WHERE для событий: базовые фильтры + пользовательский текстовый фильтр.
        Пайплайн один и тот же для списка, счётчика и группировки - фильтр применяется до всего.

        query_filter - уже скомпилированный (sql, params) свободного текстового языка фильтра
        (см. app/filter_lang.py и main.py/_parse_query_filter - разбор и ошибки синтаксиса
        живут там, сюда приходит готовый parametrized SQL-фрагмент, store.py языка не знает).
        Отдельного параметра фильтра по хосту больше нет - при необходимости он выражается
        через query_filter по полю raw_json (напр. "Hostname contains ...").

        extra_filters - условия drill-in по выбранной группе, ВСЕГДА добавляются по AND поверх
        query_filter независимо от логики внутри него (выбор группы должен сужать, а не менять
        смысл пользовательского фильтра)."""
        sql = " WHERE 1=1"
        params: list[Any] = []
        if source_batch:
            sql += " AND source_batch = ?"
            params.append(source_batch)
        if only_matched is not None:
            sql += " AND is_matched = ?"
            params.append(1 if only_matched else 0)
        # event_time хранится как есть, форматы у источников разные: EVTX даёт
        # "YYYY-MM-DD HH:MM:SS" (пробел, без TZ), другие источники - ISO с "T" и суффиксом
        # "Z" (напр. "...T04:13:05.650Z"). Границы из UI приходят как "наивная" ISO-строка
        # без суффикса (см. timeParams() в index.html - специально без Z, чтобы совпадать
        # с этим же наивным форматом и с alerts.created_at). Нормализуем event_time к тому
        # же виду перед сравнением, иначе строковое сравнение ломается на разнице форматов.
        if time_from:
            sql += " AND replace(replace(event_time, ' ', 'T'), 'Z', '') >= ?"
            params.append(time_from)
        if time_to:
            sql += " AND replace(replace(event_time, ' ', 'T'), 'Z', '') <= ?"
            params.append(time_to)
        if query_filter and query_filter[0]:
            sql += " AND " + query_filter[0]
            params += query_filter[1]
        eclause, eparams = _build_extra_filter_clause(extra_filters)
        if eclause:
            sql += " AND " + eclause
            params += eparams
        return sql, params

    def list_events(
        self,
        source_batch: str | None = None,
        only_matched: bool | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        sort_by: str | None = None,
        sort_dir: str | None = None,
        fields: list[str] | None = None,
        query_filter: tuple[str, list[Any]] | None = None,
        extra_filters: list[dict] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        # Кастом-колонки из сырого JSON: json_extract, для "горячих" полей - через литерал-путь
        # и индекс (resolve_json_path), для остальных - как раньше, bound-параметр без индекса.
        clean_fields = [f for f in (fields or []) if f]
        select_cols = ["event_id", "source_batch", "host", "event_time", "ingested_at", "is_matched", "matched_rules"]
        params: list[Any] = []
        for i, field in enumerate(clean_fields):
            col_expr, col_params = resolve_json_path(field)
            select_cols.append(f"{col_expr} AS extra_{i}")
            params += col_params

        where_sql, where_params = self._events_where(
            source_batch, only_matched, time_from, time_to, query_filter, extra_filters
        )
        order_sql, order_params = _event_order(sort_by, sort_dir)
        query = f"SELECT {', '.join(select_cols)} FROM events{where_sql} {order_sql} LIMIT ? OFFSET ?"
        params += where_params + order_params + [limit, offset]

        with self._read_lock:
            rows = [dict(r) for r in self._read_conn.execute(query, params).fetchall()]
        for row in rows:
            row["matched_rules"] = json.loads(row["matched_rules"])
            row["is_matched"] = bool(row["is_matched"])
            if clean_fields:
                row["extra"] = {field: row.pop(f"extra_{i}", None) for i, field in enumerate(clean_fields)}
        return rows

    def group_events(
        self,
        group_by: str,
        source_batch: str | None = None,
        only_matched: bool | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        query_filter: tuple[str, list[Any]] | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """Группировка (как в MaxPatrol): для выбранного поля возвращает уникальные значения
        и счётчики по убыванию (топ limit), а также ОБЩЕЕ число уникальных значений (может
        быть больше limit - тогда в списке показан только срез). Фильтр применяется ДО
        группировки. "Пусто" (поле отсутствует) - тоже отдельное уникальное значение.

        group_by == "rule"/"is_matched" - те же псевдонимы результата детекта, что и в
        filter_lang.compile_condition (не часть raw_json, см. комментарий там). "rule" -
        многозначное поле (у события может быть 0..N сработавших правил), поэтому группировка
        "разворачивает" matched_rules через LEFT JOIN json_each - событие с двумя правилами
        даёт по +1 в счётчик КАЖДОГО из них, а событие без единого сработавшего правила всё
        равно попадает в группу "(пусто)" благодаря LEFT (а не INNER) JOIN."""
        where_sql, where_params = self._events_where(
            source_batch, only_matched, time_from, time_to, query_filter
        )
        key = group_by.strip().lower()
        bind_prefix: list[Any] = []
        if key == IS_MATCHED_FIELD:
            from_clause = "events"
            gval_expr = "CASE WHEN is_matched THEN 'true' ELSE 'false' END"
        elif key == RULE_FIELD:
            from_clause = "events e LEFT JOIN json_each(e.matched_rules) mr"
            gval_expr = "mr.value"
        else:
            from_clause = "events"
            gval_expr, bind_prefix = resolve_json_path(group_by)
        count_query = (
            f"SELECT COUNT(*) AS c FROM (SELECT DISTINCT {gval_expr} AS gval "
            f"FROM {from_clause}{where_sql})"
        )
        list_query = (
            f"SELECT {gval_expr} AS gval, COUNT(*) AS c "
            f"FROM {from_clause}{where_sql} GROUP BY gval ORDER BY c DESC LIMIT ?"
        )
        with self._read_lock:
            total_groups = self._read_conn.execute(count_query, [*bind_prefix, *where_params]).fetchone()["c"]
            rows = self._read_conn.execute(list_query, [*bind_prefix, *where_params, limit]).fetchall()
        return {
            "groups": [{"value": r["gval"], "count": r["c"]} for r in rows],
            "total_groups": total_groups,
        }

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._read_lock:
            row = self._read_conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["matched_rules"] = json.loads(result["matched_rules"])
        result["raw_json"] = json.loads(result["raw_json"])
        result["is_matched"] = bool(result["is_matched"])
        return result

    def count_events(
        self,
        source_batch: str | None = None,
        only_matched: bool | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        query_filter: tuple[str, list[Any]] | None = None,
        extra_filters: list[dict] | None = None,
    ) -> int:
        where_sql, where_params = self._events_where(
            source_batch, only_matched, time_from, time_to, query_filter, extra_filters
        )
        query = f"SELECT COUNT(*) AS c FROM events{where_sql}"
        with self._read_lock:
            return self._read_conn.execute(query, where_params).fetchone()["c"]

    # ------------------------------------------------------------------ Correlation

    def evaluate_correlation_window(
        self,
        base_rule_titles: list[str],
        group_by: list[str],
        key_values: tuple[Any, ...],
        source_batch: str,
        time_from: str,
        time_to: str,
        distinct_field: str | None = None,
        sample_limit: int = 10,
    ) -> dict[str, Any]:
        """
        Считает event_count (COUNT(*)) или, если задан distinct_field, value_count
        (COUNT(DISTINCT ...)) для одного (correlation-правило, group-by-ключ) сочетания в
        пределах окна [time_from, time_to] (уже нормализованные строки, см.
        _normalize_event_time - сравниваются простым BETWEEN, см. схему rule_hits) и одного
        source_batch (корреляция считается "в рамках одного источника", см. диалог/CLAUDE.md).

        base_rule_titles - OR по всем title'ам, которые эта correlation ссылается (обычно один,
        но Sigma допускает несколько base-правил на одну корреляцию). group_by/key_values -
        параллельные списки: поле группировки -> конкретное значение этого ключа (уже известное
        вызывающей стороне, app/correlation.py, из свежесматченных событий батча).

        JOIN rule_hits (проиндексирован по (rule_title, source_batch, event_time), см. схему) ->
        events (по event_id, без дублирования raw_json) - строк на входе уже мало благодаря
        индексу, дальше json_extract по group-by полям выполняется над этим узким набором, а
        не над всей таблицей events (в отличие от прямого запроса к events без rule_hits).
        """
        if not base_rule_titles or not group_by or len(group_by) != len(key_values):
            return {"count": 0, "sample_events": []}

        rule_placeholders = ",".join("?" * len(base_rule_titles))
        where = [
            f"h.rule_title IN ({rule_placeholders})",
            "h.source_batch = ?",
            "h.event_time BETWEEN ? AND ?",
        ]
        params: list[Any] = [*base_rule_titles, source_batch, time_from, time_to]
        for field, value in zip(group_by, key_values):
            col_expr, col_params = resolve_json_path(field)
            where.append(f"{col_expr} = ?")
            params += [*col_params, str(value)]
        where_sql = " AND ".join(where)

        if distinct_field:
            dist_expr, dist_params = resolve_json_path(distinct_field)
            count_sql = (
                f"SELECT COUNT(DISTINCT {dist_expr}) AS c FROM rule_hits h "
                f"JOIN events e ON e.event_id = h.event_id WHERE {where_sql}"
            )
            count_params = [*dist_params, *params]
        else:
            count_sql = (
                f"SELECT COUNT(*) AS c FROM rule_hits h "
                f"JOIN events e ON e.event_id = h.event_id WHERE {where_sql}"
            )
            count_params = params

        sample_sql = (
            f"SELECT e.raw_json FROM rule_hits h JOIN events e ON e.event_id = h.event_id "
            f"WHERE {where_sql} ORDER BY h.event_time ASC LIMIT ?"
        )
        with self._read_lock:
            count = self._read_conn.execute(count_sql, count_params).fetchone()["c"]
            sample_rows = self._read_conn.execute(sample_sql, [*params, sample_limit]).fetchall()
        sample_events = []
        for row in sample_rows:
            try:
                sample_events.append(json.loads(row["raw_json"]))
            except (TypeError, json.JSONDecodeError):
                continue
        return {"count": count, "sample_events": sample_events}

    def upsert_correlation_alerts(self, alerts: list[Alert]) -> int:
        """Как upsert_alerts, но OVERWRITE event_count/sample_events, не increment - для
        correlation-алертов event_count описывает "сколько сейчас в текущем окне", не "сколько
        раз в сумме сработало с прошлого прогона" (окно сдвигается/пересчитывается на каждый
        flush, старые события из него естественным образом выпадают - increment был бы неверен,
        событие могло бы уже не входить в окно, а счётчик всё равно рос бы)."""
        count = 0
        with self._lock:
            cur = self._conn.cursor()
            for alert in alerts:
                cur.execute("SELECT alert_id FROM alerts WHERE dedup_key = ?", (alert.dedup_key,))
                existing = cur.fetchone()
                if existing:
                    cur.execute(
                        "UPDATE alerts SET event_count = ?, sample_events = ? WHERE dedup_key = ?",
                        (alert.event_count, json.dumps(alert.sample_events, default=str), alert.dedup_key),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO alerts (
                            alert_id, dedup_key, created_at, engine, source_batch, host,
                            rule_id, rule_title, rule_level, mitre_techniques, description,
                            entities, event_count, sample_events, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert.alert_id, alert.dedup_key, alert.created_at.isoformat(),
                            alert.engine, alert.source_batch, alert.host,
                            alert.rule.rule_id, alert.rule.title, alert.rule.level.value,
                            json.dumps(alert.rule.mitre_techniques), alert.rule.description,
                            json.dumps(alert.entities.model_dump()), alert.event_count,
                            json.dumps(alert.sample_events, default=str), alert.status,
                        ),
                    )
                count += 1
            self._conn.commit()
        return count

    # ------------------------------------------------------------------ Batches

    def list_batches(self) -> list[dict[str, Any]]:
        """Сводка по всем батчам, которые когда-либо загружались - для селектора источника в UI."""
        query = """
            SELECT
                source_batch AS source_batch,
                COUNT(*) AS event_count,
                SUM(is_matched) AS matched_event_count,
                MIN(ingested_at) AS first_ingested_at,
                MAX(ingested_at) AS last_ingested_at
            FROM events
            GROUP BY source_batch
            ORDER BY MAX(ingested_at) DESC
        """
        with self._read_lock:
            event_rows = [dict(r) for r in self._read_conn.execute(query).fetchall()]
            alert_counts = {
                r["source_batch"]: r["c"]
                for r in self._read_conn.execute(
                    "SELECT source_batch, COUNT(*) AS c FROM alerts GROUP BY source_batch"
                ).fetchall()
            }
        for row in event_rows:
            row["alert_count"] = alert_counts.get(row["source_batch"], 0)
        return event_rows

    def delete_batch(self, source_batch: str) -> dict[str, int]:
        """Полное удаление источника: все events, alerts И rule_hits с этим source_batch (не
        только события) - source_batch не отдельная сущность/таблица, просто общая метка на ВСЕХ
        трёх таблицах, поэтому "удалить источник" технически значит удалить всё с этой меткой.
        rule_hits важно чистить здесь же: иначе при повторном ingest под ТЕМ ЖЕ source_batch
        (частый случай в ручном тестировании, см. CLAUDE.md) осиротевшие строки от УДАЛЁННОГО
        батча продолжали бы учитываться в evaluate_correlation_window (окно фильтруется по
        source_batch+event_time, не по тому, жив ли ещё сам event_id в events - JOIN просто не
        вернёт по нему raw_json, но COUNT(*) без JOIN их всё равно посчитал бы; здесь JOIN есть,
        так что реального искажения счётчика нет, но мусор всё равно накапливался бы вечно)."""
        with self._lock:
            events_deleted = self._conn.execute(
                "DELETE FROM events WHERE source_batch = ?", (source_batch,)
            ).rowcount
            alerts_deleted = self._conn.execute(
                "DELETE FROM alerts WHERE source_batch = ?", (source_batch,)
            ).rowcount
            self._conn.execute("DELETE FROM rule_hits WHERE source_batch = ?", (source_batch,))
            self._conn.commit()
        return {"events_deleted": events_deleted, "alerts_deleted": alerts_deleted}

    # ------------------------------------------------------------------ Sources (потоковые источники)

    def _source_public(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        """Строка источника наружу: без token_sha256, enabled как bool."""
        d = {k: row[k] for k in (
            "source_id", "name", "description", "token_hint", "enabled", "created_at", "last_seen_at",
        )}
        d["enabled"] = bool(d["enabled"])
        return d

    def create_source(self, name: str, description: str = "") -> dict[str, Any]:
        """Регистрирует потоковый источник. name ОБЯЗАТЕЛЕН, уникален, становится меткой
        source_batch. Возвращает публичную строку источника + ОДНОРАЗОВЫЙ открытый токен в
        поле "token" (в БД только его sha256). ValueError - пустое/некорректное имя или имя
        уже занято (тогда транслируется в HTTP 400 в app/main.py)."""
        name = (name or "").strip()
        if not _SOURCE_NAME_RE.match(name):
            raise ValueError("Имя источника: 1..64 символов, буквы/цифры/пробел/точка/дефис/подчёркивание")
        token = _new_source_token()
        row = {
            "source_id": str(uuid4()),
            "name": name,
            "description": (description or "").strip()[:SOURCE_DESCRIPTION_MAX],
            "token_sha256": _hash_token(token),
            "token_hint": token[-4:],
            "enabled": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_seen_at": None,
        }
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO sources (source_id, name, description, token_sha256, token_hint, "
                    "enabled, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (row["source_id"], row["name"], row["description"], row["token_sha256"],
                     row["token_hint"], row["enabled"], row["created_at"], row["last_seen_at"]),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError(f"Источник с именем «{name}» уже существует") from None
        return {**self._source_public(row), "token": token}

    def list_sources(self) -> list[dict[str, Any]]:
        with self._read_lock:
            rows = self._read_conn.execute(
                "SELECT * FROM sources ORDER BY created_at DESC"
            ).fetchall()
        return [self._source_public(r) for r in rows]

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        with self._read_lock:
            row = self._read_conn.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source_id,)
            ).fetchone()
        return self._source_public(row) if row is not None else None

    def rotate_source_token(self, source_id: str) -> str | None:
        """Новый токен, старый перестаёт работать сразу же. None - источник не найден."""
        token = _new_source_token()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE sources SET token_sha256 = ?, token_hint = ? WHERE source_id = ?",
                (_hash_token(token), token[-4:], source_id),
            )
            self._conn.commit()
        return token if cur.rowcount > 0 else None

    def update_source(
        self, source_id: str, enabled: bool | None = None, description: str | None = None
    ) -> dict[str, Any] | None:
        """PATCH: меняет enabled и/или description (name и токен не трогает). None - не найден."""
        sets: list[str] = []
        params: list[Any] = []
        if enabled is not None:
            sets.append("enabled = ?")
            params.append(1 if enabled else 0)
        if description is not None:
            sets.append("description = ?")
            params.append(description.strip()[:SOURCE_DESCRIPTION_MAX])
        if sets:
            params.append(source_id)
            with self._lock:
                cur = self._conn.execute(
                    f"UPDATE sources SET {', '.join(sets)} WHERE source_id = ?", params
                )
                self._conn.commit()
            if cur.rowcount == 0:
                return None
        return self.get_source(source_id)

    def delete_source(self, source_id: str) -> bool:
        """Снимает РЕГИСТРАЦИЮ (токен отзывается). События/алерты этого источника не трогает -
        для них отдельное действие DELETE /batches/{name} (source_batch не завязан на sources)."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM sources WHERE source_id = ?", (source_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def authenticate_source(self, token: str | None) -> dict[str, Any] | None:
        """По открытому токену находит АКТИВНЫЙ источник (сравнение по sha256). None - токена
        нет / не совпал / источник выключен. Обновляет last_seen_at, но не чаще раза в ~60с
        (_SOURCE_LAST_SEEN_THROTTLE_S) - иначе на горячем пути /ingest/stream каждый запрос
        форвардера порождал бы отдельную запись в БД под _lock."""
        if not token:
            return None
        digest = _hash_token(token)
        with self._read_lock:
            row = self._read_conn.execute(
                "SELECT * FROM sources WHERE token_sha256 = ?", (digest,)
            ).fetchone()
        if row is None or not row["enabled"]:
            return None
        pub = self._source_public(row)
        now = datetime.now(timezone.utc)
        last = pub.get("last_seen_at")
        stale = True
        if last:
            try:
                stale = (now - datetime.fromisoformat(last)).total_seconds() > _SOURCE_LAST_SEEN_THROTTLE_S
            except ValueError:
                stale = True
        if stale:
            with self._lock:
                self._conn.execute(
                    "UPDATE sources SET last_seen_at = ? WHERE source_id = ?",
                    (now.isoformat(), pub["source_id"]),
                )
                self._conn.commit()
            pub["last_seen_at"] = now.isoformat()
        return pub

    def close(self) -> None:
        self._conn.close()
        self._read_conn.close()

    # ------------------------------------------------------------------ Health

    def health(self, detailed: bool = False) -> dict[str, Any]:
        """Проверка живости БД для /health: пробный SELECT 1 под тем же _lock, что и вся
        остальная работа с БД (никаких конкурирующих соединений мимо Store). detailed
        добавляет счётчики строк и размер файла - это уже полный COUNT(*) по обеим таблицам,
        дороже, поэтому не гоняем на каждом лёгком опросе, только по явному запросу (клик в UI)."""
        t0 = time.time()
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
                extra: dict[str, Any] = {}
                if detailed:
                    extra["alerts"] = self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
                    extra["events"] = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        except Exception as exc:  # noqa: BLE001 - health-check не должен ронять сервис
            return {"status": "error", "error": str(exc)}
        if detailed:
            try:
                extra["size_mb"] = round(Path(self.db_path).stat().st_size / (1024 * 1024), 2)
            except OSError:
                pass
        return {"status": "ok", "latency_ms": round((time.time() - t0) * 1000, 2), **extra}
