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

from app.fields import (
    DST_IP_FIELDS,
    EVENT_CODE_FIELDS,
    HOST_FIELDS,
    PROCESS_FIELDS,
    SRC_IP_FIELDS,
    TIME_FIELDS,
    USER_FIELDS,
    first_present,
)
from app.filter_lang import FILTER_OPS, IS_MATCHED_FIELD, RULE_FIELD, compile_condition, resolve_json_path
from app.models import SOURCE_DESCRIPTION_MAX, Alert, Incident, Investigation, Severity, utcnow_naive

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
    sample_events TEXT NOT NULL
    -- Статуса больше нет (был "new"/"investigating"/"closed") - триаж-статус только у incidents,
    -- см. CLAUDE.md/docs/spec/http-api.md. Ни один _SCHEMA/_migrate её не создаёт и не чистит -
    -- БД, созданные ДО этого изменения (с колонкой status на диске), не поддерживаются, только
    -- пересоздание файла с нуля (siem.db - одноразовая dev-БД, в .gitignore).
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);
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
    raw_json TEXT NOT NULL,
    -- ECS-lite колонки (Этап A дорожной карты) - извлекаются на запись из тех же кандидатов
    -- полей, что и Entities алерта (app/fields.py: USER_FIELDS/SRC_IP_FIELDS/DST_IP_FIELDS/
    -- PROCESS_FIELDS/EVENT_CODE_FIELDS), NULL если поле не найдено. Фундамент группировки
    -- Инцидентов по сущности (Этап B) - без настоящих колонок агрегация поперёк алертов
    -- получила бы ту же болезнь O(K*H), от которой лечит rule_hits.group_json ниже.
    -- raw_json остаётся источником правды, эти колонки - только денормализованный индекс
    -- для быстрого WHERE/GROUP BY, filter_lang.py их не подменяет.
    user_name TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    process TEXT,
    event_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_batch ON events(source_batch);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);

-- Индекс НА ВЫРАЖЕНИИ для "горячих" полей внутри raw_json (см. filter_lang.INDEXED_JSON_FIELDS
-- /resolve_json_path) - без него фильтр/группировка по EventID сканируют всю таблицу целиком
-- (json_extract на каждой строке). Выражение здесь должно ТЕКСТУАЛЬНО совпадать с тем, что
-- строит resolve_json_path, иначе планировщик SQLite индекс не подхватит.
CREATE INDEX IF NOT EXISTS idx_events_json_eventid ON events(json_extract(raw_json, '$."EventID"'));

-- Леджер срабатываний, "интересных" для корреляционных правил (app/detection/correlation.py) - НЕ для
-- всех сработавших правил, только для тех, что являются base_rule_titles хотя бы одной
-- активной correlation-записи (см. hit_spec у store_events) - иначе таблица росла бы
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
    -- Денормализованные значения group-by полей (и condition.field у value_count) ЭТОГО
    -- срабатывания, сериализованные {field: str(value)} - ключ app/detection/correlation.py
    -- считает счёт ИСКЛЮЧИТЕЛЬНО отсюда (json_extract(group_json, ...)), БЕЗ JOIN к events -
    -- см. store.evaluate_correlation_window(s). Заполняется точечно, только для полей, реально
    -- нужных активным correlation-правилам (app/detection/correlation.py:active_hit_spec), НЕ
    -- на каждое поле каждого события. NULL у строк, записанных до этого изменения (миграция
    -- аддитивна, не бэкфиллит старые строки) - такие строки просто не совпадут ни по одному
    -- group-by, что безопасно (окно корреляции и так смотрит только в недавнее прошлое).
    group_json TEXT,
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

-- Инциденты (Этап 4) - агрегат алертов, единица работы AI-агента расследования (Этап 5).
-- Заводится ТОЛЬКО при срабатывании correlation-правила, помеченного блоком correlation.incident
-- (см. app/detection/correlation.py:evaluate_batch, app/rules/rules_catalog.py). Обычные алерты
-- в инциденты сами не собираются - catch-all прохода по alerts НЕТ (осознанное ограничение
-- этапа, см. docs/spec/incidents.md). dedup_key - фиксированный бакет по timespan правила
-- (incident_type:group_values:window_bucket): повтор в том же бакете -> UPDATE строки
-- (store.upsert_incidents), разрыв > timespan -> новый бакет -> новый инцидент. Инцидент
-- ПЕРЕЖИВАЕТ свои events (ретеншн чистит events, не alerts/incidents) - GET /incidents/{id}/context
-- обязан работать при пустом related_events. Привязан к ОДНОМУ source_batch (как и корреляция) -
-- поэтому чистится в delete_batch вместе с events/alerts/rule_hits.
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    incident_type TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    source_batch TEXT NOT NULL,
    ruleset_path TEXT NOT NULL DEFAULT '',
    correlation_rule_id TEXT NOT NULL DEFAULT '',
    correlation_rule_title TEXT NOT NULL,
    group_key TEXT NOT NULL DEFAULT '{}',
    member_rule_titles TEXT NOT NULL DEFAULT '[]',
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    window_bucket TEXT NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    entities TEXT NOT NULL DEFAULT '{}',
    sample_events TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_type    ON incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_batch   ON incidents(source_batch);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

-- Расследования (Этап 4) - очередь + результат работы агента. На Этапе 4 тело обработки -
-- заглушка (app/incidents.py:run_pending: queued -> running -> done с placeholder-вердиктом);
-- жизненный цикл статуса и точка вызова из IngestWorker остаются под настоящего агента (Этап 5).
-- Одна строка на инцидент; при повторном срабатывании в том же бакете, если расследование уже
-- в терминальном статусе, оно ре-энкьюится в queued (store.enqueue_investigation).
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    verdict TEXT,
    rationale TEXT NOT NULL DEFAULT '',
    confidence REAL,
    steps TEXT NOT NULL DEFAULT '[]',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status   ON investigations(status);
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


def _group_json_path(field: str) -> str:
    """JSON-путь верхнего уровня для полей rule_hits.group_json - ВСЕГДА bound-параметр (в
    отличие от filter_lang.resolve_json_path/INDEXED_JSON_FIELDS, где путь для "горячих" полей
    - литерал в тексте SQL ради expression-индекса на events.raw_json). Здесь такого индекса
    нет и не нужен: узкий набор строк уже получен через idx_rule_hits_lookup по (rule_title,
    source_batch, event_time) - GROUP BY/сравнение дальше работают над этим маленьким набором
    в памяти, а не сканируют всю таблицу."""
    return f'$."{str(field).replace(chr(34), "")}"'


def _migrate(conn: sqlite3.Connection) -> None:
    """Аддитивная миграция схемы для БД, созданных ДО этого изменения - CREATE TABLE IF NOT
    EXISTS в _SCHEMA не добавит новые колонки в уже существующую таблицу (это no-op). ALTER
    TABLE ... ADD COLUMN безопасен на живых данных (новые строки NULL, без даунтайма и
    блокировки надолго). Индексы на новых колонках создаются ЗДЕСЬ, ПОСЛЕ добавления колонок
    (а не в _SCHEMA) - иначе на старой БД CREATE INDEX упал бы на ещё не существующую колонку
    раньше, чем успеет отработать ALTER TABLE. Вызывается один раз при каждом старте Store,
    под тем же _lock, что и executescript(_SCHEMA) - см. __init__."""
    events_cols = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for col in ("user_name", "src_ip", "dst_ip", "process", "event_code"):
        if col not in events_cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")

    rule_hits_cols = {row["name"] for row in conn.execute("PRAGMA table_info(rule_hits)")}
    if "group_json" not in rule_hits_cols:
        conn.execute("ALTER TABLE rule_hits ADD COLUMN group_json TEXT")

    # idx_events_matched убран - is_matched всего два различимых значения (0/1), планировщик
    # такой индекс практически никогда не выбирает, а стоимость на КАЖДУЮ вставку платилась.
    conn.execute("DROP INDEX IF EXISTS idx_events_matched")
    # idx_events_user/idx_events_src_ip - под группировку Инцидентов по сущности (Этап B) и под
    # ручной пивот аналитика. idx_events_ingested - под ретеншн (store.delete_events_older_than):
    # без индекса каждая порция удаления сканировала бы всю таблицу заново (см. докстринг метода).
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested_at)")

    # alerts.incident_id (Этап 4) - обратная ссылка алерта на инцидент, к которому он привязан
    # (store.link_alerts_to_incident). NULL у алертов, не входящих ни в один инцидент (обычный
    # случай - инциденты только сценарные). Новая таблица incidents/investigations создаётся
    # прямо в _SCHEMA (CREATE TABLE IF NOT EXISTS отрабатывает и на старой БД), миграции ей не
    # нужно - здесь только КОЛОНКА на уже существующей alerts.
    alerts_cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    if "incident_id" not in alerts_cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN incident_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")

    # events.alert_id - какой алерт "поглотил" это событие (проставляется app/main.py:
    # _process_batch сразу после store.upsert_alerts, через store.link_events_to_alerts).
    # Основа цепочки event -> alert -> incident (store.link_alerts_to_incident), заменившей
    # сопоставление по значению "сущности" (host/entities LIKE) - то молча не находило алерты,
    # если correlation group-by был не по хосту/известной категории сущности (напр. DNS
    # QueryName, путь ключа реестра - см. docs/spec/incidents.md, "Известные ограничения").
    # NULL у событий built-in-прогонов файлов (там дедуп built-in грубый - см. normalize.py -
    # и линковка к инциденту всё равно не нужна, built-in в main не допускается) и у событий,
    # не сматчивших ни одно правило (алерта для них просто нет).
    if "alert_id" not in events_cols:
        conn.execute("ALTER TABLE events ADD COLUMN alert_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_alert ON events(alert_id)")

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
    "created_at": "created_at",
}
_EVENT_SORT_COLUMNS = {
    "event_time": "event_time",
    "host": "host",
    "is_matched": "is_matched",
}
# Ранг severity инцидента для сортировки (колонка severity - строка, не rule_level).
_INCIDENT_SEVERITY_RANK_SQL = (
    "CASE severity "
    "WHEN 'critical' THEN 5 "
    "WHEN 'high' THEN 4 "
    "WHEN 'medium' THEN 3 "
    "WHEN 'low' THEN 2 "
    "ELSE 1 END"
)
_INCIDENT_SORT_COLUMNS = {
    "created_at": "created_at",
    "updated_at": "updated_at",
    "alert_count": "alert_count",
    "status": "status",
    "severity": _INCIDENT_SEVERITY_RANK_SQL,
}
# Поля investigations, которые джобе (app/incidents.py) разрешено обновлять через update_investigation.
_INVESTIGATION_UPDATABLE = {
    "status", "verdict", "rationale", "confidence", "steps", "error", "started_at", "finished_at",
}


def _order_clause(sort_by: str | None, sort_dir: str | None, columns: dict[str, str], default: str) -> str:
    """Строит безопасный ORDER BY только из whitelisted-выражений (для алертов)."""
    expr = columns.get(sort_by or "", None)
    if expr is None:
        return default
    direction = "ASC" if (sort_dir or "").lower() == "asc" else "DESC"
    return f"ORDER BY {expr} {direction}"


def _incident_matches_query(row: dict[str, Any], q: str) -> bool:
    """Поиск по вкладке Инциденты - подстрока по correlation_rule_title ("Инцидент" в UI,
    название сработавшего правила) ИЛИ title ("Описание", incident.title из YAML),
    регистронезависимо. Тот же паттерн, что rules_catalog.paginate_rules у Sigma-правил -
    str.lower() в Python, а не SQL LOWER()/LIKE (те регистронезависимы только для ASCII,
    кириллицу не берут)."""
    needle = q.strip().lower()
    if not needle:
        return True
    return (
        needle in str(row.get("correlation_rule_title", "")).lower()
        or needle in str(row.get("title", "")).lower()
    )


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
            _migrate(self._conn)
            self._conn.commit()
        self._read_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._read_conn.row_factory = sqlite3.Row
        # query_only - страховка на уровне соединения: даже случайная попытка написать через
        # read_conn упадёт явной ошибкой, а не тихо проскочит мимо self._lock.
        self._read_conn.execute("PRAGMA query_only=ON")

    # ------------------------------------------------------------------ Alerts

    def get_alert_ids_by_dedup_keys(self, dedup_keys: list[str]) -> dict[str, str]:
        """{dedup_key: alert_id} для уже сохранённых алертов - зовётся app/main.py:_process_batch
        СРАЗУ после upsert_alerts (не меняем сигнатуру upsert_alerts ради этого - она и так
        плотно покрыта тестами на count) за настоящими alert_id, нужными для
        store.link_events_to_alerts. dedup_keys без совпадения просто не попадают в результат."""
        if not dedup_keys:
            return {}
        with self._read_lock:
            ph = ",".join("?" * len(dedup_keys))
            rows = self._read_conn.execute(
                f"SELECT dedup_key, alert_id FROM alerts WHERE dedup_key IN ({ph})", dedup_keys,
            ).fetchall()
        return {r["dedup_key"]: r["alert_id"] for r in rows}

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
                            entities, event_count, sample_events
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert.alert_id, alert.dedup_key, alert.created_at.isoformat(),
                            alert.engine, alert.source_batch, alert.host,
                            alert.rule.rule_id, alert.rule.title, alert.rule.level.value,
                            json.dumps(alert.rule.mitre_techniques), alert.rule.description,
                            json.dumps(alert.entities.model_dump()), alert.event_count,
                            json.dumps(alert.sample_events, default=str),
                        ),
                    )
                count += 1
            self._conn.commit()
        return count

    def list_alerts(
        self,
        source_batch: str | None = None,
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

    # ------------------------------------------------------------------ Events

    def store_events(
        self,
        raw_events: list[dict[str, Any]],
        source_batch: str,
        matched_row_to_rules: dict[Any, list[str]],
        hit_spec: dict[str, set[str]] | None = None,
    ) -> dict[Any, str]:
        """
        raw_events            - все события батча, как вернул ZircoliteCore (включают row_id)
        matched_row_to_rules  - {row_id: [названия сработавших правил]} для этого же батча
        hit_spec               - {rule_title: {поля}} для БАЗОВЫХ (не-correlation) правил,
                                 являющихся base_rule_titles хотя бы одной АКТИВНОЙ
                                 correlation-записи (см. app/detection/correlation.py:
                                 active_hit_spec) - поля это объединение group-by ∪
                                 condition.field ВСЕХ correlation-правил, ссылающихся на
                                 rule_title. Для событий, сматченных ЭТИМИ правилами,
                                 дополнительно пишется строка в rule_hits (леджер для
                                 correlation-движка): event_id/rule_title/source_batch/
                                 event_time КАК РАНЬШЕ + group_json - денормализованные
                                 значения запрошенных полей ИЗ ЭТОГО события, сериализованные
                                 {field: str(value)} (пропуская отсутствующие) - именно отсюда
                                 store.evaluate_correlation_window(s) считает счёт БЕЗ JOIN к
                                 events (см. докстринг схемы rule_hits выше). None/пусто
                                 (обычный ingest без активных корреляций) - rule_hits не
                                 трогается вообще.

        Возврат - {row_id: event_id} (не count) для ВСЕХ сохранённых событий: row_id -
        Zircolite-локальный id этого батча (см. normalize.py:zircolite_results_to_alerts,
        Alert.source_row_ids), event_id - настоящий первичный ключ строки events. Единственное
        место, где эта связка вообще существует (row_id нигде не персистится) - нужна
        app/main.py:_process_batch, чтобы потом проставить events.alert_id (цепочка event ->
        alert -> incident без сущностей, см. store.link_alerts_to_incident). len(результата) -
        число сохранённых событий (замена старому return count)."""
        ingested_at = datetime.now(timezone.utc).isoformat()
        rows = []
        hit_rows = []
        row_id_to_event_id: dict[Any, str] = {}
        for event in raw_events:
            row_id = event.get("row_id")
            matched = matched_row_to_rules.get(row_id, [])
            host = first_present(event, HOST_FIELDS) or "unknown-host"
            event_time = first_present(event, TIME_FIELDS)
            event_id = str(uuid4())
            row_id_to_event_id[row_id] = event_id
            rows.append((
                event_id,
                source_batch,
                host,
                event_time,
                ingested_at,
                1 if matched else 0,
                json.dumps(matched),
                json.dumps(event, default=str),
                first_present(event, USER_FIELDS),
                first_present(event, SRC_IP_FIELDS),
                first_present(event, DST_IP_FIELDS),
                first_present(event, PROCESS_FIELDS),
                first_present(event, EVENT_CODE_FIELDS),
            ))
            if hit_spec:
                normalized_time = _normalize_event_time(event_time)
                for title in matched:
                    fields = hit_spec.get(title)
                    if fields is None:
                        continue
                    group_values = {f: str(event[f]) for f in fields if event.get(f) is not None}
                    hit_rows.append((
                        event_id, title, source_batch, normalized_time,
                        json.dumps(group_values) if group_values else None,
                    ))

        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO events (
                    event_id, source_batch, host, event_time, ingested_at,
                    is_matched, matched_rules, raw_json,
                    user_name, src_ip, dst_ip, process, event_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            if hit_rows:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO rule_hits
                        (event_id, rule_title, source_batch, event_time, group_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    hit_rows,
                )
            self._conn.commit()
        return row_id_to_event_id

    def link_events_to_alerts(self, event_id_to_alert_id: dict[str, str]) -> int:
        """Проставляет events.alert_id - основа цепочки event -> alert -> incident (см.
        link_alerts_to_incident) вместо сопоставления по значению "сущности". Зовётся
        app/main.py:_process_batch СРАЗУ после store.upsert_alerts (там уже известны настоящие
        alert_id - и вновь созданные, и переиспользованные по dedup_key), но ДО обработки
        link_specs correlation-инцидентов этого же батча. Пустой словарь - no-op."""
        if not event_id_to_alert_id:
            return 0
        with self._lock:
            cur = self._conn.executemany(
                "UPDATE events SET alert_id = ? WHERE event_id = ?",
                [(alert_id, event_id) for event_id, alert_id in event_id_to_alert_id.items()],
            )
            self._conn.commit()
        return cur.rowcount

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
        mode: str | None = None,
        distinct_field: str | None = None,
        sample_limit: int = 10,
    ) -> dict[str, Any]:
        """
        Точная оценка ОДНОГО (correlation-правило, group-by-ключ) сочетания в пределах окна
        [time_from, time_to] (нормализованные строки, см. _normalize_event_time - сравниваются
        простым BETWEEN, использует idx_rule_hits_lookup как range-scan) и одного source_batch
        (корреляция считается "в рамках одного источника", см. CLAUDE.md). Вызывается ФАЗОЙ 2
        двухфазного счёта (app/detection/correlation.py) - точная перепроверка кандидатов,
        прошедших грубый порог evaluate_correlation_windows (фаза 1).

        Счёт - ИСКЛЮЧИТЕЛЬНО по rule_hits.group_json, БЕЗ JOIN к events: group_json уже несёт
        денормализованные значения нужных полей (group-by ∪ condition.field, см.
        store_events/insert_correlation_hits), поэтому стоимость определяется плотностью
        попаданий в окне, а НЕ размером events/БД в целом (обязательное требование, см.
        CLAUDE.md/docs/spec/correlation.md). JOIN к events нужен ТОЛЬКО для sample_events
        (реальный контент события для карточки алерта) - отдельный маленький запрос
        (LIMIT sample_limit), не влияющий на стоимость счёта.

        mode: "events" (по умолчанию) - COUNT(*) (event_count); "distinct_values" - COUNT(DISTINCT
        json_extract(group_json, distinct_field)) (value_count, mode подставляется автоматически,
        если distinct_field задан, а mode - нет); "distinct_rules" - COUNT(DISTINCT rule_title)
        (temporal/temporal_ordered - "сколько РАЗНЫХ ссылок правила видели в окне").

        base_rule_titles - OR по всем title'ам, которые эта correlation ссылается. group_by/
        key_values - параллельные списки: поле группировки -> конкретное значение ключа.
        """
        if not base_rule_titles or not group_by or len(group_by) != len(key_values):
            return {"count": 0, "sample_events": [], "event_ids": []}
        effective_mode = mode or ("distinct_values" if distinct_field else "events")

        rule_placeholders = ",".join("?" * len(base_rule_titles))
        key_clauses: list[str] = []
        key_params: list[Any] = []
        for field, value in zip(group_by, key_values):
            key_clauses.append("json_extract(h.group_json, ?) = ?")
            key_params += [_group_json_path(field), str(value)]
        where_sql = " AND ".join([
            f"h.rule_title IN ({rule_placeholders})",
            "h.source_batch = ?",
            "h.event_time BETWEEN ? AND ?",
            *key_clauses,
        ])
        base_params: list[Any] = [*base_rule_titles, source_batch, time_from, time_to, *key_params]

        if effective_mode == "distinct_values":
            if not distinct_field:
                return {"count": 0, "sample_events": [], "event_ids": []}
            count_sql = (
                f"SELECT COUNT(DISTINCT json_extract(h.group_json, ?)) AS c "
                f"FROM rule_hits h WHERE {where_sql}"
            )
            count_params = [_group_json_path(distinct_field), *base_params]
        elif effective_mode == "distinct_rules":
            count_sql = f"SELECT COUNT(DISTINCT h.rule_title) AS c FROM rule_hits h WHERE {where_sql}"
            count_params = base_params
        else:
            count_sql = f"SELECT COUNT(*) AS c FROM rule_hits h WHERE {where_sql}"
            count_params = base_params

        sample_sql = (
            f"SELECT e.raw_json FROM rule_hits h JOIN events e ON e.event_id = h.event_id "
            f"WHERE {where_sql} ORDER BY h.event_time ASC LIMIT ?"
        )
        # event_id ВСЕХ попаданий окна (не усечено sample_limit'ом, в отличие от sample_events) -
        # без JOIN, event_id уже есть прямо в rule_hits. Реальные (события базовых правил) и
        # синтетические "corr:{dedup}:{title}:{anchor_time}" (сработки других correlation-записей
        # в цепочках, см. app/detection/correlation.py) вперемешку - разбор на два вида делает
        # store.link_alerts_to_incident. Основа цепочки event -> alert -> incident без "сущностей"
        # (см. докстринг link_alerts_to_incident, docs/spec/incidents.md).
        event_ids_sql = f"SELECT h.event_id FROM rule_hits h WHERE {where_sql}"
        with self._read_lock:
            count = self._read_conn.execute(count_sql, count_params).fetchone()["c"]
            sample_rows = self._read_conn.execute(sample_sql, [*base_params, sample_limit]).fetchall()
            event_id_rows = self._read_conn.execute(event_ids_sql, base_params).fetchall()
        event_ids = [row["event_id"] for row in event_id_rows]
        sample_events = []
        for row in sample_rows:
            try:
                sample_events.append(json.loads(row["raw_json"]))
            except (TypeError, json.JSONDecodeError):
                continue
        return {"count": count, "sample_events": sample_events, "event_ids": event_ids}

    def evaluate_correlation_windows(
        self,
        rule_titles: list[str],
        source_batch: str,
        time_from: str,
        time_to: str,
        group_by: list[str],
        mode: str,
        distinct_field: str | None = None,
    ) -> dict[tuple[Any, ...], int]:
        """
        ФАЗА 1 двухфазного счёта (app/detection/correlation.py): ОДИН GROUP BY-запрос по ВСЕМ
        group-by-ключам сразу вместо запроса на каждый ключ (было O(K*H) с JOIN к events на
        каждый ключ - см. CLAUDE.md/docs/spec/correlation.md) - без JOIN к events, читает
        только rule_hits (индекс idx_rule_hits_lookup даёт узкий диапазон строк по (rule_title,
        source_batch, event_time), GROUP BY дальше работает над этим маленьким набором в
        памяти). Стоимость определяется плотностью попаданий в окне, НЕ размером БД.

        Окно [time_from, time_to] здесь - ОБЪЕДИНЁННОЕ окно нескольких ключей сразу (могло бы
        завысить счёт отдельных ключей с более ранним anchor, чем у самого позднего в группе) -
        это ГРУБАЯ оценка для короткого замыкания: ключи, прошедшие здесь порог, перепроверяются
        ТОЧНО (evaluate_correlation_window) в СВОЁМ индивидуальном окне.

        mode: "events" - COUNT(*); "distinct_values" - COUNT(DISTINCT json_extract(group_json,
        distinct_field)); "distinct_rules" - COUNT(DISTINCT rule_title). Возвращает
        {tuple(значения group_by): count} - ключи с хотя бы одним None-полем (group_json не
        содержал нужного поля) пропускаются, они не образуют валидный ключ группировки.
        """
        if not rule_titles or not group_by:
            return {}
        if mode == "distinct_values" and not distinct_field:
            return {}

        rule_placeholders = ",".join("?" * len(rule_titles))
        key_params: list[Any] = []
        key_cols = []
        for i, field in enumerate(group_by):
            key_cols.append(f"json_extract(group_json, ?) AS k{i}")
            key_params.append(_group_json_path(field))
        key_cols_sql = ", ".join(key_cols)
        group_cols_sql = ", ".join(f"k{i}" for i in range(len(group_by)))

        if mode == "distinct_values":
            agg_sql = "COUNT(DISTINCT json_extract(group_json, ?)) AS c"
            agg_params = [_group_json_path(distinct_field)]
        elif mode == "distinct_rules":
            agg_sql = "COUNT(DISTINCT rule_title) AS c"
            agg_params = []
        else:
            agg_sql = "COUNT(*) AS c"
            agg_params = []

        query = (
            f"SELECT {key_cols_sql}, {agg_sql} FROM rule_hits "
            f"WHERE rule_title IN ({rule_placeholders}) AND source_batch = ? "
            f"AND event_time BETWEEN ? AND ? "
            f"GROUP BY {group_cols_sql}"
        )
        params = [*key_params, *agg_params, *rule_titles, source_batch, time_from, time_to]
        with self._read_lock:
            rows = self._read_conn.execute(query, params).fetchall()
        result: dict[tuple[Any, ...], int] = {}
        for row in rows:
            key = tuple(row[f"k{i}"] for i in range(len(group_by)))
            if any(v is None for v in key):
                continue
            result[key] = row["c"]
        return result

    def fetch_correlation_hit_sequence(
        self,
        rule_titles: list[str],
        source_batch: str,
        time_from: str,
        time_to: str,
        group_by: list[str],
        key_values: tuple[Any, ...],
        limit: int = 500,
    ) -> list[tuple[str, str]]:
        """(rule_title, event_time) для ОДНОГО group-by-ключа, по возрастанию времени - только
        для temporal_ordered: после того как evaluate_correlation_windows(mode="distinct_rules")
        уже отобрал кандидатов с числом уникальных rule_title >= числа ссылок, здесь -
        РЕАЛЬНЫЙ порядок появления (жадное сопоставление подпоследовательности делает вызывающая
        сторона, app/detection/correlation.py: SQL не выражает "порядок Sigma-ссылок" напрямую,
        а строк на выходе и так немного - окно уже узкое, limit подстраховка от аномалий)."""
        if not rule_titles or not group_by or len(group_by) != len(key_values):
            return []
        rule_placeholders = ",".join("?" * len(rule_titles))
        where = ["rule_title IN (" + rule_placeholders + ")", "source_batch = ?", "event_time BETWEEN ? AND ?"]
        params: list[Any] = [*rule_titles, source_batch, time_from, time_to]
        for field, value in zip(group_by, key_values):
            where.append("json_extract(group_json, ?) = ?")
            params += [_group_json_path(field), str(value)]
        query = (
            f"SELECT rule_title, event_time FROM rule_hits WHERE {' AND '.join(where)} "
            f"ORDER BY event_time ASC LIMIT ?"
        )
        with self._read_lock:
            rows = self._read_conn.execute(query, [*params, limit]).fetchall()
        return [(row["rule_title"], row["event_time"]) for row in rows]

    def fetch_correlation_hits(
        self,
        rule_titles: list[str],
        source_batch: str,
        time_from: str,
        time_to: str,
        group_by: list[str],
        keys: list[tuple[str, ...]],
        distinct_field: str | None = None,
    ) -> list[tuple[tuple[str, ...], str, str, str | None]]:
        """Все попадания base-правил в окне [time_from, time_to] для source_batch, СУЖЕННЫЕ до
        перечисленных group-by-ключей (keys - список кортежей строковых значений). Возвращает
        [(ключ-кортеж, event_time, rule_title, значение distinct_field|None)], по возрастанию
        event_time. Один индексный range-scan по idx_rule_hits_lookup + OR-фильтр по ключам -
        стоимость от плотности попаданий В ОКНЕ для ЭТИХ ключей, не от размера БД (тот же
        принцип, что у evaluate_correlation_windows). Строки с None в любом компоненте ключа
        отбрасываются (group_json не содержал поля).

        Используется A3-оценкой (app/detection/correlation.py): вместо SQL-счёта на каждое
        под-окно - один проход скользящим окном в памяти по всем кандидатным точкам-якорям.
        """
        if not rule_titles or not group_by or not keys:
            return []
        rule_ph = ",".join("?" * len(rule_titles))
        sel_cols: list[str] = []
        sel_params: list[Any] = []
        for i, field in enumerate(group_by):
            sel_cols.append(f"json_extract(group_json, ?) AS k{i}")
            sel_params.append(_group_json_path(field))
        select_sql = ", ".join(sel_cols) + ", event_time, rule_title"
        params: list[Any] = list(sel_params)
        if distinct_field:
            select_sql += ", json_extract(group_json, ?) AS dval"
            params.append(_group_json_path(distinct_field))

        params += [*rule_titles, source_batch, time_from, time_to]
        where = [
            f"rule_title IN ({rule_ph})",
            "source_batch = ?",
            "event_time BETWEEN ? AND ?",
        ]
        # Сужение до кандидатных ключей: OR по каждому ключу, AND по его полям. Путь поля -
        # bound-параметр (_group_json_path, как везде в этом модуле), значение ключа - тоже.
        or_clauses: list[str] = []
        for kv in keys:
            parts: list[str] = []
            for field, val in zip(group_by, kv):
                parts.append("json_extract(group_json, ?) = ?")
                params += [_group_json_path(field), str(val)]
            if parts:
                or_clauses.append("(" + " AND ".join(parts) + ")")
        if or_clauses:
            where.append("(" + " OR ".join(or_clauses) + ")")

        query = (
            f"SELECT {select_sql} FROM rule_hits WHERE {' AND '.join(where)} "
            f"ORDER BY event_time ASC"
        )
        with self._read_lock:
            rows = self._read_conn.execute(query, params).fetchall()
        out: list[tuple[tuple[str, ...], str, str, str | None]] = []
        for row in rows:
            key = tuple(row[f"k{i}"] for i in range(len(group_by)))
            if any(v is None for v in key):
                continue
            out.append((
                tuple(str(v) for v in key),
                row["event_time"],
                row["rule_title"],
                row["dval"] if distinct_field else None,
            ))
        return out

    def insert_correlation_hits(self, rows: list[tuple[str, str, str, str, str | None]]) -> None:
        """Записывает сработавшую корреляцию как обычное попадание в rule_hits: (синтетический
        event_id якоря, title самой корреляции, source_batch, нормализованный event_time якоря,
        group_json - значения ЕЁ СОБСТВЕННЫХ group-by полей). Так родительская корреляция при
        цепочке (correlation ссылается на другую correlation) видит потомка ТЕМ ЖЕ запросом,
        что и обычное базовое правило - см. app/detection/correlation.py:evaluate_batch.
        INSERT OR IGNORE - идемпотентно при повторных flush'ах с тем же синтетическим event_id."""
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO rule_hits
                    (event_id, rule_title, source_batch, event_time, group_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._conn.commit()

    def delete_events_older_than(self, cutoff: str, chunk: int = 5000) -> int:
        """Ретеншн (см. docs/spec/storage.md): удаляет events с ingested_at < cutoff (НЕ
        event_time - тот сырой формат источника, может отсутствовать или быть в прошлом/будущем
        при replay исторических датасетов; ingested_at - наше собственное время приёма, всегда
        ISO8601 UTC с 'timezone.utc.isoformat()', монотонно растёт с ingest - надёжный ключ
        ретеншна независимо от качества данных источника; cutoff должен быть в ТОМ ЖЕ формате
        для корректного строкового сравнения). Порциями по `chunk` строк, лок на запись
        (self._lock) берётся и отпускается НА КАЖДУЮ порцию отдельно (а не на весь проход
        разом) - иначе ingest-воркер не смог бы писать новые события, пока идёт чистка
        многомиллионной таблицы. idx_events_ingested (см. _migrate) держит это range-scan'ом,
        а не полным сканом на каждой порции. Осиротевшие rule_hits чистятся ОДНИМ проходом в
        конце, не на каждую порцию - полное сканирование rule_hits незачем повторять. alerts не
        трогает - у алертов свой жизненный цикл (см. CLAUDE.md/план Этапа A)."""
        total = 0
        while True:
            with self._lock:
                cur = self._conn.execute(
                    "DELETE FROM events WHERE event_id IN "
                    "(SELECT event_id FROM events WHERE ingested_at < ? LIMIT ?)",
                    (cutoff, chunk),
                )
                deleted = cur.rowcount
                self._conn.commit()
            total += deleted
            if deleted < chunk:
                break
        if total:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM rule_hits WHERE event_id NOT IN (SELECT event_id FROM events)"
                )
                self._conn.commit()
        return total

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
                            entities, event_count, sample_events
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert.alert_id, alert.dedup_key, alert.created_at.isoformat(),
                            alert.engine, alert.source_batch, alert.host,
                            alert.rule.rule_id, alert.rule.title, alert.rule.level.value,
                            json.dumps(alert.rule.mitre_techniques), alert.rule.description,
                            json.dumps(alert.entities.model_dump()), alert.event_count,
                            json.dumps(alert.sample_events, default=str),
                        ),
                    )
                count += 1
            self._conn.commit()
        return count

    # ------------------------------------------------------------------ Incidents / Investigations

    @staticmethod
    def _incident_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        """Строка incidents наружу: JSON-колонки распарсены (как entities у алертов)."""
        d = dict(row)
        for col in ("group_key", "member_rule_titles", "mitre_techniques", "entities", "sample_events"):
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (TypeError, ValueError):
                    d[col] = {} if col in ("group_key", "entities") else []
        return d

    def upsert_incidents(self, incidents: list[Incident]) -> list[tuple[str, bool]]:
        """Создаёт/обновляет строки incidents по dedup_key (фиксированный бакет по timespan,
        см. схему). Для существующей строки - OVERWRITE-семантика окна: severity =
        Severity.roll_up([старое, новое]), window_start = min, window_end = max, обновляются
        sample_events/entities/mitre_techniques/member_rule_titles/title, updated_at = сейчас.
        alert_count здесь НЕ трогается - его досчитывает link_alerts_to_incident после привязки
        алертов. Возврат - [(incident_id, was_new), ...] в порядке входа (evaluate_batch по
        was_new решает, ре-энкьюить ли расследование)."""
        result: list[tuple[str, bool]] = []
        now = utcnow_naive().isoformat()
        with self._lock:
            cur = self._conn.cursor()
            for inc in incidents:
                cur.execute(
                    "SELECT incident_id, severity, window_start, window_end FROM incidents WHERE dedup_key = ?",
                    (inc.dedup_key,),
                )
                existing = cur.fetchone()
                if existing:
                    severity = Severity.roll_up([existing["severity"], inc.severity]).value
                    window_start = min(existing["window_start"], inc.window_start)
                    window_end = max(existing["window_end"], inc.window_end)
                    cur.execute(
                        """
                        UPDATE incidents SET
                            severity = ?, title = ?, window_start = ?, window_end = ?,
                            member_rule_titles = ?, mitre_techniques = ?, entities = ?,
                            sample_events = ?, updated_at = ?
                        WHERE dedup_key = ?
                        """,
                        (
                            severity, inc.title, window_start, window_end,
                            json.dumps(inc.member_rule_titles), json.dumps(inc.mitre_techniques),
                            json.dumps(inc.entities.model_dump()),
                            json.dumps(inc.sample_events, default=str), now, inc.dedup_key,
                        ),
                    )
                    result.append((existing["incident_id"], False))
                else:
                    cur.execute(
                        """
                        INSERT INTO incidents (
                            incident_id, dedup_key, incident_type, title, severity, status,
                            source_batch, ruleset_path, correlation_rule_id, correlation_rule_title,
                            group_key, member_rule_titles, window_start, window_end, window_bucket,
                            alert_count, mitre_techniques, entities, sample_events, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inc.incident_id, inc.dedup_key, inc.incident_type, inc.title,
                            inc.severity.value, inc.status, inc.source_batch, inc.ruleset_path,
                            inc.correlation_rule_id, inc.correlation_rule_title,
                            json.dumps(inc.group_key), json.dumps(inc.member_rule_titles),
                            inc.window_start, inc.window_end, inc.window_bucket, inc.alert_count,
                            json.dumps(inc.mitre_techniques), json.dumps(inc.entities.model_dump()),
                            json.dumps(inc.sample_events, default=str),
                            inc.created_at.isoformat(), inc.updated_at.isoformat(),
                        ),
                    )
                    result.append((inc.incident_id, True))
            self._conn.commit()
        return result

    def link_alerts_to_incident(
        self,
        incident_id: str,
        source_batch: str,
        event_ids: list[str],
    ) -> int:
        """Привязывает уже сохранённые алерты к инциденту (проставляет alerts.incident_id) и
        досчитывает incidents.alert_count + roll-up severity по привязанным member-алертам.

        event_ids - ВСЕ event_id, реально вошедшие в выигрышное окно correlation-правила (см.
        app/detection/correlation.py:_evaluate_correlation_rule/evaluate_correlation_window) -
        цепочка "какое событие вошло в окно -> какой алерт его поглотил", ЗАМЕНА старому
        сопоставлению по значению "сущности" (host IN (...) OR entities LIKE '%...%') - то молча
        не находило алерты, если group-by correlation-правила был не по хосту и не по одной из
        5 жёстко зашитых категорий _extract_entities (напр. DNS QueryName, путь ключа реестра -
        ни то ни другое не "user"/"host"/"src_ip"/"dst_ip"/"process", см. docs/spec/incidents.md).

        Два вида event_id вперемешку: (1) настоящий - events.event_id (сработка БАЗОВОГО
        правила) - резолвится через events.alert_id (проставляет app/main.py:_process_batch
        сразу после store.upsert_alerts, см. link_events_to_alerts); (2) синтетический
        "corr:{dedup}:{title}:{anchor_time}" (сработка ДРУГОЙ correlation-записи в цепочке, см.
        докстринг correlation.py) - dedup_key ВСЕГДА второй ":"-сегмент (формат гарантирован
        кодом, который его строит), резолвится прямым поиском alerts.dedup_key. Если та
        correlation была инцидентной (не рекомендуется - инцидентная запись должна быть
        терминальной в цепочке, см. CLAUDE.md), её dedup_key принадлежит incidents, не alerts -
        просто не находится, без падения.

        events НЕ трогаем. Временнóго сужения по created_at НЕТ намеренно: alerts.created_at -
        наивный wall-clock приёма, а окно корреляции считается по event_time источника; при
        replay исторических датасетов это разные шкалы (см. docs/spec/incidents.md, "Известные
        ограничения"). Возврат - число реально привязанных алертов."""
        if not event_ids:
            return 0
        real_ids: list[str] = []
        synthetic_dedup_keys: set[str] = set()
        for eid in event_ids:
            if eid.startswith("corr:"):
                parts = eid.split(":", 2)
                if len(parts) >= 2 and parts[1]:
                    synthetic_dedup_keys.add(parts[1])
            else:
                real_ids.append(eid)

        with self._lock:
            alert_ids: set[str] = set()
            if real_ids:
                ph = ",".join("?" * len(real_ids))
                rows = self._conn.execute(
                    f"SELECT DISTINCT alert_id FROM events WHERE event_id IN ({ph}) AND alert_id IS NOT NULL",
                    real_ids,
                ).fetchall()
                alert_ids.update(r["alert_id"] for r in rows)
            if synthetic_dedup_keys:
                ph2 = ",".join("?" * len(synthetic_dedup_keys))
                rows2 = self._conn.execute(
                    f"SELECT alert_id FROM alerts WHERE dedup_key IN ({ph2})",
                    list(synthetic_dedup_keys),
                ).fetchall()
                alert_ids.update(r["alert_id"] for r in rows2)
            if not alert_ids:
                return 0

            ph3 = ",".join("?" * len(alert_ids))
            cur = self._conn.execute(
                f"UPDATE alerts SET incident_id = ? "
                f"WHERE incident_id IS NULL AND source_batch = ? AND alert_id IN ({ph3})",
                (incident_id, source_batch, *alert_ids),
            )
            linked = cur.rowcount
            rows = self._conn.execute(
                "SELECT rule_level FROM alerts WHERE incident_id = ?", (incident_id,)
            ).fetchall()
            sev_row = self._conn.execute(
                "SELECT severity FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if sev_row is not None:
                new_sev = Severity.roll_up([sev_row["severity"], *(r["rule_level"] for r in rows)]).value
                self._conn.execute(
                    "UPDATE incidents SET alert_count = ?, severity = ?, updated_at = ? WHERE incident_id = ?",
                    (len(rows), new_sev, utcnow_naive().isoformat(), incident_id),
                )
            self._conn.commit()
        return linked

    def enqueue_investigation(self, incident_id: str, requeue_terminal: bool = True) -> str | None:
        """Ставит расследование инцидента в очередь. Строка queued/running уже есть -> None
        (не дублируем). Строка в терминальном статусе (done/error) и requeue_terminal -> сброс
        в queued (новый контекст для агента), тот же investigation_id. Иначе - INSERT новой
        queued-строки. Возврат - investigation_id или None."""
        now = utcnow_naive().isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT investigation_id, status FROM investigations WHERE incident_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            if row is not None and row["status"] in ("queued", "running"):
                return None
            if row is not None and requeue_terminal:
                self._conn.execute(
                    "UPDATE investigations SET status = 'queued', verdict = NULL, rationale = '', "
                    "confidence = NULL, steps = '[]', error = '', started_at = NULL, "
                    "finished_at = NULL WHERE investigation_id = ?",
                    (row["investigation_id"],),
                )
                self._conn.commit()
                return row["investigation_id"]
            inv = Investigation(incident_id=incident_id)
            self._conn.execute(
                "INSERT INTO investigations (investigation_id, incident_id, status, created_at) "
                "VALUES (?, ?, 'queued', ?)",
                (inv.investigation_id, incident_id, now),
            )
            self._conn.commit()
            return inv.investigation_id

    def list_incidents(
        self,
        status: str | None = None,
        incident_type: str | None = None,
        source_batch: str | None = None,
        severity: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        q: str | None = None,
        sort_by: str | None = None,
        sort_dir: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """q - подстрока по correlation_rule_title ("Инцидент" в UI) / title ("Описание"),
        регистронезависимо, ВКЛЮЧАЯ кириллицу (см. _incident_matches_query - тот же паттерн, что
        rules_catalog.paginate_rules у Sigma-правил: SQLite LIKE/LOWER регистронезависимы
        только для ASCII, для кириллицы нужен Python str.lower()). При заданном q LIMIT/OFFSET
        накладываются уже В ПАМЯТИ, после фильтра по q - инцидентов мало (единицы работы
        агента, не сырые события, "N алертов -> M инцидентов, M ≪ N"), тянуть их все и
        фильтровать в Python дёшево."""
        query = (
            "SELECT i.*, "
            "(SELECT v.status FROM investigations v WHERE v.incident_id = i.incident_id "
            " ORDER BY v.created_at DESC LIMIT 1) AS investigation_status "
            "FROM incidents i WHERE 1=1"
        )
        params: list[Any] = []
        if status:
            query += " AND i.status = ?"
            params.append(status)
        if incident_type:
            query += " AND i.incident_type = ?"
            params.append(incident_type)
        if source_batch:
            query += " AND i.source_batch = ?"
            params.append(source_batch)
        if severity:
            query += " AND i.severity = ?"
            params.append(severity)
        if time_from:
            query += " AND i.created_at >= ?"
            params.append(time_from)
        if time_to:
            query += " AND i.created_at <= ?"
            params.append(time_to)
        order = _order_clause(sort_by, sort_dir, _INCIDENT_SORT_COLUMNS, "ORDER BY created_at DESC")
        if q:
            query += f" {order}"
            with self._read_lock:
                rows = [self._incident_row(r) for r in self._read_conn.execute(query, params).fetchall()]
            rows = [r for r in rows if _incident_matches_query(r, q)][offset:offset + limit]
        else:
            query += f" {order} LIMIT ? OFFSET ?"
            params += [limit, offset]
            with self._read_lock:
                rows = [self._incident_row(r) for r in self._read_conn.execute(query, params).fetchall()]
        for row in rows:
            row.pop("sample_events", None)
        return rows

    def count_incidents(
        self,
        status: str | None = None,
        incident_type: str | None = None,
        source_batch: str | None = None,
        severity: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        q: str | None = None,
    ) -> int:
        if q:
            # Точный count при активном q требует того же Python-фильтра, что list_incidents -
            # SQL COUNT(*) тут не годится (см. докстринг list_incidents про кириллицу).
            rows = self.list_incidents(
                status=status, incident_type=incident_type, source_batch=source_batch,
                severity=severity, time_from=time_from, time_to=time_to, q=q,
                limit=1_000_000, offset=0,
            )
            return len(rows)
        query = "SELECT COUNT(*) AS c FROM incidents WHERE 1=1"
        params: list[Any] = []
        for col, val in (
            ("status", status), ("incident_type", incident_type),
            ("source_batch", source_batch), ("severity", severity),
        ):
            if val:
                query += f" AND {col} = ?"
                params.append(val)
        if time_from:
            query += " AND created_at >= ?"
            params.append(time_from)
        if time_to:
            query += " AND created_at <= ?"
            params.append(time_to)
        with self._read_lock:
            return int(self._read_conn.execute(query, params).fetchone()["c"])

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Полная карточка инцидента: строка incidents (JSON-колонки распарсены) + member_alerts
        (облегчённые строки привязанных алертов) + investigation (последняя строка расследования)."""
        with self._read_lock:
            row = self._read_conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            result = self._incident_row(row)
            result["member_alerts"] = [
                dict(r) for r in self._read_conn.execute(
                    "SELECT alert_id, rule_title, rule_level, host, event_count, created_at "
                    "FROM alerts WHERE incident_id = ? ORDER BY created_at ASC",
                    (incident_id,),
                ).fetchall()
            ]
            inv = self._read_conn.execute(
                "SELECT * FROM investigations WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
        result["investigation"] = self._investigation_row(inv) if inv is not None else None
        return result

    def update_incident_status(self, incident_id: str, status: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (status, utcnow_naive().isoformat(), incident_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    @staticmethod
    def _investigation_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        d = dict(row)
        if isinstance(d.get("steps"), str):
            try:
                d["steps"] = json.loads(d["steps"])
            except (TypeError, ValueError):
                d["steps"] = []
        return d

    def list_pending_investigations(self, limit: int = 20) -> list[dict[str, Any]]:
        """Расследования в статусе queued, FIFO по created_at - для фоновой джобы (app/incidents.py)."""
        with self._read_lock:
            return [
                self._investigation_row(r) for r in self._read_conn.execute(
                    "SELECT * FROM investigations WHERE status = 'queued' ORDER BY created_at ASC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]

    def get_investigation(self, incident_id: str) -> dict[str, Any] | None:
        with self._read_lock:
            row = self._read_conn.execute(
                "SELECT * FROM investigations WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
        return self._investigation_row(row) if row is not None else None

    def update_investigation(self, investigation_id: str, **fields: Any) -> bool:
        """Точечное обновление строки расследования джобой. Только whitelisted-поля
        (_INVESTIGATION_UPDATABLE); steps сериализуется в JSON."""
        cols = [k for k in fields if k in _INVESTIGATION_UPDATABLE]
        if not cols:
            return False
        sets = ", ".join(f"{c} = ?" for c in cols)
        values = [json.dumps(fields[c]) if c == "steps" else fields[c] for c in cols]
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE investigations SET {sets} WHERE investigation_id = ?",
                (*values, investigation_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

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
        """Полное удаление источника: все events, alerts, rule_hits, incidents И investigations
        с этим source_batch (не только события) - source_batch не отдельная сущность/таблица,
        просто общая метка на этих таблицах, поэтому "удалить источник" технически значит
        удалить всё с этой меткой. rule_hits важно чистить здесь же: иначе при повторном ingest
        под ТЕМ ЖЕ source_batch (частый случай в ручном тестировании, см. CLAUDE.md) осиротевшие
        строки от УДАЛЁННОГО батча продолжали бы учитываться в evaluate_correlation_window (окно
        фильтруется по source_batch+event_time, не по тому, жив ли ещё сам event_id в events -
        JOIN просто не вернёт по нему raw_json, но COUNT(*) без JOIN их всё равно посчитал бы;
        здесь JOIN есть, так что реального искажения счётчика нет, но мусор всё равно накапливался
        бы вечно). incidents/investigations (Этап 4) привязаны к одному source_batch - чистим их
        тем же проходом (investigations - по incident_id удаляемых инцидентов, своей метки
        source_batch у них нет). Таблица sources под это правило НЕ подпадает намеренно: снять
        регистрацию источника - отдельное действие (delete_source)."""
        with self._lock:
            incident_ids = [
                r["incident_id"] for r in self._conn.execute(
                    "SELECT incident_id FROM incidents WHERE source_batch = ?", (source_batch,)
                )
            ]
            if incident_ids:
                placeholders = ",".join("?" * len(incident_ids))
                self._conn.execute(
                    f"DELETE FROM investigations WHERE incident_id IN ({placeholders})", incident_ids
                )
            incidents_deleted = self._conn.execute(
                "DELETE FROM incidents WHERE source_batch = ?", (source_batch,)
            ).rowcount
            events_deleted = self._conn.execute(
                "DELETE FROM events WHERE source_batch = ?", (source_batch,)
            ).rowcount
            alerts_deleted = self._conn.execute(
                "DELETE FROM alerts WHERE source_batch = ?", (source_batch,)
            ).rowcount
            self._conn.execute("DELETE FROM rule_hits WHERE source_batch = ?", (source_batch,))
            self._conn.commit()
        return {
            "events_deleted": events_deleted,
            "alerts_deleted": alerts_deleted,
            "incidents_deleted": incidents_deleted,
        }

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
