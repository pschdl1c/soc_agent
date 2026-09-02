"""
База знаний (Knowledge Base) - доступ к матрице MITRE ATT&CK на чтение.

Данные лежат в ОТДЕЛЬНОМ SQLite-файле `kb.db` (путь - `config.KB_DB_PATH`), который собирается
на этапе `docker build` скриптом `scripts/build_kb.py` и вшивается в образ read-only. Этот модуль
файл НЕ создаёт и НЕ пишет в него - только открывает `mode=ro` и читает.

Назначение:
  * вкладка «База знаний» в UI (`GET /kb/mitre/*`) - матрица тактик/техник, карточка техники;
  * обогащение карточки алерта (`enrich_techniques` из `main.py:get_alert`) - гибрид: техника
    найдена в KB -> отдаём название/тактики/ссылку; не найдена -> помечаем `matched=false`,
    UI покажет сырой тег как раньше;
  * (позже) источник для агентского tool'а `lookup_mitre` - те же query-функции.

Если `kb.db` отсутствует (частый случай при локальном запуске без сборки), модуль деградирует
тихо: `available()` -> False, остальные функции возвращают пустой результат / `matched=false`,
исключения наружу не летят.
"""
from __future__ import annotations

import json
import sqlite3
import threading

from app.config import KB_DB_PATH


class KbError(Exception):
    """Ошибка работы с базой знаний (для трансляции в HTTP в app/main.py)."""


_lock = threading.Lock()
_kb_path: str = KB_DB_PATH
_conn: sqlite3.Connection | None = None
_open_attempted = False


# --------------------------------------------------------------------------- соединение


def _ensure_conn_locked() -> sqlite3.Connection | None:
    """Ленивое открытие read-only соединения. Вызывать под _lock. Один неудачный
    заход (файла нет) кэшируется - не долбимся в отсутствующий файл на каждый запрос."""
    global _conn, _open_attempted
    if _conn is not None:
        return _conn
    if _open_attempted:
        return None
    _open_attempted = True
    try:
        conn = sqlite3.connect(f"file:{_kb_path}?mode=ro", uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("SELECT 1 FROM mitre_meta LIMIT 1")  # проверка, что схема на месте
        _conn = conn
        return _conn
    except sqlite3.Error:
        _conn = None
        return None


def configure(path: str | None) -> None:
    """Подменить путь к kb.db и переоткрыть соединение. Нужно тестам; в проде не зовётся.
    path=None -> вернуться к значению из config."""
    global _kb_path
    with _lock:
        _close_locked()
        _kb_path = path or KB_DB_PATH


def _reset() -> None:
    """Сбросить кэш соединения (тесты). Путь не меняет."""
    with _lock:
        _close_locked()


def _close_locked() -> None:
    global _conn, _open_attempted
    if _conn is not None:
        try:
            _conn.close()
        except sqlite3.Error:
            pass
    _conn = None
    _open_attempted = False


# --------------------------------------------------------------------------- запросы


def available() -> bool:
    with _lock:
        return _ensure_conn_locked() is not None


def meta() -> dict:
    """Строки mitre_meta (attack_version / built_at / *_count / source) + флаг available."""
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return {"available": False}
        rows = conn.execute("SELECT key, value FROM mitre_meta").fetchall()
    out: dict = {r["key"]: r["value"] for r in rows}
    out["available"] = True
    return out


def list_tactics() -> list[dict]:
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return []
        rows = conn.execute(
            "SELECT tactic_id, shortname, name, description, url, sort_order "
            "FROM mitre_tactic ORDER BY sort_order, tactic_id"
        ).fetchall()
    return [dict(r) for r in rows]


def matrix() -> dict:
    """Тактики-колонки (в порядке kill-chain) с вложенным списком техник каждой.
    Сабтехники идут сразу за своей базовой техникой (лексикографика technique_id это уже даёт)."""
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return {"available": False, "tactics": []}
        tactics = [
            dict(r)
            for r in conn.execute(
                "SELECT tactic_id, shortname, name, description, url, sort_order "
                "FROM mitre_tactic ORDER BY sort_order, tactic_id"
            )
        ]
        rows = conn.execute(
            "SELECT tt.tactic_shortname AS sn, t.technique_id, t.name, t.is_subtechnique, t.parent_id "
            "FROM mitre_technique_tactic tt "
            "JOIN mitre_technique t ON t.technique_id = tt.technique_id "
            "ORDER BY t.technique_id"
        ).fetchall()
    by_sn: dict[str, list[dict]] = {}
    for r in rows:
        by_sn.setdefault(r["sn"], []).append(
            {
                "technique_id": r["technique_id"],
                "name": r["name"],
                "is_subtechnique": bool(r["is_subtechnique"]),
                "parent_id": r["parent_id"],
            }
        )
    return {
        "available": True,
        "tactics": [{**tac, "techniques": by_sn.get(tac["shortname"], [])} for tac in tactics],
    }


def list_techniques(
    tactic: str | None = None, q: str | None = None, limit: int = 100, offset: int = 0
) -> dict:
    """Плоский список техник с фильтрами: `tactic` (shortname) и `q` (подстрока по id/названию)."""
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return {"available": False, "techniques": [], "total": 0}
        base = "FROM mitre_technique t"
        params: list = []
        where: list[str] = []
        if tactic:
            base += (
                " JOIN mitre_technique_tactic tt ON tt.technique_id = t.technique_id "
                "AND tt.tactic_shortname = ?"
            )
            params.append(tactic)
        if q:
            where.append("(t.technique_id LIKE ? OR t.name LIKE ?)")
            like = f"%{q}%"
            params += [like, like]
        wsql = (" WHERE " + " AND ".join(where)) if where else ""
        total = conn.execute(f"SELECT COUNT(*) {base}{wsql}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT t.technique_id, t.name, t.is_subtechnique, t.parent_id, t.url {base}{wsql} "
            f"ORDER BY t.technique_id LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return {
        "available": True,
        "total": total,
        "techniques": [
            {
                "technique_id": r["technique_id"],
                "name": r["name"],
                "is_subtechnique": bool(r["is_subtechnique"]),
                "parent_id": r["parent_id"],
                "url": r["url"],
            }
            for r in rows
        ],
    }


def get_technique(technique_id: str) -> dict | None:
    """Полная карточка техники: описание, detection, платформы, data sources + тактики,
    митигации и сабтехники. Это же - форма ответа будущего агентского tool'а."""
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return None
        row = conn.execute(
            "SELECT * FROM mitre_technique WHERE technique_id = ?", (technique_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["is_subtechnique"] = bool(d["is_subtechnique"])
        d["platforms"] = json.loads(d["platforms"] or "[]")
        d["data_sources"] = json.loads(d["data_sources"] or "[]")
        d["tactics"] = [
            dict(r)
            for r in conn.execute(
                "SELECT ta.tactic_id, ta.shortname, ta.name FROM mitre_technique_tactic tt "
                "JOIN mitre_tactic ta ON ta.shortname = tt.tactic_shortname "
                "WHERE tt.technique_id = ? ORDER BY ta.sort_order",
                (technique_id,),
            )
        ]
        d["mitigations"] = [
            dict(r)
            for r in conn.execute(
                "SELECT m.mitigation_id, m.name, m.url FROM mitre_technique_mitigation tm "
                "JOIN mitre_mitigation m ON m.mitigation_id = tm.mitigation_id "
                "WHERE tm.technique_id = ? ORDER BY m.mitigation_id",
                (technique_id,),
            )
        ]
        d["subtechniques"] = [
            dict(r)
            for r in conn.execute(
                "SELECT technique_id, name, url FROM mitre_technique WHERE parent_id = ? "
                "ORDER BY technique_id",
                (technique_id,),
            )
        ]
    return d


def _normalize_tags(tags: list[str] | None) -> list[tuple[str, str]]:
    """[`attack.t1059.001`, ...] -> [(исходный_тег, `T1059.001`), ...]. Не-attack.t* игнор."""
    out: list[tuple[str, str]] = []
    for tag in tags or []:
        s = str(tag)
        low = s.lower()
        if not low.startswith("attack.t"):
            continue
        out.append((s, low.split(".", 1)[1].upper()))
    return out


def enrich_techniques(tags: list[str] | None) -> list[dict]:
    """Гибридный матчинг тегов правила против KB. На каждый `attack.t*` тег:
      * найдено в KB -> {tag, technique_id, name, url, is_subtechnique, parent_id, tactics, matched=True}
      * не найдено / KB недоступна -> {tag, technique_id, matched=False}
    O(1) запросов независимо от числа тегов."""
    norm = _normalize_tags(tags)
    if not norm:
        return []
    with _lock:
        conn = _ensure_conn_locked()
        if conn is None:
            return [{"tag": tag, "technique_id": tid, "matched": False} for tag, tid in norm]
        ids = list({tid for _, tid in norm})
        ph = ",".join("?" * len(ids))
        found = {
            r["technique_id"]: r
            for r in conn.execute(
                f"SELECT technique_id, name, url, is_subtechnique, parent_id "
                f"FROM mitre_technique WHERE technique_id IN ({ph})",
                ids,
            )
        }
        tac_by_tid: dict[str, list[dict]] = {}
        if found:
            ph2 = ",".join("?" * len(found))
            for r in conn.execute(
                f"SELECT tt.technique_id AS tid, ta.tactic_id, ta.shortname, ta.name "
                f"FROM mitre_technique_tactic tt "
                f"JOIN mitre_tactic ta ON ta.shortname = tt.tactic_shortname "
                f"WHERE tt.technique_id IN ({ph2}) ORDER BY ta.sort_order",
                list(found),
            ):
                tac_by_tid.setdefault(r["tid"], []).append(
                    {"tactic_id": r["tactic_id"], "shortname": r["shortname"], "name": r["name"]}
                )
    out: list[dict] = []
    for tag, tid in norm:
        rec = found.get(tid)
        if rec is None:
            out.append({"tag": tag, "technique_id": tid, "matched": False})
        else:
            out.append(
                {
                    "tag": tag,
                    "technique_id": tid,
                    "name": rec["name"],
                    "url": rec["url"],
                    "is_subtechnique": bool(rec["is_subtechnique"]),
                    "parent_id": rec["parent_id"],
                    "tactics": tac_by_tid.get(tid, []),
                    "matched": True,
                }
            )
    return out
