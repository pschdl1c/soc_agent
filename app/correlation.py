"""
Стейтфул-корреляция поверх постоянной таблицы events/rule_hits (app/store.py).

Почему отдельный модуль, а не pysigma-backend-sqlite/Zircolite (см. CLAUDE.md за подробным
разбором): (1) ZircoliteCore создаётся заново на каждый micro-batch flush ingest-воркера с
пустой in-memory БД - между вызовами никакого state вообще нет; (2) даже НЕЗАВИСИМО от этого -
пропатченный backend pysigma-backend-sqlite==1.2.0 для event_count/value_count генерирует
SQL без единого упоминания timespan (только temporal/temporal_ordered реально накладывают
окно). Здесь - свой маленький компилятор по образцу app/filter_lang.py: bound-параметры,
json_extract(raw_json, ...) через уже существующий filter_lang.resolve_json_path, без eval/
конкатенации пользовательского текста в SQL.

Поддержаны только correlation type: event_count/value_count. temporal/temporal_ordered
(в т.ч. цепочки корреляция-ссылается-на-корреляцию, auth_after_brutforce_by_* в
artifacts/content/auth_after_brutforce.yml) сознательно НЕ эвалуируются в этой итерации -
отдельная, более сложная задача (см. CLAUDE.md).

Триггер - вызывается из app/main.py:_process_batch ПОСЛЕ каждого store.store_events(...), т.е.
после каждого flush ingest-воркера, с коротким замыканием: если ни одно активное
correlation-правило не ссылается на правило, сработавшее В ЭТОМ батче, до БД дело не доходит
вообще.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from typing import Any

from app import main_ruleset, rules_catalog
from app.fields import (
    DST_IP_FIELDS,
    HOST_FIELDS,
    PROCESS_FIELDS,
    SRC_IP_FIELDS,
    TIME_FIELDS,
    USER_FIELDS,
    first_present,
)
from app.models import Alert, Entities, Severity, SigmaRuleRef
from app.store import Store

# Свой маленький парсер Sigma timespan (5m/1h/1d/...) - единицы, реально встречающиеся в
# правилах проекта. 'M' (месяц)/'y' (год) намеренно не поддержаны (неоднозначная длина в
# секундах, в текущих правилах не используются) - тот же принцип "свой маленький парсер без
# внешней зависимости", что и у filter_lang.py; не тянем sigma.correlations ради одной строки,
# тем более что сам backend этого пакета для event_count/value_count всё равно игнорирует
# timespan (см. докстринг модуля/CLAUDE.md) - полагаться на него в целом не стоит.
_TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_COND_OPS: dict[str, Any] = {
    "gte": lambda c, n: c >= n,
    "gt": lambda c, n: c > n,
    "lte": lambda c, n: c <= n,
    "lt": lambda c, n: c < n,
    "eq": lambda c, n: c == n,
}


def _parse_timespan(text: Any) -> int | None:
    if not text:
        return None
    m = _TIMESPAN_RE.match(str(text).strip())
    if not m:
        return None
    return int(m.group(1)) * _TIMESPAN_UNITS[m.group(2).lower()]


def _condition_met(condition: dict[str, Any], count: int) -> bool:
    """condition - {"gte": 10} (event_count) или {"field": "Image", "gte": 5} (value_count,
    'field' - имя поля для distinct, обрабатывается отдельно store.evaluate_correlation_window,
    здесь просто пропускается как не-оператор). Пустое/без единого распознанного оператора
    условие - НЕ считается выполненным (иначе пустая condition молча пропускала бы всё)."""
    checked = False
    for op, threshold in condition.items():
        if op == "field":
            continue
        fn = _COND_OPS.get(op)
        if fn is None:
            continue
        try:
            threshold_num = float(threshold)
        except (TypeError, ValueError):
            continue
        checked = True
        if not fn(count, threshold_num):
            return False
    return checked


def _normalize_event_time(event_time: str | None) -> str | None:
    """Дублирует store._normalize_event_time (та же 1-строчная трансформация) - окно, которое
    здесь считается, должно быть в ТОЙ ЖЕ нормализованной форме, что и rule_hits.event_time
    (см. app/store.py), иначе BETWEEN в evaluate_correlation_window сравнивал бы разные форматы.
    Не импортируется напрямую из store.py (private-имя, отдельный модуль) - сознательно
    небольшое дублирование вместо кросс-модульной завязки на чужую приватную функцию."""
    if event_time is None:
        return None
    return event_time.replace(" ", "T").replace("Z", "")


def _shift_iso(normalized_time: str, delta_seconds: int) -> str | None:
    try:
        dt = datetime.fromisoformat(normalized_time)
    except ValueError:
        return None
    return (dt + timedelta(seconds=delta_seconds)).isoformat()


def _extract_entities(events: list[dict[str, Any]]) -> Entities:
    """Минимальный локальный аналог normalize._extract_entities - не импортируется оттуда
    (приватная функция другого модуля, normalize.py сознательно не трогаем, см. план)."""
    users, hosts, src_ips, dst_ips, processes = set(), set(), set(), set(), set()
    for event in events:
        if v := first_present(event, USER_FIELDS):
            users.add(v)
        if v := first_present(event, HOST_FIELDS):
            hosts.add(v)
        if v := first_present(event, SRC_IP_FIELDS):
            src_ips.add(v)
        if v := first_present(event, DST_IP_FIELDS):
            dst_ips.add(v)
        if v := first_present(event, PROCESS_FIELDS):
            processes.add(v)
    return Entities(
        users=sorted(users), hosts=sorted(hosts), src_ips=sorted(src_ips),
        dst_ips=sorted(dst_ips), processes=sorted(processes),
    )


def _dedup_key(rule_id: str, key_values: tuple[Any, ...]) -> str:
    """Независимая от normalize._dedup_key функция - другая семантика ключа (group-by значения
    корреляции, не (host, main_entity) одного алерта)."""
    raw = f"{rule_id}:" + ":".join(str(v) for v in key_values)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _active_correlation_rules(ruleset_path: str | None) -> list[dict[str, Any]]:
    """Активные (event_count/value_count и любые другие типы - фильтрация по типу делает
    вызывающая сторона) correlation-правила для ruleset_path: для "main" - объединение из всех
    custom-рулсетов, реально включённых в основной рулсет (main_ruleset.resolve_with_sources,
    та же логика видимости, что уже использует остальной проект); для обычного custom
    ruleset_path - напрямую; для builtin/None - пусто (builtin корреляций не содержит)."""
    if not ruleset_path:
        return []
    if ruleset_path == main_ruleset.MAIN_RULESET_ID:
        active_ids_by_ruleset: dict[str, set[str]] = {}
        for src, rule in main_ruleset.resolve_with_sources():
            if rule.get("correlation"):
                active_ids_by_ruleset.setdefault(src, set()).add(rule.get("id"))
        result: list[dict[str, Any]] = []
        for src, ids in active_ids_by_ruleset.items():
            result += [c for c in rules_catalog.load_correlation_rules(src) if c["id"] in ids]
        return result
    return rules_catalog.load_correlation_rules(ruleset_path)


def active_base_rule_titles(ruleset_path: str | None) -> set[str]:
    """Названия правил, которые являются base_rule_titles хотя бы одной активной
    correlation-записи - используется app/main.py ПЕРЕД store.store_events(...), чтобы решить,
    какие срабатывания вообще стоит записывать в rule_hits (см. докстринг таблицы в store.py)."""
    titles: set[str] = set()
    for corr in _active_correlation_rules(ruleset_path):
        titles.update(corr.get("base_rule_titles") or [])
    return titles


def _build_alert(
    corr: dict[str, Any],
    key: tuple[Any, ...],
    count: int,
    sample_events: list[dict[str, Any]],
    source_batch: str,
) -> Alert:
    rule_ref = SigmaRuleRef(
        rule_id=corr.get("id") or "",
        title=corr["title"],
        level=Severity.from_zircolite(corr.get("level")),
        mitre_techniques=[t for t in (corr.get("tags") or []) if str(t).startswith("attack.t")],
        description=corr.get("description", ""),
    )
    entities = _extract_entities(sample_events)
    host = first_present(sample_events[0], HOST_FIELDS) if sample_events else None
    if not host:
        host = "-".join(str(v) for v in key) or "unknown-host"
    return Alert(
        dedup_key=_dedup_key(rule_ref.rule_id, key),
        engine="correlation",
        source_batch=source_batch,
        host=host,
        rule=rule_ref,
        entities=entities,
        event_count=count,
        sample_events=sample_events,
    )


def evaluate_batch(
    store: Store,
    ruleset_path: str | None,
    source_batch: str,
    matched_events_by_title: dict[str, list[dict[str, Any]]],
) -> int:
    """Точка входа, зовётся из app/main.py:_process_batch после каждого store.store_events(...)
    (т.е. после каждого flush ingest-воркера). matched_events_by_title - {rule_title: [сырые
    dict событий, сматченных В ЭТОМ батче под этим source_batch]}. Возвращает число
    созданных/обновлённых correlation-алертов."""
    if not ruleset_path or not matched_events_by_title:
        return 0
    corr_rules = _active_correlation_rules(ruleset_path)
    if not corr_rules:
        return 0

    alerts: list[Alert] = []
    for corr in corr_rules:
        if corr.get("type") not in ("event_count", "value_count"):
            continue  # temporal/temporal_ordered - следующая задача (chaining), см. CLAUDE.md
        if Severity.from_zircolite(corr.get("level")) == Severity.informational:
            continue  # informational - шум, алерты по нему не заводим (см. normalize.py/UI)
        group_by = corr.get("group_by") or []
        if not group_by:
            continue  # без group-by корреляция была бы "по всей выборке" - не поддерживаем пока

        base_titles = corr.get("base_rule_titles") or []
        new_matches: list[dict[str, Any]] = []
        for title in base_titles:
            new_matches += matched_events_by_title.get(title, [])
        if not new_matches:
            continue  # короткое замыкание - базовое правило не срабатывало в этом батче

        timespan_seconds = _parse_timespan(corr.get("timespan"))
        if timespan_seconds is None:
            continue

        distinct_field = None
        if corr["type"] == "value_count":
            distinct_field = (corr.get("condition") or {}).get("field")
            if not distinct_field:
                continue

        # Один кандидатный ключ на набор значений group-by полей; якорь конца окна - event_time
        # САМОГО ПОЗДНЕГО из новых событий с этим ключом (НЕ datetime.now() - иначе корреляции
        # никогда бы не срабатывали при replay исторических датасетов, напр. OTRF
        # Security-Datasets, где все event_time уже в прошлом).
        anchors: dict[tuple[Any, ...], str] = {}
        for event in new_matches:
            key = tuple(event.get(f) for f in group_by)
            if any(v is None for v in key):
                continue
            normalized = _normalize_event_time(first_present(event, TIME_FIELDS))
            if not normalized:
                continue
            if key not in anchors or normalized > anchors[key]:
                anchors[key] = normalized

        for key, anchor_time in anchors.items():
            window_start = _shift_iso(anchor_time, -timespan_seconds)
            if window_start is None:
                continue
            result = store.evaluate_correlation_window(
                base_rule_titles=base_titles,
                group_by=group_by,
                key_values=key,
                source_batch=source_batch,
                time_from=window_start,
                time_to=anchor_time,
                distinct_field=distinct_field,
            )
            count = result["count"]
            if not _condition_met(corr.get("condition") or {}, count):
                continue
            alerts.append(_build_alert(corr, key, count, result["sample_events"], source_batch))

    if not alerts:
        return 0
    return store.upsert_correlation_alerts(alerts)
