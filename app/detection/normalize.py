"""
Нормализация: сырой результат Zircolite (правило + список сматченных событий)
-> список объектов Alert, сгруппированных по хосту.

Один прогон правила может дать события с разных хостов (особенно на многохостовых
датасетах вроде AD Playbook) - разумно разбивать на отдельные Alert по хосту,
а не мешать всё в одну кучу.

Извлечение entities намеренно упрощено (общие имена полей на все источники).
Следующий шаг - сделать таблицу маппинга под конкретный источник
(EVTX Security-канал / Sysmon / Auditd), т.к. поля называются по-разному.
"""
from __future__ import annotations

import hashlib
from typing import Any

from app.fields import (
    DST_IP_FIELDS,
    HOST_FIELDS,
    INGEST_SOURCE_FIELD,
    PROCESS_FIELDS,
    SRC_IP_FIELDS,
    USER_FIELDS,
    first_present,
)
from app.models import Alert, Entities, Severity, SigmaRuleRef

_SAMPLE_EVENTS_LIMIT = 10
_first_present = first_present
_HOST_FIELDS = HOST_FIELDS
_USER_FIELDS = USER_FIELDS
_SRC_IP_FIELDS = SRC_IP_FIELDS
_DST_IP_FIELDS = DST_IP_FIELDS
_PROCESS_FIELDS = PROCESS_FIELDS


def _extract_entities(events: list[dict[str, Any]]) -> Entities:
    users, hosts, src_ips, dst_ips, processes = set(), set(), set(), set(), set()
    for event in events:
        if (v := _first_present(event, _USER_FIELDS)):
            users.add(v)
        if (v := _first_present(event, _HOST_FIELDS)):
            hosts.add(v)
        if (v := _first_present(event, _SRC_IP_FIELDS)):
            src_ips.add(v)
        if (v := _first_present(event, _DST_IP_FIELDS)):
            dst_ips.add(v)
        if (v := _first_present(event, _PROCESS_FIELDS)):
            processes.add(v)
    return Entities(
        users=sorted(users),
        hosts=sorted(hosts),
        src_ips=sorted(src_ips),
        dst_ips=sorted(dst_ips),
        processes=sorted(processes),
    )


def _pick_sample_events(events: list[dict[str, Any]], limit: int = _SAMPLE_EVENTS_LIMIT) -> list[dict[str, Any]]:
    """Первые N + последние N, без дублей, чтобы не тащить сотни событий в контекст агента."""
    if len(events) <= limit:
        return events
    half = limit // 2
    head, tail = events[:half], events[-half:]
    return head + tail


def _dedup_key(rule_id: str, host: str, main_entity: str) -> str:
    raw = f"{rule_id}:{host}:{main_entity}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def zircolite_results_to_alerts(
    raw_results: list[dict[str, Any]],
    default_source_batch: str,
) -> list[Alert]:
    """Превращает список сработавших правил Zircolite в список Alert, по одному на (хост, источник).

    default_source_batch - метка батча-запуска движка (может объединять НЕСКОЛЬКО реальных
    источников за раз, см. app/ingest_queue.py); реальный source_batch каждого события
    приезжает внутри самого события через INGEST_SOURCE_FIELD (см. app/main.py:_process_events)
    и снимается здесь (event.pop) - наружу (в sample_events) он утечь не должен. Если маркера
    нет (события пришли напрямую через /ingest/file - там per-event маркера никогда не
    проставляется), просто используется default_source_batch - поведение не меняется для
    однисточникового прогона."""
    alerts: list[Alert] = []

    for rule in raw_results:
        matches: list[dict[str, Any]] = rule.get("matches", [])
        if not matches:
            continue

        rule_ref = SigmaRuleRef(
            rule_id=rule.get("id", ""),
            title=rule.get("title", "Unnamed Rule"),
            level=Severity.from_zircolite(rule.get("rule_level")),
            mitre_techniques=[t for t in rule.get("tags", []) if t.startswith("attack.t")],
            description=rule.get("description", ""),
        )
        if rule_ref.level == Severity.informational:
            continue  # informational - шум, алерты по нему не заводим (см. CLAUDE.md/UI)

        # Группируем сматченные события правила по (хосту, реальному источнику) - см. докстринг.
        events_by_group: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in matches:
            source_batch = event.pop(INGEST_SOURCE_FIELD, default_source_batch)
            host = _first_present(event, _HOST_FIELDS) or "unknown-host"
            events_by_group.setdefault((host, source_batch), []).append(event)

        for (host, source_batch), host_events in events_by_group.items():
            entities = _extract_entities(host_events)
            main_entity = entities.users[0] if entities.users else host

            alerts.append(
                Alert(
                    dedup_key=_dedup_key(rule_ref.rule_id, host, main_entity),
                    source_batch=source_batch,
                    host=host,
                    rule=rule_ref,
                    entities=entities,
                    event_count=len(host_events),
                    sample_events=_pick_sample_events(host_events),
                )
            )

    return alerts
