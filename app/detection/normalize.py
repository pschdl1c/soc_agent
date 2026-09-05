"""
Нормализация: сырой результат Zircolite (правило + список сматченных событий)
-> список объектов Alert, сгруппированных по хосту (+ дедуп, см. ниже).

Один прогон правила может дать события с разных хостов (особенно на многохостовых
датасетах вроде AD Playbook) - разумно разбивать на отдельные Alert по хосту,
а не мешать всё в одну кучу.

Уровень informational НЕ отсекается (был отсечён раньше - "шум"): базовые правила
сценариев/корреляций пишутся именно на этом уровне, их сработки нужны и как обычные
алерты (для видимости/отладки сценария через Events), и как member-алерты инцидента
(store.link_alerts_to_incident ищет их по rule_title среди уже сохранённых Alert).

Дедуп (dedup_key) - два режима, выбираются вызывающей стороной через dedup_by_content
(app/main.py:_process_batch решает по тому, custom или built-in ruleset_path у батча):
  - dedup_by_content=True (custom-правила) - по ХЭШУ ВСЕГО СОБЫТИЯ (минус служебные и
    временные поля, см. _content_signature). Не привязан к конкретной сущности (юзер/ip/
    процесс/...) - работает для ЛЮБОГО правила без знания его семантики: два вхождения
    считаются "тем же самым", только если совпадают ВСЕ поля кроме времени. Одинаковых
    событий будет много отдельных алертов - зато каждый строго унифицирован.
  - dedup_by_content=False (built-in правила, rules_windows_merged.json и т.п.) - грубее,
    просто (rule_id, host), без учёта содержимого события и без времени. Built-in сейчас
    используется только для разовых batch-прогонов файлов (не для /ingest/stream - основной
    рулсет составляется ТОЛЬКО из custom-рулсетов, см. app/rules/main_ruleset.py), точность
    на уровне сущности там не нужна, а объём built-in-контента (~4291 правило) сделал бы
    дедуп по содержимому избыточно дробным.

Извлечение entities намеренно упрощено (общие имена полей на все источники).
Следующий шаг - сделать таблицу маппинга под конкретный источник
(EVTX Security-канал / Sysmon / Auditd), т.к. поля называются по-разному.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from app.fields import (
    DST_IP_FIELDS,
    HOST_FIELDS,
    INGEST_SOURCE_FIELD,
    PROCESS_FIELDS,
    SRC_IP_FIELDS,
    TIME_FIELDS,
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

# Поля, которые не должны участвовать в подписи содержимого события (см. _content_signature):
# TIME_FIELDS - иначе "то же самое, просто позже" никогда бы не дедупилось; row_id - Zircolite
# сам проставляет автоинкрементный номер на КАЖДОЕ событие (Zircolite/zircolite/core.py);
# OriginalLogfile - Zircolite пишет туда имя обрабатываемого файла (streaming.py) - на потоке
# это СИНТЕТИЧЕСКОЕ имя временного файла, СВОЁ на каждый flush IngestWorker'а, а не что-то
# стабильное про источник события - без исключения кросс-батчевый дедуп молча ломался бы
# (идентичные события в разных flush'ах никогда не совпадали бы по хэшу).
_CONTENT_SIGNATURE_EXCLUDED_FIELDS = frozenset(TIME_FIELDS) | {"row_id", "OriginalLogfile"}


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


def _content_signature(event: dict[str, Any]) -> str:
    """Канонический JSON события без служебных/временных полей (см.
    _CONTENT_SIGNATURE_EXCLUDED_FIELDS) - два вхождения одного и того же события в разное
    время дают ОДИНАКОВУЮ подпись, любое другое отличие (другой хост уже отсечён группировкой
    выше по стеку, но и любое отличие в остальных полях) - разную. sort_keys - подпись не
    должна зависеть от порядка ключей в исходном JSON события."""
    filtered = {k: v for k, v in event.items() if k not in _CONTENT_SIGNATURE_EXCLUDED_FIELDS}
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False, default=str)


def _dedup_key(rule_id: str, host: str, detail: str) -> str:
    raw = f"{rule_id}:{host}:{detail}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def zircolite_results_to_alerts(
    raw_results: list[dict[str, Any]],
    default_source_batch: str,
    dedup_by_content: bool = True,
) -> list[Alert]:
    """Превращает список сработавших правил Zircolite в список Alert, по одному на
    (хост, источник, [подпись содержимого - см. dedup_by_content в докстринге модуля]).

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

        # Группируем сматченные события правила по (хосту, реальному источнику, подписи
        # содержимого) - подпись пустая и одинаковая для всех при dedup_by_content=False, тогда
        # группировка вырождается в (хост, источник), как у built-in-режима.
        events_by_group: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for event in matches:
            source_batch = event.pop(INGEST_SOURCE_FIELD, default_source_batch)
            host = _first_present(event, _HOST_FIELDS) or "unknown-host"
            detail = _content_signature(event) if dedup_by_content else ""
            events_by_group.setdefault((host, source_batch, detail), []).append(event)

        for (host, source_batch, detail), group_events in events_by_group.items():
            alerts.append(
                Alert(
                    dedup_key=_dedup_key(rule_ref.rule_id, host, detail),
                    source_batch=source_batch,
                    host=host,
                    rule=rule_ref,
                    entities=_extract_entities(group_events),
                    event_count=len(group_events),
                    sample_events=_pick_sample_events(group_events),
                    # Полный (не усечённый, в отличие от sample_events) список row_id этого
                    # батча - см. Alert.source_row_ids. row_id может отсутствовать (событие
                    # собрано вручную в тестах без него) - None тогда просто выпадет позже при
                    # переводе в events.event_id (main.py его не найдёт в row_id->event_id и
                    # молча пропустит), это не ошибка.
                    source_row_ids=[e.get("row_id") for e in group_events],
                )
            )

    return alerts
