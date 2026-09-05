"""
Тесты normalize.zircolite_results_to_alerts: группировка сработавших событий в Alert
по (хост, источник, [подпись содержимого]), дедуп-ключ в двух режимах (dedup_by_content),
извлечение entities, отбор sample_events, снятие служебного INGEST_SOURCE_FIELD (не должен
утечь наружу). informational больше не отсекается - см. докстринг normalize.py.
"""
from __future__ import annotations

from app.fields import INGEST_SOURCE_FIELD
from app.detection.normalize import (
    _content_signature,
    _dedup_key,
    _pick_sample_events,
    zircolite_results_to_alerts,
)


def test_alert_created_at_is_naive_utc():
    """Контракт формата времени алерта: Alert.created_at должен быть НАИВНЫМ (без tzinfo),
    а его .isoformat() - без суффикса 'Z'/'+00:00'. store.list_alerts сравнивает/сортирует
    его строкой с наивными границами из UI; aware-объект (или переход обратно на deprecated
    datetime.utcnow) этот контракт нарушит. См. app/models.py:utcnow_naive."""
    matches = [{"Hostname": "HOST-A"}]
    alert = zircolite_results_to_alerts([_rule(matches)], default_source_batch="batch-1")[0]
    assert alert.created_at.tzinfo is None
    iso = alert.created_at.isoformat()
    assert "+" not in iso and not iso.endswith("Z")


def _rule(matches: list[dict], **overrides) -> dict:
    base = {
        "id": "rule-1",
        "title": "Test Rule",
        "rule_level": "high",
        "tags": ["attack.t1059", "attack.execution", "car.2016-04-002"],
        "description": "desc",
        "matches": matches,
    }
    base.update(overrides)
    return base


def test_groups_alerts_by_host():
    # Разные хосты - всегда отдельные алерты, в обоих режимах дедупа.
    matches = [
        {"Hostname": "HOST-A", "TargetUserName": "alice"},
        {"Hostname": "HOST-A", "TargetUserName": "alice"},
        {"Hostname": "HOST-B", "TargetUserName": "bob"},
    ]
    alerts = zircolite_results_to_alerts([_rule(matches)], default_source_batch="batch-1")

    assert len(alerts) == 2
    by_host = {a.host: a for a in alerts}
    assert by_host["HOST-A"].event_count == 2
    assert by_host["HOST-B"].event_count == 1
    assert all(a.source_batch == "batch-1" for a in alerts)


def test_rule_without_matches_is_skipped():
    alerts = zircolite_results_to_alerts([_rule([])], default_source_batch="batch-1")
    assert alerts == []


def test_informational_level_still_produces_alerts():
    """Уровень informational больше НЕ отсекается (было отсечено раньше) - базовые правила
    сценариев/корреляций пишутся именно так, их сработки нужны и как алерты, и как
    member-алерты инцидента (store.link_alerts_to_incident ищет по rule_title)."""
    matches = [{"Hostname": "HOST-A"}]
    alerts = zircolite_results_to_alerts(
        [_rule(matches, rule_level="informational")], default_source_batch="batch-1",
    )
    assert len(alerts) == 1
    assert alerts[0].rule.level.value == "informational"


def test_only_technique_tags_become_mitre_techniques():
    # "attack.t..." (technique id) проходит фильтр, "attack.execution" (тактика) и
    # сторонние теги (car.*) - нет, см. normalize.zircolite_results_to_alerts.
    matches = [{"Hostname": "HOST-A"}]
    alerts = zircolite_results_to_alerts([_rule(matches)], default_source_batch="batch-1")
    assert alerts[0].rule.mitre_techniques == ["attack.t1059"]


def test_dedup_key_is_deterministic_and_depends_on_inputs():
    k1 = _dedup_key("rule-1", "HOST-A", "detail-a")
    k2 = _dedup_key("rule-1", "HOST-A", "detail-a")
    k3 = _dedup_key("rule-1", "HOST-A", "detail-b")
    assert k1 == k2
    assert k1 != k3


# ------------------------------------------------------------------ dedup_by_content=True (custom)

def test_content_dedup_merges_identical_events_differing_only_by_time():
    """Два вхождения ОДНОГО И ТОГО ЖЕ события (отличаются только временем/служебными полями) -
    один алерт со счётчиком, не два."""
    matches = [
        {"Hostname": "HOST-A", "TargetUserName": "alice", "EventTime": "2026-01-01 00:00:00", "row_id": 1},
        {"Hostname": "HOST-A", "TargetUserName": "alice", "EventTime": "2026-01-01 00:05:00", "row_id": 2},
    ]
    alerts = zircolite_results_to_alerts(
        [_rule(matches)], default_source_batch="batch-1", dedup_by_content=True,
    )
    assert len(alerts) == 1
    assert alerts[0].event_count == 2


def test_content_dedup_splits_events_that_differ_in_any_other_field():
    """Разные пользователи (или любое другое отличие, кроме времени/служебных полей) на одном
    хосте - отдельные алерты, а не один со счётчиком=2, как раньше (main_entity=alice/bob обоих
    сводил к первому по алфавиту)."""
    matches = [
        {"Hostname": "HOST-A", "TargetUserName": "alice"},
        {"Hostname": "HOST-A", "TargetUserName": "bob"},
    ]
    alerts = zircolite_results_to_alerts(
        [_rule(matches)], default_source_batch="batch-1", dedup_by_content=True,
    )
    assert len(alerts) == 2
    assert all(a.event_count == 1 for a in alerts)


def test_content_signature_ignores_time_and_internal_fields():
    a = {"Hostname": "H", "EventTime": "t1", "SystemTime": "s1", "row_id": 1, "OriginalLogfile": "f1.jsonl"}
    b = {"Hostname": "H", "EventTime": "t2", "SystemTime": "s2", "row_id": 2, "OriginalLogfile": "f2.jsonl"}
    assert _content_signature(a) == _content_signature(b)


def test_content_signature_field_order_does_not_matter():
    a = {"Hostname": "H", "TargetUserName": "alice"}
    b = {"TargetUserName": "alice", "Hostname": "H"}
    assert _content_signature(a) == _content_signature(b)


# ------------------------------------------------------------------ dedup_by_content=False (built-in)

def test_builtin_dedup_ignores_content_merges_by_rule_and_host_only():
    """dedup_by_content=False (built-in-рулсеты) - грубее: разные пользователи на одном хосте
    всё равно один алерт, счётчик растёт."""
    matches = [
        {"Hostname": "HOST-A", "TargetUserName": "alice"},
        {"Hostname": "HOST-A", "TargetUserName": "bob"},
        {"Hostname": "HOST-A", "TargetUserName": "carol"},
    ]
    alerts = zircolite_results_to_alerts(
        [_rule(matches)], default_source_batch="batch-1", dedup_by_content=False,
    )
    assert len(alerts) == 1
    assert alerts[0].event_count == 3


def test_ingest_source_field_splits_group_and_does_not_leak():
    matches = [
        {"Hostname": "HOST-A", INGEST_SOURCE_FIELD: "source-1"},
        {"Hostname": "HOST-A", INGEST_SOURCE_FIELD: "source-2"},
    ]
    alerts = zircolite_results_to_alerts([_rule(matches)], default_source_batch="default-batch")

    assert len(alerts) == 2
    source_batches = {a.source_batch for a in alerts}
    assert source_batches == {"source-1", "source-2"}
    for alert in alerts:
        for event in alert.sample_events:
            assert INGEST_SOURCE_FIELD not in event


def test_falls_back_to_default_source_batch_when_marker_absent():
    matches = [{"Hostname": "HOST-A"}]
    alerts = zircolite_results_to_alerts([_rule(matches)], default_source_batch="default-batch")
    assert alerts[0].source_batch == "default-batch"


def test_pick_sample_events_returns_all_when_under_limit():
    events = [{"i": i} for i in range(5)]
    assert _pick_sample_events(events, limit=10) == events


def test_pick_sample_events_returns_head_and_tail_when_over_limit():
    events = [{"i": i} for i in range(20)]
    sample = _pick_sample_events(events, limit=10)
    assert len(sample) == 10
    assert [e["i"] for e in sample] == [0, 1, 2, 3, 4, 15, 16, 17, 18, 19]


def test_entities_extraction_collects_unique_sorted_values():
    # dedup_by_content=False - иначе alice/bob разошлись бы по разным алертам (см. тесты выше)
    # и сравнивать entities одного алерта было бы не с чем.
    matches = [
        {"Hostname": "HOST-A", "TargetUserName": "bob", "Image": "cmd.exe"},
        {"Hostname": "HOST-A", "TargetUserName": "alice", "Image": "cmd.exe"},
    ]
    alerts = zircolite_results_to_alerts(
        [_rule(matches)], default_source_batch="batch-1", dedup_by_content=False,
    )
    entities = alerts[0].entities
    assert entities.users == ["alice", "bob"]
    assert entities.hosts == ["HOST-A"]
    assert entities.processes == ["cmd.exe"]
