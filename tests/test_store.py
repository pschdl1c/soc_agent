"""
Тесты Store (app/store.py): дедупликация алертов, хранение/фильтр/группировка событий,
удаление батча, health(). Каждый тест получает свежий временный siem.db через фикстуру
`store` (tests/conftest.py) - реальная production siem.db не трогается.
"""
from __future__ import annotations

from app.models import Alert, Entities, Severity, SigmaRuleRef


def _alert(dedup_key: str, host: str = "HOST-A", source_batch: str = "batch-1", event_count: int = 1) -> Alert:
    return Alert(
        dedup_key=dedup_key,
        source_batch=source_batch,
        host=host,
        rule=SigmaRuleRef(rule_id="rule-1", title="Test Rule", level=Severity.high),
        entities=Entities(hosts=[host]),
        event_count=event_count,
        sample_events=[{"Hostname": host}],
    )


def test_upsert_alerts_inserts_new(store):
    count = store.upsert_alerts([_alert("dedup-1")])
    assert count == 1
    rows = store.list_alerts()
    assert len(rows) == 1
    assert rows[0]["host"] == "HOST-A"
    assert rows[0]["event_count"] == 1


def test_upsert_alerts_dedup_increments_event_count(store):
    store.upsert_alerts([_alert("dedup-1", event_count=1)])
    store.upsert_alerts([_alert("dedup-1", event_count=3)])

    rows = store.list_alerts()
    assert len(rows) == 1
    assert rows[0]["event_count"] == 4


def test_upsert_alerts_different_dedup_keys_create_separate_alerts(store):
    store.upsert_alerts([_alert("dedup-1"), _alert("dedup-2", host="HOST-B")])
    assert len(store.list_alerts()) == 2


def test_get_alert_returns_full_row_with_sample_events(store):
    store.upsert_alerts([_alert("dedup-1")])
    alert_id = store.list_alerts()[0]["alert_id"]

    row = store.get_alert(alert_id)
    assert row is not None
    assert row["sample_events"] == [{"Hostname": "HOST-A"}]
    assert row["entities"]["hosts"] == ["HOST-A"]


def test_get_alert_missing_returns_none(store):
    assert store.get_alert("does-not-exist") is None


def test_update_alert_status(store):
    store.upsert_alerts([_alert("dedup-1")])
    alert_id = store.list_alerts()[0]["alert_id"]

    assert store.update_alert_status(alert_id, "closed") is True
    assert store.get_alert(alert_id)["status"] == "closed"
    assert store.update_alert_status("does-not-exist", "closed") is False


def test_list_alerts_filters_by_source_batch(store):
    store.upsert_alerts([_alert("dedup-1", source_batch="batch-a"), _alert("dedup-2", source_batch="batch-b")])
    rows = store.list_alerts(source_batch="batch-a")
    assert len(rows) == 1
    assert rows[0]["source_batch"] == "batch-a"


def test_store_events_and_list_events_roundtrip(store):
    events = [
        {"row_id": 1, "Hostname": "HOST-A", "EventID": 1, "Image": "cmd.exe"},
        {"row_id": 2, "Hostname": "HOST-A", "EventID": 2, "Image": "notepad.exe"},
    ]
    inserted = store.store_events(events, source_batch="batch-1", matched_row_to_rules={1: ["Test Rule"]})
    assert inserted == 2

    rows = store.list_events(source_batch="batch-1")
    assert len(rows) == 2
    matched = {r["is_matched"]: r for r in rows}
    assert matched[True]["matched_rules"] == ["Test Rule"]
    assert matched[False]["matched_rules"] == []


def test_list_events_only_matched_filter(store):
    events = [
        {"row_id": 1, "Hostname": "HOST-A"},
        {"row_id": 2, "Hostname": "HOST-A"},
    ]
    store.store_events(events, source_batch="batch-1", matched_row_to_rules={1: ["Test Rule"]})

    only_matched = store.list_events(source_batch="batch-1", only_matched=True)
    assert len(only_matched) == 1
    assert only_matched[0]["is_matched"] is True

    only_unmatched = store.list_events(source_batch="batch-1", only_matched=False)
    assert len(only_unmatched) == 1
    assert only_unmatched[0]["is_matched"] is False


def test_list_events_custom_field_extraction(store):
    events = [{"row_id": 1, "Hostname": "HOST-A", "CommandLine": "powershell -enc AAA"}]
    store.store_events(events, source_batch="batch-1", matched_row_to_rules={})

    rows = store.list_events(source_batch="batch-1", fields=["CommandLine", "MissingField"])
    assert rows[0]["extra"]["CommandLine"] == "powershell -enc AAA"
    assert rows[0]["extra"]["MissingField"] is None


def test_group_events_counts_by_field(store):
    events = [
        {"row_id": 1, "Hostname": "HOST-A", "EventID": 1},
        {"row_id": 2, "Hostname": "HOST-A", "EventID": 1},
        {"row_id": 3, "Hostname": "HOST-A", "EventID": 2},
    ]
    store.store_events(events, source_batch="batch-1", matched_row_to_rules={})

    result = store.group_events(group_by="EventID", source_batch="batch-1")
    assert result["total_groups"] == 2
    counts = {g["value"]: g["count"] for g in result["groups"]}
    assert counts == {1: 2, 2: 1}


def test_count_events(store):
    events = [{"row_id": i, "Hostname": "HOST-A"} for i in range(3)]
    store.store_events(events, source_batch="batch-1", matched_row_to_rules={})
    assert store.count_events(source_batch="batch-1") == 3
    assert store.count_events(source_batch="does-not-exist") == 0


def test_list_batches_reports_event_and_alert_counts(store):
    store.upsert_alerts([_alert("dedup-1", source_batch="batch-1")])
    store.store_events(
        [{"row_id": 1, "Hostname": "HOST-A"}], source_batch="batch-1", matched_row_to_rules={}
    )
    batches = {b["source_batch"]: b for b in store.list_batches()}
    assert batches["batch-1"]["event_count"] == 1
    assert batches["batch-1"]["alert_count"] == 1


def test_delete_batch_removes_events_and_alerts(store):
    store.upsert_alerts([_alert("dedup-1", source_batch="batch-1")])
    store.store_events(
        [{"row_id": 1, "Hostname": "HOST-A"}], source_batch="batch-1", matched_row_to_rules={}
    )

    result = store.delete_batch("batch-1")
    assert result == {"events_deleted": 1, "alerts_deleted": 1}
    assert store.list_alerts(source_batch="batch-1") == []
    assert store.list_events(source_batch="batch-1") == []


def test_delete_batch_missing_returns_zero_counts(store):
    assert store.delete_batch("does-not-exist") == {"events_deleted": 0, "alerts_deleted": 0}


def test_health_ok(store):
    health = store.health()
    assert health["status"] == "ok"

    detailed = store.health(detailed=True)
    assert detailed["alerts"] == 0
    assert detailed["events"] == 0
