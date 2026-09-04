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


# ------------------------------------------------------------------ Correlation storage layer


def _corr_alert(dedup_key: str, source_batch: str = "b1", event_count: int = 1) -> Alert:
    return Alert(
        dedup_key=dedup_key,
        engine="correlation",
        source_batch=source_batch,
        host="10.0.0.1",
        rule=SigmaRuleRef(rule_id="corr-1", title="Bruteforce", level=Severity.high),
        entities=Entities(src_ips=["10.0.0.1"]),
        event_count=event_count,
        sample_events=[{"IpAddress": "10.0.0.1"}],
    )


def test_evaluate_correlation_windows_counts_multiple_keys_at_once(store):
    """Фаза 1 двухфазного счёта - один запрос должен вернуть счётчики СРАЗУ по нескольким
    group-by-ключам, без отдельного запроса на каждый (см. app/detection/correlation.py)."""
    events = [
        {"row_id": 1, "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:00:00"},
        {"row_id": 2, "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:00:01"},
        {"row_id": 3, "IpAddress": "10.0.0.2", "SystemTime": "2024-01-01T00:00:02"},
    ]
    store.store_events(
        events, source_batch="b1",
        matched_row_to_rules={1: ["Failed Auth"], 2: ["Failed Auth"], 3: ["Failed Auth"]},
        hit_spec={"Failed Auth": {"IpAddress"}},
    )
    counts = store.evaluate_correlation_windows(
        rule_titles=["Failed Auth"], source_batch="b1",
        time_from="0000-01-01T00:00:00", time_to="9999-12-31T23:59:59",
        group_by=["IpAddress"], mode="events",
    )
    assert counts == {("10.0.0.1",): 2, ("10.0.0.2",): 1}


def test_evaluate_correlation_windows_respects_time_bounds(store):
    old = [{"row_id": 1, "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:00:00"}]
    new = [{"row_id": 2, "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:10:00"}]
    # store_events сам не нормализует event_time для rule_hits кроме как через hit_spec -
    # normalized event_time пишется из event_time колонки events (SystemTime как TIME_FIELDS).
    store.store_events(
        old, source_batch="b1", matched_row_to_rules={1: ["Failed Auth"]},
        hit_spec={"Failed Auth": {"IpAddress"}},
    )
    store.store_events(
        new, source_batch="b1", matched_row_to_rules={2: ["Failed Auth"]},
        hit_spec={"Failed Auth": {"IpAddress"}},
    )
    counts = store.evaluate_correlation_windows(
        rule_titles=["Failed Auth"], source_batch="b1",
        time_from="2024-01-01T00:05:00", time_to="2024-01-01T00:10:00",
        group_by=["IpAddress"], mode="events",
    )
    assert counts == {("10.0.0.1",): 1}  # только "новое" событие внутри окна


def test_insert_correlation_hits_is_idempotent(store):
    row = ("corr:X:dedup1:2024-01-01T00:00:00", "Bruteforce", "b1", "2024-01-01T00:00:00", '{"IpAddress": "10.0.0.1"}')
    store.insert_correlation_hits([row])
    store.insert_correlation_hits([row])  # повторная запись того же (event_id, rule_title)

    counts = store.evaluate_correlation_windows(
        rule_titles=["Bruteforce"], source_batch="b1",
        time_from="0000-01-01T00:00:00", time_to="9999-12-31T23:59:59",
        group_by=["IpAddress"], mode="events",
    )
    assert counts == {("10.0.0.1",): 1}  # не задвоилось


def test_upsert_correlation_alerts_overwrites_not_increments(store):
    """В отличие от upsert_alerts (increment) - correlation-алерт ПЕРЕЗАПИСЫВАЕТ event_count,
    т.к. окно пересчитывается заново на каждый flush (см. докстринг upsert_correlation_alerts)."""
    store.upsert_correlation_alerts([_corr_alert("dedup-1", event_count=10)])
    store.upsert_correlation_alerts([_corr_alert("dedup-1", event_count=3)])

    rows = store.list_alerts(source_batch="b1")
    assert len(rows) == 1
    assert rows[0]["event_count"] == 3  # не 13


def test_delete_events_older_than_removes_old_events_and_orphaned_hits(store):
    import time
    from datetime import datetime, timezone

    store.store_events(
        [{"row_id": 1, "Hostname": "HOST-A", "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:00:00"}],
        source_batch="b1",
        matched_row_to_rules={1: ["Failed Auth"]}, hit_spec={"Failed Auth": {"IpAddress"}},
    )
    time.sleep(0.05)
    cutoff = datetime.now(timezone.utc).isoformat()
    time.sleep(0.05)
    store.store_events(
        [{"row_id": 2, "Hostname": "HOST-A", "IpAddress": "10.0.0.1", "SystemTime": "2024-01-01T00:00:01"}],
        source_batch="b1",
        matched_row_to_rules={2: ["Failed Auth"]}, hit_spec={"Failed Auth": {"IpAddress"}},
    )

    deleted = store.delete_events_older_than(cutoff)
    assert deleted == 1
    assert store.count_events(source_batch="b1") == 1

    # Осиротевший rule_hits (для удалённого старого события) должен быть вычищен тоже -
    # иначе счёт корреляции видел бы 2 попадания вместо 1.
    counts = store.evaluate_correlation_windows(
        rule_titles=["Failed Auth"], source_batch="b1",
        time_from="0000-01-01T00:00:00", time_to="9999-12-31T23:59:59",
        group_by=["IpAddress"], mode="events",
    )
    assert counts == {("10.0.0.1",): 1}


def test_delete_events_older_than_keeps_recent_events(store):
    from datetime import datetime, timedelta, timezone

    store.store_events([{"row_id": 1, "Hostname": "HOST-A"}], source_batch="b1", matched_row_to_rules={})
    cutoff_in_past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    assert store.delete_events_older_than(cutoff_in_past) == 0
    assert store.count_events(source_batch="b1") == 1


def test_migrate_adds_missing_columns_to_pre_existing_db(tmp_path):
    """Аддитивная миграция (app/store.py:_migrate) на БД, созданной ДО появления ECS-lite
    колонок/group_json/новых индексов - CREATE TABLE IF NOT EXISTS в _SCHEMA сам по себе не
    добавил бы их в уже существующую таблицу."""
    import sqlite3

    db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            source_batch TEXT NOT NULL,
            host TEXT NOT NULL,
            event_time TEXT,
            ingested_at TEXT NOT NULL,
            is_matched INTEGER NOT NULL DEFAULT 0,
            matched_rules TEXT NOT NULL DEFAULT '[]',
            raw_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE rule_hits (
            event_id TEXT NOT NULL,
            rule_title TEXT NOT NULL,
            source_batch TEXT NOT NULL,
            event_time TEXT,
            PRIMARY KEY (event_id, rule_title)
        )
        """
    )
    conn.execute("CREATE INDEX idx_events_matched ON events(is_matched)")
    conn.commit()
    conn.close()

    from app.store import Store

    s = Store(db_path=db_path)
    try:
        event_cols = {row["name"] for row in s._conn.execute("PRAGMA table_info(events)")}
        assert {"user_name", "src_ip", "dst_ip", "process", "event_code"} <= event_cols

        hit_cols = {row["name"] for row in s._conn.execute("PRAGMA table_info(rule_hits)")}
        assert "group_json" in hit_cols

        index_names = {row["name"] for row in s._conn.execute("PRAGMA index_list(events)")}
        assert "idx_events_matched" not in index_names
        assert "idx_events_user" in index_names
        assert "idx_events_src_ip" in index_names
        assert "idx_events_ingested" in index_names

        # Запись/чтение работают как обычно на уже "мигрированной" таблице.
        s.store_events(
            [{"row_id": 1, "Hostname": "HOST-A", "User": "alice"}], source_batch="b1",
            matched_row_to_rules={},
        )
        assert s.count_events(source_batch="b1") == 1
    finally:
        s.close()
