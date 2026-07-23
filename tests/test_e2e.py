"""
Один e2e-тест на весь пайплайн: события -> ZircoliteEngine -> normalize -> Store,
теми же строительными блоками, что использует app/main.py:_process_batch, но БЕЗ
импорта app.main (тот на импорте создаёт глобальные engine/store поверх РЕАЛЬНЫХ
production-путей из app/config.py - siem.db и полный дефолтный рулсет, см. tests/conftest.py).
"""
from __future__ import annotations

from app.engine import ZircoliteEngine
from app.normalize import zircolite_results_to_alerts


def _build_matched_row_map(raw_results: list[dict]) -> dict[int, list[str]]:
    """1-в-1 копия app/main.py:_build_matched_row_map - см. докстринг модуля выше."""
    mapping: dict[int, list[str]] = {}
    for rule in raw_results:
        for event in rule.get("matches", []):
            row_id = event.get("row_id")
            if row_id is None:
                continue
            mapping.setdefault(row_id, []).append(rule.get("title", "Unnamed Rule"))
    return mapping


def test_full_pipeline_ingest_to_alert_and_event_storage(
    zircolite_config_path, test_ruleset_path, test_events_path, store
):
    events_path = test_events_path([
        {"Image": "C:\\Windows\\System32\\malicious.exe", "Hostname": "WIN-TEST-01",
         "TargetUserName": "alice", "EventID": 1},
        {"Image": "C:\\Windows\\System32\\notepad.exe", "Hostname": "WIN-TEST-01",
         "TargetUserName": "bob", "EventID": 1},
        {"Image": "C:\\Windows\\System32\\malicious.exe", "Hostname": "WIN-TEST-02",
         "TargetUserName": "carol", "EventID": 1},
    ])
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)

    raw_results, all_events, total_events, _ = engine.run_batch(events_path, input_type="json")
    assert total_events == 3

    matched_map = _build_matched_row_map(raw_results)
    store.store_events(all_events, source_batch="e2e-batch", matched_row_to_rules=matched_map)

    alerts = zircolite_results_to_alerts(raw_results, default_source_batch="e2e-batch")
    created = store.upsert_alerts(alerts)

    # 2 события матчат правило, но на РАЗНЫХ хостах -> 2 отдельных алерта.
    assert created == 2
    stored_alerts = {a["host"]: a for a in store.list_alerts(source_batch="e2e-batch")}
    assert set(stored_alerts) == {"WIN-TEST-01", "WIN-TEST-02"}
    assert all(a["event_count"] == 1 for a in stored_alerts.values())
    assert all(a["rule_title"] == "Test Rule - Suspicious Image" for a in stored_alerts.values())

    # Все 3 события сохранены как есть (включая не сработавшее), с корректным флагом is_matched.
    stored_events = store.list_events(source_batch="e2e-batch")
    assert len(stored_events) == 3
    assert sum(1 for e in stored_events if e["is_matched"]) == 2

    # Второй прогон ТЕХ ЖЕ данных - дедуп по dedup_key должен инкрементить, не плодить алерты.
    raw_results_2, all_events_2, _, _ = engine.run_batch(events_path, input_type="json")
    matched_map_2 = _build_matched_row_map(raw_results_2)
    store.store_events(all_events_2, source_batch="e2e-batch", matched_row_to_rules=matched_map_2)
    alerts_2 = zircolite_results_to_alerts(raw_results_2, default_source_batch="e2e-batch")
    store.upsert_alerts(alerts_2)

    stored_alerts_after = {a["host"]: a for a in store.list_alerts(source_batch="e2e-batch")}
    assert set(stored_alerts_after) == {"WIN-TEST-01", "WIN-TEST-02"}  # не новые алерты
    assert all(a["event_count"] == 2 for a in stored_alerts_after.values())  # инкремент
