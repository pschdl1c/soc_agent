"""
Тесты Этапа 4 - инциденты и расследования.

Движковая часть (app/detection/correlation.py:evaluate_batch) - тем же приёмом, что и
tests/test_correlation.py: _active_correlation_rules подменяется на фиксированный список
correlation-словарей, события кладутся в Store через store_events(..., hit_spec=...). app.main
не импортируется.

Хранилищная часть (app/store.py) и заглушка джобы (app/incidents.py) - напрямую через фикстуру store.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app import incidents as incidents_mod
from app.detection import correlation
from app.models import Entities, Incident


# ------------------------------------------------------------------ helpers (форма tests/test_correlation.py)


def _corr(
    title: str,
    base_titles: list[str],
    corr_type: str,
    group_by: list[str],
    timespan: str,
    condition: dict[str, Any] | None = None,
    level: str = "high",
    base_refs: list[dict[str, str]] | None = None,
    incident: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"id-{title}",
        "title": title,
        "level": level,
        "description": "",
        "tags": ["attack.credential-access", "attack.t1110"],
        "type": corr_type,
        "group_by": group_by,
        "timespan": timespan,
        "condition": condition or {},
        "base_rule_titles": base_titles,
        "base_rule_refs": base_refs or [{"title": t, "kind": "base"} for t in base_titles],
        "ruleset_path": "custom_rulesets/test",
        "incident": incident,
    }


def _events(rule_title: str, n: int, group_values: dict[str, Any], start_ts: str, step_seconds: int = 1):
    base_dt = datetime.fromisoformat(start_ts)
    out = []
    for i in range(n):
        ts = (base_dt + timedelta(seconds=i * step_seconds)).isoformat()
        out.append({"row_id": f"{rule_title}-{start_ts}-{i}", **group_values, "SystemTime": ts})
    return out


def _ingest(store, events: list[dict], source_batch: str, rule_title: str, hit_fields: set[str]):
    matched = {e["row_id"]: [rule_title] for e in events}
    store.store_events(
        events, source_batch=source_batch, matched_row_to_rules=matched,
        hit_spec={rule_title: hit_fields},
    )


def _active(monkeypatch, corr_rules: list[dict[str, Any]]):
    monkeypatch.setattr(correlation, "_active_correlation_rules", lambda ruleset_path: corr_rules)


_INC = {"type": "brute_force", "severity": "high"}


# ------------------------------------------------------------------ движок: инцидент вместо алерта


def test_marked_rule_creates_incident_not_alert(store, monkeypatch):
    events = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr("BF Scenario", ["Failed Auth"], "event_count", ["IpAddress"], "5m",
                 {"gte": 10}, incident=_INC)
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})
    assert created == 1
    assert store.list_alerts(source_batch="b1") == []  # НЕ correlation-алерт
    incs = store.list_incidents(source_batch="b1")
    assert len(incs) == 1
    assert incs[0]["incident_type"] == "brute_force"
    assert incs[0]["severity"] == "high"
    assert incs[0]["group_key"] == {"IpAddress": "10.0.0.1"}
    assert incs[0]["correlation_rule_title"] == "BF Scenario"
    assert incs[0]["investigation_status"] == "queued"


def test_new_incident_enqueues_investigation(store, monkeypatch):
    events = _events("Failed Auth", 10, {"IpAddress": "10.0.0.9"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr("BF", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10}, incident=_INC)
    _active(monkeypatch, [corr])
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})

    inc_id = store.list_incidents(source_batch="b1")[0]["incident_id"]
    inv = store.get_investigation(inc_id)
    assert inv is not None and inv["status"] == "queued"


def test_same_bucket_refire_updates_single_incident(store, monkeypatch):
    corr = _corr("BF", ["Failed Auth"], "event_count", ["IpAddress"], "1h", {"gte": 10}, incident=_INC)
    _active(monkeypatch, [corr])

    first = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, first, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": first})

    # ещё события в пределах того же часового бакета -> UPDATE той же строки, не новая
    second = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:20:00")
    _ingest(store, second, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": second})

    incs = store.list_incidents(source_batch="b1")
    assert len(incs) == 1
    assert incs[0]["window_end"] >= "2024-01-01T00:20"


def test_gap_beyond_timespan_creates_second_incident(store, monkeypatch):
    corr = _corr("BF", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10}, incident=_INC)
    _active(monkeypatch, [corr])

    first = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, first, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": first})

    # намного позже - другой бакет по 5m -> другой dedup_key -> второй инцидент
    later = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T09:00:00")
    _ingest(store, later, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": later})

    assert len(store.list_incidents(source_batch="b1")) == 2


def test_chain_with_marked_top_link(store, monkeypatch):
    """Цепочка: непомеченный event_count-роллап (даёт correlation-алерт) + помеченное сверху
    temporal_ordered (даёт инцидент, НЕ алерт)."""
    child = _corr("Failures By Account", ["Failed Auth"], "event_count",
                  ["TargetDomainName", "TargetUserName"], "1d", {"gte": 10}, level="medium")
    parent = _corr(
        "Account Compromised", ["Failures By Account", "Success Auth"], "temporal_ordered",
        ["TargetDomainName", "TargetUserName"], "1d", level="high",
        base_refs=[
            {"title": "Failures By Account", "kind": "correlation"},
            {"title": "Success Auth", "kind": "base"},
        ],
        incident={"type": "account_compromise"},
    )
    _active(monkeypatch, [child, parent])

    key = {"TargetDomainName": "CORP", "TargetUserName": "bob"}
    failed = _events("Failed Auth", 10, key, "2024-01-01T00:00:00")
    _ingest(store, failed, "b1", "Failed Auth", {"TargetDomainName", "TargetUserName"})
    success = _events("Success Auth", 1, key, "2024-01-01T00:20:00")
    _ingest(store, success, "b1", "Success Auth", {"TargetDomainName", "TargetUserName"})

    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": failed, "Success Auth": success})

    alert_titles = {a["rule_title"] for a in store.list_alerts(source_batch="b1")}
    assert alert_titles == {"Failures By Account"}  # только промежуточный роллап
    incs = store.list_incidents(source_batch="b1")
    assert len(incs) == 1
    assert incs[0]["correlation_rule_title"] == "Account Compromised"
    assert incs[0]["incident_type"] == "account_compromise"


def test_informational_marked_rule_still_fires(store, monkeypatch):
    """Помеченное правило пробивает informational-отсечку (severity инцидента - из incident.severity)."""
    events = _events("Failed Auth", 10, {"IpAddress": "10.0.0.2"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr("BF", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10},
                 level="informational", incident={"type": "brute_force", "severity": "medium"})
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})
    assert created == 1
    assert store.list_incidents(source_batch="b1")[0]["severity"] == "medium"


# ------------------------------------------------------------------ store: upsert / link / enqueue


def _incident(dedup="d1", itype="brute_force", severity="medium", source_batch="b1",
              bucket="2024-01-01T00:00:00", titles=None):
    return Incident(
        dedup_key=dedup, incident_type=itype, title="T", severity=severity, source_batch=source_batch,
        correlation_rule_title="R", correlation_rule_id="id-R",
        group_key={"IpAddress": "10.0.0.1"}, member_rule_titles=titles or ["Failed Auth"],
        window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:04:00", window_bucket=bucket,
        entities=Entities(src_ips=["10.0.0.1"]),
    )


def test_upsert_incidents_insert_then_update_same_bucket(store):
    r1 = store.upsert_incidents([_incident()])
    assert r1 == [(r1[0][0], True)]
    r2 = store.upsert_incidents([_incident(severity="critical")])
    assert r2[0][1] is False and r2[0][0] == r1[0][0]
    row = store.get_incident(r1[0][0])
    assert row["severity"] == "critical"  # roll-up medium -> critical
    assert len(store.list_incidents()) == 1


def test_link_alerts_to_incident_counts_and_rolls_up(store):
    from app.models import Alert, Entities as E, SigmaRuleRef, Severity

    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    alert = Alert(
        dedup_key="a1", source_batch="b1", host="HOST-A",
        rule=SigmaRuleRef(rule_id="r1", title="Failed Auth", level=Severity.high),
        entities=E(src_ips=["10.0.0.1"]), event_count=3, sample_events=[],
    )
    store.upsert_alerts([alert])

    linked = store.link_alerts_to_incident(inc_id, "b1", ["Failed Auth"], ["10.0.0.1"])
    assert linked == 1
    row = store.get_incident(inc_id)
    assert row["alert_count"] == 1
    assert row["severity"] == "high"  # roll-up low(incident) + high(member alert)
    assert row["member_alerts"][0]["rule_title"] == "Failed Auth"


def test_enqueue_investigation_dedup_and_requeue(store):
    inc_id = store.upsert_incidents([_incident()])[0][0]
    first = store.enqueue_investigation(inc_id)
    assert first is not None
    assert store.enqueue_investigation(inc_id) is None  # уже queued
    # завершаем -> ре-энкью терминального
    store.update_investigation(first, status="done", verdict="TP")
    again = store.enqueue_investigation(inc_id, requeue_terminal=True)
    assert again == first
    assert store.get_investigation(inc_id)["status"] == "queued"


def test_delete_batch_purges_incidents_and_investigations(store):
    inc_id = store.upsert_incidents([_incident(source_batch="b1")])[0][0]
    store.enqueue_investigation(inc_id)
    res = store.delete_batch("b1")
    assert res["incidents_deleted"] == 1
    assert store.list_incidents() == []
    assert store.get_investigation(inc_id) is None


def test_list_incidents_filters_and_pagination(store):
    store.upsert_incidents([_incident(dedup="d1", itype="brute_force", source_batch="b1")])
    store.upsert_incidents([_incident(dedup="d2", itype="recon", source_batch="b1", bucket="2024-02-01T00:00:00")])
    store.upsert_incidents([_incident(dedup="d3", itype="brute_force", source_batch="b2", bucket="2024-03-01T00:00:00")])

    assert store.count_incidents(incident_type="brute_force") == 2
    assert len(store.list_incidents(source_batch="b1")) == 2
    assert len(store.list_incidents(limit=1)) == 1


# ------------------------------------------------------------------ заглушка джобы (app/incidents.py)


def test_run_pending_stub_marks_done(store):
    inc_id = store.upsert_incidents([_incident()])[0][0]
    store.enqueue_investigation(inc_id)

    n = incidents_mod.run_pending(store)
    assert n == 1
    inv = store.get_investigation(inc_id)
    assert inv["status"] == "done"
    assert inv["verdict"] == "needs-review"
    assert inv["rationale"]
    # повторный проход не трогает done
    assert incidents_mod.run_pending(store) == 0
    assert store.get_investigation(inc_id)["status"] == "done"


def test_run_pending_error_path(store, monkeypatch):
    inc_id = store.upsert_incidents([_incident()])[0][0]
    store.enqueue_investigation(inc_id)

    real = store.update_investigation
    calls = {"n": 0}

    def flaky(investigation_id, **fields):
        calls["n"] += 1
        if calls["n"] == 2:  # первый вызов (running) проходит, второй (done) падает
            raise RuntimeError("boom")
        return real(investigation_id, **fields)

    monkeypatch.setattr(store, "update_investigation", flaky)
    incidents_mod.run_pending(store)
    assert store.get_investigation(inc_id)["status"] == "error"
