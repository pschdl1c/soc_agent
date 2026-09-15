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


def test_same_entity_in_two_sources_creates_two_incidents(store, monkeypatch):
    """source_batch входит в dedup_key. Без него два источника, увидевшие одну сущность в одном
    бакете (один IP по двум серверам, у каждого свой форвардер), схлопывались в ОДНУ строку:
    UPDATE перезаписывал окно/сэмплы/сущности данными второго, а метка source_batch оставалась
    от первого - карточка показывала события B под ярлыком A, member-алерты приезжали из обоих,
    а /incidents/{id}/context собирал related_events по источнику A."""
    corr = _corr("BF", ["Failed Auth"], "event_count", ["IpAddress"], "1h", {"gte": 10}, incident=_INC)
    _active(monkeypatch, [corr])

    # Один и тот же IP, одно и то же время - различается ТОЛЬКО источник.
    from_a = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, from_a, "forwarder-a", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "forwarder-a", {"Failed Auth": from_a})

    from_b = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, from_b, "forwarder-b", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "forwarder-b", {"Failed Auth": from_b})

    a = store.list_incidents(source_batch="forwarder-a")
    b = store.list_incidents(source_batch="forwarder-b")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["incident_id"] != b[0]["incident_id"]
    assert a[0]["dedup_key"] != b[0]["dedup_key"]

    # Удаление одного источника не трогает инцидент другого.
    store.delete_batch("forwarder-a")
    assert store.list_incidents(source_batch="forwarder-a") == []
    assert len(store.list_incidents(source_batch="forwarder-b")) == 1


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


def _alert_with_event(store, dedup_key, source_batch, host, rule_title, level, ip=None):
    """Хелпер: заводит Alert + одно реальное event, привязывает event->alert через
    store.link_events_to_alerts (1-в-1 то, что делает app/main.py:_process_batch), возвращает
    (alert_id, event_id) - готовый вход для store.link_alerts_to_incident."""
    from app.models import Alert, Entities as E, SigmaRuleRef, Severity

    alert = Alert(
        dedup_key=dedup_key, source_batch=source_batch, host=host,
        rule=SigmaRuleRef(rule_id="r1", title=rule_title, level=Severity(level)),
        entities=E(src_ips=[ip] if ip else []), event_count=1, sample_events=[],
    )
    store.upsert_alerts([alert])
    alert_id = store.get_alert_ids_by_dedup_keys([dedup_key])[dedup_key]

    row_id_to_event_id = store.store_events(
        [{"row_id": f"{dedup_key}-ev", "Hostname": host, **({"IpAddress": ip} if ip else {})}],
        source_batch=source_batch, matched_row_to_rules={f"{dedup_key}-ev": [rule_title]},
    )
    event_id = row_id_to_event_id[f"{dedup_key}-ev"]
    store.link_events_to_alerts({event_id: alert_id})
    return alert_id, event_id


def test_link_alerts_to_incident_counts_and_rolls_up(store):
    """Базовый случай: реальный event_id -> events.alert_id -> alert найден и привязан."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    alert_id, event_id = _alert_with_event(
        store, "a1", "b1", "HOST-A", "Failed Auth", "high", ip="10.0.0.1",
    )

    linked = store.link_alerts_to_incident(inc_id, "b1", [event_id])
    assert linked == 1
    row = store.get_incident(inc_id)
    assert row["alert_count"] == 1
    assert row["severity"] == "high"  # roll-up low(incident) + high(member alert)
    assert row["member_alerts"][0]["rule_title"] == "Failed Auth"
    assert row["member_alerts"][0]["alert_id"] == alert_id


def test_link_alerts_to_incident_via_synthetic_correlation_id(store):
    """Цепочка: событие вида 'corr:{dedup}:{title}:{time}' (сработка ДРУГОЙ, не-инцидентной
    correlation-записи, см. докстринг correlation.py про цепочки) резолвится напрямую по
    alerts.dedup_key - тот же dedup_key, что достаётся correlation._dedup_key при постройке её
    собственного алерта, без похода через events вообще."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    from app.models import Alert, Entities as E, SigmaRuleRef, Severity

    corr_dedup = "deadbeefcafef00d"  # ровно 16 hex, как настоящий sha256[:16]
    corr_alert = Alert(
        dedup_key=corr_dedup, source_batch="b1", host="HOST-B", engine="correlation",
        rule=SigmaRuleRef(rule_id="r2", title="Failures By IP", level=Severity.medium),
        entities=E(), event_count=10, sample_events=[],
    )
    store.upsert_alerts([corr_alert])
    corr_alert_id = store.get_alert_ids_by_dedup_keys([corr_dedup])[corr_dedup]

    synthetic_id = f"corr:{corr_dedup}:Failures By IP:2024-01-01T00:05:00"
    linked = store.link_alerts_to_incident(inc_id, "b1", [synthetic_id])
    assert linked == 1
    row = store.get_incident(inc_id)
    assert row["member_alerts"][0]["alert_id"] == corr_alert_id


def test_link_alerts_to_incident_mixes_real_and_synthetic_ids(store):
    """Реалистичный смешанный случай (напр. temporal_ordered, ссылающийся И на другую
    correlation, И на базовое правило напрямую) - оба вида event_id в одном вызове, оба находят
    свой алерт."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    _, real_event_id = _alert_with_event(store, "a-real", "b1", "HOST-A", "Success Auth", "high")

    from app.models import Alert, Entities as E, SigmaRuleRef, Severity
    corr_dedup = "0123456789abcdef"
    store.upsert_alerts([Alert(
        dedup_key=corr_dedup, source_batch="b1", host="HOST-A", engine="correlation",
        rule=SigmaRuleRef(rule_id="r3", title="Failures By IP", level=Severity.medium),
        entities=E(), event_count=10, sample_events=[],
    )])
    synthetic_id = f"corr:{corr_dedup}:Failures By IP:2024-01-01T00:05:00"

    linked = store.link_alerts_to_incident(inc_id, "b1", [real_event_id, synthetic_id])
    assert linked == 2
    assert store.get_incident(inc_id)["alert_count"] == 2


def test_link_alerts_to_incident_unknown_event_id_links_nothing(store):
    """Мусорный/несуществующий event_id (например, событие вычищено ретеншном) - не падает,
    просто ничего не привязывает."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    linked = store.link_alerts_to_incident(inc_id, "b1", ["does-not-exist-anywhere"])
    assert linked == 0
    assert store.get_incident(inc_id)["alert_count"] == 0


def test_link_alerts_to_incident_synthetic_id_for_incident_marked_correlation_is_noop(store):
    """Синтетический id ссылается на correlation, которая САМА была инцидентной (не
    рекомендуемый паттерн - см. CLAUDE.md, инцидентная запись должна быть терминальной в
    цепочке) - её dedup_key живёт в incidents, не в alerts. Не должно падать, просто не находит
    алерт для этого конкретного event_id (у самой correlation алерта и не было)."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    other_inc_dedup = "1111222233334444"
    store.upsert_incidents([_incident(dedup=other_inc_dedup, itype="child_incident")])
    synthetic_id = f"corr:{other_inc_dedup}:Some Marked Correlation:2024-01-01T00:05:00"

    linked = store.link_alerts_to_incident(inc_id, "b1", [synthetic_id])
    assert linked == 0


def test_link_alerts_to_incident_shares_alert_between_incidents(store):
    """Два сценария на одних событиях (напр. SCE_Recon_Scripted_Discovery и
    SCE_TH_Recon_Discovery_Burst) - алерт входит в ОБА инцидента (incident_alerts, many-to-many).
    Раньше второй инцидент оставался с 0 member-алертов. Повторная привязка к тому же инциденту
    дубля не даёт."""
    inc1 = store.upsert_incidents([_incident(dedup="i1", severity="low")])[0][0]
    inc2 = store.upsert_incidents([_incident(dedup="i2", severity="low")])[0][0]
    alert_id, event_id = _alert_with_event(store, "a1", "b1", "HOST-A", "Failed Auth", "high")

    assert store.link_alerts_to_incident(inc1, "b1", [event_id]) == 1
    assert store.link_alerts_to_incident(inc2, "b1", [event_id]) == 1
    assert store.link_alerts_to_incident(inc2, "b1", [event_id]) == 0
    for inc in (inc1, inc2):
        row = store.get_incident(inc)
        assert row["alert_count"] == 1
        assert row["severity"] == "high"
        assert [a["alert_id"] for a in row["member_alerts"]] == [alert_id]

    # Удаление источника снимает связи вместе с инцидентами и алертами.
    store.delete_batch("b1")
    conn = store._conn
    assert conn.execute("SELECT COUNT(*) FROM incident_alerts").fetchone()[0] == 0


def test_alerts_incident_filter_search_and_groups(store):
    """Вкладка "Алерты": фильтр участия в инцидентах, поиск (в т.ч. кириллица в сущностях),
    incident_ids в строках, группировка по правилу - всё на одних и тех же условиях WHERE."""
    from app.models import Alert, Entities as E, SigmaRuleRef, Severity

    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    a_in, ev_in = _alert_with_event(store, "d1", "b1", "HOST-A", "Discovery Utility Execution", "low")
    _alert_with_event(store, "d2", "b1", "HOST-B", "Discovery Utility Execution", "medium")
    store.upsert_alerts([Alert(
        dedup_key="u1", source_batch="b1", host="HOST-C",
        rule=SigmaRuleRef(rule_id="r9", title="Failed Logon", level=Severity.high),
        entities=E(users=["Иван"]), event_count=3, sample_events=[],
    )])
    store.link_alerts_to_incident(inc_id, "b1", [ev_in])

    inside = store.list_alerts(incident="in")
    assert [a["alert_id"] for a in inside] == [a_in]
    assert inside[0]["incident_ids"] == [inc_id]
    outside = store.list_alerts(incident="none")
    assert len(outside) == 2 and all(a["incident_ids"] == [] for a in outside)
    assert store.count_alerts(incident="none") == 2

    assert {a["host"] for a in store.list_alerts(q="host-b")} == {"HOST-B"}
    assert [a["host"] for a in store.list_alerts(q="ИВАН")] == ["HOST-C"]
    assert store.count_alerts(q="discovery") == 2
    assert store.count_alerts(rule_title="Discovery Utility Execution", incident="none") == 1

    groups, total = store.group_alerts_by_rule(sort_by="alert_count", sort_dir="desc")
    assert total == 2
    top = groups[0]
    assert (top["rule_title"], top["alert_count"], top["event_count"], top["in_incident_count"],
            top["rule_level"]) == ("Discovery Utility Execution", 2, 2, 1, "medium")
    assert store.group_alerts_by_rule(incident="in")[1] == 1

    alert = store.get_alert(a_in)
    assert [i["incident_id"] for i in alert["incidents"]] == [inc_id]


def test_link_alerts_to_incident_groups_multiple_distinct_alerts(store):
    """Несколько РАЗНЫХ алертов (напр. дедуп по содержимому custom-правила разбил их на
    отдельные строки, см. normalize.py) от одного сценария - все привязываются и группируются
    под одним инцидентом, не только первый найденный."""
    inc_id = store.upsert_incidents([_incident(severity="low")])[0][0]
    _, ev1 = _alert_with_event(store, "a1", "b1", "HOST-A", "LOLBin Execution", "informational")
    _, ev2 = _alert_with_event(store, "a2", "b1", "HOST-A", "LOLBin Execution", "informational")
    _, ev3 = _alert_with_event(store, "a3", "b1", "HOST-A", "LOLBin Execution", "informational")

    linked = store.link_alerts_to_incident(inc_id, "b1", [ev1, ev2, ev3])
    assert linked == 3
    assert store.get_incident(inc_id)["alert_count"] == 3


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


# ------------------------------------------------------------------ поиск (q) по вкладке Инциденты

def _incident_with_titles(dedup: str, correlation_rule_title: str, title: str) -> Incident:
    return Incident(
        dedup_key=dedup, incident_type="t", title=title, severity="medium", source_batch="b1",
        correlation_rule_title=correlation_rule_title, correlation_rule_id="id",
        group_key={}, member_rule_titles=[],
        window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:04:00",
        window_bucket="2024-01-01T00:00:00",
    )


def test_list_incidents_q_matches_correlation_rule_title_or_title(store):
    store.upsert_incidents([_incident_with_titles(
        "d1", "T5 - Suspicious Domain Queried By Multiple Hosts",
        "Один и тот же C2-домен запрошен с нескольких хостов",
    )])
    store.upsert_incidents([_incident_with_titles(
        "d2", "T4 - Multiple Run Keys Modified On Host",
        "Несколько разных ключей автозапуска изменено на хосте",
    )])

    # По подстроке из "Инцидент" (correlation_rule_title).
    assert {r["dedup_key"] for r in store.list_incidents(q="Suspicious Domain")} == {"d1"}
    # По подстроке из "Описание" (title) - в т.ч. кириллица.
    assert {r["dedup_key"] for r in store.list_incidents(q="ключей автозапуска")} == {"d2"}
    # Не совпадает ни с чем.
    assert store.list_incidents(q="совсем другое") == []
    assert store.count_incidents(q="ключей автозапуска") == 1


def test_list_incidents_q_is_case_insensitive_including_cyrillic(store):
    store.upsert_incidents([_incident_with_titles(
        "d1", "T5 - Suspicious Domain", "Один и тот же C2-домен",
    )])
    assert len(store.list_incidents(q="suspicious domain")) == 1  # разный регистр, ASCII
    assert len(store.list_incidents(q="ДОМЕН")) == 1  # разный регистр, кириллица
    assert len(store.list_incidents(q="один и тот же")) == 1


def test_list_incidents_q_combines_with_other_filters(store):
    store.upsert_incidents([_incident_with_titles("d1", "Same Title", "desc a")])
    store.upsert_incidents([Incident(
        dedup_key="d2", incident_type="t", title="desc a", severity="medium", source_batch="b2",
        correlation_rule_title="Same Title", correlation_rule_id="id",
        group_key={}, member_rule_titles=[],
        window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:04:00",
        window_bucket="2024-01-01T00:00:00",
    )])

    # q совпадает с обоими, но source_batch сужает до одного.
    assert {r["dedup_key"] for r in store.list_incidents(q="Same Title", source_batch="b1")} == {"d1"}
    assert store.count_incidents(q="Same Title", source_batch="b1") == 1


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


def test_chain_incident_carries_events_of_the_child_correlation(store, monkeypatch):
    """AGT-1: у корреляции НАД корреляцией sample_events/entities приходили пустыми - попадание
    правила-предка живёт в rule_hits с синтетическим event_id ("corr:..."), которому в events
    не соответствует ничего, и JOIN его молча пропускал. Для агента Этапа 5 это означало
    инцидент вообще без входных данных."""
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

    inc = store.get_incident(store.list_incidents(source_batch="b1")[0]["incident_id"])
    samples = inc["sample_events"]
    # И успешный вход (окно самой корреляции), и предшествующие неудачи (окно предка).
    assert len(samples) > 1
    row_ids = {s.get("row_id", "") for s in samples}
    assert any(str(r).startswith("Failed Auth-") for r in row_ids)
    assert any(str(r).startswith("Success Auth-") for r in row_ids)
    # Сэмплы идут по времени, а не "успешный вход первым".
    times = [s["SystemTime"] for s in samples]
    assert times == sorted(times)
    # entities извлекаются из сэмплов - раньше они были пустыми вместе с ними.
    assert inc["entities"]["users"] == ["bob"]


def test_update_incident_status_rejects_unknown_value(store):
    """API-1: раньше {"status": "bogus"} доезжал до БД, после чего инцидент не находился
    ни одним фильтром /incidents?status=..."""
    import pytest

    store.upsert_incidents([_incident("d-status")])
    incident_id = store.list_incidents(source_batch="b1")[0]["incident_id"]

    assert store.update_incident_status(incident_id, "investigating") is True
    with pytest.raises(ValueError):
        store.update_incident_status(incident_id, "bogus")
    assert store.get_incident(incident_id)["status"] == "investigating"


def test_migrate_repairs_garbage_incident_status(tmp_path):
    """Мусор, записанный до появления проверки, возвращается в 'new' - иначе инцидент навсегда
    выпадает из триажа (ни один фильтр по статусу его не находит)."""
    import sqlite3

    from app.store import Store

    db_path = str(tmp_path / "garbage.db")
    s = Store(db_path=db_path)
    s.upsert_incidents([_incident("d-garbage")])
    incident_id = s.list_incidents(source_batch="b1")[0]["incident_id"]
    s.close()

    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE incidents SET status = 'bogus' WHERE incident_id = ?", (incident_id,))
    conn.commit()
    conn.close()

    s = Store(db_path=db_path)
    try:
        assert s.get_incident(incident_id)["status"] == "new"
    finally:
        s.close()
