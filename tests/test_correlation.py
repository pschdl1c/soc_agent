"""
Тесты app/detection/correlation.py: стейтфул-корреляция поверх Store (events/rule_hits).

Юнит-уровень - _active_correlation_rules подменяется monkeypatch'ем на фиксированный список
correlation-словарей (той же формы, что отдаёт app/rules/rules_catalog.load_correlation_rules),
без похода в реальный custom_rulesets на диске - интеграция с rules_catalog (резолв ссылок по
name/id, кэш по сигнатуре директории) покрыта отдельно, tests/test_rules_catalog_correlation.py.

Каждый тест собирает события руками и кладёт их в Store через store_events(..., hit_spec=...) -
ТОЧНО так же, как это делает app/main.py:_process_batch перед вызовом evaluate_batch - чтобы
rule_hits.group_json заполнялся тем же путём, что и в проде, а не подсовывался напрямую в БД.
"""
from __future__ import annotations

from typing import Any

from app.detection import correlation


def _corr(
    title: str,
    base_titles: list[str],
    corr_type: str,
    group_by: list[str],
    timespan: str,
    condition: dict[str, Any] | None = None,
    level: str = "high",
    base_refs: list[dict[str, str]] | None = None,
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
    }


def _events(rule_title: str, n: int, group_values: dict[str, Any], start_ts: str, step_seconds: int = 1):
    """n событий с одним и тем же group_values + монотонно растущим SystemTime, начиная с
    start_ts (формат 'YYYY-MM-DDTHH:MM:SS'), с шагом step_seconds. row_id уникален глобально
    через модульный счётчик, чтобы разные вызовы в одном тесте не коллизировали."""
    from datetime import datetime, timedelta

    base_dt = datetime.fromisoformat(start_ts)
    events = []
    for i in range(n):
        ts = (base_dt + timedelta(seconds=i * step_seconds)).isoformat()
        events.append({"row_id": f"{rule_title}-{start_ts}-{i}", **group_values, "SystemTime": ts})
    return events


def _ingest(store, events: list[dict], source_batch: str, rule_title: str, hit_fields: set[str]):
    """Кладёт события в Store так же, как app/main.py:_process_batch - matched_row_to_rules
    маппит КАЖДЫЙ row_id на rule_title, hit_spec ограничивает group_json полями hit_fields
    (то, что реально вычислил бы active_hit_spec)."""
    matched = {e["row_id"]: [rule_title] for e in events}
    store.store_events(events, source_batch=source_batch, matched_row_to_rules=matched, hit_spec={rule_title: hit_fields})


def _active(monkeypatch, corr_rules: list[dict[str, Any]]):
    monkeypatch.setattr(correlation, "_active_correlation_rules", lambda ruleset_path: corr_rules)


# ------------------------------------------------------------------ parse_timespan


def test_parse_timespan_units():
    from app.timespan import parse_timespan

    assert parse_timespan("5m") == 300
    assert parse_timespan("1h") == 3600
    assert parse_timespan("1d") == 86400
    assert parse_timespan("2w") == 1209600
    assert parse_timespan("30s") == 30


def test_parse_timespan_rejects_unsupported_units_and_garbage():
    from app.timespan import parse_timespan

    assert parse_timespan("1y") is None  # год не поддержан (единицы - только s/m/h/d/w)
    assert parse_timespan("1 month") is None
    assert parse_timespan("garbage") is None
    assert parse_timespan("-5m") is None  # регэксп требует цифры без знака
    assert parse_timespan("") is None
    assert parse_timespan(None) is None


# ------------------------------------------------------------------ event_count


def test_event_count_fires_at_threshold(store, monkeypatch):
    events = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr("Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10})
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})
    assert created == 1
    alerts = store.list_alerts(source_batch="b1")
    assert len(alerts) == 1
    assert alerts[0]["rule_title"] == "Bruteforce"
    assert alerts[0]["event_count"] == 10


def test_event_count_does_not_fire_below_threshold(store, monkeypatch):
    events = _events("Failed Auth", 9, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr("Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10})
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})
    assert created == 0
    assert store.list_alerts(source_batch="b1") == []


def test_event_count_window_boundary_excludes_stale_events(store, monkeypatch):
    """Ключевая регрессия, ради которой весь этот слой существует: событие ЗА пределами
    timespan не должно учитываться, даже если оно того же правила/ключа."""
    corr = _corr("Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10})
    _active(monkeypatch, [corr])

    # 9 "старых" событий в 00:00:00 - ВНЕ будущего окна [00:05:00, 00:10:00].
    old_events = _events("Failed Auth", 9, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, old_events, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": old_events})  # 9 < 10, не срабатывает

    # 1 новое событие в 00:10:00 - anchor этого флаша, окно = [00:05:00, 00:10:00].
    new_event = _events("Failed Auth", 1, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:10:00")
    _ingest(store, new_event, "b1", "Failed Auth", {"IpAddress"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": new_event})

    assert created == 0  # старые 9 событий не должны попасть в окно - итого 1, не 10
    assert store.list_alerts(source_batch="b1") == []


def test_event_count_window_boundary_includes_events_inside_window(store, monkeypatch):
    """Контроль к предыдущему тесту - те же 9 "старых" событий, но ВНУТРИ окна, должны
    засчитаться вместе с новым (итого 10 -> срабатывает)."""
    corr = _corr("Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10})
    _active(monkeypatch, [corr])

    # 9 событий в 00:06:00 - ВНУТРИ будущего окна [00:05:00, 00:10:00].
    old_events = _events("Failed Auth", 9, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:06:00")
    _ingest(store, old_events, "b1", "Failed Auth", {"IpAddress"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": old_events})

    new_event = _events("Failed Auth", 1, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:10:00")
    _ingest(store, new_event, "b1", "Failed Auth", {"IpAddress"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": new_event})

    assert created == 1
    assert store.list_alerts(source_batch="b1")[0]["event_count"] == 10


def test_event_count_numeric_group_by_field_counts_correctly(store, monkeypatch):
    """Регрессия дефекта, из-за которого group-by по ЧИСЛОВОМУ полю (EventID и т.п.) всегда
    считал 0: старый evaluate_correlation_window сравнивал json_extract(raw_json,...)
    (INTEGER-affinity для числового JSON-поля) с bound-параметром str(value) (TEXT) - SQLite
    никогда не считает INTEGER и TEXT равными. group_json теперь хранит ВСЕ значения строками
    на запись (store_events), сравнение тоже строковое - типового рассогласования больше нет."""
    events = _events("Logon Failure", 10, {"EventID": 4625}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Logon Failure", {"EventID"})
    corr = _corr("Bruteforce By EventID", ["Logon Failure"], "event_count", ["EventID"], "5m", {"gte": 10})
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Logon Failure": events})
    assert created == 1
    assert store.list_alerts(source_batch="b1")[0]["event_count"] == 10


# ------------------------------------------------------------------ value_count


def test_value_count_counts_distinct_field(store, monkeypatch):
    events = []
    for i in range(5):
        events += _events("Logon", 1, {"User": "alice", "Image": f"c{i}.exe"}, f"2024-01-01T00:0{i}:00")
    _ingest(store, events, "b1", "Logon", {"User", "Image"})
    corr = _corr(
        "Many Images", ["Logon"], "value_count", ["User"], "1h",
        condition={"field": "Image", "gte": 5},
    )
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Logon": events})
    assert created == 1
    assert store.list_alerts(source_batch="b1")[0]["event_count"] == 5


def test_value_count_without_field_is_skipped(store, monkeypatch):
    events = _events("Logon", 5, {"User": "alice", "Image": "a.exe"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Logon", {"User", "Image"})
    corr = _corr("Bad", ["Logon"], "value_count", ["User"], "1h", condition={"gte": 5})  # без field
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Logon": events})
    assert created == 0


# ------------------------------------------------------------------ temporal


def test_temporal_fires_when_all_refs_present_in_window(store, monkeypatch):
    corr = _corr("Recon Chain", ["Recon A", "Recon B"], "temporal", ["User"], "5m")
    _active(monkeypatch, [corr])

    events_a = _events("Recon A", 1, {"User": "alice"}, "2024-01-01T00:00:00")
    _ingest(store, events_a, "b1", "Recon A", {"User"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Recon A": events_a})
    assert created == 0  # только одна из двух ссылок

    events_b = _events("Recon B", 1, {"User": "alice"}, "2024-01-01T00:01:00")
    _ingest(store, events_b, "b1", "Recon B", {"User"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Recon B": events_b})
    assert created == 1
    assert store.list_alerts(source_batch="b1")[0]["rule_title"] == "Recon Chain"


def test_temporal_does_not_fire_when_one_ref_missing(store, monkeypatch):
    corr = _corr("Recon Chain", ["Recon A", "Recon B"], "temporal", ["User"], "5m")
    _active(monkeypatch, [corr])

    events_a = _events("Recon A", 1, {"User": "alice"}, "2024-01-01T00:00:00")
    _ingest(store, events_a, "b1", "Recon A", {"User"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Recon A": events_a})
    assert created == 0
    assert store.list_alerts(source_batch="b1") == []


# ------------------------------------------------------------------ temporal_ordered


def test_temporal_ordered_fires_on_correct_order(store, monkeypatch):
    corr = _corr(
        "Auth After Brute", ["Failed Auth", "Success Auth"], "temporal_ordered", ["User"], "1d",
    )
    _active(monkeypatch, [corr])

    failed = _events("Failed Auth", 1, {"User": "bob"}, "2024-01-01T00:00:00")
    _ingest(store, failed, "b1", "Failed Auth", {"User"})
    correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": failed})

    success = _events("Success Auth", 1, {"User": "bob"}, "2024-01-01T00:10:00")
    _ingest(store, success, "b1", "Success Auth", {"User"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Success Auth": success})

    assert created == 1
    assert store.list_alerts(source_batch="b1")[0]["rule_title"] == "Auth After Brute"


def test_temporal_ordered_does_not_fire_on_reverse_order(store, monkeypatch):
    """Апстрим Sigma-бэкенды (pysigma-backend-sqlite/-clickhouse) считают GROUP_CONCAT-
    последовательность и НИКОГДА её не сравнивают - temporal_ordered у них фактически равен
    temporal. Здесь порядок реально проверяется: success ДО failure не должен срабатывать."""
    corr = _corr(
        "Auth After Brute", ["Failed Auth", "Success Auth"], "temporal_ordered", ["User"], "1d",
    )
    _active(monkeypatch, [corr])

    success = _events("Success Auth", 1, {"User": "bob"}, "2024-01-01T00:00:00")
    _ingest(store, success, "b1", "Success Auth", {"User"})
    correlation.evaluate_batch(store, "rs", "b1", {"Success Auth": success})

    failed = _events("Failed Auth", 1, {"User": "bob"}, "2024-01-01T00:10:00")
    _ingest(store, failed, "b1", "Failed Auth", {"User"})
    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": failed})

    assert created == 0
    assert store.list_alerts(source_batch="b1") == []


# ------------------------------------------------------------------ цепочки (correlation -> correlation)


def test_chained_correlation_fires_within_same_flush(store, monkeypatch):
    """Форма artifacts/content/auth_after_brutforce.yml: temporal_ordered ссылается не на
    базовое правило, а на ДРУГУЮ correlation (event_count-роллап неудачных попыток). Обе
    корреляции активны одновременно, и родитель должен увидеть срабатывание потомка В ТОМ ЖЕ
    вызове evaluate_batch (см. _topo_order + immediate insert_correlation_hits)."""
    child = _corr(
        "Failures By Account", ["Failed Auth"], "event_count",
        ["TargetDomainName", "TargetUserName"], "1d", {"gte": 10}, level="medium",
    )
    parent = _corr(
        "Auth After Brute By Account", ["Failures By Account", "Success Auth"], "temporal_ordered",
        ["TargetDomainName", "TargetUserName"], "1d", level="high",
        base_refs=[
            {"title": "Failures By Account", "kind": "correlation"},
            {"title": "Success Auth", "kind": "base"},
        ],
    )
    _active(monkeypatch, [child, parent])

    key_fields = {"TargetDomainName": "CORP", "TargetUserName": "bob"}
    failed = _events("Failed Auth", 10, key_fields, "2024-01-01T00:00:00")
    _ingest(store, failed, "b1", "Failed Auth", {"TargetDomainName", "TargetUserName"})
    success = _events("Success Auth", 1, key_fields, "2024-01-01T00:20:00")
    _ingest(store, success, "b1", "Success Auth", {"TargetDomainName", "TargetUserName"})

    # ОДИН вызов - оба срабатывания (child event_count и parent temporal_ordered) видны
    # В ЭТОМ ЖЕ flush'е, т.к. и failed, и success событий "новые" для этого батча.
    created = correlation.evaluate_batch(
        store, "rs", "b1", {"Failed Auth": failed, "Success Auth": success},
    )
    assert created == 2
    titles = {a["rule_title"] for a in store.list_alerts(source_batch="b1")}
    assert titles == {"Failures By Account", "Auth After Brute By Account"}


def test_correlation_reference_cycle_does_not_hang(store, monkeypatch):
    """Правило A ссылается на B, B ссылается на A (некорректный, но возможный контент) -
    _topo_order не должен зациклиться/упасть, best-effort порядок допустим."""
    a = _corr(
        "A", ["B"], "temporal", ["User"], "5m",
        base_refs=[{"title": "B", "kind": "correlation"}],
    )
    b = _corr(
        "B", ["A"], "temporal", ["User"], "5m",
        base_refs=[{"title": "A", "kind": "correlation"}],
    )
    _active(monkeypatch, [a, b])

    # Не должно бросить исключение и не должно зависнуть (pytest сам ограничит время теста).
    created = correlation.evaluate_batch(store, "rs", "b1", {})
    assert created == 0


# ------------------------------------------------------------------ прочее


def test_informational_correlation_is_skipped(store, monkeypatch):
    events = _events("Failed Auth", 10, {"IpAddress": "10.0.0.1"}, "2024-01-01T00:00:00")
    _ingest(store, events, "b1", "Failed Auth", {"IpAddress"})
    corr = _corr(
        "Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10},
        level="informational",
    )
    _active(monkeypatch, [corr])

    created = correlation.evaluate_batch(store, "rs", "b1", {"Failed Auth": events})
    assert created == 0
    assert store.list_alerts(source_batch="b1") == []


def test_active_hit_spec_collects_group_by_and_value_count_field(monkeypatch):
    event_count_corr = _corr("Bruteforce", ["Failed Auth"], "event_count", ["IpAddress"], "5m", {"gte": 10})
    value_count_corr = _corr(
        "Many Images", ["Logon"], "value_count", ["User"], "1h", {"field": "Image", "gte": 5},
    )
    chain_child = _corr("Child", ["Base Rule"], "event_count", ["User"], "1h", {"gte": 3})
    chain_parent = _corr(
        "Parent", ["Child"], "temporal", ["User"], "1h",
        base_refs=[{"title": "Child", "kind": "correlation"}],
    )
    monkeypatch.setattr(
        correlation, "_active_correlation_rules",
        lambda ruleset_path: [event_count_corr, value_count_corr, chain_child, chain_parent],
    )

    spec = correlation.active_hit_spec("rs")
    assert spec["Failed Auth"] == {"IpAddress"}
    assert spec["Logon"] == {"User", "Image"}
    assert spec["Base Rule"] == {"User"}
    # "Child" - correlation, не base - не должен попасть в hit_spec (см. докстринг
    # active_hit_spec: её rule_hits пишет сама evaluate_batch через insert_correlation_hits).
    assert "Child" not in spec
