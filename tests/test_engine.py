"""
Тесты ZircoliteEngine (app/detection/engine.py): кэширование скомпилированного рулсета,
run_batch отдаёт и raw_results (сработавшие правила), и all_events (ВСЕ события батча),
health()/invalidate() отражают состояние кэша.
"""
from __future__ import annotations

from app.detection.engine import ZircoliteEngine


def test_run_batch_matches_only_expected_events(zircolite_config_path, test_ruleset_path, test_events_path):
    events_path = test_events_path([
        {"Image": "C:\\Windows\\System32\\malicious.exe", "Hostname": "WIN-TEST-01", "EventID": 1},
        {"Image": "C:\\Windows\\System32\\notepad.exe", "Hostname": "WIN-TEST-01", "EventID": 1},
    ])
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)

    raw_results, all_events, total_events, elapsed = engine.run_batch(events_path, input_type="json")

    assert total_events == 2
    assert len(all_events) == 2
    assert elapsed >= 0
    assert len(raw_results) == 1
    matches = raw_results[0]["matches"]
    assert len(matches) == 1
    assert matches[0]["Image"].endswith("malicious.exe")


def test_run_batch_no_matches_returns_empty_raw_results(zircolite_config_path, test_ruleset_path, test_events_path):
    events_path = test_events_path([
        {"Image": "C:\\Windows\\System32\\notepad.exe", "Hostname": "WIN-TEST-01", "EventID": 1},
    ])
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)

    raw_results, all_events, total_events, _ = engine.run_batch(events_path, input_type="json")

    assert total_events == 1
    assert len(all_events) == 1
    # Правило было прогнано, но не сработало ни на одном событии - matches у него пустой,
    # либо оно вообще не попадает в raw_results (оба варианта не должны давать alert).
    assert all(not r.get("matches") for r in raw_results)


def test_ruleset_is_compiled_once_and_cached(zircolite_config_path, test_ruleset_path):
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)
    assert len(engine._rulesets_cache) == 1

    handler_before = engine._rulesets_cache[test_ruleset_path]
    engine._load_ruleset(test_ruleset_path)
    handler_after = engine._rulesets_cache[test_ruleset_path]

    # Тот же объект - повторный вызов не перекомпилировал рулсет заново.
    assert handler_before is handler_after
    assert len(engine._rulesets_cache) == 1


def test_invalidate_drops_cache_entry(zircolite_config_path, test_ruleset_path):
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)
    assert engine.invalidate(test_ruleset_path) is True
    assert test_ruleset_path not in engine._rulesets_cache
    # Повторный invalidate несуществующего ключа - не ошибка, просто False.
    assert engine.invalidate(test_ruleset_path) is False


def test_health_reports_loaded_rules(zircolite_config_path, test_ruleset_path):
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)
    health = engine.health()
    assert health["status"] == "ok"
    assert health["rules_loaded"] == 1
    assert health["cached_rulesets"] == 1


# --- Досоздание колонок таблицы флаша и логирование ошибок SQL правил ---------------------------

def _rule(title: str, sql: str) -> dict:
    return {"title": title, "id": title, "level": "high", "tags": [], "rule": [sql],
            "channel": [], "eventid": []}


def test_rule_with_field_absent_in_flush_does_not_break(zircolite_config_path, test_ruleset_path, test_events_path):
    """Флаш из одних 4104: правило с полем ParentImage (его нет ни в одном событии) раньше падало
    с `no such column` и молча не срабатывало. Теперь колонка досоздаётся NULL-ом: правило, где
    редкое поле под OR, срабатывает, соседние правила флаша - тоже."""
    events_path = test_events_path([
        {"EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational",
         "ScriptBlockText": "Invoke-Mimikatz", "Computer": "WIN-TEST-01"},
    ])
    rules = [
        _rule("Rare Field OR",
              "SELECT * FROM logs WHERE ParentImage LIKE '%evil.exe' OR ScriptBlockText LIKE '%Mimikatz%'"),
        _rule("Plain 4104", "SELECT * FROM logs WHERE EventID=4104"),
        _rule("Rare Field Only", "SELECT * FROM logs WHERE ParentCommandLine='x' AND OriginalFileName='y'"),
    ]
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)

    raw_results, all_events, total_events, _ = engine.run_batch_with_rules(events_path, rules)

    assert total_events == 1
    fired = {r["title"] for r in raw_results if r.get("matches")}
    assert fired == {"Rare Field OR", "Plain 4104"}
    # Досозданные NULL-колонки не протекают в события (Zircolite отбрасывает None).
    assert "ParentImage" not in all_events[0]
    assert "ParentCommandLine" not in all_events[0]


def test_rule_sql_error_is_logged_once_per_interval(
    zircolite_config_path, test_ruleset_path, test_events_path, caplog
):
    events_path = test_events_path([{"EventID": 1, "Image": "a.exe"}])
    rules = [_rule("Broken SQL", "SELECT * FROM logs WHERE Image LIKE")]
    engine = ZircoliteEngine(config_path=zircolite_config_path, default_ruleset_path=test_ruleset_path)

    with caplog.at_level("WARNING", logger="app.detection.engine"):
        engine.run_batch_with_rules(events_path, rules)
        engine.run_batch_with_rules(events_path, rules)

    messages = [r.getMessage() for r in caplog.records if "Broken SQL" in r.getMessage()]
    assert len(messages) == 1


def test_rule_column_index_finds_referenced_columns():
    from app.detection.engine import RuleColumnIndex

    index = RuleColumnIndex()
    sql = ("SELECT * FROM logs WHERE Channel='Security' AND (EventID=4625 AND "
           "(TargetUserName LIKE '%$' ESCAPE '\\' OR IpAddress regexp 'a=b') AND NOT `Logon Type`=3)")
    # Строковые литералы с '=' и LIKE-шаблоны за колонки не принимаются.
    assert index.columns_for(sql) == {"Channel", "EventID", "TargetUserName", "IpAddress", "Logon Type"}
    # Существующие колонки (без учёта регистра) не досоздаются.
    missing = index.missing_columns([{"rule": [sql]}], {"channel", "EVENTID", "row_id"})
    assert set(missing) == {"TargetUserName", "IpAddress", "Logon Type"}
