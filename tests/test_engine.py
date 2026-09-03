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
