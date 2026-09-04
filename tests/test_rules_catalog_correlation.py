"""
Тесты app/rules/rules_catalog.py для correlation-правил: резолв ссылок correlation.rules
по name/id (в т.ч. ссылка на ДРУГУЮ correlation - цепочки) и валидация при сохранении.

Гоняет настоящий compile_custom_rule/save_ruleset_yaml/load_correlation_rules с CUSTOM_ROOT,
подменённым на tmp_path (тот же паттерн, что и tests/test_rules_catalog_expand.py) - реальный
data/custom_rulesets проекта не трогается.
"""
from __future__ import annotations

import pytest

from app.rules import rules_catalog
from app.rules.rules_catalog import RuleValidationError


@pytest.fixture(autouse=True)
def _isolate_custom_root(tmp_path, monkeypatch):
    root = tmp_path / "custom_rulesets"
    root.mkdir()
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", root)
    return root


_BASE_RULE_A = """\
title: Failed Auth
name: failed_auth
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
"""

_BASE_RULE_B = """\
title: Successful Auth
name: success_auth
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: informational
"""

_CORR_BY_NAME = """\
title: Bruteforce By Name
name: bruteforce_by_name
id: 33333333-3333-3333-3333-333333333333
correlation:
  type: event_count
  rules:
    - failed_auth
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
level: high
"""

_CORR_BY_ID = """\
title: Bruteforce By Id
name: bruteforce_by_id
id: 44444444-4444-4444-4444-444444444444
correlation:
  type: event_count
  rules:
    - 11111111-1111-1111-1111-111111111111
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
level: high
"""

_CORR_CHAIN_PARENT = """\
title: Auth After Brute
name: auth_after_brute
id: 55555555-5555-5555-5555-555555555555
correlation:
  type: temporal_ordered
  rules:
    - bruteforce_by_name
    - success_auth
  group-by:
    - IpAddress
  timespan: 1d
level: high
"""


def _save(ruleset_path: str, yaml_text: str) -> None:
    summary, path, collisions, imported = rules_catalog.save_ruleset_yaml(yaml_text, ruleset=ruleset_path)
    assert collisions == [], collisions


def test_load_correlation_rules_resolves_ref_by_name():
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _CORR_BY_NAME)

    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert len(rules) == 1
    corr = rules[0]
    assert corr["title"] == "Bruteforce By Name"
    assert corr["base_rule_titles"] == ["Failed Auth"]
    assert corr["base_rule_refs"] == [{"title": "Failed Auth", "kind": "base"}]
    assert corr["group_by"] == ["IpAddress"]
    assert corr["timespan"] == "5m"


def test_load_correlation_rules_resolves_ref_by_id():
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _CORR_BY_ID)

    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert len(rules) == 1
    assert rules[0]["base_rule_titles"] == ["Failed Auth"]


def test_load_correlation_rules_resolves_reference_to_another_correlation():
    """Регрессия ключевого дефекта (см. CLAUDE.md/план Этапа A): раньше индекс ссылок строился
    ТОЛЬКО по *.yml/*.yaml - ссылка correlation -> correlation никогда не резолвилась, и ВСЯ
    correlation-запись (включая её собственные корректные base-ссылки) молча пропускалась
    целиком. Форма - как artifacts/content/auth_after_brutforce.yml."""
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _BASE_RULE_B)
    _save(ruleset_path, _CORR_BY_NAME)  # bruteforce_by_name - потомок в цепочке
    _save(ruleset_path, _CORR_CHAIN_PARENT)  # ссылается на bruteforce_by_name (correlation) + success_auth (base)

    rules = {r["title"]: r for r in rules_catalog.load_correlation_rules(ruleset_path)}
    assert set(rules) == {"Bruteforce By Name", "Auth After Brute"}

    parent = rules["Auth After Brute"]
    assert parent["base_rule_titles"] == ["Bruteforce By Name", "Successful Auth"]
    assert parent["base_rule_refs"] == [
        {"title": "Bruteforce By Name", "kind": "correlation"},
        {"title": "Successful Auth", "kind": "base"},
    ]


def test_load_correlation_rules_skips_rule_with_unresolved_reference():
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    # Только корреляция, БЕЗ базового правила failed_auth - ссылка не резолвится.
    _save(ruleset_path, _CORR_BY_NAME)
    assert rules_catalog.load_correlation_rules(ruleset_path) == []


def test_load_correlation_rules_cache_reflects_new_file(tmp_path):
    """Кэш по сигнатуре директории (число файлов + макс. mtime) - должен увидеть новый файл,
    добавленный ПОСЛЕ первого вызова load_correlation_rules (иначе rules_catalog отдавал бы
    протухший список весь остаток жизни процесса)."""
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _CORR_BY_NAME)
    assert len(rules_catalog.load_correlation_rules(ruleset_path)) == 1

    _save(ruleset_path, _BASE_RULE_B)
    _save(ruleset_path, _CORR_CHAIN_PARENT)
    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert len(rules) == 2


def test_builtin_ruleset_has_no_correlation_rules():
    assert rules_catalog.load_correlation_rules("Zircolite/rules/rules_windows_generic_pysigma.json") == []


# ------------------------------------------------------------------ Валидация при сохранении


def _corr_doc(overrides: dict) -> str:
    base = {
        "title": "Test Corr",
        "id": "66666666-6666-6666-6666-666666666666",
        "correlation": {
            "type": "event_count",
            "rules": ["failed_auth"],
            "group-by": ["IpAddress"],
            "timespan": "5m",
            "condition": {"gte": 10},
        },
        "level": "high",
    }
    base.update(overrides)
    import yaml as _yaml

    return _yaml.safe_dump(base, sort_keys=False)


def test_validate_rejects_empty_group_by():
    doc = _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": [],
        "timespan": "5m", "condition": {"gte": 10},
    }})
    with pytest.raises(RuleValidationError, match="group-by"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_rejects_bad_timespan_unit():
    doc = _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": ["IpAddress"],
        "timespan": "5 fortnights", "condition": {"gte": 10},
    }})
    with pytest.raises(RuleValidationError, match="timespan"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_rejects_missing_condition_for_event_count():
    doc = _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": ["IpAddress"], "timespan": "5m",
    }})
    with pytest.raises(RuleValidationError, match="condition"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_rejects_value_count_without_field():
    doc = _corr_doc({"correlation": {
        "type": "value_count", "rules": ["failed_auth"], "group-by": ["IpAddress"],
        "timespan": "5m", "condition": {"gte": 10},
    }})
    with pytest.raises(RuleValidationError, match="value_count"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_rejects_extended_condition_expression():
    doc = _corr_doc({"correlation": {
        "type": "temporal_ordered", "rules": ["failed_auth", "success_auth"], "group-by": ["IpAddress"],
        "timespan": "1d", "condition": {"expression": "rule_a and rule_b"},
    }})
    with pytest.raises(RuleValidationError, match="[Рр]асширенные"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_accepts_temporal_without_condition():
    doc = _corr_doc({"correlation": {
        "type": "temporal", "rules": ["failed_auth", "success_auth"], "group-by": ["IpAddress"],
        "timespan": "1d",
    }})
    compiled = rules_catalog.compile_custom_rule(doc)
    assert compiled["correlation"] is True
