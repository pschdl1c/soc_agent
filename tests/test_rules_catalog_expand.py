"""
Интеграция value lists <-> компиляция правил (app/rules/rules_catalog.py): правило с
`%name%` / `|expand` реально компилируется в SQL, содержащий значения списка; неизвестный
плейсхолдер даёт RuleValidationError (а не 500). Гоняет настоящий pySigma/RulesetHandler.
"""
from __future__ import annotations

import pytest

from app.rules import rules_catalog, value_lists
from app.rules.rules_catalog import RuleValidationError


@pytest.fixture(autouse=True)
def _isolate_value_lists(tmp_path, monkeypatch):
    root = tmp_path / "value_lists"
    root.mkdir()
    monkeypatch.setattr(value_lists, "VALUE_LISTS_ROOT", root)
    return root


_RULE = """\
title: Recon Tool Execution
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith|expand:
      - '%recon_binaries%'
  condition: selection
level: medium
"""


def test_rule_with_expand_compiles_with_list_values():
    value_lists.create_list("recon_binaries", "", ["\\whoami.exe", "\\net.exe", "\\ipconfig.exe"])
    compiled = rules_catalog.compile_custom_rule(_RULE)
    sql = " ".join(compiled.get("rule") or [])
    assert "whoami.exe" in sql
    assert "net.exe" in sql
    assert "ipconfig.exe" in sql
    assert "%recon_binaries%" not in sql


def test_rule_with_unknown_placeholder_raises_validation_error():
    with pytest.raises(RuleValidationError):
        rules_catalog.compile_custom_rule(_RULE)  # список не создан


def test_saved_rule_manifest_has_expanded_sql(tmp_path, monkeypatch):
    """load_rules(custom_ruleset) отдаёт .manifest.json с УЖЕ развёрнутыми плейсхолдерами -
    именно его использует main.py:_process_batch для детекта по кастомному рулсету (не
    пересборку сырых .yml через RulesetHandler, который на %name% дал бы 0 правил)."""
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", tmp_path / "custom_rulesets")
    (tmp_path / "custom_rulesets").mkdir()
    value_lists.create_list("recon_binaries", "", ["\\whoami", "\\netstat"])

    _compiled, ruleset_path = rules_catalog.save_custom_rule(_RULE, new_ruleset_name="t")
    rules = rules_catalog.load_rules(ruleset_path)
    sql = " ".join(sql for rule in rules for sql in (rule.get("rule") or []))
    assert "whoami" in sql and "netstat" in sql
    assert "%recon_binaries%" not in sql


_BUNDLE = """\
name: recon lists
transformations:
  - type: value_placeholders
    mapping:
      recon_binaries:
        - \\whoami
        - \\netstat
---
title: Recon Tool Execution
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith|expand:
      - '%recon_binaries%'
  condition: selection
level: medium
"""


def test_ruleset_upload_bundles_list_and_rule(tmp_path, monkeypatch):
    """'+ Загрузить рулсет' с multi-doc: pipeline-документ со списком + правило, которое на
    него ссылается. Список пишется ПЕРВЫМ, правило компилируется уже со значениями."""
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", tmp_path / "custom_rulesets")
    (tmp_path / "custom_rulesets").mkdir()

    info, target, _collisions, imported = rules_catalog.save_ruleset_yaml(_BUNDLE, new_ruleset_name="pack")
    assert imported["created"] == ["recon_binaries"]
    assert info is not None and target is not None

    rules = rules_catalog.load_rules(target)
    sql = " ".join(sql for rule in rules for sql in (rule.get("rule") or []))
    assert "whoami" in sql and "netstat" in sql and "%recon_binaries%" not in sql


def test_ruleset_upload_only_lists_creates_no_ruleset(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", tmp_path / "custom_rulesets")
    (tmp_path / "custom_rulesets").mkdir()
    only_lists = _BUNDLE.split("---")[0]

    info, target, _collisions, imported = rules_catalog.save_ruleset_yaml(only_lists, new_ruleset_name="x")
    assert info is None and target is None
    assert imported["created"] == ["recon_binaries"]
