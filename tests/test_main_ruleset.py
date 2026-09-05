"""
Тесты app/rules/main_ruleset.py: основной рулсет собирается ТОЛЬКО из custom-рулсетов -
toggle_rule/toggle_ruleset должны отклонять built-in ruleset_path (см. докстринг модуля).

CUSTOM_ROOT подменён на tmp_path (тот же паттерн, что и tests/test_rules_catalog_correlation.py) -
реальный data/custom_rulesets проекта не трогается. main_ruleset.STATE_PATH вычисляется ОДИН РАЗ
при импорте модуля из rules_catalog.CUSTOM_ROOT (снимок на момент импорта, монки-патч
rules_catalog.CUSTOM_ROOT его не меняет) - поэтому STATE_PATH подменяется отдельно, иначе тесты
писали бы в custom_rulesets/main_ruleset.json реального проекта.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.rules import main_ruleset, rules_catalog
from app.rules.rules_catalog import CatalogError

BUILTIN_RULESET_PATH = "Zircolite/rules/rules_linux.json"


@pytest.fixture(autouse=True)
def _isolate_custom_root(tmp_path, monkeypatch):
    root = tmp_path / "custom_rulesets"
    root.mkdir()
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", root)
    monkeypatch.setattr(main_ruleset, "STATE_PATH", root / "main_ruleset.json")
    return root


@pytest.fixture
def custom_ruleset_path() -> str:
    return rules_catalog.create_custom_ruleset("test-main-ruleset")


def _skip_if_no_builtin_clone():
    if not Path(BUILTIN_RULESET_PATH).exists():
        pytest.skip("Локальный клон Zircolite не найден (Zircolite/rules) - см. README")


def test_toggle_ruleset_accepts_custom(custom_ruleset_path):
    status = main_ruleset.toggle_ruleset(custom_ruleset_path, True)
    assert status == "full"
    state = main_ruleset.load_state()
    assert custom_ruleset_path in state["included_rulesets"]


def test_toggle_ruleset_rejects_builtin():
    _skip_if_no_builtin_clone()
    with pytest.raises(CatalogError):
        main_ruleset.toggle_ruleset(BUILTIN_RULESET_PATH, True)
    state = main_ruleset.load_state()
    assert BUILTIN_RULESET_PATH not in state["included_rulesets"]


def test_toggle_ruleset_exclude_does_not_require_custom_check():
    """include=False (снятие) built-in не отклоняет - built-in там физически не может
    оказаться, но сам вызов не должен падать (идемпотентное "убрать несуществующую ссылку")."""
    _skip_if_no_builtin_clone()
    status = main_ruleset.toggle_ruleset(BUILTIN_RULESET_PATH, False)
    assert status == "none"


def test_toggle_rule_accepts_custom(custom_ruleset_path):
    in_main = main_ruleset.toggle_rule(custom_ruleset_path, "any-rule-id", True)
    assert in_main is True
    state = main_ruleset.load_state()
    assert "any-rule-id" in state["included_rules"].get(custom_ruleset_path, [])


def test_toggle_rule_rejects_builtin():
    _skip_if_no_builtin_clone()
    with pytest.raises(CatalogError):
        main_ruleset.toggle_rule(BUILTIN_RULESET_PATH, "some-rule-id", True)
    state = main_ruleset.load_state()
    assert BUILTIN_RULESET_PATH not in state["included_rules"]
