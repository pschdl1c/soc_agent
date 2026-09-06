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
from app.rules.rules_catalog import CatalogError, CatalogNotFound

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


# ---------------------------------------------------------------- 404 vs 400 (API-4)
# Отказ по смыслу ("встроенный рулсет в main нельзя") и отсутствие объекта ("такого рулсета
# нет") - разные вещи: main.py транслирует первое в 400, второе в 404 (см. _catalog_http).

def test_toggle_ruleset_builtin_is_not_a_not_found():
    _skip_if_no_builtin_clone()
    with pytest.raises(CatalogError) as exc:
        main_ruleset.toggle_ruleset(BUILTIN_RULESET_PATH, True)
    assert not isinstance(exc.value, CatalogNotFound)  # существует, просто недопустим как цель


def test_toggle_ruleset_missing_custom_is_not_found():
    with pytest.raises(CatalogNotFound):
        main_ruleset.toggle_ruleset("custom_rulesets/deadbeefdeadbeef", True)


def test_toggle_rule_missing_custom_is_not_found():
    with pytest.raises(CatalogNotFound):
        main_ruleset.toggle_rule("custom_rulesets/deadbeefdeadbeef", "some-rule-id", True)


# ---------------------------------------------------------------- on_rule_deleted
# Удаление ОДНОГО правила (DELETE /rules/custom/{id}) обязано чистить точечные ссылки на него
# в составе main - парно к on_ruleset_deleted у удаления рулсета целиком. Раньше такой чистки
# не было: resolve() осиротевший id молча пропускал (детект не ломался), но main_ruleset.json
# копил мусор, а удалённое правило продолжало числиться включённым в main.

def test_on_rule_deleted_drops_pointwise_inclusion(custom_ruleset_path):
    main_ruleset.toggle_rule(custom_ruleset_path, "rule-a", True)
    main_ruleset.toggle_rule(custom_ruleset_path, "rule-b", True)

    main_ruleset.on_rule_deleted(custom_ruleset_path, "rule-a")

    state = main_ruleset.load_state()
    assert state["included_rules"][custom_ruleset_path] == ["rule-b"]
    assert main_ruleset.is_rule_included(state, custom_ruleset_path, "rule-a") is False


def test_on_rule_deleted_drops_exclusion_inside_included_ruleset(custom_ruleset_path):
    """Правило, ИСКЛЮЧЁННОЕ из целиком добавленного рулсета, после удаления с диска тоже
    незачем держать в state - привязывать исключение больше не к чему."""
    main_ruleset.toggle_ruleset(custom_ruleset_path, True)
    main_ruleset.toggle_rule(custom_ruleset_path, "rule-x", False)
    assert main_ruleset.load_state()["excluded_rules"][custom_ruleset_path] == ["rule-x"]

    main_ruleset.on_rule_deleted(custom_ruleset_path, "rule-x")

    state = main_ruleset.load_state()
    assert custom_ruleset_path not in state["excluded_rules"]  # опустевший список убран целиком
    assert custom_ruleset_path in state["included_rulesets"]   # сам рулсет в main остаётся


def test_on_rule_deleted_is_noop_for_unknown_rule(custom_ruleset_path):
    main_ruleset.toggle_rule(custom_ruleset_path, "rule-a", True)
    before = main_ruleset.load_state()

    main_ruleset.on_rule_deleted(custom_ruleset_path, "no-such-rule")
    main_ruleset.on_rule_deleted("custom_rulesets/deadbeefdeadbeef", "rule-a")

    assert main_ruleset.load_state() == before
