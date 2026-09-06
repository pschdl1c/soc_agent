"""
Тесты разделения «объекта нет» и «действие недопустимо» в каталоге правил
(app/rules/rules_catalog.py: CatalogNotFound vs CatalogError -> 404 vs 400 в app/main.py).

Регрессия, ради которой написаны: обе ситуации были одним CatalogError и на всех ручках
каталога отдавались как 404 - попытка тронуть встроенный рулсет отвечала «не найден» про
существующий файл, а запрос к несуществующему кастомному пути - наоборот, сообщением про
встроенность (или «недопустимый путь»).

CUSTOM_ROOT подменён на tmp_path (тот же паттерн, что и tests/test_rules_catalog_correlation.py).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.rules import rules_catalog
from app.rules.rules_catalog import CatalogError, CatalogNotFound

BUILTIN_RULESET_PATH = "Zircolite/rules/rules_linux.json"
MISSING_CUSTOM_PATH = "custom_rulesets/deadbeefdeadbeef"

_RULE_YAML = """\
title: Catalog Error Probe
id: 44444444-4444-4444-4444-444444444444
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: low
"""


@pytest.fixture(autouse=True)
def _isolate_custom_root(tmp_path, monkeypatch):
    root = tmp_path / "custom_rulesets"
    root.mkdir()
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", root)
    return root


def _skip_if_no_builtin_clone():
    if not Path(BUILTIN_RULESET_PATH).exists():
        pytest.skip("Локальный клон Zircolite не найден (Zircolite/rules) - см. README")


def test_load_rules_missing_custom_is_not_found():
    with pytest.raises(CatalogNotFound) as exc:
        rules_catalog.load_rules(MISSING_CUSTOM_PATH)
    assert "не найден" in str(exc.value).lower()


def test_load_rules_missing_builtin_is_not_found():
    with pytest.raises(CatalogNotFound):
        rules_catalog.load_rules("Zircolite/rules/no_such_ruleset.json")


def test_save_custom_rule_into_missing_ruleset_is_not_found():
    """Путь кастовный по форме - значит и сообщение про отсутствие, а не про «встроенность»."""
    with pytest.raises(CatalogNotFound) as exc:
        rules_catalog.save_custom_rule(_RULE_YAML, ruleset=MISSING_CUSTOM_PATH)
    assert "встроен" not in str(exc.value).lower()


def test_save_custom_rule_into_builtin_is_rejected_not_missing():
    _skip_if_no_builtin_clone()
    with pytest.raises(CatalogError) as exc:
        rules_catalog.save_custom_rule(_RULE_YAML, ruleset=BUILTIN_RULESET_PATH)
    assert not isinstance(exc.value, CatalogNotFound)
    assert "встроен" in str(exc.value).lower()


def test_delete_builtin_ruleset_is_rejected_not_missing():
    _skip_if_no_builtin_clone()
    with pytest.raises(CatalogError) as exc:
        rules_catalog.delete_custom_ruleset(BUILTIN_RULESET_PATH)
    assert not isinstance(exc.value, CatalogNotFound)


def test_delete_missing_custom_ruleset_is_not_found():
    with pytest.raises(CatalogNotFound):
        rules_catalog.delete_custom_ruleset(MISSING_CUSTOM_PATH)


def test_delete_missing_rule_is_not_found():
    target = rules_catalog.create_custom_ruleset("catalog-errors")
    with pytest.raises(CatalogNotFound):
        rules_catalog.delete_custom_rule(target, "no-such-rule")
