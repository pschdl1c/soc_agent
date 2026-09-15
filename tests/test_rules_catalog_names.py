"""
Тесты колонки name в списке правил вкладки «Sigma-правила» (app/rules/rules_catalog.py:
paginate_rules/_rule_names). name в .manifest.json не хранится - подмешивается из скана YAML
по паре (рулсет строки, id).

CUSTOM_ROOT подменён на tmp_path (тот же паттерн, что и tests/test_catalog_errors.py).
"""
from __future__ import annotations

import pytest

from app.rules import rules_catalog

_RULE_ID = "55555555-5555-5555-5555-555555555555"

_RULE_YAML = f"""\
title: Name Column Probe
id: {_RULE_ID}
name: probe_name_column
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

_UNNAMED_YAML = """\
title: Unnamed Probe
id: 66666666-6666-6666-6666-666666666666
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
"""


@pytest.fixture(autouse=True)
def _isolate_custom_root(tmp_path, monkeypatch):
    root = tmp_path / "custom_rulesets"
    root.mkdir()
    monkeypatch.setattr(rules_catalog, "CUSTOM_ROOT", root)
    rules_catalog.invalidate_scan_cache()
    yield root
    rules_catalog.invalidate_scan_cache()


def _ruleset_with_rules() -> str:
    target = rules_catalog.create_custom_ruleset("names")
    rules_catalog.save_custom_rule(_RULE_YAML, ruleset=target)
    rules_catalog.save_custom_rule(_UNNAMED_YAML, ruleset=target)
    return target


def test_custom_rule_row_carries_name():
    target = _ruleset_with_rules()
    rows = rules_catalog.search_rules(target, None, None, "asc", 50, 0)["rules"]
    by_title = {r["title"]: r for r in rows}
    assert by_title["Name Column Probe"]["name"] == "probe_name_column"
    assert not by_title["Unnamed Probe"].get("name")


def test_search_and_sort_by_name():
    target = _ruleset_with_rules()
    found = rules_catalog.search_rules(target, "PROBE_NAME", None, "asc", 50, 0)["rules"]
    assert [r["title"] for r in found] == ["Name Column Probe"]

    desc = rules_catalog.search_rules(target, None, "name", "desc", 50, 0)["rules"]
    assert desc[0]["title"] == "Name Column Probe"


def test_main_view_uses_source_ruleset():
    """Просмотр main: строки без ruleset_path, рулсет - из source_ruleset."""
    target = _ruleset_with_rules()
    rows = [{**r, "source_ruleset": target} for r in rules_catalog.load_rules(target)]
    page = rules_catalog.paginate_rules(rows, None, None, "asc", 50, 0)["rules"]
    assert "probe_name_column" in {r.get("name") for r in page}


def test_kind_filter_splits_base_correlation_and_scenario():
    """kind: базовые / корреляции без инцидента / сценарные (correlation.incident)."""
    rows = [
        {"id": "1", "title": "Base"},
        {"id": "2", "title": "Silent link", "correlation": True, "incident": False},
        {"id": "3", "title": "SCE_Probe", "correlation": True, "incident": True},
    ]

    def titles(kind):
        page = rules_catalog.paginate_rules(rows, None, None, "asc", 50, 0, kind=kind)
        return [r["title"] for r in page["rules"]], page["total"]

    assert titles(["base"]) == (["Base"], 1)
    assert titles(["correlation"]) == (["Silent link"], 1)
    assert titles(["incident"]) == (["SCE_Probe"], 1)
    # Мультиселект: несколько видов разом; пустой/None - фильтра нет.
    assert titles(["correlation", "incident"]) == (["Silent link", "SCE_Probe"], 2)
    assert titles([])[1] == 3
    assert titles(None)[1] == 3


def test_same_id_in_other_ruleset_gets_no_name():
    """Встроенная запись с тем же id, что у своего правила, чужое name не получает."""
    _ruleset_with_rules()
    builtin_row = {"id": _RULE_ID, "title": "Builtin Twin", "level": "low"}
    page = rules_catalog.paginate_rules(
        [builtin_row], None, None, "asc", 50, 0, ruleset_path="Zircolite/rules/rules_windows_merged.json",
    )["rules"]
    assert not page[0].get("name")
