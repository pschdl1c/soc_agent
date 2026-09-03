"""
Тесты app/rules/value_lists.py: CRUD списков и разворот Sigma-плейсхолдеров `%name%` / `|expand`
до компиляции. Чистый модуль - реальный data/value_lists не трогаем, VALUE_LISTS_ROOT
переставляется на tmp_path фикстурой.
"""
from __future__ import annotations

import pytest
import yaml

from app.rules import value_lists
from app.rules.value_lists import ValueListError


@pytest.fixture(autouse=True)
def _isolate_root(tmp_path, monkeypatch):
    root = tmp_path / "value_lists"
    root.mkdir()
    monkeypatch.setattr(value_lists, "VALUE_LISTS_ROOT", root)
    return root


# ------------------------------------------------------------------ CRUD

def test_create_and_get_roundtrip():
    value_lists.create_list("bins", "утилиты", ["  mimikatz.exe ", "psexec.exe", "psexec.exe", ""])
    got = value_lists.get_list("bins")
    assert got["name"] == "bins"
    assert got["description"] == "утилиты"
    # trim + дедуп + выкидывание пустых
    assert got["values"] == ["mimikatz.exe", "psexec.exe"]
    assert got["created_at"] and got["updated_at"]


def test_create_rejects_bad_name_and_duplicate():
    with pytest.raises(ValueListError):
        value_lists.create_list("bad name!", "", ["x"])
    value_lists.create_list("ok", "", ["x"])
    with pytest.raises(ValueListError):
        value_lists.create_list("ok", "", ["y"])


def test_update_preserves_created_at_changes_values():
    value_lists.create_list("l", "d1", ["a"])
    created = value_lists.get_list("l")["created_at"]
    value_lists.update_list("l", "d2", ["a", "b"])
    after = value_lists.get_list("l")
    assert after["created_at"] == created
    assert after["description"] == "d2"
    assert after["values"] == ["a", "b"]


def test_update_missing_returns_none_and_delete():
    assert value_lists.update_list("nope", "", ["x"]) is None
    assert value_lists.delete_list("nope") is False
    value_lists.create_list("l", "", ["x"])
    assert value_lists.delete_list("l") is True
    assert value_lists.get_list("l") is None


# ------------------------------------------------------------------ expand_placeholders

_LIST_FORM = """\
title: T
logsource:
  product: windows
detection:
  selection:
    Image|endswith|expand:
      - '%bins%'
  condition: selection
"""

_SCALAR_MULTI_MOD = """\
title: T
logsource:
  product: windows
detection:
  selection:
    CommandLine|windash|contains|expand: '%flags%'
  condition: selection
"""

_MIXED = """\
title: T
logsource:
  product: windows
detection:
  selection:
    Image|endswith|expand:
      - '%bins%'
      - c.exe
      - a.exe
  condition: selection
"""

_NO_EXPAND = """\
title: T
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\\evil.exe'
  condition: selection
"""


def test_expand_list_form_replaces_values_and_drops_modifier():
    value_lists.create_list("bins", "", ["mimikatz.exe", "psexec.exe"])
    sel = yaml.safe_load(value_lists.expand_placeholders(_LIST_FORM))["detection"]["selection"]
    assert "Image|endswith|expand" not in sel
    assert sel["Image|endswith"] == ["mimikatz.exe", "psexec.exe"]


def test_expand_scalar_form_and_multi_modifier():
    value_lists.create_list("flags", "", ["-enc", "-nop"])
    sel = yaml.safe_load(value_lists.expand_placeholders(_SCALAR_MULTI_MOD))["detection"]["selection"]
    assert sel["CommandLine|windash|contains"] == ["-enc", "-nop"]


def test_expand_mixes_placeholder_with_literals_and_dedupes():
    value_lists.create_list("bins", "", ["a.exe", "b.exe"])
    sel = yaml.safe_load(value_lists.expand_placeholders(_MIXED))["detection"]["selection"]
    assert sel["Image|endswith"] == ["a.exe", "b.exe", "c.exe"]


def test_expand_unknown_placeholder_raises():
    with pytest.raises(ValueListError):
        value_lists.expand_placeholders(_LIST_FORM)  # 'bins' не создан


def test_expand_empty_list_raises():
    value_lists.create_list("bins", "", ["x"])
    value_lists.update_list("bins", "", [])
    with pytest.raises(ValueListError):
        value_lists.expand_placeholders(_LIST_FORM)


def test_expand_noop_when_no_expand_modifier_returns_identity():
    assert value_lists.expand_placeholders(_NO_EXPAND) is _NO_EXPAND


def test_expand_multi_document():
    value_lists.create_list("bins", "", ["m.exe"])
    src = _LIST_FORM + "---\n" + _NO_EXPAND
    docs = list(yaml.safe_load_all(value_lists.expand_placeholders(src)))
    assert docs[0]["detection"]["selection"]["Image|endswith"] == ["m.exe"]
    assert docs[1]["detection"]["selection"]["Image|endswith"] == "\\evil.exe"


# ------------------------------------------------------------------ placeholders_used

def test_placeholders_used_collects_names():
    src = """\
title: T
logsource:
  product: windows
detection:
  selection:
    Image|endswith|expand:
      - '%a%'
    CommandLine|contains|expand: '%b%'
  condition: selection
"""
    assert value_lists.placeholders_used(src) == {"a", "b"}


def test_placeholders_used_empty_without_expand():
    assert value_lists.placeholders_used(_NO_EXPAND) == set()


# ------------------------------------------------------------------ parse_list_file / import_lists

_PIPELINE_FILE = """\
name: Recon value lists
priority: 100
transformations:
  - id: recon
    type: value_placeholders
    mapping:
      recon_tools:
        - /whoami
        - /netstat
      hacktool_binaries:
        - mimikatz.exe
        - psexec.exe
"""

_NATIVE_MULTI = """\
name: list_a
description: первый
values:
  - a1
  - a2
---
name: list_b
values:
  - b1
"""

_BARE_MAPPING = """\
list_c:
  - c1
  - c2
list_d: d1
"""

_RULE_DOC = """\
title: Some Rule
logsource:
  product: windows
detection:
  selection:
    Image: x
  condition: selection
"""


def test_parse_pipeline_file_many_lists():
    lists = {pl.name: pl for pl in value_lists.parse_list_file(_PIPELINE_FILE)}
    assert set(lists) == {"recon_tools", "hacktool_binaries"}
    assert lists["recon_tools"].values == ["/whoami", "/netstat"]
    assert lists["recon_tools"].description == "Recon value lists"


def test_parse_query_expansion_placeholders_type():
    text = _PIPELINE_FILE.replace("value_placeholders", "query_expansion_placeholders")
    assert {pl.name for pl in value_lists.parse_list_file(text)} == {"recon_tools", "hacktool_binaries"}


def test_parse_native_multi_document():
    lists = {pl.name: pl for pl in value_lists.parse_list_file(_NATIVE_MULTI)}
    assert lists["list_a"].values == ["a1", "a2"] and lists["list_a"].description == "первый"
    assert lists["list_b"].values == ["b1"]


def test_parse_bare_mapping():
    lists = {pl.name: pl.values for pl in value_lists.parse_list_file(_BARE_MAPPING)}
    assert lists == {"list_c": ["c1", "c2"], "list_d": ["d1"]}


def test_parse_rejects_bad_name_and_unknown_doc():
    with pytest.raises(ValueListError):
        value_lists.parse_list_file("bad name!:\n  - x\n")
    with pytest.raises(ValueListError):
        value_lists.parse_list_file(_RULE_DOC)  # это правило, не список


def test_is_list_document_strict():
    assert value_lists.is_list_document(yaml.safe_load(_PIPELINE_FILE)) is True
    assert value_lists.is_list_document(yaml.safe_load("name: n\nvalues: [x]\n")) is True
    assert value_lists.is_list_document(yaml.safe_load(_RULE_DOC)) is False
    # «голый» mapping СТРОГОЙ проверкой (для '+ Загрузить рулсет') НЕ распознаётся
    assert value_lists.is_list_document(yaml.safe_load(_BARE_MAPPING)) is False


def test_import_lists_modes():
    value_lists.create_list("recon_tools", "old", ["/whoami"])
    parsed = value_lists.parse_list_file(_PIPELINE_FILE)  # recon_tools=[/whoami,/netstat], hacktool_binaries=[...]

    # create: существующий recon_tools не трогаем, hacktool_binaries создаём
    r = value_lists.import_lists(parsed, "create")
    assert r["skipped"] == ["recon_tools"] and r["created"] == ["hacktool_binaries"]
    assert value_lists.get_list("recon_tools")["values"] == ["/whoami"]
    assert r["recompile_needed"] == []

    # replace: recon_tools перезаписан целиком
    r = value_lists.import_lists(parsed, "replace")
    assert set(r["replaced"]) == {"recon_tools", "hacktool_binaries"}
    assert value_lists.get_list("recon_tools")["values"] == ["/whoami", "/netstat"]
    assert set(r["recompile_needed"]) == {"recon_tools", "hacktool_binaries"}

    # merge: объединение значений
    value_lists.update_list("recon_tools", "", ["/id"])
    r = value_lists.import_lists(parsed, "merge")
    assert value_lists.get_list("recon_tools")["values"] == ["/id", "/whoami", "/netstat"]
    assert "recon_tools" in r["merged"] and "recon_tools" in r["recompile_needed"]


def test_import_lists_bad_mode():
    with pytest.raises(ValueListError):
        value_lists.import_lists([], "nope")
