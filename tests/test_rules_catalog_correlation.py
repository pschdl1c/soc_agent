"""
Тесты app/rules/rules_catalog.py для correlation-правил: резолв ссылок correlation.rules
по name/id (в т.ч. ссылка на ДРУГУЮ correlation - цепочки) и валидация при сохранении.

Гоняет настоящий compile_custom_rule/save_ruleset_yaml/load_correlation_rules с CUSTOM_ROOT,
подменённым на tmp_path (тот же паттерн, что и tests/test_rules_catalog_expand.py) - реальный
data/custom_rulesets проекта не трогается.
"""
from __future__ import annotations

from uuid import UUID

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
    assert corr["base_rule_refs"] == [{"title": "Failed Auth", "kind": "base", "ruleset_path": ruleset_path}]
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
        {"title": "Bruteforce By Name", "kind": "correlation", "ruleset_path": ruleset_path},
        {"title": "Successful Auth", "kind": "base", "ruleset_path": ruleset_path},
    ]


def test_load_correlation_rules_skips_rule_with_unresolved_reference(_isolate_custom_root):
    """Защитный пропуск в рантайме остаётся - но добраться до него теперь можно только правкой
    файла мимо API (через save_* неразрешимая ссылка отклоняется, см. тест ниже), поэтому
    correlation-файл кладём на диск руками."""
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    ruleset_dir = _isolate_custom_root / ruleset_path.split("/")[-1]
    # Только корреляция, БЕЗ базового правила failed_auth - ссылка не резолвится.
    (ruleset_dir / f"orphan{rules_catalog.CORRELATION_EXT}").write_text(_CORR_BY_NAME, encoding="utf-8")
    assert rules_catalog.load_correlation_rules(ruleset_path) == []


def test_save_rejects_correlation_with_unresolved_reference():
    """RUL-2: раньше такое правило сохранялось с 201 и молча исчезало из load_correlation_rules -
    корреляция никогда не срабатывала, а в UI выглядела как обычное сохранённое правило."""
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    with pytest.raises(RuleValidationError) as exc:
        rules_catalog.save_custom_rule(_CORR_BY_NAME, ruleset=ruleset_path)
    assert "failed_auth" in str(exc.value)

    # То же самое при загрузке пака целиком.
    with pytest.raises(RuleValidationError):
        rules_catalog.save_ruleset_yaml(_CORR_BY_NAME, ruleset=ruleset_path)

    # А вместе с базовым правилом в ОДНОМ multi-document файле - проходит: ссылки резолвятся
    # и по документам самого файла, не только по уже лежащим в рулсете.
    _save(ruleset_path, _BASE_RULE_A + "\n---\n" + _CORR_BY_NAME)
    assert [r["title"] for r in rules_catalog.load_correlation_rules(ruleset_path)] == ["Bruteforce By Name"]


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


# ------------------------------------------------------------------ Межрулсетные ссылки


def _two_domains():
    """auth - базовые правила, killchain - корреляция, ссылающаяся на них из ДРУГОГО рулсета."""
    auth = rules_catalog.create_custom_ruleset("auth")
    _save(auth, _BASE_RULE_A)
    _save(auth, _BASE_RULE_B)
    chain = rules_catalog.create_custom_ruleset("killchain")
    _save(chain, _CORR_BY_NAME)
    return auth, chain


def test_correlation_resolves_reference_into_another_ruleset():
    auth, chain = _two_domains()
    rules = rules_catalog.load_correlation_rules(chain)
    assert len(rules) == 1
    assert rules[0]["base_rule_refs"] == [{"title": "Failed Auth", "kind": "base", "ruleset_path": auth}]


def test_cross_ruleset_chain_to_correlation_resolves():
    auth, chain = _two_domains()
    lateral = rules_catalog.create_custom_ruleset("lateral")
    _save(lateral, _CORR_CHAIN_PARENT)  # bruteforce_by_name (killchain) + success_auth (auth)
    parent = rules_catalog.load_correlation_rules(lateral)[0]
    assert [(r["kind"], r["ruleset_path"]) for r in parent["base_rule_refs"]] == [
        ("correlation", chain), ("base", auth),
    ]


def test_title_must_be_unique_across_rulesets():
    auth, _chain = _two_domains()
    other = rules_catalog.create_custom_ruleset("other")
    dup_title = _BASE_RULE_A.replace("name: failed_auth", "name: failed_auth_copy").replace(
        "11111111-1111-1111-1111-111111111111", "77777777-1111-1111-1111-111111111111"
    )
    with pytest.raises(RuleValidationError, match="title 'Failed Auth'"):
        rules_catalog.save_custom_rule(dup_title, ruleset=other)


def test_name_must_be_unique_across_rulesets():
    _two_domains()
    other = rules_catalog.create_custom_ruleset("other")
    dup_name = _BASE_RULE_A.replace("title: Failed Auth", "title: Failed Auth Copy").replace(
        "11111111-1111-1111-1111-111111111111", "77777777-1111-1111-1111-111111111111"
    )
    with pytest.raises(RuleValidationError, match="name 'failed_auth'"):
        rules_catalog.save_custom_rule(dup_name, ruleset=other)


def test_duplicate_title_inside_one_pack_is_rejected():
    ruleset = rules_catalog.create_custom_ruleset("pack")
    twin = _BASE_RULE_B.replace("title: Successful Auth", "title: Failed Auth")
    with pytest.raises(RuleValidationError, match="больше одного раза"):
        rules_catalog.save_ruleset_yaml(_BASE_RULE_A + "\n---\n" + twin, ruleset=ruleset)


def test_reuploading_same_pack_reports_collisions_not_uniqueness_error():
    """Тот же id у владельца title - это то же правило: пак не отклоняется целиком, а даёт
    коллизии по id, как раньше."""
    ruleset = rules_catalog.create_custom_ruleset("pack")
    _save(ruleset, _BASE_RULE_A)
    _summary, _path, collisions, _imported = rules_catalog.save_ruleset_yaml(_BASE_RULE_A, ruleset=ruleset)
    assert [c["id"] for c in collisions] == ["11111111-1111-1111-1111-111111111111"]


def test_delete_rule_referenced_from_other_ruleset_conflicts_until_force():
    auth, chain = _two_domains()
    with pytest.raises(rules_catalog.CatalogConflict) as exc:
        rules_catalog.delete_custom_rule(auth, "11111111-1111-1111-1111-111111111111")
    assert exc.value.references[0]["ruleset"] == chain
    # Не упомянутое ни одной корреляцией правило удаляется как раньше.
    rules_catalog.delete_custom_rule(auth, "22222222-2222-2222-2222-222222222222")
    rules_catalog.delete_custom_rule(auth, "11111111-1111-1111-1111-111111111111", force=True)
    assert rules_catalog.load_correlation_rules(chain) == []


def test_delete_ruleset_referenced_from_other_ruleset_conflicts_until_force():
    auth, chain = _two_domains()
    with pytest.raises(rules_catalog.CatalogConflict):
        rules_catalog.delete_custom_ruleset(auth)
    # Ссылки ИЗНУТРИ удаляемого рулсета конфликтом не считаются.
    rules_catalog.delete_custom_ruleset(chain)
    rules_catalog.delete_custom_ruleset(auth)


def test_renaming_referenced_name_conflicts():
    auth, _chain = _two_domains()
    renamed = _BASE_RULE_A.replace("name: failed_auth", "name: failed_auth_v2")
    with pytest.raises(rules_catalog.CatalogConflict):
        rules_catalog.update_custom_rule(auth, "11111111-1111-1111-1111-111111111111", renamed)
    # Правка без смены name проходит.
    same_name = _BASE_RULE_A.replace("level: informational", "level: low")
    rules_catalog.update_custom_rule(auth, "11111111-1111-1111-1111-111111111111", same_name)


def test_with_dependencies_pulls_base_rules_of_other_ruleset():
    from app.rules import main_ruleset

    auth, chain = _two_domains()
    pairs = main_ruleset.resolve_for(chain)
    by_title = {rule["title"]: (src, rule) for src, rule in pairs}
    assert set(by_title) == {"Bruteforce By Name", "Failed Auth"}
    src, dep = by_title["Failed Auth"]
    assert src == auth and dep["via_dependency"] is True
    assert not by_title["Bruteforce By Name"][1].get("via_dependency")


def test_find_rules_by_titles_searches_all_rulesets():
    auth, _chain = _two_domains()
    found = rules_catalog.find_rules_by_titles({"Failed Auth", "Bruteforce By Name"})
    assert {(src, r["title"]) for src, r in found} == {
        (auth, "Failed Auth"), (_chain, "Bruteforce By Name"),
    }


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


# ------------------------------------------------------------------ correlation.incident (Этап 4)


def _corr_doc_with_incident(incident: dict) -> str:
    return _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": ["IpAddress"],
        "timespan": "5m", "condition": {"gte": 10}, "incident": incident,
    }})


def test_validate_rejects_incident_without_type():
    with pytest.raises(RuleValidationError, match="incident.type"):
        rules_catalog.compile_custom_rule(_corr_doc_with_incident({"severity": "high"}))


def test_validate_rejects_incident_non_slug_type():
    with pytest.raises(RuleValidationError, match="incident.type"):
        rules_catalog.compile_custom_rule(_corr_doc_with_incident({"type": "Brute Force!"}))


def test_validate_rejects_incident_bad_severity():
    with pytest.raises(RuleValidationError, match="incident.severity"):
        rules_catalog.compile_custom_rule(_corr_doc_with_incident({"type": "bf", "severity": "urgent"}))


def test_validate_accepts_incident_block():
    compiled = rules_catalog.compile_custom_rule(
        _corr_doc_with_incident({"type": "brute_force", "severity": "high", "title": "Подбор пароля"})
    )
    assert compiled["correlation"] is True
    assert compiled["incident"] is True


def test_load_correlation_rules_surfaces_incident_spec():
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _corr_doc_with_incident({"type": "brute_force", "severity": "high"}))

    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert len(rules) == 1
    assert rules[0]["incident"] == {"type": "brute_force", "severity": "high", "title": None}


def test_load_correlation_rules_incident_none_when_unmarked():
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)
    _save(ruleset_path, _CORR_BY_NAME)

    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert rules[0]["incident"] is None


# ------------------------------------------------------------------ timespan vs ретеншн


def test_validate_rejects_timespan_longer_than_retention(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "EVENTS_RETENTION_DAYS", 14)
    doc = _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": ["IpAddress"],
        "timespan": "30d", "condition": {"gte": 10},
    }})
    with pytest.raises(RuleValidationError, match="хранени"):
        rules_catalog.compile_custom_rule(doc)


def test_validate_allows_long_timespan_when_retention_disabled(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "EVENTS_RETENTION_DAYS", 0)  # ретеншн выключен - храним вечно
    doc = _corr_doc({"correlation": {
        "type": "event_count", "rules": ["failed_auth"], "group-by": ["IpAddress"],
        "timespan": "30d", "condition": {"gte": 10},
    }})
    compiled = rules_catalog.compile_custom_rule(doc)
    assert compiled["correlation"] is True


# ------------------------------------------------------------------ Ошибки компиляции/сохранения


def test_broken_yaml_reports_real_parser_error():
    """RUL-1: раньше любая синтаксическая ошибка YAML маскировалась общим "YAML должен
    содержать title, logsource и detection" - ветка с реальной позицией ошибки парсера была
    недостижима, потому что структурная пре-проверка сама глотала yaml.YAMLError."""
    broken = """\
title: Broken
logsource:
  product: windows
detection:
  selection:
     - EventID: 4625
    - bad indent
  condition: selection
"""
    with pytest.raises(RuleValidationError) as exc:
        rules_catalog.compile_custom_rule(broken)
    message = str(exc.value)
    assert "Некорректный YAML" in message
    assert "line" in message  # позиция ошибки от pyyaml доезжает до пользователя


def test_fully_collided_pack_does_not_leave_empty_ruleset(_isolate_custom_root):
    """RUL-3: пак, все правила которого столкнулись по id с уже существующими, не должен
    оставлять в каталоге пустую директорию рулсета."""
    first = rules_catalog.create_custom_ruleset("first")
    _save(first, _BASE_RULE_A)
    before = {e["path"] for e in rules_catalog.list_rulesets()}

    summary, path, collisions, _imported = rules_catalog.save_ruleset_yaml(
        _BASE_RULE_A, new_ruleset_name="second"
    )
    assert summary is None and path is None
    assert [c["id"] for c in collisions] == ["11111111-1111-1111-1111-111111111111"]
    assert {e["path"] for e in rules_catalog.list_rulesets()} == before
    assert sorted(p.name for p in _isolate_custom_root.iterdir()) == [first.split("/")[-1]]


def test_failed_single_rule_does_not_leave_empty_ruleset(_isolate_custom_root):
    """RUL-3, тот же дефект на пути ОДИНОЧНОГО правила (POST /rules/custom): рулсет создавался
    ДО компиляции, поэтому любая ошибка (битый YAML, неразрешимая ссылка, занятый id)
    оставляла в каталоге пустую директорию с rule_count: 0."""
    broken = """\
title: Broken
logsource:
  product: windows
detection:
  selection:
     - EventID: 4625
    - bad
  condition: selection
"""
    with pytest.raises(RuleValidationError):
        rules_catalog.save_custom_rule(broken, new_ruleset_name="from-broken-yaml")
    with pytest.raises(RuleValidationError):
        rules_catalog.save_custom_rule(_CORR_BY_NAME, new_ruleset_name="from-bad-ref")

    first = rules_catalog.create_custom_ruleset("first")
    _save(first, _BASE_RULE_A)
    with pytest.raises(RuleValidationError):  # id занят правилом другого рулсета
        rules_catalog.save_custom_rule(_BASE_RULE_A, new_ruleset_name="from-collision")

    assert sorted(p.name for p in _isolate_custom_root.iterdir()) == [first.split("/")[-1]]


def test_correlation_rule_without_explicit_id_gets_id_from_filename(_isolate_custom_root):
    """Sigma не требует поля 'id:', и в файл мы его не дописываем - но по id correlation-запись
    сопоставляется с .manifest.json в correlation._active_correlation_rules для «основного
    рулсета». С id=None правило молча выпадало из main: сохранено, видно в UI, никогда не
    срабатывает. Фолбэк - имя файла, оно же rule_id манифеста."""
    ruleset_path = rules_catalog.create_custom_ruleset("test-ruleset")
    _save(ruleset_path, _BASE_RULE_A)

    no_id = "\n".join(line for line in _CORR_BY_NAME.splitlines() if not line.startswith("id:"))
    compiled, _target = rules_catalog.save_custom_rule(no_id, ruleset=ruleset_path)
    manifest_id = compiled["id"]

    rules = rules_catalog.load_correlation_rules(ruleset_path)
    assert len(rules) == 1
    assert rules[0]["id"] == manifest_id  # то же значение, что в манифесте -> правило видно в main


# ---------------------------------------------------------------- формат 'id' (диагностика)
# Sigma требует UUID в 'id:'. pySigma это проверяет и бросает внятное
# "Sigma rule identifier must be an UUID", но наружу оно не выходит: Zircolite отсеивает
# невалидные правила в RulesetHandler (is_valid_sigma_rule) МОЛЧА и отдаёт пустой рулсет,
# после чего compile_custom_rule печатал догадку "проверь detection/logsource" - при
# безупречных detection и logsource. Проверяем формат сами, ДО компиляции.

_PLAIN_RULE_TMPL = """\
title: Id Format Check
name: id_format_check
%s
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
"""


@pytest.mark.parametrize("bad_id", [
    "77777777-0001-4000-8000-00000000abcdef",  # лишние символы в последней группе
    "not-a-uuid",
    "12345",
    "",                                        # явная пустая строка (pySigma её тоже отвергает)
])
def test_compile_rejects_non_uuid_id_with_message_about_id(bad_id):
    with pytest.raises(RuleValidationError) as exc:
        rules_catalog.compile_custom_rule(_PLAIN_RULE_TMPL % f"id: '{bad_id}'")
    text = str(exc.value)
    assert "id" in text and "UUID" in text
    assert "detection" not in text and "logsource" not in text  # больше не уводим не туда


def test_compile_rejects_non_string_id():
    """YAML отдаёт int для `id: 12345` - pySigma ловит только ValueError, а UUID(int) бросает
    TypeError, то есть ошибка была бы ещё менее внятной."""
    with pytest.raises(RuleValidationError, match="UUID"):
        rules_catalog.compile_custom_rule(_PLAIN_RULE_TMPL % "id: 12345")


@pytest.mark.parametrize("good_id", [
    "77777777-0001-4000-8000-000000000001",     # канонический вид с дефисами
    "c3cce47451254da0a37c010e12690400",         # 32 hex без дефисов - так их генерируем сами
])
def test_compile_accepts_valid_uuid_forms(good_id):
    """Обе формы, которые принимает UUID(), проходят проверку. Сам id в скомпилированной
    записи приводится pySigma к каноническому виду с дефисами - это его поведение, не наше,
    поэтому сравниваем через UUID, а не по строке."""
    compiled = rules_catalog.compile_custom_rule(_PLAIN_RULE_TMPL % f"id: {good_id}")
    assert UUID(compiled["id"]) == UUID(good_id)


def test_compile_accepts_rule_without_id():
    """Поле необязательное: без него id генерируется автоматически (_safe_rule_id)."""
    compiled = rules_catalog.compile_custom_rule(_PLAIN_RULE_TMPL % "")
    assert compiled.get("rule")  # правило реально скомпилировалось в SQL


def test_compile_accepts_empty_id_line():
    """`id:` без значения YAML разбирает в None - это "поле не задано", не ошибка."""
    compiled = rules_catalog.compile_custom_rule(_PLAIN_RULE_TMPL % "id:")
    assert compiled.get("rule")


def test_correlation_rule_with_non_uuid_id_is_rejected():
    """У correlation-правил свой путь компиляции (без pySigma), но требование к id то же -
    иначе кривой id молча заменялся сгенерированным, и правило сохранялось не под тем id."""
    with pytest.raises(RuleValidationError, match="UUID"):
        rules_catalog.compile_custom_rule(_corr_doc({"id": "corr-rule-1"}))


def test_ruleset_pack_rejects_document_with_bad_id():
    """В multi-document паке кривой id одного документа раньше просто выкидывал его из
    компиляции - пак сохранялся неполным, без единого сообщения."""
    pack = _PLAIN_RULE_TMPL % "id: 77777777-0001-4000-8000-000000000001" + "\n---\n" + (
        _PLAIN_RULE_TMPL % "id: nope"
    ).replace("Id Format Check", "Second Rule").replace("id_format_check", "second_rule")
    with pytest.raises(RuleValidationError, match="UUID"):
        rules_catalog.compile_ruleset_yaml(pack)
