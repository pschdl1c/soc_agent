"""
Тесты базы знаний MITRE ATT&CK: парсинг STIX-бандла (scripts/build_kb.py) и чтение через
app/kb.py, включая гибридный матчинг тегов правил и деградацию при отсутствии kb.db.

Сеть не трогаем: работаем с рукотворным мини-бандлом, зовём только parse_bundle/write_kb_db.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from app import kb

_BUILD_KB_PATH = Path(__file__).resolve().parent.parent / "scripts" / "build_kb.py"
_spec = importlib.util.spec_from_file_location("build_kb", _BUILD_KB_PATH)
build_kb = importlib.util.module_from_spec(_spec)
sys.modules["build_kb"] = build_kb  # нужно до exec_module: @dataclass ищет модуль в sys.modules
_spec.loader.exec_module(build_kb)


def _ref(ext_id: str, path: str) -> dict:
    return {
        "source_name": "mitre-attack",
        "external_id": ext_id,
        "url": f"https://attack.mitre.org/{path}",
    }


MINI_BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "0.9"},
        {
            "type": "x-mitre-matrix",
            "id": "x-mitre-matrix--1",
            "tactic_refs": ["x-mitre-tactic--exec", "x-mitre-tactic--persist"],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--persist",
            "name": "Persistence",
            "description": "Keep access.",
            "x_mitre_shortname": "persistence",
            "external_references": [_ref("TA0003", "tactics/TA0003")],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--exec",
            "name": "Execution",
            "description": "Run code.",
            "x_mitre_shortname": "execution",
            "external_references": [_ref("TA0002", "tactics/TA0002")],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command interpreters.",
            "x_mitre_detection": "Monitor command-line activity.",
            "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_data_sources": ["Process: Process Creation"],
            "x_mitre_is_subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [_ref("T1059", "techniques/T1059")],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059-001",
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell.",
            "x_mitre_is_subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [_ref("T1059.001", "techniques/T1059/001")],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1547",
            "name": "Boot or Logon Autostart Execution",
            "description": "Adversaries may configure autostart.",
            "x_mitre_is_subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
            "external_references": [_ref("T1547", "techniques/T1547")],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--dead",
            "name": "Revoked technique",
            "revoked": True,
            "external_references": [_ref("T9998", "techniques/T9998")],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--deprecated",
            "name": "Deprecated technique",
            "x_mitre_deprecated": True,
            "external_references": [_ref("T9997", "techniques/T9997")],
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--m1038",
            "name": "Execution Prevention",
            "description": "Block execution of unknown code.",
            "external_references": [_ref("M1038", "mitigations/M1038")],
        },
        {
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--m1038",
            "target_ref": "attack-pattern--t1059",
        },
        # --- структурный детект (ATT&CK v18+) ---
        {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--ds1",
            "name": "Behavioral Detection of Interpreter Abuse",
            "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
            "external_references": [_ref("DET0001", "detections/DET0001")],
        },
        {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--an1",
            "name": "Analytic 0001",
            "description": "Detects powershell.exe with encoded arguments outside admin hours.",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": "x-mitre-data-component--x", "name": "WinEventLog:Sysmon", "channel": "EventCode=1"}
            ],
            "x_mitre_mutable_elements": [
                {"field": "TimeWindow", "description": "Restrict to work hours."}
            ],
            "external_references": [_ref("AN0001", "analytics/AN0001")],
        },
        {
            "type": "relationship",
            "relationship_type": "detects",
            "source_ref": "x-mitre-detection-strategy--ds1",
            "target_ref": "attack-pattern--t1059",
        },
        # --- procedure examples (кто применял технику) ---
        {
            "type": "intrusion-set",
            "id": "intrusion-set--g1",
            "name": "TestGroup",
            "external_references": [_ref("G0001", "groups/G0001")],
        },
        {
            "type": "malware",
            "id": "malware--s1",
            "name": "TestMal",
            "external_references": [_ref("S0001", "software/S0001")],
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--g1",
            "target_ref": "attack-pattern--t1059",
            "description": "TestGroup ran powershell -enc to stage a payload.",
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--s1",
            "target_ref": "attack-pattern--t1059-001",
            "description": "TestMal spawns PowerShell for execution.",
        },
    ],
}


# --------------------------------------------------------------------------- parse_bundle


def test_parse_bundle_shapes():
    parsed = build_kb.parse_bundle(MINI_BUNDLE["objects"])

    assert {t["shortname"] for t in parsed.tactics} == {"execution", "persistence"}
    # порядок колонок - из x-mitre-matrix.tactic_refs (execution раньше persistence)
    assert [t["shortname"] for t in parsed.tactics] == ["execution", "persistence"]
    assert parsed.tactics[0]["sort_order"] == 0

    tech_ids = {t["technique_id"] for t in parsed.techniques}
    assert tech_ids == {"T1059", "T1059.001", "T1547"}  # revoked/deprecated отброшены

    sub = next(t for t in parsed.techniques if t["technique_id"] == "T1059.001")
    assert sub["is_subtechnique"] == 1
    assert sub["parent_id"] == "T1059"

    assert ("T1059", "execution") in parsed.technique_tactic
    assert ("T1547", "persistence") in parsed.technique_tactic
    assert parsed.technique_mitigation == [("T1059", "M1038")]
    assert parsed.meta["technique_count"] == "3"

    # структурный детект: стратегия привязана к T1059 через `detects`, её аналитика подтянута
    assert [(s["strategy_id"], s["technique_id"]) for s in parsed.detection_strategies] == [("DET0001", "T1059")]
    assert parsed.analytics[0]["strategy_id"] == "DET0001"
    assert parsed.analytics[0]["log_sources"] == [{"name": "WinEventLog:Sysmon", "channel": "EventCode=1"}]
    assert parsed.analytics[0]["mutable_elements"][0]["field"] == "TimeWindow"

    # procedure examples: группа -> T1059, софт -> T1059.001
    procs = {(p["source_id"], p["technique_id"], p["source_type"]) for p in parsed.procedures}
    assert procs == {("G0001", "T1059", "group"), ("S0001", "T1059.001", "malware")}


# --------------------------------------------------------------------------- kb.py (есть база)


@pytest.fixture
def kb_db(tmp_path: Path):
    path = tmp_path / "kb.db"
    build_kb.write_kb_db(str(path), build_kb.parse_bundle(MINI_BUNDLE["objects"]))
    kb.configure(str(path))
    yield path
    kb.configure(None)


def test_available_and_meta(kb_db):
    assert kb.available() is True
    meta = kb.meta()
    assert meta["available"] is True
    assert meta["technique_count"] == "3"


def test_matrix_groups_by_tactic(kb_db):
    m = kb.matrix()
    assert m["available"] is True
    assert [t["shortname"] for t in m["tactics"]] == ["execution", "persistence"]
    exec_techs = {t["technique_id"] for t in m["tactics"][0]["techniques"]}
    assert exec_techs == {"T1059", "T1059.001"}
    persist_techs = {t["technique_id"] for t in m["tactics"][1]["techniques"]}
    assert persist_techs == {"T1547"}


def test_get_technique_full_card(kb_db):
    t = kb.get_technique("T1059")
    assert t["name"] == "Command and Scripting Interpreter"
    assert t["platforms"] == ["Windows", "Linux"]
    assert [x["shortname"] for x in t["tactics"]] == ["execution"]
    assert [x["mitigation_id"] for x in t["mitigations"]] == ["M1038"]
    assert [x["technique_id"] for x in t["subtechniques"]] == ["T1059.001"]

    # структурный детект в карточке: стратегия -> вложенные аналитики
    assert [s["strategy_id"] for s in t["detection_strategies"]] == ["DET0001"]
    an = t["detection_strategies"][0]["analytics"][0]
    assert an["analytic_id"] == "AN0001"
    assert an["log_sources"] == [{"name": "WinEventLog:Sysmon", "channel": "EventCode=1"}]
    assert an["mutable_elements"][0]["field"] == "TimeWindow"

    # procedure examples в карточке
    assert [(p["source_id"], p["source_type"]) for p in t["procedures"]] == [("G0001", "group")]
    assert "powershell" in t["procedures"][0]["description"]

    # сабтехника несёт свой procedure (софт)
    sub = kb.get_technique("T1059.001")
    assert [p["source_id"] for p in sub["procedures"]] == ["S0001"]

    assert kb.get_technique("T9999") is None


def test_list_techniques_filters(kb_db):
    assert kb.list_techniques(q="powershell")["total"] == 1
    assert kb.list_techniques(tactic="persistence")["total"] == 1
    assert kb.list_techniques()["total"] == 3


def test_enrich_techniques_hybrid(kb_db):
    out = kb.enrich_techniques(
        ["attack.t1059", "attack.t9999", "attack.t1059.001", "attack.execution"]
    )
    # attack.execution (тактика, не attack.t*) отброшен
    assert [e["technique_id"] for e in out] == ["T1059", "T9999", "T1059.001"]

    assert out[0]["matched"] is True
    assert out[0]["name"] == "Command and Scripting Interpreter"
    assert [x["shortname"] for x in out[0]["tactics"]] == ["execution"]

    assert out[1]["matched"] is False  # нет в KB -> UI покажет сырой тег

    assert out[2]["matched"] is True
    assert out[2]["is_subtechnique"] is True
    assert out[2]["parent_id"] == "T1059"


# --------------------------------------------------------------------------- kb.py (базы нет)


@pytest.fixture
def kb_missing(tmp_path: Path):
    kb.configure(str(tmp_path / "nonexistent.db"))
    yield
    kb.configure(None)


def test_degrades_without_db(kb_missing):
    assert kb.available() is False
    assert kb.meta() == {"available": False}
    assert kb.matrix() == {"available": False, "tactics": []}
    assert kb.list_tactics() == []
    assert kb.get_technique("T1059") is None

    out = kb.enrich_techniques(["attack.t1059", "attack.t1078"])
    assert [e["matched"] for e in out] == [False, False]
    assert out[0]["technique_id"] == "T1059"
