"""
Тесты HTTP-кодов ответа на некорректный ввод (app/main.py). Ровно то, что раньше «тихо»
проходило успехом или отдавало вводящий в заблуждение код:

  * PATCH /incidents/{id}/status с произвольным статусом отдавал 200 и писал мусор в БД
    (после чего инцидент не находился ни одним фильтром /incidents?status=...);
  * group_cond с неизвестным оператором отдавал 200 и НЕ сужал выборку (fail-open);
  * встроенный рулсет как цель отвечал 404 «не найден» про существующий файл, а
    несуществующий кастомный путь - сообщением про встроенность.

Первые HTTP-тесты в проекте (TestClient, httpx из [project.optional-dependencies].dev).
app.main на импорте поднимает глобальные engine/store поверх РЕАЛЬНЫХ путей из app/config.py -
поэтому модуль импортируется ЛЕНИВО, после подмены SIEM_*-переменных на tmp_path (тот же
паттерн, что и tests/test_ingest_stream.py). Проверки по каталогу правил намеренно используют
ТОЛЬКО отвергаемые цели: до записи в реальный data/custom_rulesets дело не доходит.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.models import Entities, Incident

BUILTIN_RULESET_PATH = "Zircolite/rules/rules_linux.json"
MISSING_CUSTOM_PATH = "custom_rulesets/deadbeefdeadbeef"


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    """(TestClient, app.main) поверх временной БД вместо реальной siem.db. Store того же
    процесса нужен тестам, чтобы завести инцидент - ручки на его создание нет (инциденты
    заводит только correlation-движок)."""
    tmp = tmp_path_factory.mktemp("api_errors")
    saved = {k: os.environ.get(k) for k in ("SIEM_DB_PATH", "SIEM_UPLOADS_DIR")}
    os.environ["SIEM_DB_PATH"] = str(tmp / "test.db")
    os.environ["SIEM_UPLOADS_DIR"] = str(tmp / "uploads")

    from app import config

    importlib.reload(config)
    main = importlib.reload(importlib.import_module("app.main"))
    try:
        with TestClient(main.app) as client:
            yield client, main
    finally:
        main.store.close()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(config)


@pytest.fixture
def incident_id(api) -> str:
    _client, main = api
    main.store.upsert_incidents([
        Incident(
            dedup_key="api-errors-1", incident_type="brute_force", title="T", severity="medium",
            source_batch="b1", correlation_rule_title="R", group_key={"IpAddress": "10.0.0.1"},
            window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:05:00",
            window_bucket="2024-01-01T00:00:00", entities=Entities(src_ips=["10.0.0.1"]),
        )
    ])
    return main.store.list_incidents(source_batch="b1")[0]["incident_id"]


def _skip_if_no_builtin_clone():
    if not Path(BUILTIN_RULESET_PATH).exists():
        pytest.skip("Локальный клон Zircolite не найден (Zircolite/rules) - см. README")


# ------------------------------------------------------------------ статус инцидента (API-1)

def test_incident_status_rejects_unknown_value(api, incident_id):
    client, main = api
    assert client.patch(f"/incidents/{incident_id}/status", json={"status": "bogus"}).status_code == 422
    assert main.store.get_incident(incident_id)["status"] == "new"  # в БД ничего не записалось


@pytest.mark.parametrize("status", ["investigating", "closed", "new"])
def test_incident_status_accepts_lifecycle_values(api, incident_id, status):
    client, main = api
    assert client.patch(f"/incidents/{incident_id}/status", json={"status": status}).status_code == 200
    assert main.store.get_incident(incident_id)["status"] == status


def test_alert_groups_route_and_incident_filter_validation(api):
    """/alerts/groups не перехватывается ручкой /alerts/{alert_id}; неизвестное значение
    incident - 422, а не молча игнорируемый фильтр."""
    client, _main = api
    r = client.get("/alerts/groups")
    assert r.status_code == 200
    assert set(r.json()) == {"groups", "total", "limit", "offset"}
    assert client.get("/alerts", params={"incident": "bogus"}).status_code == 422
    assert client.get("/alerts", params={"incident": "none", "q": "x"}).status_code == 200


def test_incident_status_missing_incident_is_404(api):
    client, _main = api
    r = client.patch("/incidents/no-such-incident/status", json={"status": "closed"})
    assert r.status_code == 404


# ------------------------------------------------------------------ drill-in по группе (API-3)

def test_group_cond_with_unknown_operator_is_400(api):
    client, _main = api
    r = client.get("/events", params={"group_cond": '{"field": "EventID", "op": "regex", "value": 1}'})
    assert r.status_code == 400
    assert "regex" in r.json()["detail"]


def test_group_cond_without_field_is_400(api):
    client, _main = api
    r = client.get("/events", params={"group_cond": '{"field": "", "op": "eq", "value": 1}'})
    assert r.status_code == 400


def test_group_cond_valid_condition_still_works(api):
    client, _main = api
    r = client.get("/events", params={"group_cond": '{"field": "EventID", "op": "eq", "value": 1}'})
    assert r.status_code == 200


# ------------------------------------------------------------------ каталог правил (API-4)

def test_add_builtin_ruleset_to_main_is_400(api):
    _skip_if_no_builtin_clone()
    client, _main = api
    r = client.post("/main-ruleset/rulesets", json={"ruleset": BUILTIN_RULESET_PATH, "include": True})
    assert r.status_code == 400
    assert "встроен" in r.json()["detail"].lower()


def test_add_missing_ruleset_to_main_is_404(api):
    client, _main = api
    r = client.post("/main-ruleset/rulesets", json={"ruleset": MISSING_CUSTOM_PATH, "include": True})
    assert r.status_code == 404


def test_add_builtin_rule_to_main_is_400(api):
    _skip_if_no_builtin_clone()
    client, _main = api
    r = client.post(
        "/main-ruleset/rules",
        json={"ruleset": BUILTIN_RULESET_PATH, "rule_id": "some-rule-id", "include": True},
    )
    assert r.status_code == 400


def test_delete_builtin_ruleset_is_400(api):
    _skip_if_no_builtin_clone()
    client, _main = api
    assert client.delete("/rulesets", params={"ruleset": BUILTIN_RULESET_PATH}).status_code == 400


def test_delete_missing_ruleset_is_404(api):
    client, _main = api
    assert client.delete("/rulesets", params={"ruleset": MISSING_CUSTOM_PATH}).status_code == 404


def test_rules_of_missing_ruleset_is_404(api):
    client, _main = api
    assert client.get("/rulesets/rules", params={"ruleset": MISSING_CUSTOM_PATH}).status_code == 404


def test_create_rule_in_builtin_ruleset_is_400(api):
    _skip_if_no_builtin_clone()
    client, _main = api
    r = client.post("/rules/custom", json={"yaml_text": "title: X", "ruleset": BUILTIN_RULESET_PATH})
    assert r.status_code == 400
    assert "встроен" in r.json()["detail"].lower()


def test_create_rule_in_missing_custom_ruleset_is_404(api):
    client, _main = api
    r = client.post("/rules/custom", json={"yaml_text": "title: X", "ruleset": MISSING_CUSTOM_PATH})
    assert r.status_code == 404


# ------------------------------------------------------------------ время (API-2)

def test_time_bounds_are_normalized_end_to_end(api):
    """Все три следствия наивного строкового сравнения времени, через HTTP: граница в формате
    колонки «Время» (с пробелом), событие ровно на верхней границе с дробной частью, событие
    со смещением (+03:00 = 18:00 UTC) в UTC-окне."""
    client, main = api
    main.store.store_events(
        [
            {"row_id": 1, "Hostname": "HOST-A", "SystemTime": "2026-09-05 21:01:30.113"},
            {"row_id": 2, "Hostname": "HOST-A", "SystemTime": "2026-09-05T21:00:00+03:00"},
        ],
        source_batch="time-b1", matched_row_to_rules={},
    )
    def total(**params):
        r = client.get("/events", params={"source_batch": "time-b1", **params})
        assert r.status_code == 200
        return r.json()["total"]

    # Граница с пробелом (раньше 0 - параметр не нормализовался вовсе).
    assert total(time_from="2026-09-05 21:00:00") == 1
    # Событие ровно на верхней границе, с дробной частью (раньше выпадало: .113 > :30).
    assert total(time_to="2026-09-05T21:01:30") == 2
    # "+03:00" - это 18:00 UTC, и окно в UTC его находит (раньше сравнивалось как 21:00).
    assert total(time_from="2026-09-05T17:59:00", time_to="2026-09-05T18:01:00") == 1
    assert total(time_from="2026-09-05T21:01:31") == 0


# ------------------------------------------------------------------ пагинация списков (UI-1)

def test_alerts_response_is_paged_envelope(api):
    """/alerts отдаёт {alerts, total, limit, offset} - без total UI не мог показать пейджер
    и молча выводил только первую страницу из скольких угодно алертов."""
    from app.models import Alert, Severity, SigmaRuleRef

    _client, main = api
    main.store.upsert_alerts([
        Alert(
            dedup_key=f"paged-{i}", source_batch="paged", host=f"H{i}",
            rule=SigmaRuleRef(rule_id=f"r{i}", title=f"Rule {i}", level=Severity.medium),
            entities=Entities(hosts=[f"H{i}"]), event_count=1, sample_events=[],
        )
        for i in range(5)
    ])
    client = _client

    res = client.get("/alerts", params={"source_batch": "paged", "limit": 2, "offset": 0}).json()
    assert res["total"] == 5
    assert res["limit"] == 2 and res["offset"] == 0
    assert len(res["alerts"]) == 2

    tail = client.get("/alerts", params={"source_batch": "paged", "limit": 2, "offset": 4}).json()
    assert tail["total"] == 5
    assert len(tail["alerts"]) == 1

    # total считается по тем же фильтрам, что и выдача
    other = client.get("/alerts", params={"source_batch": "нет-такого"}).json()
    assert other["total"] == 0 and other["alerts"] == []


# ------------------------------------------------------------------ границы пагинации (API-5)
# Раньше валидация была разной у соседних ручек: /events и /rulesets/rules отдавали 400,
# /incidents молча зажимал значение, а /alerts и /events/group не проверяли НИЧЕГО - limit=0
# возвращал пустой список при total>0 (UI рисовал пустую страницу с непустым пейджером), а
# limit без верхней границы вытягивал таблицу целиком. Теперь одна точка - main._check_paging.

@pytest.mark.parametrize("path", ["/alerts", "/incidents", "/events", "/rulesets/rules",
                                  "/kb/mitre/techniques", "/events/group"])
@pytest.mark.parametrize("limit", [0, -1, 501, 1000000])
def test_paging_limit_out_of_range_is_400(api, path, limit):
    client, _main = api
    params = {"limit": limit}
    if path == "/events/group":
        params["group_by"] = "EventID"
    if path == "/rulesets/rules":
        params["ruleset"] = "main"
    res = client.get(path, params=params)
    assert res.status_code == 400, (path, limit, res.text[:200])
    assert "limit" in res.json()["detail"]


@pytest.mark.parametrize("path", ["/alerts", "/incidents", "/events", "/rulesets/rules",
                                  "/kb/mitre/techniques"])
def test_paging_negative_offset_is_400(api, path):
    """SQLite молча трактует отрицательный OFFSET как 0 - опечатка выглядела бы как успех."""
    client, _main = api
    params = {"offset": -1}
    if path == "/rulesets/rules":
        params["ruleset"] = "main"
    res = client.get(path, params=params)
    assert res.status_code == 400, (path, res.text[:200])
    assert "offset" in res.json()["detail"]


@pytest.mark.parametrize("path", ["/alerts", "/incidents", "/events", "/kb/mitre/techniques"])
def test_paging_boundary_values_are_accepted(api, path):
    """Границы диапазона (limit=1 и limit=500, offset=0) остаются валидными."""
    client, _main = api
    for params in ({"limit": 1, "offset": 0}, {"limit": 500, "offset": 0}):
        res = client.get(path, params=params)
        assert res.status_code == 200, (path, params, res.text[:200])
