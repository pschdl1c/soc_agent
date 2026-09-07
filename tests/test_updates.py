"""
Счётчики изменений для автообновления списков в UI (app/updates.py + GET /updates).

Проверяем ровно то, ради чего счётчик вообще заведён отдельным от БД (см. докстринг модуля):

  * version растёт на ЛЮБОМ изменении списка, created - только на реально созданных строках;
  * изменение существующего алерта (инкремент event_count при дедупе) двигает version, но не
    created - по "максимальному created_at" такое изменение вообще не видно, и UI, сравнивая
    только created, молча показывал бы устаревший список;
  * смена статуса инцидента и удаление источника - тоже изменения (UI перечитывает список);
  * ручка отдаёт снимок целиком (epoch + оба канала) и не ходит в БД.

app.main на импорте поднимает глобальные engine/store поверх РЕАЛЬНЫХ путей из app/config.py,
поэтому импортируется ЛЕНИВО, после подмены SIEM_*-переменных на tmp_path (тот же паттерн, что
в tests/test_api_errors.py).
"""
from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient

from app import updates
from app.models import Alert, Entities, Incident, Severity, SigmaRuleRef


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("updates")
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


@pytest.fixture(autouse=True)
def clean_counters():
    """Состояние модуля глобальное на процесс - каждому тесту свой ноль."""
    updates._reset()
    yield
    updates._reset()


def _alert(dedup_key: str, source_batch: str = "b-upd", event_count: int = 1) -> Alert:
    return Alert(
        dedup_key=dedup_key, engine="zircolite", source_batch=source_batch, host="HOST1",
        rule=SigmaRuleRef(rule_id="r1", title="R1", level=Severity.medium, description=""),
        entities=Entities(users=["u1"]), event_count=event_count, sample_events=[{"a": 1}],
    )


def test_snapshot_shape_and_bump():
    snap = updates.snapshot()
    assert set(snap) == {"epoch", "alerts", "incidents"}
    assert snap["alerts"] == {"version": 0, "created": 0}

    updates.bump("alerts", created=3)
    updates.bump("alerts")  # изменение без создания (инкремент event_count / удаление)
    snap2 = updates.snapshot()
    assert snap2["alerts"] == {"version": 2, "created": 3}
    assert snap2["incidents"] == {"version": 0, "created": 0}
    assert snap2["epoch"] == snap["epoch"]

    # Снимок - копия: правка результата не должна протекать в состояние модуля.
    snap2["alerts"]["version"] = 999
    assert updates.snapshot()["alerts"]["version"] == 2


def test_unknown_channel_is_ignored():
    """Счётчик - вспомогательная штука для UI: опечатка в имени канала не должна ронять
    запись алерта, из которой bump зовут."""
    updates.bump("events", created=5)
    assert updates.snapshot()["alerts"]["version"] == 0


def test_endpoint_returns_snapshot(api):
    client, _main = api
    res = client.get("/updates")
    assert res.status_code == 200
    assert res.json() == updates.snapshot()


def test_dedup_increment_moves_version_but_not_created(api):
    """Ключевой случай: повторное срабатывание того же правила на том же событии НЕ создаёт
    алерт, а инкрементит event_count существующего (app/detection/normalize.py). Список в UI при
    этом меняется - version обязана вырасти, created - нет.

    Воспроизводим тот же расчёт, что делает _process_batch: число НОВЫХ строк считается по
    dedup_key ДО записи, а не по возврату upsert_alerts (та отдаёт число ОБРАБОТАННЫХ строк -
    повтор от новинки по нему не отличить, см. комментарий в app/main.py)."""
    _client, main = api

    def upsert_like_process_batch(alerts) -> int:
        known_before = set(main.store.get_alert_ids_by_dedup_keys([a.dedup_key for a in alerts]))
        main.store.upsert_alerts(alerts)
        new_count = len({a.dedup_key for a in alerts} - known_before)
        main.updates.bump("alerts", created=new_count)
        return new_count

    assert upsert_like_process_batch([_alert("upd-dedup-1")]) == 1
    assert updates.snapshot()["alerts"] == {"version": 1, "created": 1}

    # Тот же dedup_key - новой строки нет, но event_count вырос: version двигается, created нет.
    assert upsert_like_process_batch([_alert("upd-dedup-1")]) == 0
    assert updates.snapshot()["alerts"] == {"version": 2, "created": 1}
    assert main.store.list_alerts(source_batch="b-upd")[0]["event_count"] == 2


def test_incident_status_change_and_batch_delete_bump(api):
    client, main = api
    main.store.upsert_incidents([
        Incident(
            dedup_key="upd-inc-1", incident_type="brute_force", title="T", severity="medium",
            source_batch="b-upd", correlation_rule_title="R", group_key={"IpAddress": "10.0.0.1"},
            window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:05:00",
            window_bucket="2024-01-01T00:00:00", entities=Entities(src_ips=["10.0.0.1"]),
        )
    ])
    incident_id = main.store.list_incidents(source_batch="b-upd")[0]["incident_id"]

    before = updates.snapshot()["incidents"]["version"]
    assert client.patch(f"/incidents/{incident_id}/status", json={"status": "investigating"}).status_code == 200
    assert updates.snapshot()["incidents"]["version"] == before + 1

    # Удаление источника: строки ИСЧЕЗЛИ - для открытого UI это тоже изменение обоих списков.
    main.store.upsert_alerts([_alert("upd-del-1")])
    before_alerts = updates.snapshot()["alerts"]["version"]
    before_incidents = updates.snapshot()["incidents"]["version"]
    assert client.delete("/batches/b-upd").status_code == 200
    assert updates.snapshot()["alerts"]["version"] == before_alerts + 1
    assert updates.snapshot()["incidents"]["version"] == before_incidents + 1


def test_investigation_job_bumps_incidents(api):
    """Заглушка вердиктов (app/incidents.py:run_pending) меняет investigation_status, который
    показан колонкой в списке инцидентов - значит список тоже надо перечитать."""
    from app import incidents as incidents_job

    _client, main = api
    main.store.upsert_incidents([
        Incident(
            dedup_key="upd-inc-2", incident_type="brute_force", title="T", severity="low",
            source_batch="b-upd-2", correlation_rule_title="R", group_key={},
            window_start="2024-01-01T00:00:00", window_end="2024-01-01T00:05:00",
            window_bucket="2024-01-01T00:00:00", entities=Entities(),
        )
    ])
    incident_id = main.store.list_incidents(source_batch="b-upd-2")[0]["incident_id"]
    main.store.enqueue_investigation(incident_id)

    updates._reset()
    assert incidents_job.run_pending(main.store) == 1
    assert updates.snapshot()["incidents"]["version"] == 1
    assert updates.snapshot()["incidents"]["created"] == 0  # вердикт - не новый инцидент

    updates._reset()
    assert incidents_job.run_pending(main.store) == 0  # очередь пуста
    assert updates.snapshot()["incidents"]["version"] == 0
