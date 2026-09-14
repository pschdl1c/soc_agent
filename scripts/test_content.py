r"""
Прогон фикстур детект-контента (artifacts/content/<domain>/tests/*.yml) через ПОТОКОВЫЙ ingest
живого SIEM: события -> /ingest/stream -> основной рулсет -> корреляции -> проверка инцидентов.

Контент должен быть уже задеплоен (scripts/deploy_content.py) и включён в основной рулсет.
Рекомендуемый стенд - изолированный экземпляр на отдельном порту, чтобы не трогать рабочие
правила и БД:

    set SIEM_DB_PATH=%TEMP%\siem-content.db
    set SIEM_CUSTOM_RULESETS_DIR=%TEMP%\content-rulesets
    set SIEM_VALUE_LISTS_DIR=%TEMP%\content-lists
    uv run uvicorn app.main:app --port 8001
    uv run python scripts/deploy_content.py http://localhost:8001
    uv run python scripts/test_content.py http://localhost:8001 [--domain auth] [--scenario SCE_Auth_BruteForce]

Формат фикстуры:

    scenario: SCE_Auth_BruteForce
    cases:
      - name: positive
        expect_incidents: [auth_bruteforce]    # ТОЧНЫЙ набор incident_type этого кейса
        events:
          - at: 0          # смещение первого события, секунды (дефолт 0)
            repeat: 20     # сколько раз повторить (дефолт 1)
            step: 3        # шаг между повторами, секунды (дефолт 1)
            phase: 1       # фаза отправки (дефолт 1): фаза N+1 уходит после флаша фазы N
            vary:          # значение поля на i-м повторе - options[i % len(options)]
              TargetUserName: [admin, backup]
            event: {EventID: 4625, Channel: Security, IpAddress: 203.0.113.7}
    lab:                   # команды эмуляции на win10-lab (информативно, скрипт их не выполняет)
      - ...

Каждый кейс получает СВОЙ временный источник (изоляция инцидентов по source_batch) и свой
случайный хост. В строковых значениях события подставляются ${host}, ${i} (номер повтора),
${guidN} (стабильный в пределах кейса GUID вида {XXXXXXXX-...}), ${rand} (случайный хвост кейса).
Автоматически добавляются Computer (если не задан), TimeCreated/EventTime по смещению.
Проверка точная: лишний инцидент - такой же FAIL, как недостающий (ловит пересечения сценариев).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from content_lib import CONTENT_DIR, Api, ApiError, domain_dirs

_VAR_RE = re.compile(r"\$\{(host|i|rand|guid\d+)\}")

# Реальный набор полей каждого (Channel, EventID) со стенда win10-lab (artifacts/content/telemetry/
# event_fields.json). Недостающие в фикстуре поля дополняются "-" (как пустые поля у самого Sysmon;
# пустую строку Zircolite при flatten выбрасывает вместе с полем). Zircolite строит
# таблицу флаша из полей событий, и правило, упоминающее поле, которого нет НИ В ОДНОМ событии
# флаша, падает с "no such column" и молча не срабатывает. На живом потоке у Sysmon 1 всегда есть
# ParentImage/User/... - синтетика без них проверяла бы не то, что придёт с форвардера.
_SCHEMA: dict[str, list[str]] = {}
# event_fields_manual.json - события, которых на стенде ещё нет (по документации); выгрузка со
# стенда (event_fields.json) читается второй и при совпадении ключа побеждает.
for _name in ("event_fields_manual.json", "event_fields.json"):
    _p = CONTENT_DIR / "telemetry" / _name
    if _p.exists():
        _SCHEMA.update({k: v for k, v in json.loads(_p.read_text(encoding="utf-8")).items() if not k.startswith("_")})


@dataclass
class Case:
    domain: str
    scenario: str
    name: str
    expect: set[str]
    specs: list[dict[str, Any]]
    host: str = ""
    rand: str = ""
    guids: dict[str, str] = field(default_factory=dict)
    source_id: str = ""
    source_name: str = ""
    token: str = ""
    actual: set[str] = field(default_factory=set)
    titles: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.domain}/{self.scenario}/{self.name}"


def _subst(value: Any, case: Case, i: int) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key == "host":
                return case.host
            if key == "i":
                return str(i)
            if key == "rand":
                return case.rand
            return case.guids.setdefault(key, "{" + str(uuid.uuid4()).upper() + "}")
        return _VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _subst(v, case, i) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, case, i) for v in value]
    return value


def _build_events(case: Case, base: datetime) -> dict[int, list[dict[str, Any]]]:
    phases: dict[int, list[dict[str, Any]]] = {}
    for spec in case.specs:
        at = float(spec.get("at", 0))
        step = float(spec.get("step", 1))
        for i in range(int(spec.get("repeat", 1))):
            ts = base + timedelta(seconds=at + i * step)
            ev = dict(spec["event"])
            for fname, options in (spec.get("vary") or {}).items():
                ev[fname] = options[i % len(options)]
            ev = _subst(ev, case, i)
            for fname in _SCHEMA.get(f"{ev.get('Channel')}|{ev.get('EventID')}", ()):
                ev.setdefault(fname, "-")
            ev.setdefault("Computer", case.host)
            ev["TimeCreated"] = ts.strftime("%Y-%m-%d %H:%M:%S +0000")
            ev["EventTime"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            phases.setdefault(int(spec.get("phase", 1)), []).append(ev)
    return phases


def _load_cases(content_dir: Path, domains: set[str] | None, scenarios: set[str] | None) -> list[Case]:
    cases: list[Case] = []
    for ddir in domain_dirs(content_dir):
        if domains and ddir.name not in domains:
            continue
        for p in sorted((ddir / "tests").glob("*.yml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            scenario = doc["scenario"]
            if scenarios and scenario not in scenarios:
                continue
            for c in doc["cases"]:
                cases.append(Case(ddir.name, scenario, c["name"], set(c.get("expect_incidents") or []), c["events"]))
    return cases


def _post_events(api: Api, token: str, events: list[dict[str, Any]]) -> None:
    body = "\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode("utf-8")
    api.request("POST", "/ingest/stream", raw=body, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson",
    })


def _wait_flush(api: Api, sync_source: str, sync_token: str) -> None:
    """Дождаться, пока ВСЁ отправленное обработано, включая корреляции.

    queue_size == 0 значит лишь "воркер забрал события", а не "флаш закончен": на флаше с десятками
    источников движок + запись + корреляции идут дольше интервала, и проверка без маркера читала
    инциденты раньше, чем они появлялись (нестабильные FAIL). Маркер - событие служебного источника:
    воркер обрабатывает флаши последовательно, поэтому когда в БД появился ВТОРОЙ маркер, отправленный
    после записи первого, флаш с событиями кейсов гарантированно завершён целиком."""
    for _ in range(2):
        marker = uuid.uuid4().hex
        _post_events(api, sync_token, [{"EventID": 0, "Channel": "SocContentTestSync", "SyncMarker": marker}])
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if api.get("/events", source_batch=sync_source, query=f'SyncMarker = "{marker}"', limit=1)["total"]:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("маркер синхронизации не дошёл до БД за 5 минут")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", nargs="?", default="http://localhost:8001")
    parser.add_argument("--content", type=Path, default=CONTENT_DIR)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--scenario", action="append")
    parser.add_argument("--keep", action="store_true", help="не удалять источники/события после прогона")
    args = parser.parse_args()

    api = Api(args.url)
    cases = _load_cases(args.content, set(args.domain or []) or None, set(args.scenario or []) or None)
    if not cases:
        print("Нет фикстур под фильтр")
        sys.exit(1)

    run = uuid.uuid4().hex[:6]
    base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30)
    phases: dict[int, list[tuple[Case, list[dict[str, Any]]]]] = {}
    sync_name = f"ct-{run}-sync"
    sync = None
    try:
        sync = api.request("POST", "/sources", body={"name": sync_name, "description": "test_content sync markers"})
        for n, case in enumerate(cases):
            case.rand = uuid.uuid4().hex[:8]
            case.host = f"CT-{case.rand.upper()}"
            case.source_name = f"ct-{run}-{n}"
            src = api.request("POST", "/sources", body={"name": case.source_name, "description": case.label[:64]})
            case.source_id, case.token = src["source_id"], src["token"]
            for phase, events in _build_events(case, base).items():
                phases.setdefault(phase, []).append((case, events))

        total = sum(len(ev) for items in phases.values() for _, ev in items)
        print(f"Кейсов: {len(cases)}, событий: {total}, фаз: {len(phases)}")
        for phase in sorted(phases):
            for case, events in phases[phase]:
                for k in range(0, len(events), 400):
                    _post_events(api, case.token, events[k:k + 400])
            _wait_flush(api, sync_name, sync["token"])

        failed = 0
        for case in cases:
            incidents = api.get("/incidents", source_batch=case.source_name, limit=500)["incidents"]
            case.actual = {i["incident_type"] for i in incidents}
            case.titles = sorted({i["correlation_rule_title"] for i in incidents})
            ok = case.actual == case.expect
            failed += not ok
            mark = "PASS" if ok else "FAIL"
            print(f"[{mark}] {case.label}")
            if not ok:
                print(f"        ожидалось: {sorted(case.expect)}")
                print(f"        получено:  {sorted(case.actual)}  ({', '.join(case.titles)})")
                alerts = api.get("/alerts", source_batch=case.source_name, limit=500)["alerts"]
                seen = sorted({a["rule_title"] for a in alerts})
                print(f"        алерты:    {seen}")
        print(f"\nИтого: {len(cases) - failed}/{len(cases)} PASS")
    except (ApiError, RuntimeError) as exc:
        print(f"\nОШИБКА: {exc}", file=sys.stderr)
        failed = 1
    finally:
        cleanup = [(c.source_name, c.source_id) for c in cases if c.source_id and not args.keep]
        if sync:
            cleanup.append((sync_name, sync["source_id"]))
        for name, source_id in cleanup:
            for method, path in (("DELETE", f"/batches/{name}"), ("DELETE", f"/sources/{source_id}")):
                try:
                    api.request(method, path)
                except ApiError:
                    pass
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
