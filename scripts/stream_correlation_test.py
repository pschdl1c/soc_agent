r"""
Проверка стейтфул-корреляции (app/detection/correlation.py) через ПОТОКОВЫЙ ingest (/ingest/stream +
IngestWorker, app/ingest_queue.py) - конкретно то, что раньше не работало: временное окно
correlation-правила (`timespan: 5m`) шире одного micro-batch flush'а (SIEM_INGEST_FLUSH_INTERVAL,
дефолт 5с). Скрипт шлёт 20 событий EventID=4625 (провал аутентификации) с одного IpAddress
НЕСКОЛЬКИМИ отдельными HTTP-запросами, специально разнесёнными по времени дольше flush_interval -
события гарантированно попадают в РАЗНЫЕ батчи, и инцидент должен появиться только если корреляция
реально смотрит на уже сохранённые (постоянная таблица events/rule_hits, не in-memory Zircolite-БД
одного батча) события, а не только на текущий батч.

Правило - сценарий SCE_Auth_BruteForce детект-контента (artifacts/content/auth, 20 отказов с одного
адреса за 5 минут -> инцидент auth_bruteforce). Контент должен быть задеплоен и включён в основной
рулсет (scripts/deploy_content.py) - скрипт только шлёт события. Полная проверка контента на
синтетике - scripts/test_content.py; этот скрипт - ручная проверка одного пути на живом сервере.

Как пользоваться:
    1. Убедись, что сервис запущен и контент задеплоен.
    2. Вкладка "Источник данных" -> "Создать источник" с именем correlation-stream-test (или
       своим, тогда передай его в --source). Сохрани показанный токен - /ingest/stream без
       него отвечает 401.
    3. python scripts/stream_correlation_test.py --token <токен_источника>
       (или SIEM_INGEST_TOKEN=<токен> python scripts/stream_correlation_test.py)
       Отправит 20 событий тремя отдельными запросами с паузами дольше flush_interval, дождётся
       флаша, поллит /incidents - ожидается инцидент auth_bruteforce по хосту прогона.
    4. python scripts/stream_correlation_test.py --token <токен> --negative
       Контрольный прогон: те же 20 событий, но с шагом 20с (любое 5-минутное окно накрывает
       не больше 16) - инцидента появляться НЕ должно.

Хост и адрес рандомизируются на прогон, поэтому прогоны не мешают друг другу (проверка фильтрует
инциденты по group_key прогона). Удалить всё разом - DELETE /batches/{имя_источника} через вкладку
"Источник данных".
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from uuid import uuid4

DEFAULT_URL = "http://localhost:8000"
SOURCE_LABEL = "correlation-stream-test"
TARGET_INCIDENT_TYPE = "auth_bruteforce"
EVENT_COUNT = 20


def _event(host: str, ip: str, user: str, event_time: datetime) -> dict:
    # Форма события агента Vector (dist/vector.toml): Computer, TimeCreated ISO UTC.
    return {
        "EventID": 4625,
        "Channel": "Security",
        "TimeCreated": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "Computer": host,
        "LogonType": 3,
        "IpAddress": ip,
        "IpPort": "0",
        "TargetUserName": user,
        "TargetDomainName": host,
        "WorkstationName": "ATTACKER-PC",
        "Status": "0xc000006d",
        "SubStatus": "0xc000006a",
    }


def _get_json(url: str, path: str) -> dict | list:
    req = urllib.request.Request(f"{url}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_stream(url: str, token: str, events: list[dict]) -> None:
    """Метку источника задаёт сам сервис по токену (?source= больше не используется)."""
    body = "\n".join(json.dumps(e, default=str) for e in events).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/ingest/stream",
        data=body, method="POST",
        headers={"Content-Type": "application/x-ndjson", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            res = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"Ошибка HTTP {exc.code} на /ingest/stream: {detail}", file=sys.stderr)
        sys.exit(1)
    print(f"  -> queued={res.get('queued')}")


def _wait_for_flush(url: str, timeout: float = 15.0) -> None:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        health = _get_json(url, "/health?detailed=true")
        q = health["checks"]["ingest_queue"]
        print(f"  queue_size={q['queue_size']}")
        if q["queue_size"] == 0:
            time.sleep(0.5)
            return
        time.sleep(1.0)
    print("  таймаут ожидания флаша")


def _flush_interval(url: str) -> float:
    health = _get_json(url, "/health?detailed=true")
    return float(health["checks"]["ingest_queue"]["flush_interval"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--token", default=os.environ.get("SIEM_INGEST_TOKEN"),
                        help="токен зарегистрированного источника (или переменная SIEM_INGEST_TOKEN)")
    parser.add_argument("--source", default=SOURCE_LABEL,
                        help=f"имя источника, созданного в UI (default: {SOURCE_LABEL})")
    parser.add_argument(
        "--negative", action="store_true",
        help="растянуть события так, чтобы в 5-минутное окно не попало 20 - инцидента быть не должно",
    )
    args = parser.parse_args()
    if not args.token:
        parser.error("нужен --token (или SIEM_INGEST_TOKEN): создайте источник во вкладке «Источник данных»")
    url = args.url

    interval = _flush_interval(url)
    pause = interval + 2.0  # с запасом, чтобы гарантированно попасть в РАЗНЫЙ flush
    step = timedelta(seconds=20 if args.negative else 12)

    run_id = uuid4().hex[:8]
    source = args.source  # имя зарегистрированного источника (метку выдаёт сервис по токену)
    ip = f"203.0.113.{int(run_id[:2], 16) % 250 + 1}"
    host = f"WS-{run_id.upper()}"
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    events = [_event(host, ip, "administrator", base + i * step) for i in range(EVENT_COUNT)]

    print(f"Отправляю {EVENT_COUNT} событий EventID=4625 (source={source!r}, host={host}) тремя батчами, "
          f"с паузой {pause:.1f}с (> flush_interval={interval:.1f}с) между ними:")
    chunks = [events[0:7], events[7:14], events[14:]]
    for i, chunk in enumerate(chunks):
        print(f"Батч {i + 1}/{len(chunks)} ({len(chunk)} событий)")
        _post_stream(url, args.token, chunk)
        if i < len(chunks) - 1:
            time.sleep(pause)

    _wait_for_flush(url)

    print("\nПоллю /incidents...")
    query = urllib.parse.urlencode({"source_batch": source, "incident_type": TARGET_INCIDENT_TYPE, "limit": 500})
    t0 = time.monotonic()
    hit: list[dict] = []
    while time.monotonic() - t0 < 20.0:
        incidents = _get_json(url, f"/incidents?{query}")["incidents"]
        hit = [i for i in incidents if (i.get("group_key") or {}).get("Computer") == host]
        if hit:
            break
        time.sleep(1.5)

    if args.negative:
        if hit:
            print(f"\nFAIL: инцидент появился, хотя в 5-минутное окно не попадает 20 событий: {hit}")
            sys.exit(1)
        print(f"\nOK: инцидент {TARGET_INCIDENT_TYPE} по {host} НЕ появился.")
        return

    if not hit:
        print(
            f"\nFAIL: инцидент {TARGET_INCIDENT_TYPE} по {host} не появился. Проверь, что детект-контент "
            "задеплоен и рулсет auth включён в основной рулсет (scripts/deploy_content.py)."
        )
        sys.exit(1)

    inc = hit[0]
    print(f"\nOK: {inc.get('incident_type')} [{inc.get('severity')}] group_key={inc.get('group_key')} "
          f"alert_count={inc.get('alert_count')} source_batch={source}")


if __name__ == "__main__":
    main()
