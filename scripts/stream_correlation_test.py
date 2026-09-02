r"""
Проверка стейтфул-корреляции (app/correlation.py) через ПОТОКОВЫЙ ingest (/ingest/stream +
IngestWorker, app/ingest_queue.py) - конкретно то, что раньше не работало: временное окно
correlation-правила (`timespan: 5m`) шире одного micro-batch flush'а (SIEM_INGEST_FLUSH_INTERVAL,
дефолт 5с). Скрипт шлёт 10 событий EventID=4625 (провал аутентификации) с одним IpAddress/
TargetUserName НЕСКОЛЬКИМИ отдельными HTTP-запросами, специально разнесёнными по времени дольше
flush_interval - события гарантированно попадают в РАЗНЫЕ батчи, и алерт должен появиться только
если корреляция реально смотрит на уже сохранённые (постоянная таблица events/rule_hits, не
in-memory Zircolite-БД одного батча) события, а не только на текущий батч.

Только форвард событий - правило (`artifacts/content/windows_bruteforce.yml`) нужно ЗАГРУЗИТЬ И
ДОБАВИТЬ В ОСНОВНОЙ РУЛСЕТ САМОСТОЯТЕЛЬНО (вкладка «Sigma-правила») ДО запуска - именно основной
рулсет по умолчанию обрабатывает /ingest/stream (app/main_ruleset.py). Скрипт этим не занимается
и ничего не пишет в custom_rulesets.

Как пользоваться:
    1. Убедись, что сервис запущен и правило уже в основном рулсете.
    2. Вкладка "Источник данных" -> "Создать источник" с именем correlation-stream-test (или
       своим, тогда передай его в --source). Сохрани показанный токен - /ingest/stream без
       него отвечает 401.
    3. python scripts/stream_correlation_test.py --token <токен_источника>
       (или SIEM_INGEST_TOKEN=<токен> python scripts/stream_correlation_test.py)
       Отправит 10 событий EventID=4625 тремя отдельными запросами с паузами между ними дольше
       flush_interval, дождётся флаша, поллит /alerts - ожидается алерт "Windows Brute Force -
       Ten Failures By Source IP And Account" с event_count >= 10.
    4. python scripts/stream_correlation_test.py --token <токен> --negative
       Контрольный прогон: те же 10 событий, но растянутые ЗА ПРЕДЕЛЫ 5-минутного timespan
       (40с между событиями, итого 360с > 300с) - алерт с этим rule_title появляться НЕ должен.

Батчи оседают под меткой источника (его имя); host/ip/user рандомизируются на прогон, поэтому
разные прогоны не мешают друг другу (проверка алерта фильтруется по host прогона). Удалить всё
разом - DELETE /batches/{имя_источника} через вкладку "Источник данных".
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
TARGET_RULE_TITLE = "Windows Brute Force - Ten Failures By Source IP And Account"

_DOMAIN = "CORP"


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _event(host: str, ip: str, user: str, event_time: datetime) -> dict:
    return {
        "EventID": 4625,
        "Channel": "Security",
        "EventTime": _fmt(event_time),
        "Hostname": host,
        "IpAddress": ip,
        "TargetUserName": user,
        "TargetDomainName": _DOMAIN,
        "WorkstationName": "ATTACKER-PC",
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
        help="растянуть события ЗА ПРЕДЕЛЫ 5-минутного timespan - алерт не должен появиться",
    )
    args = parser.parse_args()
    if not args.token:
        parser.error("нужен --token (или SIEM_INGEST_TOKEN): создайте источник во вкладке «Источник данных»")
    url = args.url

    interval = _flush_interval(url)
    pause = interval + 2.0  # с запасом, чтобы гарантированно попасть в РАЗНЫЙ flush
    step = timedelta(seconds=40 if args.negative else 20)

    # IP/юзер/хост РАНДОМИЗИРУЮТСЯ на каждый прогон (не фиксированные константы) - иначе
    # alerts.dedup_key = sha256(rule_id:host:main_entity) (см. app/normalize.py, НЕ включает
    # source_batch) коллизирует между прогонами скрипта и обычные (не-correlation) алерты просто
    # инкрементят event_count у алерта ПЕРВОГО прогона вместо создания под новым source_batch -
    # см. предупреждение в CLAUDE.md "При ручном тестировании alert-дедупликации". Сама
    # корреляция при этом фактически срабатывает верно - но /alerts?source_batch=<новый прогон>
    # ложно показывает пусто, потому что алерт остался приписан к source_batch ПЕРВОГО прогона.
    run_id = uuid4().hex[:8]
    source = args.source  # имя зарегистрированного источника (метку выдаёт сервис по токену)
    ip = f"203.0.113.{int(run_id[:2], 16) % 250 + 1}"
    user = f"user-{run_id}"
    host = f"WORKSTATION-{run_id}.corp.local"
    base = datetime.now(timezone.utc)
    events = [_event(host, ip, user, base + i * step) for i in range(10)]

    print(f"Отправляю 10 событий EventID=4625 (source={source!r}) тремя батчами, "
          f"с паузой {pause:.1f}с (> flush_interval={interval:.1f}с) между ними:")
    chunks = [events[0:4], events[4:7], events[7:10]]
    for i, chunk in enumerate(chunks):
        print(f"Батч {i + 1}/{len(chunks)} ({len(chunk)} событий)")
        _post_stream(url, args.token, chunk)
        if i < len(chunks) - 1:
            time.sleep(pause)

    _wait_for_flush(url)

    print("\nПоллю /alerts...")
    t0 = time.monotonic()
    alerts: list[dict] = []
    # source_batch теперь общий для всех прогонов этого источника - изолируем прогон по host
    # (рандомизирован выше), иначе stale-алерт от прошлого позитивного прогона сломал бы --negative.
    while time.monotonic() - t0 < 20.0:
        alerts = _get_json(url, f"/alerts?{urllib.parse.urlencode({'source_batch': source})}")
        if any(a.get("rule_title") == TARGET_RULE_TITLE and a.get("host") == host for a in alerts):
            break
        time.sleep(1.5)

    hit = [a for a in alerts if a.get("rule_title") == TARGET_RULE_TITLE and a.get("host") == host]
    if args.negative:
        if hit:
            print(f"\nFAIL: алерт появился, хотя события растянуты за пределы timespan: {hit}")
            sys.exit(1)
        print(f"\nOK: алерт '{TARGET_RULE_TITLE}' НЕ появился (события за пределами 5-минутного окна).")
        return

    if not hit:
        print(
            f"\nFAIL: алерт '{TARGET_RULE_TITLE}' не появился. Все алерты source_batch={source}:\n"
            + "\n".join(f"  - {a.get('rule_title')} event_count={a.get('event_count')}" for a in alerts)
            + "\n\nПроверь, что правило windows_bruteforce.yml загружено И добавлено в основной "
            "рулсет (вкладка «Sigma-правила»)."
        )
        sys.exit(1)

    a = hit[0]
    print(f"\nOK: '{a.get('rule_title')}' event_count={a.get('event_count')} host={a.get('host')} "
          f"engine={a.get('engine')} source_batch={source}")


if __name__ == "__main__":
    main()
