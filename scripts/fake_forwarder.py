"""
Тестовый форвардер для проверки потокового ingest (POST /ingest/stream + IngestWorker,
см. app/ingest_queue.py и docs/forwarder.md). Генерирует синтетические события и шлёт их
в очередь, печатая после каждой порции текущее состояние воркера (GET /health?detailed=true
-> checks.ingest_queue) - видно queue_size/worker_alive без второго терминала.

Два режима бьют в оба триггера флаша («N событий ИЛИ T секунд» - см. _flush в ingest_queue.py):

    burst - разом отправить N событий крупными порциями. При --count больше
            SIEM_INGEST_BATCH_SIZE (дефолт 500) флаш должен сработать по количеству,
            не дожидаясь SIEM_INGEST_FLUSH_INTERVAL.

    drip  - слать по несколько событий в секунду долго. Буфер копится и флашится по
            таймауту (SIEM_INGEST_FLUSH_INTERVAL, дефолт 5с), даже не набрав полный батч.

Событие сгенерировано в духе того, что реально шлют форвардеры (Hostname/EventID/Channel/
EventTime, см. docs/forwarder.md) - проходит весь пайплайн ingest -> Zircolite -> store,
не только саму очередь. source specifically помечен "fake-*", чтобы легко отличить
от настоящих батчей в UI и почистить отдельно.

/ingest/stream требует токен зарегистрированного источника (вкладка «Источник данных» ->
«Создать источник»): заголовок Authorization: Bearer <token>. Токен передаётся флагом
--token либо через переменную окружения SIEM_INGEST_TOKEN. Метку источника (source_batch)
задаёт сам источник по токену - параметр --source остался только для подписи в выводе и
должен совпадать с именем созданного источника, если хотите чистить его через UI.

Примеры:
    SIEM_INGEST_TOKEN=... python scripts/fake_forwarder.py burst --count 1200 --source fake-burst
    python scripts/fake_forwarder.py drip --rate 2 --duration 30 --token <token> --source fake-drip
    python scripts/fake_forwarder.py drip --rate 1 --token <token>   # без --duration - бесконечно, Ctrl+C
    python scripts/fake_forwarder.py burst --count 150000 --chunk 2000 --token <token>   # backpressure/переполнение очереди
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "http://localhost:8000"

_HOSTS = ["WORKSTATION1.theshire.local", "WORKSTATION2.theshire.local", "MORDORDC.theshire.local"]
_EVENT_IDS = [4624, 4625, 4688, 4690, 4656, 4658, 5140, 7045]
_CHANNELS = ["Security", "Microsoft-Windows-Sysmon/Operational", "Windows PowerShell"]

# Изредка подмешиваем событие, которое реально сработает на Sigma-правило (закодированная
# PowerShell-команда) - чтобы видеть в UI не только "сырые" события в очереди, но и алерты,
# доехавшие через весь пайплайн ingest -> detect -> store.
_SUSPICIOUS_COMMANDLINE = (
    "powershell.exe -nop -w hidden -enc "
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
)


def _make_event(seq: int) -> dict:
    host = random.choice(_HOSTS)
    event_id = random.choice(_EVENT_IDS)
    now = datetime.now(timezone.utc)
    event = {
        "EventTime": now.strftime("%Y-%m-%d %H:%M:%S"),
        "Hostname": host,
        "EventID": event_id,
        "Channel": random.choice(_CHANNELS),
        "Severity": "INFO",
        "seq": seq,  # чисто для читаемости при отладке, на детект не влияет
    }
    if event_id == 4688 and random.random() < 0.05:
        event["CommandLine"] = _SUSPICIOUS_COMMANDLINE
        event["Image"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    return event


def _send(url: str, token: str, events: list[dict]) -> dict | None:
    """POST одной NDJSON-порции. Возвращает распарсенный ответ или None при ошибке
    (печатает причину и не роняет форвардер - ретраи форвардеру не нужны, это просто тест).
    Метку источника задаёт сам сервис по токену - ?source= больше не используется."""
    body = "\n".join(json.dumps(e, default=str) for e in events).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/ingest/stream",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-ndjson", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"  ошибка HTTP {exc.code}: {detail}", file=sys.stderr)
    except urllib.error.URLError as exc:
        print(f"  ошибка соединения: {exc.reason}", file=sys.stderr)
    return None


def _print_queue_status(url: str) -> None:
    try:
        req = urllib.request.Request(f"{url}/health?detailed=true", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        q = data["checks"]["ingest_queue"]
        print(
            f"    [очередь] worker_alive={q['worker_alive']} "
            f"queue_size={q['queue_size']}/{q['queue_max']} "
            f"batch_size={q['batch_size']} flush_interval={q['flush_interval']}с"
        )
    except Exception as exc:  # noqa: BLE001 - диагностика не должна ронять сам форвардер
        print(f"    [очередь] не удалось получить статус: {exc}")


def cmd_burst(args: argparse.Namespace) -> None:
    print(f"burst: {args.count} событий, порциями по {args.chunk}, source={args.source!r} -> {args.url}")
    sent = 0
    seq = 0
    t0 = time.monotonic()
    while sent < args.count:
        chunk = [_make_event(seq + i) for i in range(min(args.chunk, args.count - sent))]
        seq += len(chunk)
        res = _send(args.url, args.token, chunk)
        sent += len(chunk)
        print(f"[{sent}/{args.count}] отправлено, queued={res.get('queued') if res else '?'}")
        _print_queue_status(args.url)
    print(f"готово за {time.monotonic() - t0:.1f}с")


def cmd_drip(args: argparse.Namespace) -> None:
    print(
        f"drip: {args.rate} событий/с, source={args.source!r} -> {args.url} "
        f"({'бесконечно, Ctrl+C для остановки' if args.duration <= 0 else f'{args.duration:.0f}с'})"
    )
    interval = 1.0 / args.rate if args.rate > 0 else 1.0
    status_every = max(1, round(args.rate))  # печатать статус очереди примерно раз в секунду
    seq = 0
    t0 = time.monotonic()
    try:
        while args.duration <= 0 or (time.monotonic() - t0) < args.duration:
            res = _send(args.url, args.token, [_make_event(seq)])
            seq += 1
            elapsed = time.monotonic() - t0
            print(f"[{elapsed:6.1f}с] отправлено {seq}, queued={res.get('queued') if res else '?'}")
            if seq % status_every == 0:
                _print_queue_status(args.url)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nостановлено пользователем")
    print(f"итого отправлено {seq} событий за {time.monotonic() - t0:.1f}с")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=DEFAULT_URL, help=f"базовый URL сервиса (default: {DEFAULT_URL})")
    parser.add_argument(
        "--token", default=os.environ.get("SIEM_INGEST_TOKEN"),
        help="токен зарегистрированного источника (или переменная окружения SIEM_INGEST_TOKEN)",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    p_burst = sub.add_parser("burst", help="отправить N событий разом, порциями - проверка size-trigger флаша")
    p_burst.add_argument("--count", type=int, default=1200, help="сколько событий отправить всего (default: 1200)")
    p_burst.add_argument("--chunk", type=int, default=100, help="сколько событий в одном HTTP-запросе (default: 100)")
    p_burst.add_argument("--source", default="fake-burst", help="имя созданного источника - только для подписи в выводе")
    p_burst.set_defaults(func=cmd_burst)

    p_drip = sub.add_parser("drip", help="слать события медленно и долго - проверка time-trigger флаша")
    p_drip.add_argument("--rate", type=float, default=2.0, help="событий в секунду (default: 2.0)")
    p_drip.add_argument("--duration", type=float, default=30.0, help="сколько секунд слать, 0 = бесконечно (default: 30)")
    p_drip.add_argument("--source", default="fake-drip", help="имя созданного источника - только для подписи в выводе")
    p_drip.set_defaults(func=cmd_drip)

    args = parser.parse_args()
    if not args.token:
        parser.error("нужен --token (или переменная окружения SIEM_INGEST_TOKEN): "
                     "создайте источник во вкладке «Источник данных» и возьмите его токен")
    args.func(args)


if __name__ == "__main__":
    main()
