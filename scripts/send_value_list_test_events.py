r"""
Тест именованных списков значений (value lists, %name% + модификатор |expand — см.
app/rules/value_lists.py, вкладка «Списки»). Скрипт ТОЛЬКО шлёт события через POST /ingest/stream
(потоковый ingest → очередь → микробатч, app/ingest_queue.py), ничего не создаёт и не удаляет
на сервере — список и правило нужно завести самому в UI ДО запуска (шаги ниже).

Как пользоваться:
    1. Вкладка «Списки» → «+ Создать список»:
         имя:      recon_tools
         значения: по одному в строке (список ниже целиком)
       → «Сохранить».
    2. Вкладка «Sigma-правила» → «Редактор правил» → вставь YAML правила (ниже) целиком →
       укажи существующий свой рулсет ИЛИ создай новый → «Сохранить». Правило ссылается на
       список плейсхолдером %recon_tools% + |expand.
    3. Добавь это правило в «Основной рулсет»: найди его в списке правил того рулсета и нажми
       «+» в колонке слева от строки (у /ingest/stream нельзя выбрать ruleset — всегда main).
    3a. Вкладка «Источник данных» → «Создать источник» с именем value-list-test (или своим,
        тогда --source). Сохрани показанный токен — /ingest/stream без него отвечает 401.
    4. Запусти сервис:  uvicorn app.main:app --port 8000   (или docker compose up -d)
    5. python scripts/send_value_list_test_events.py --token <токен_источника>
       (SIEM_INGEST_TOKEN=<токен> в окружении тоже подойдёт; другой хост — первым позиционным
        аргументом: python scripts/send_value_list_test_events.py http://1.2.3.4:8000 --token ...)
    6. Скрипт напечатает source_batch и сработавшие правила. Ожидается 2 алерта
       «Linux Recon Tool Execution (value-list test)» (по хосту web / db, event_count=2 у
       каждого — 4 совпавших события из 7). 3 контрольных события — без алерта.
    7. Проверка «живого» списка: поменяй значения recon_tools во вкладке «Списки» и Сохрани —
       правило пересоберётся сразу (см. app/rules/value_lists.py), следующий прогон это отразит.

--------------------------------------------------------------------------------------------
ТЕСТОВЫЙ СПИСОК (вкладка «Списки» → «+ Создать список»):

    имя:      recon_tools
    описание: Linux-утилиты разведки (для теста |expand)
    значения:
      /whoami
      /id
      /hostname
      /uname
      /netstat
      /ss
      /nmap
      /ip
      /ifconfig
      /arp

ТЕСТОВОЕ ПРАВИЛО (Sigma YAML — вставить во вкладке «Sigma-правила» как есть):

```yaml
title: Linux Recon Tool Execution (value-list test)
id: 6d4e2f8a-1c3b-45a7-9e0d-2f1a8b7c6d50
status: experimental
description: >-
  Обнаруживает запуск распространённых Linux-утилит разведки. Перечень бинарников вынесен
  в именованный список %recon_tools% (вкладка «Списки») и подставляется модификатором
  |expand при компиляции — само правило перечень не содержит.
author: soc_agent test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith|expand:
      - '%recon_tools%'
  condition: selection
falsepositives:
  - Администраторы, диагностирующие систему
level: medium
tags:
  - attack.discovery
  - attack.t1082
  - attack.t1016
  - attack.t1049
```

Условие после раскрытия плейсхолдера:
    Image LIKE '%/whoami' OR Image LIKE '%/id' OR ... OR Image LIKE '%/arp'
Контрольные события ниже намеренно ломают этот единственный признак (утилита не из списка /
суффикс «whoami» есть, но не после «/»).
--------------------------------------------------------------------------------------------
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
from datetime import datetime, timezone
from uuid import uuid4

DEFAULT_URL = "http://localhost:8000"
SOURCE_LABEL = "value-list-test"
RULE_TITLE = "Linux Recon Tool Execution (value-list test)"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _event(host: str, image: str, command_line: str) -> dict:
    return {
        "EventID": 1,
        "EventTime": _now(),
        "Hostname": host,
        "Image": image,
        "CommandLine": command_line,
        "ProcessId": 1000 + hash(command_line) % 8000,
    }


def build_events(run: str) -> list[dict]:
    """run — короткий суффикс запуска, вшивается в имена хостов: дедуп алертов идёт по
    (rule_id, host, entity) (см. app/detection/normalize.py), поэтому без суффикса повторный запуск
    инкрементил бы event_count у СТАРОГО алерта (он остаётся в source_batch первого запуска),
    и новый source_batch выглядел бы пустым — см. CLAUDE.md §8."""
    web, db, other = f"web-01-{run}.corp.local", f"db-02-{run}.corp.local", f"web-03-{run}.corp.local"
    matching = [
        # Image заканчивается на путь из списка recon_tools. Разбиваются на 2 алерта по хосту
        # (web / db), event_count=2 у каждого — см. normalize.py (алерт на (host, source)).
        _event(web, "/usr/bin/whoami", "whoami"),
        _event(web, "/usr/bin/netstat", "netstat -tulpn"),
        _event(db, "/usr/sbin/ss", "ss -tlpn"),
        _event(db, "/usr/bin/nmap", "nmap -sS 10.0.0.0/24"),
    ]
    non_matching = [
        # Утилита не из списка.
        _event(web, "/usr/bin/cat", "cat /etc/passwd"),
        _event(db, "/usr/bin/vim", "vim /root/notes.txt"),
        # Суффикс "whoami" есть, но не после "/" -> endswith '/whoami' НЕ совпадает.
        _event(other, "/opt/tools/fake-whoami", "fake-whoami --spoof"),
    ]
    return matching + non_matching


def _post_stream(url: str, token: str, events: list[dict]) -> dict | None:
    """Метку источника задаёт сам сервис по токену (?source= больше не используется)."""
    body = "\n".join(json.dumps(e, default=str) for e in events).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/ingest/stream",
        data=body, method="POST",
        headers={"Content-Type": "application/x-ndjson", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"Ошибка HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Ошибка соединения ({url}): {exc.reason}", file=sys.stderr)
        sys.exit(1)


def _get_json(url: str) -> dict | list:
    with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _wait_for_flush(url: str, timeout: float = 15.0) -> None:
    print("Жду флаша очереди ingest...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            q = _get_json(f"{url}/health?detailed=true")["checks"]["ingest_queue"]  # type: ignore[call-overload,index]
            print(f"  queue_size={q['queue_size']} worker_alive={q['worker_alive']}")
            if q["queue_size"] == 0:
                time.sleep(0.5)
                return
        except Exception as exc:  # noqa: BLE001 — диагностика не должна ронять скрипт
            print(f"  не удалось получить статус очереди: {exc}")
        time.sleep(1.0)
    print("  таймаут ожидания флаша — проверяю алерты как есть")


def _poll_alerts(url: str, source_batch: str, run: str, timeout: float = 30.0) -> list[dict]:
    """source_batch теперь общий для всех прогонов источника - фильтруем по суффиксу run в
    имени хоста (он вшит в хосты событий, см. build_events), чтобы не подхватить stale-алерты
    прошлых прогонов."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        alerts = _get_json(f"{url}/alerts?{urllib.parse.urlencode({'source_batch': source_batch})}")
        mine = [a for a in alerts if run in (a.get("host") or "")]
        if mine:
            return mine  # type: ignore[return-value]
        time.sleep(1.5)
    return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Тест value lists через /ingest/stream")
    parser.add_argument("url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--token", default=os.environ.get("SIEM_INGEST_TOKEN"),
                        help="токен зарегистрированного источника (или переменная SIEM_INGEST_TOKEN)")
    parser.add_argument("--source", default=SOURCE_LABEL,
                        help=f"имя источника, созданного в UI (default: {SOURCE_LABEL})")
    args = parser.parse_args()
    if not args.token:
        parser.error("нужен --token (или SIEM_INGEST_TOKEN): создайте источник во вкладке «Источник данных»")
    url, source = args.url, args.source
    run = uuid4().hex[:6]
    events = build_events(run)

    print(f"Отправляю {len(events)} событий в /ingest/stream (source={source!r}) -> {url}")
    res = _post_stream(url, args.token, events)
    print(f"202 Accepted: queued={res.get('queued') if res else '?'}")

    _wait_for_flush(url)
    alerts = _poll_alerts(url, source, run)
    if not alerts:
        print(
            "\nАлертов не появилось. Проверь, что ДО запуска ты:\n"
            "  1) создал список 'recon_tools' во вкладке «Списки»;\n"
            "  2) сохранил правило из докстринга этого файла во вкладке «Sigma-правила»;\n"
            "  3) добавил это правило в «Основной рулсет» («+» в колонке слева от строки);\n"
            f"  4) создал источник {source!r} в UI, --token соответствует ему и он включён;\n"
            "  и что сервис запущен, а /ingest/stream доступен."
        )
        sys.exit(1)

    print(f"\nПолучено алертов: {len(alerts)} (source_batch={source})")
    for a in alerts:
        print(f"  - [{a.get('rule_level', '?')}] {a.get('rule_title', '?')} "
              f"host={a.get('host', '?')} event_count={a.get('event_count', '?')}")
    print(f"\nОжидалось: правило «{RULE_TITLE}», 2 алерта (web / db) по event_count=2, "
          f"3 контрольных события — без алерта.")


if __name__ == "__main__":
    main()
