r"""
Тестовые события для проверки вкладки "Sigma-правила" (см. README/CLAUDE.md, форма "Написать
своё правило" в app/static/index.html) - шлёт готовый набор событий через POST /ingest/file
с ruleset=custom_rulesets/my_rules, чтобы прогнать их именно против СВОИХ правил (не против
дефолтного rules_windows_merged.json - у /ingest/stream и /ingest/events такого выбора нет,
только /ingest/file и /ingest/upload принимают ruleset, см. app/models.py:IngestFileRequest).

Как пользоваться:
    1. Открой вкладку "Sigma-правила" -> "+ Написать своё правило" -> вставь YAML ниже целиком
       -> "Скомпилировать и сохранить".
    2. Запусти этот скрипт: python scripts/send_rule_test_events.py
    3. Проверь вкладку "Алерты" (source_batch=rule-test) - должно появиться 3 алерта на
       "Suspicious Encoded PowerShell Command"; во вкладке "События" остальные 3 события того же
       батча останутся без срабатывания - специально подобраны похожими, но НЕ подходящими под
       условие (это и есть тест на отсутствие ложных срабатываний, не только на детект).

Тестовое правило (Sigma YAML, вставить в UI как есть):

```yaml
title: Suspicious Encoded PowerShell Command
id: 7c1e0f2a-4b3d-4a1a-9e2c-6f5a8d3b1c00
status: experimental
description: Detects PowerShell execution with a base64-encoded command (-enc/-EncodedCommand) - a common technique to obfuscate malicious payloads.
author: soc_agent test
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_cli:
    CommandLine|contains:
      - "-enc"
      - "-EncodedCommand"
  condition: selection_img and selection_cli
level: high
falsepositives:
  - Legitimate scripts using encoded commands for compatibility
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

Условие правила: Image заканчивается на "\powershell.exe" И CommandLine содержит "-enc" ИЛИ
"-EncodedCommand" - оба селектора обязательны (and), поэтому в контрольных событиях ниже
намеренно ломается ровно один из двух признаков за раз.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

DEFAULT_URL = "http://localhost:8000"
RULESET_PATH = "custom_rulesets/my_rules"
SOURCE_LABEL = "rule-test"

BASE_DIR = Path(__file__).resolve().parent.parent
EVENTS_FILE = BASE_DIR / "uploads" / "rule_test_events.jsonl"

_ENCODED_PAYLOAD = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


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
        # Оба признака есть (Image = powershell.exe И CommandLine содержит -enc/-EncodedCommand) -
        # должны дать 3 алерта на "Suspicious Encoded PowerShell Command".
        _event("WORKSTATION1.theshire.local", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               f"powershell.exe -nop -w hidden -enc {_ENCODED_PAYLOAD}"),
        _event("WORKSTATION2.theshire.local", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               f"powershell -EncodedCommand {_ENCODED_PAYLOAD}"),
        _event("MORDORDC.theshire.local", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
               f"\"powershell.exe\" -ep bypass -enc {_ENCODED_PAYLOAD}"),
    ]
    non_matching = [
        # Тот же хост/процесс, но БЕЗ -enc/-EncodedCommand в командной строке - selection_cli
        # не выполняется, событие не должно попасть в алерты.
        _event("WORKSTATION1.theshire.local", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "powershell.exe -File C:\\scripts\\backup.ps1"),
        # Похожий CommandLine ("-enc" есть), но Image - НЕ powershell.exe - selection_img не
        # выполняется (реалистичный false positive trap: имитация powershell из другого бинаря).
        _event("WORKSTATION3.theshire.local", "C:\\Windows\\System32\\notepad.exe",
               f"notepad.exe --enc {_ENCODED_PAYLOAD}"),
        # Полностью не по теме - контрольное "шумовое" событие.
        _event("WORKSTATION2.theshire.local", "C:\\Windows\\System32\\whoami.exe", "whoami.exe /all", event_id=1),
    ]
    return matching + non_matching


def _post_json(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"Ошибка HTTP {exc.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Ошибка соединения: {exc.reason}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    events = build_events()

    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVENTS_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, default=str) + "\n")
    print(f"Записано {len(events)} событий в {EVENTS_FILE} (3 под правило + 3 контрольных)")

    source_label = f"{SOURCE_LABEL}-{uuid4().hex[:6]}"
    res = _post_json(f"{url}/ingest/file", {
        "events_path": str(EVENTS_FILE),
        "input_type": "json",
        "ruleset": RULESET_PATH,
        "source_label": source_label,
    })
    print(f"source_batch={res['source_batch']}: событий {res['events_processed']}, "
          f"правил сработало {res['rules_matched']}, алертов создано {res['alerts_created']}, "
          f"{res['duration_seconds']}с")
    if res["rules_matched"] == 0:
        print(
            "\nПравил не сработало - похоже, правило ещё не добавлено в custom_rulesets/my_rules.\n"
            "Сначала вставь YAML из докстринга этого файла во вкладке Sigma-правила -> "
            "'+ Написать своё правило' -> 'Скомпилировать и сохранить', потом перезапусти скрипт."
        )
    else:
        print(f"\nПроверь вкладку Алерты/События с источником '{source_label}'.")


if __name__ == "__main__":
    main()
