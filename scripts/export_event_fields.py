"""Выгружает реальный набор полей событий со стенда в artifacts/content/telemetry/event_fields.json.

Схема нужна scripts/test_content.py: синтетические события дополняются полями, которые реально
доставляет агент (Zircolite строит таблицу флаша из полей событий, и правило с полем, которого нет
ни в одном событии флаша, молча не срабатывает - см. CLAUDE.md §8).

Ключ - "Channel|EventID", значение - отсортированное объединение полей всех событий этого ключа.
Всегда присутствующие поля (Channel, EventID, Computer, TimeCreated) и служебные поля Zircolite
не пишутся.

Ключи, которых нет в новой выгрузке, остаются из старого файла: по умолчанию они переносятся
как есть, а с --rename-legacy системные поля Fluent Bit переименовываются в имена агента Vector
(ProcessID -> ExecutionProcessID, ThreadID -> ExecutionThreadID) и ключ попадает в
"_legacy_keys" - поля не подтверждены стендом.

    uv run python scripts/export_event_fields.py http://localhost:8000 --source win10-lab-vector --rename-legacy
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "artifacts" / "content" / "telemetry" / "event_fields.json"

# Есть у каждого события - в схему не пишем (как и в прежней выгрузке).
ALWAYS_PRESENT = {"Channel", "EventID", "Computer", "TimeCreated", "EventTime"}
# Добавляет сам SIEM/Zircolite, от агента не приходят.
SERVICE_FIELDS = {"row_id", "OriginalLogfile", "SocIngestSourceMarker"}
LEGACY_RENAMES = {"ProcessID": "ExecutionProcessID", "ThreadID": "ExecutionThreadID"}


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=60) as resp:
        return json.load(resp)


def collect(base: str, source: str) -> dict[str, set[str]]:
    fields: dict[str, set[str]] = {}
    offset, limit = 0, 500
    while True:
        page = _get(base, f"/events?source_batch={urllib.parse.quote(source)}&limit={limit}&offset={offset}")
        for ev in page["events"]:
            raw = _get(base, f"/events/{ev['event_id']}")["raw_json"]
            if isinstance(raw, str):
                raw = json.loads(raw)
            key = f"{raw.get('Channel')}|{raw.get('EventID')}"
            names = {k for k in raw if k not in ALWAYS_PRESENT and k not in SERVICE_FIELDS}
            fields.setdefault(key, set()).update(names)
        offset += limit
        if offset >= page["total"]:
            return fields


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", nargs="?", default="http://localhost:8000")
    parser.add_argument("--source", required=True, help="имя источника (source_batch) стенда")
    parser.add_argument("--rename-legacy", action="store_true",
                        help="переименовать системные поля Fluent Bit у ключей, не попавших в выгрузку")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    fresh = collect(args.url.rstrip("/"), args.source)
    old = {}
    if args.out.exists():
        old = {k: v for k, v in json.loads(args.out.read_text(encoding="utf-8")).items() if not k.startswith("_")}

    result: dict[str, list[str]] = {}
    legacy: list[str] = []
    for key, names in old.items():
        if key in fresh:
            continue
        if args.rename_legacy:
            names = [LEGACY_RENAMES.get(n, n) for n in names]
        result[key] = sorted(set(names))
        legacy.append(key)
    for key, names in fresh.items():
        result[key] = sorted(names)

    doc: dict = {
        "_comment": (
            f"Поля событий со стенда (источник '{args.source}', агент Vector, dist/vector.toml). "
            "Channel/EventID/Computer/TimeCreated есть всегда и не перечислены. Ключи из _legacy_keys "
            "стендом на Vector не подтверждены - перенесены из прежней выгрузки Fluent Bit"
            + (" с переименованием системных полей." if args.rename_legacy else ".")
        ),
        "_legacy_keys": sorted(legacy, key=_sort_key),
    }
    doc.update({k: result[k] for k in sorted(result, key=_sort_key)})
    args.out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(fresh)} ключей со стенда, {len(legacy)} перенесено из старого файла")


def _sort_key(key: str) -> tuple[str, int]:
    channel, _, event_id = key.partition("|")
    return (channel, int(event_id) if event_id.isdigit() else 0)


if __name__ == "__main__":
    main()
