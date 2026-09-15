r"""
Поиск правил в клоне SigmaHQ (https://github.com/SigmaHQ/sigma) - кандидаты на адаптацию
(scripts/content/adapt_sigma.py). Печатает id, level, title и путь; фильтры складываются по И.

    uv run python scripts/content/sigma_find.py --sigma-repo ..\sigma --eventid 4697
    uv run python scripts/content/sigma_find.py --q psexec --category process_creation --level high
    uv run python scripts/content/sigma_find.py --tag attack.t1003.001 --json > candidates.json

--eventid ищет по значениям EventID в detection (в т.ч. в списках). Без --include-deprecated каталоги
deprecated/ и unsupported/ пропускаются. Правило уже в контенте (related: derived на его id или тот же
id) помечается '*'.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parents[2]
CONTENT_DIR = BASE_DIR / "artifacts" / "content"
_SKIP_DIRS = {"deprecated", "unsupported", "tests", "regression_data", "documentation", ".github"}


def _event_ids(node: Any) -> set[int]:
    found: set[int] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).split("|")[0] == "EventID":
                for v in value if isinstance(value, list) else [value]:
                    if str(v).isdigit():
                        found.add(int(v))
            else:
                found |= _event_ids(value)
    elif isinstance(node, list):
        for item in node:
            found |= _event_ids(item)
    return found


def _adapted_ids() -> set[str]:
    ids: set[str] = set()
    for p in CONTENT_DIR.glob("*/rules/*.yml"):
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        ids.add(str(doc.get("id")))
        ids |= {str(r.get("id")) for r in doc.get("related") or [] if isinstance(r, dict)}
    return ids


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sigma-repo", type=Path, default=os.environ.get("SIGMA_REPO"))
    p.add_argument("--q", help="подстрока в title/description (без регистра)")
    p.add_argument("--eventid", type=int, action="append")
    p.add_argument("--category", help="logsource.category")
    p.add_argument("--service", help="logsource.service")
    p.add_argument("--tag", help="точный тег, например attack.t1059.001")
    p.add_argument("--level", action="append")
    p.add_argument("--include-deprecated", action="store_true")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    if not a.sigma_repo or not Path(a.sigma_repo).is_dir():
        sys.exit("укажи клон SigmaHQ: --sigma-repo или SIGMA_REPO")

    adapted = _adapted_ids()
    rows: list[dict[str, Any]] = []
    for path in sorted(Path(a.sigma_repo).rglob("*.yml")):
        rel = path.relative_to(a.sigma_repo)
        if not a.include_deprecated and _SKIP_DIRS & set(rel.parts):
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        logsource = doc.get("logsource") or {}
        text = f"{doc.get('title', '')} {doc.get('description', '')}".lower()
        if a.q and a.q.lower() not in text:
            continue
        if a.category and logsource.get("category") != a.category:
            continue
        if a.service and logsource.get("service") != a.service:
            continue
        if a.tag and a.tag not in (doc.get("tags") or []):
            continue
        if a.level and doc.get("level") not in a.level:
            continue
        ids = _event_ids(doc["detection"])
        if a.eventid and not ids & set(a.eventid):
            continue
        rows.append({
            "id": str(doc.get("id")), "level": doc.get("level"), "status": doc.get("status"),
            "title": doc.get("title"), "path": str(rel).replace("\\", "/"), "event_ids": sorted(ids),
            "adapted": str(doc.get("id")) in adapted,
        })

    if a.json:
        json.dump(rows, sys.stdout, ensure_ascii=False, indent=1)
        return
    for r in rows:
        print(f"{'*' if r['adapted'] else ' '} {r['id']}  {r['level']!s:13} {r['title']}\n      {r['path']}")
    print(f"\nНайдено: {len(rows)} (* - уже в контенте)")


if __name__ == "__main__":
    main()
