r"""
Адаптация правила SigmaHQ под этот SIEM (соглашения - CLAUDE.md §9): guard по Channel/EventID вместо
logsource-пайплайна, Provider_Name долой (агент шлёт ProviderName, роль сужения берёт guard), новый UUID,
related: derived на оригинал, авторство '<оригинал>, ET, Claude', перечисления - в value lists.

Источник - путь к YAML или id правила SigmaHQ (ищется в --sigma-repo / переменной SIGMA_REPO, клон
https://github.com/SigmaHQ/sigma). Результат - черновик: condition и фильтры проверь глазами, потом
фикстура + scripts/test_content.py.

    uv run python scripts/content/adapt_sigma.py d7a95147-145f-4678-b85d-d1ff4a3bb3f6 \
        artifacts/content/lateral/rules/cobaltstrike_service_install.yml \
        --name lateral_cobaltstrike_service_4697 --channel Security --eventid 4697

    --vl "selection.Image|endswith=exec_rmm_images:Описание"   вынести список значений ключа в value list
                                                               (блок[индекс].ключ - для списка словарей)
    --auto-vl 8        выносить автоматически перечисления от 8 значений (имя <name>_<поле>[N]; переименуй
                       в осмысленное перед коммитом - автоимена не держим)
    --drop filter_x    удалить блок detection
    --condition TEXT   свой condition (без guard - он добавляется сам)
    --keep-id UUID     перегенерация уже задеплоенного правила с тем же id

Только PyYAML (зависимость проекта). Значения с пробелами по краям в список не выносятся: сервер их
обрезает (см. scripts/content_lib.py).
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parents[2]
LISTS_DIR = BASE_DIR / "artifacts" / "content" / "value_lists"


class _Dumper(yaml.SafeDumper):
    """Блочные списки с отступом и многострочные строки через '|' - как у правил SigmaHQ."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _str_rep(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)


_Dumper.add_representer(str, _str_rep)


def _dump(doc: Any) -> str:
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=4096, indent=4)


def find_sigma_rule(ref: str, repo: Path | None) -> Path:
    path = Path(ref)
    if path.is_file():
        return path
    if repo is None:
        sys.exit(f"'{ref}' не файл; для поиска по id укажи --sigma-repo или SIGMA_REPO")
    pattern = re.compile(rf"^id:\s*{re.escape(ref)}\s*$", re.M)
    for p in repo.rglob("*.yml"):
        if pattern.search(p.read_text(encoding="utf-8", errors="replace")):
            return p
    sys.exit(f"правило с id {ref} не найдено в {repo}")


def _drop_provider_name(det: dict[str, Any]) -> None:
    for name, block in det.items():
        maps = block if isinstance(block, list) else [block]
        for m in maps:
            if isinstance(m, dict):
                for key in [k for k in m if k.split("|")[0] == "Provider_Name"]:
                    del m[key]
        if isinstance(block, dict) and not block:
            sys.exit(f"{name}: после удаления Provider_Name блок пуст - адаптируй вручную")


def _auto_value_lists(det: dict[str, Any], rule_name: str, min_values: int, title: str) -> list[str]:
    specs: list[str] = []
    for block_name, block in det.items():
        if block_name == "condition":
            continue
        maps = [(f"{block_name}[{i}]", m) for i, m in enumerate(block)] if isinstance(block, list) else [(block_name, block)]
        for path, m in maps:
            if not isinstance(m, dict):
                continue
            for key, values in m.items():
                if (isinstance(values, list) and len(values) >= min_values and "expand" not in key
                        and all(isinstance(v, str) and v == v.strip() for v in values)):
                    base = f"{rule_name}_{key.split('|')[0].lower()}"
                    list_name, n = base, 2
                    while any(s.split("=", 1)[1].split(":")[0] == list_name for s in specs):
                        list_name, n = f"{base}{n}", n + 1
                    specs.append(f"{path}.{key}={list_name}:{title} - {key}")
    return specs


def _extract_value_list(det: dict[str, Any], spec: str, lists_dir: Path) -> None:
    path, rest = spec.split("=", 1)
    list_name, _, description = rest.partition(":")
    block, key = path.split(".", 1)
    m = re.match(r"^(\w+)\[(\d+)\]$", block)
    target = det[m.group(1)][int(m.group(2))] if m else det[block]
    values = target.get(key)
    if not isinstance(values, list):
        sys.exit(f"{path}: не список значений")
    if any(isinstance(v, str) and v != v.strip() for v in values):
        sys.exit(f"{path}: значения с пробелами по краям в список не выносятся - оставь inline")
    items = list(target.items())
    target.clear()
    for k, v in items:  # порядок ключей блока сохраняется
        if k == key:
            target[f"{k}|expand"] = f"%{list_name}%"
        else:
            target[k] = v
    list_path = lists_dir / f"{list_name}.yml"
    str_values = [str(v) for v in values]
    if list_path.exists():
        existing = yaml.safe_load(list_path.read_text(encoding="utf-8"))
        if existing.get("values") != str_values:
            sys.exit(f"{list_path}: список уже есть с другим содержимым")
        return
    list_path.write_text(_dump({"name": list_name, "description": description, "values": str_values}), encoding="utf-8")
    print(f"  + value list {list_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("src", help="путь к правилу SigmaHQ или его id")
    p.add_argument("out", type=Path)
    p.add_argument("--sigma-repo", type=Path, default=os.environ.get("SIGMA_REPO"))
    p.add_argument("--name", required=True, help="Sigma name - ключ ссылок correlation.rules")
    p.add_argument("--channel", required=True)
    p.add_argument("--eventid", action="append", type=int, required=True)
    p.add_argument("--title")
    p.add_argument("--level")
    p.add_argument("--note", help="строка в конец description: что изменено при адаптации")
    p.add_argument("--vl", action="append", default=[])
    p.add_argument("--auto-vl", type=int, default=0)
    p.add_argument("--drop", action="append", default=[])
    p.add_argument("--condition")
    p.add_argument("--keep-id")
    p.add_argument("--lists-dir", type=Path, default=LISTS_DIR)
    a = p.parse_args()

    src = find_sigma_rule(a.src, a.sigma_repo)
    d = yaml.safe_load(src.read_text(encoding="utf-8"))
    det = d["detection"]
    for block in a.drop:
        det.pop(block)
    _drop_provider_name(det)
    for spec in a.vl + (_auto_value_lists(det, a.name, a.auto_vl, d["title"]) if a.auto_vl else []):
        _extract_value_list(det, spec, a.lists_dir)

    condition = a.condition or det.pop("condition")
    det.pop("condition", None)
    eventid: Any = a.eventid[0] if len(a.eventid) == 1 else a.eventid
    new_det = {"guard_logsource": {"Channel": a.channel, "EventID": eventid}, **det}
    new_det["condition"] = f"guard_logsource and ({condition})"

    description = str(d.get("description", "")).rstrip()
    if a.note:
        description = f"{description}\n{a.note}"
    today = dt.date.today().isoformat()
    out: dict[str, Any] = {
        "title": a.title or d["title"],
        "id": a.keep_id or str(uuid.uuid4()),
        "name": a.name,
        "related": [*(d.get("related") or []), {"id": d["id"], "type": "derived"}],
        "status": d.get("status", "test"),
        "description": description + ("\n" if "\n" in description else ""),
    }
    if d.get("references"):
        out["references"] = d["references"]
    out["author"] = f"{d.get('author', '')}, ET, Claude"
    out["date"] = str(d.get("date", today))
    out["modified"] = today
    for key in ("tags", "logsource"):
        if d.get(key):
            out[key] = d[key]
    out["detection"] = new_det
    if d.get("falsepositives"):
        out["falsepositives"] = d["falsepositives"]
    out["level"] = a.level or d.get("level")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(_dump(out), encoding="utf-8")
    print(f"{a.out}: {out['id']} (из {src})")


if __name__ == "__main__":
    main()
