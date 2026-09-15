r"""
Заготовка correlation-файла контента в стиле artifacts/content (соглашения - CLAUDE.md §9). Если файл уже
есть, его id сохраняется (перегенерация не рвёт ссылки и не плодит новое правило при деплое).

    # тихое звено / агрегатор (level informational, без incident)
    uv run python scripts/content/new_correlation.py lateral host_inbound_lateral_movement \
        --title "Host Inbound Lateral Movement" --name lateral_host_inbound --type event_count \
        --rule lateral_psexesvc_execution --rule lateral_impacket_psexec_service_4697 \
        --group-by Computer --timespan 1h --gte 1 --desc "Intermediate link for the killchain ruleset: ..."

    # сценарий (SCE_) - с инцидентом
    uv run python scripts/content/new_correlation.py auth sce_auth_account_bruteforce \
        --title SCE_Auth_Account_BruteForce --name sce_auth_account_bruteforce --type event_count \
        --rule auth_failed_logon_no_address --group-by Computer --group-by TargetUserName --timespan 5m \
        --gte 20 --incident auth_account_bruteforce:medium --level medium --tag attack.t1110.001 \
        --fp "Script running under a user whose password was changed" --desc "..."

value_count: --field TargetUserName --gte 5. temporal/temporal_ordered: без --gte (все ссылки) или
с --gte N. Описание - по-английски, одним абзацем (переносится по 96 символов).
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import textwrap
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
CONTENT_DIR = BASE_DIR / "artifacts" / "content"
_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain")
    p.add_argument("file", help="имя файла без .yml")
    p.add_argument("--title", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--type", required=True, choices=_TYPES)
    p.add_argument("--rule", action="append", required=True, help="ссылка correlation.rules (Sigma name)")
    p.add_argument("--group-by", action="append", required=True)
    p.add_argument("--timespan", required=True)
    p.add_argument("--gte", type=int)
    p.add_argument("--field", help="condition.field для value_count")
    p.add_argument("--incident", help="type:severity")
    p.add_argument("--level", default="informational")
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("--fp", action="append", default=[], help="falsepositives")
    p.add_argument("--desc", required=True)
    p.add_argument("--content", type=Path, default=CONTENT_DIR)
    a = p.parse_args()
    if a.type in ("event_count", "value_count") and a.gte is None:
        p.error(f"{a.type} требует --gte")
    if a.type == "value_count" and not a.field:
        p.error("value_count требует --field")
    if a.incident and ":" not in a.incident:
        p.error("--incident в виде type:severity")

    path = a.content / a.domain / "correlations" / f"{a.file}.yml"
    rule_id = str(uuid.uuid4())
    date = dt.date.today().isoformat()
    modified = None
    if path.exists():
        old = path.read_text(encoding="utf-8")
        if m := re.search(r"^id: (\S+)", old, re.M):
            rule_id = m.group(1)
        if m := re.search(r"^date: (\S+)", old, re.M):
            date, modified = m.group(1), dt.date.today().isoformat()

    lines = [f"title: {a.title}", f"id: {rule_id}", f"name: {a.name}", "status: experimental", "description: |"]
    lines += ["    " + ln for ln in textwrap.wrap(a.desc, 96)]
    lines += ["author: ET, Claude", f"date: {date}"] + ([f"modified: {modified}"] if modified else [])
    if a.tag:
        lines += ["tags:"] + [f"    - {t}" for t in a.tag]
    lines += ["correlation:", f"    type: {a.type}", "    rules:"] + [f"        - {r}" for r in a.rule]
    lines += ["    group-by:"] + [f"        - {g}" for g in a.group_by] + [f"    timespan: {a.timespan}"]
    if a.gte is not None:
        lines += ["    condition:"] + ([f"        field: {a.field}"] if a.field else []) + [f"        gte: {a.gte}"]
    if a.incident:
        itype, severity = a.incident.split(":", 1)
        lines += ["    incident:", f"        type: {itype}", f"        severity: {severity}"]
    if a.fp:
        lines += ["falsepositives:"] + [f"    - {f}" for f in a.fp]
    lines += [f"level: {a.level}"]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{path}: {rule_id}")


if __name__ == "__main__":
    main()
