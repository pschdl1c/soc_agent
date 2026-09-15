r"""
Деплой детект-контента из artifacts/content (git - источник правды) в SIEM через его HTTP API.

Порядок (каждый шаг идемпотентен, повторный запуск ничего не ломает):
  1. value lists            - GET /value-lists/{name} -> POST (нет) или PUT (есть, отличается)
  2. базовые правила ВСЕХ   - POST /rules/custom (нет) или PUT /rules/custom/{id} (текст другой).
     доменов                  Рулсет домена создаётся первым POST (new_ruleset_name = имя каталога).
  3. корреляции             - в топологическом порядке (сервер проверяет ссылки на сохранении,
                              межрулсетные ссылки разрешены - поэтому все базовые правила раньше)
  4. --prune                - удалить из рулсетов доменов правила, которых нет в git
                              (сначала корреляции, потом базовые; force - удаляется весь хвост),
                              затем value lists контента, которых нет в git (только имена с
                              префиксом, который носят списки в git - cred_, exec_, common_...;
                              списки с другими именами, заведённые руками в UI, не
                              трогаются; список, на который ещё ссылается правило, - 409, пропуск)
  5. main                   - включить рулсеты доменов в основной рулсет целиком (--no-main - нет)

Правило, переехавшее в другой домен (тот же id, другой рулсет), удаляется из старого рулсета и
создаётся в новом.

    uv run python scripts/deploy_content.py                       # всё, в http://localhost:8000
    uv run python scripts/deploy_content.py http://localhost:8001 --domain auth --prune

Без Python на хосте - обёртки scripts/deploy_content.ps1 / scripts/deploy_content.sh (тот же скрипт в
одноразовом контейнере из образа soc_agent).
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.error
from pathlib import Path

from content_lib import (
    CONTENT_DIR,
    Api,
    ApiError,
    ContentRule,
    custom_rulesets_by_name,
    load_content,
    ruleset_rule_ids,
    topo_correlations,
)


def _sync_value_lists(api: Api, lists: list[dict]) -> None:
    for vl in lists:
        name = vl["name"]
        body = {"description": vl.get("description", ""), "values": vl["values"]}
        try:
            current = api.get(f"/value-lists/{name}")
        except ApiError as exc:
            if exc.status != 404:
                raise
            api.request("POST", "/value-lists", body={"name": name, **body})
            print(f"  + список {name} ({len(vl['values'])})")
            continue
        if current.get("values") == vl["values"] and current.get("description", "") == body["description"]:
            continue
        res = api.request("PUT", f"/value-lists/{name}", body=body)
        errors = res.get("errors") or []
        print(f"  ~ список {name}: пересобрано правил {len(res.get('recompiled') or [])}, ошибок {len(errors)}")
        for e in errors:
            print(f"      ! {e}")


class Deployer:
    def __init__(self, api: Api):
        self.api = api
        self.rulesets = custom_rulesets_by_name(api)
        # id -> (ruleset_path, строка списка) по всем custom-рулсетам - для поиска переездов
        self.server_rules: dict[str, tuple[str, dict]] = {}
        for path in self.rulesets.values():
            for rid, row in ruleset_rule_ids(api, path).items():
                self.server_rules[rid] = (path, row)
        self.created = self.updated = self.unchanged = 0

    def upsert(self, rule: ContentRule) -> None:
        target = self.rulesets.get(rule.domain)
        existing = self.server_rules.get(rule.id)
        if existing and existing[0] != target:
            self.api.request("DELETE", f"/rules/custom/{rule.id}", params={"ruleset": existing[0], "force": "true"})
            print(f"  - {rule.title}: удалено из {existing[0]} (переезд в {rule.domain})")
            existing = None
        if existing:
            current = self.api.get("/rulesets/rule", ruleset=target, rule_id=rule.id)
            if (current.get("yaml_text") or "").strip() == rule.text.strip():
                self.unchanged += 1
                return
            self.api.request("PUT", f"/rules/custom/{rule.id}", params={"ruleset": target}, body={"yaml_text": rule.text})
            self.updated += 1
            print(f"  ~ {rule.domain}: {rule.title}")
            return
        body = {"yaml_text": rule.text}
        body.update({"ruleset": target} if target else {"new_ruleset_name": rule.domain})
        res = self.api.request("POST", "/rules/custom", body=body)
        if not target:
            self.rulesets[rule.domain] = res["ruleset_path"]
            print(f"  * рулсет {rule.domain} -> {res['ruleset_path']}")
        self.server_rules[rule.id] = (res["ruleset_path"], {"id": rule.id})
        self.created += 1
        print(f"  + {rule.domain}: {rule.title}")

    def prune(self, content_ids: set[str], domains: list[str]) -> None:
        stale: list[tuple[str, str, bool]] = []
        for domain in domains:
            path = self.rulesets.get(domain)
            if not path:
                continue
            for rid, row in ruleset_rule_ids(self.api, path).items():
                if rid not in content_ids:
                    stale.append((path, rid, bool(row.get("correlation"))))
        for path, rid, _is_corr in sorted(stale, key=lambda s: not s[2]):  # корреляции первыми
            self.api.request("DELETE", f"/rules/custom/{rid}", params={"ruleset": path, "force": "true"})
            print(f"  - {path}: {rid}")

    def prune_value_lists(self, content_names: set[str]) -> None:
        # Пространство имён контента - префиксы, которые реально носят списки в git (cred_, exec_, persist_,
        # common_...): имя домена с ними не совпадает (credaccess -> cred_).
        prefixes = tuple({n.split("_", 1)[0] + "_" for n in content_names})
        for vl in self.api.get("/value-lists"):
            name = vl["name"]
            if name in content_names or not name.startswith(prefixes):
                continue
            try:
                self.api.request("DELETE", f"/value-lists/{name}")
                print(f"  - список {name}")
            except ApiError as exc:
                if exc.status != 409:
                    raise
                print(f"  ! список {name} не удалён - на него ссылаются правила вне контента")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", nargs="?", default="http://localhost:8000")
    parser.add_argument("--content", type=Path, default=CONTENT_DIR)
    parser.add_argument("--domain", action="append", help="только эти домены (можно несколько раз)")
    parser.add_argument("--prune", action="store_true", help="удалить из рулсетов доменов правила, которых нет в git")
    parser.add_argument("--no-main", action="store_true", help="не включать рулсеты доменов в основной рулсет")
    args = parser.parse_args()

    api = Api(args.url)
    content = load_content(args.content, set(args.domain) if args.domain else None)
    t0 = time.monotonic()
    try:
        print(f"Value lists: {len(content.value_lists)}")
        _sync_value_lists(api, content.value_lists)
        dep = Deployer(api)
        base = [r for r in content.rules if r.kind == "base"]
        print(f"Базовые правила: {len(base)}")
        for rule in base:
            dep.upsert(rule)
        corrs = topo_correlations(content.rules)
        print(f"Корреляции: {len(corrs)}")
        for rule in corrs:
            dep.upsert(rule)
        if args.prune:
            print("Prune:")
            dep.prune({r.id for r in content.rules}, content.domains)
            if not args.domain:  # списки глобальные - чистим только при полном деплое
                dep.prune_value_lists({vl["name"] for vl in content.value_lists})
        if not args.no_main:
            for domain in content.domains:
                api.request("POST", "/main-ruleset/rulesets", body={"ruleset": dep.rulesets[domain], "include": True})
            print(f"В основном рулсете: {', '.join(content.domains)}")
    except ApiError as exc:
        print(f"\nОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"\nОШИБКА: SIEM {args.url} недоступен: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    print(
        f"\nГотово за {time.monotonic() - t0:.1f}с: создано {dep.created}, обновлено {dep.updated}, "
        f"без изменений {dep.unchanged}"
    )


if __name__ == "__main__":
    main()
