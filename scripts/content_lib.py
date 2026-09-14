"""
Общие помощники для scripts/deploy_content.py и scripts/test_content.py - детект-контент из
artifacts/content (git - источник правды) против живого SIEM через его обычный HTTP API.

Раскладка контента:
    artifacts/content/
      value_lists/<name>.yml             # {name, description, values}
      <domain>/rules/*.yml               # по одному базовому Sigma-правилу на файл
      <domain>/correlations/*.yml        # корреляции (агрегаторы, промежуточные звенья, SCE_)
      <domain>/tests/*.yml               # фикстуры для test_content.py
      telemetry/                         # конфиг Sysmon и схема полей стенда, в SIEM не грузятся

Имя каталога домена = имя custom-рулсета в SIEM. Только stdlib (+PyYAML, уже зависимость проекта).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
CONTENT_DIR = BASE_DIR / "artifacts" / "content"
NON_DOMAIN_DIRS = {"value_lists", "telemetry"}


class ApiError(Exception):
    def __init__(self, status: int, detail: Any, method: str, path: str):
        super().__init__(f"{method} {path} -> HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class Api:
    def __init__(self, url: str, timeout: float = 120.0):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None,
        body: Any = None, raw: bytes | None = None, headers: dict[str, str] | None = None,
    ) -> Any:
        if params:
            path = f"{path}?{urllib.parse.urlencode(params)}"
        data = raw
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(text).get("detail", text)
            except (json.JSONDecodeError, AttributeError):
                detail = text
            raise ApiError(exc.code, detail, method, path) from None
        return json.loads(text) if text else None

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params or None)


@dataclass
class ContentRule:
    domain: str
    path: Path
    kind: str  # "base" | "correlation"
    text: str
    doc: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.doc["id"])

    @property
    def title(self) -> str:
        return str(self.doc["title"])

    @property
    def refs(self) -> list[str]:
        corr = self.doc.get("correlation") or {}
        return [str(r) for r in corr.get("rules") or []]


@dataclass
class Content:
    value_lists: list[dict[str, Any]] = field(default_factory=list)
    rules: list[ContentRule] = field(default_factory=list)

    @property
    def domains(self) -> list[str]:
        return sorted({r.domain for r in self.rules})


def domain_dirs(content_dir: Path = CONTENT_DIR) -> list[Path]:
    return sorted(
        p for p in content_dir.iterdir()
        if p.is_dir() and p.name not in NON_DOMAIN_DIRS and not p.name.startswith((".", "_"))
    )


def load_content(content_dir: Path = CONTENT_DIR, domains: set[str] | None = None) -> Content:
    content = Content()
    lists_dir = content_dir / "value_lists"
    if lists_dir.is_dir():
        for p in sorted(lists_dir.glob("*.yml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or not doc.get("name"):
                raise ValueError(f"{p}: ожидается {{name, description, values}}")
            # Сервер обрезает пробелы по краям значений (app/rules/value_lists.py) - у Sigma-значений
            # вроде ' -nop ' или 'cmd ' пробел значим, после обрезки правило молча расширится.
            spaced = [v for v in doc.get("values") or [] if isinstance(v, str) and v != v.strip()]
            if spaced:
                raise ValueError(f"{p}: значения с пробелами по краям нельзя выносить в список, оставь inline: {spaced}")
            content.value_lists.append(doc)
    for ddir in domain_dirs(content_dir):
        if domains and ddir.name not in domains:
            continue
        for sub, kind in (("rules", "base"), ("correlations", "correlation")):
            for p in sorted((ddir / sub).glob("*.yml")):
                text = p.read_text(encoding="utf-8")
                doc = yaml.safe_load(text)
                if not isinstance(doc, dict) or not doc.get("id") or not doc.get("title"):
                    raise ValueError(f"{p}: у правила обязательны title и id")
                if (kind == "correlation") != isinstance(doc.get("correlation"), dict):
                    raise ValueError(f"{p}: в каталоге {sub}/ лежит правило не того типа")
                content.rules.append(ContentRule(ddir.name, p, kind, text, doc))
    return content


def topo_correlations(rules: list[ContentRule]) -> list[ContentRule]:
    """Корреляции в порядке «зависимость раньше зависящего» - сервер проверяет ссылки
    correlation.rules на сохранении, ссылка на ещё не загруженную корреляцию дала бы 400."""
    corrs = [r for r in rules if r.kind == "correlation"]
    by_key: dict[str, ContentRule] = {}
    for r in corrs:
        by_key[r.id] = r
        if r.doc.get("name"):
            by_key[str(r.doc["name"])] = r
    ordered: list[ContentRule] = []
    state: dict[str, int] = {}

    def visit(r: ContentRule) -> None:
        mark = state.get(r.id)
        if mark == 2:
            return
        if mark == 1:
            raise ValueError(f"цикл ссылок correlation.rules через {r.path}")
        state[r.id] = 1
        for ref in r.refs:
            dep = by_key.get(ref)
            if dep is not None:
                visit(dep)
        state[r.id] = 2
        ordered.append(r)

    for r in corrs:
        visit(r)
    return ordered


def custom_rulesets_by_name(api: Api) -> dict[str, str]:
    """{имя рулсета: ruleset_path} для custom-рулсетов. Имя домена обязано быть уникальным."""
    out: dict[str, str] = {}
    for entry in api.get("/rulesets"):
        if entry.get("category") != "custom":
            continue
        name = entry.get("name")
        if name in out:
            raise ValueError(f"в SIEM несколько custom-рулсетов с именем '{name}' - переименуй лишний")
        out[name] = entry["path"]
    return out


def ruleset_rule_ids(api: Api, ruleset_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = api.get("/rulesets/rules", ruleset=ruleset_path, limit=500, offset=offset)
        for r in page["rules"]:
            out[str(r.get("id"))] = r
        offset += len(page["rules"])
        if not page["rules"] or offset >= page["total"]:
            return out
