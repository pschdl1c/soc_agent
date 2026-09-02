"""
Сборщик базы знаний MITRE ATT&CK (Enterprise) в компактный SQLite-файл `kb.db`.

Запускается ОДИН РАЗ на этапе `docker build` (см. Dockerfile, builder-стадия) и вручную для
локальной разработки:

    python scripts/build_kb.py --out kb/kb.db --attack-version 15.1
    python scripts/build_kb.py --out kb/kb.db --from-file enterprise-attack.json   # офлайн

Результат (`kb.db`) вшивается в образ read-only и НЕ монтируется как volume - обновление базы
знаний = пересборка образа. Приложение открывает файл только на чтение через `app/kb.py`.

Зависимости: только стандартная библиотека + `requests` (уже в зависимостях проекта). Библиотека
`stix2` НЕ используется намеренно - нам нужно несколько типов объектов из бандла, обычный проход
по `bundle["objects"]` быстрее и без лишней зависимости. Модуль не импортирует `app.*` - его
COPY'ят в builder-стадию до того, как в образ попадает код приложения.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_REF = "master"
DEFAULT_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ref}/enterprise-attack/{filename}"
)

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
_MITIGATION_ID_RE = re.compile(r"^M\d{4}$")


@dataclass
class ParsedKb:
    """Плоское представление нужных нам кусков ATT&CK - ровно то, что уедет в таблицы kb.db."""

    meta: dict[str, str] = field(default_factory=dict)
    tactics: list[dict] = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    technique_tactic: list[tuple[str, str]] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    technique_mitigation: list[tuple[str, str]] = field(default_factory=list)


# --------------------------------------------------------------------------- fetch


def _resolve_url(source: str | None, ref: str, attack_version: str | None) -> str:
    if source:
        return source
    filename = f"enterprise-attack-{attack_version}.json" if attack_version else "enterprise-attack.json"
    return DEFAULT_URL_TEMPLATE.format(ref=ref, filename=filename)


def fetch_bundle(url: str) -> dict:
    """Скачивает STIX-бандл. requests импортируется здесь, чтобы модуль оставался
    импортируемым в тестах без установленного requests (тесты зовут только parse_bundle/write_kb_db)."""
    import requests  # noqa: PLC0415

    resp = requests.get(url, timeout=180)
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- parse


def _mitre_ref(obj: dict) -> tuple[str, str]:
    """(external_id, url) из первой ссылки source_name == 'mitre-attack'. ('', '') если нет."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""


def _is_dead(obj: dict) -> bool:
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


def parse_bundle(objects: list[dict]) -> ParsedKb:
    """STIX-объекты бандла -> ParsedKb. Отброшены revoked/deprecated и всё, что вне
    Enterprise-таксономии (id не матчит T####/TA####/M####)."""
    kb = ParsedKb()

    # STIX-id -> ATT&CK external_id, чтобы разрешить target_ref/source_ref в relationship'ах.
    stixid_to_technique: dict[str, str] = {}
    stixid_to_mitigation: dict[str, str] = {}
    # STIX-id тактики -> shortname (для порядка колонок матрицы из x-mitre-matrix).
    tacticstixid_to_shortname: dict[str, str] = {}
    matrix_order: list[str] = []

    collection_version = ""

    for obj in objects:
        otype = obj.get("type")

        if otype == "x-mitre-collection":
            collection_version = obj.get("x_mitre_version", "") or collection_version

        elif otype == "x-mitre-matrix":
            matrix_order = list(obj.get("tactic_refs", []))

        elif otype == "x-mitre-tactic":
            if _is_dead(obj):
                continue
            ext_id, url = _mitre_ref(obj)
            shortname = obj.get("x_mitre_shortname", "")
            if not (_TACTIC_ID_RE.match(ext_id) and shortname):
                continue
            tacticstixid_to_shortname[obj.get("id", "")] = shortname
            kb.tactics.append(
                {
                    "tactic_id": ext_id,
                    "shortname": shortname,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": url,
                    "sort_order": 999,  # проставим ниже из matrix_order
                }
            )

        elif otype == "attack-pattern":
            if _is_dead(obj):
                continue
            ext_id, url = _mitre_ref(obj)
            if not _TECHNIQUE_ID_RE.match(ext_id):
                continue
            stixid_to_technique[obj.get("id", "")] = ext_id
            is_sub = bool(obj.get("x_mitre_is_subtechnique"))
            kb.techniques.append(
                {
                    "technique_id": ext_id,
                    "name": obj.get("name", ""),
                    "is_subtechnique": 1 if is_sub else 0,
                    "parent_id": ext_id.split(".")[0] if "." in ext_id else None,
                    "description": obj.get("description", "") or "",
                    "detection": obj.get("x_mitre_detection", "") or "",
                    "platforms": list(obj.get("x_mitre_platforms", []) or []),
                    "data_sources": list(obj.get("x_mitre_data_sources", []) or []),
                    "url": url,
                }
            )
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
                    kb.technique_tactic.append((ext_id, phase["phase_name"]))

        elif otype == "course-of-action":
            if _is_dead(obj):
                continue
            ext_id, url = _mitre_ref(obj)
            if not _MITIGATION_ID_RE.match(ext_id):
                continue
            stixid_to_mitigation[obj.get("id", "")] = ext_id
            kb.mitigations.append(
                {
                    "mitigation_id": ext_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": url,
                }
            )

    # relationship'и разрешаем вторым проходом - к этому моменту карты id заполнены целиком.
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        mit = stixid_to_mitigation.get(obj.get("source_ref", ""))
        tech = stixid_to_technique.get(obj.get("target_ref", ""))
        if mit and tech:
            kb.technique_mitigation.append((tech, mit))

    # Порядок колонок матрицы: индекс тактики в x-mitre-matrix.tactic_refs.
    order_by_shortname = {
        tacticstixid_to_shortname[sid]: i
        for i, sid in enumerate(matrix_order)
        if sid in tacticstixid_to_shortname
    }
    for tactic in kb.tactics:
        tactic["sort_order"] = order_by_shortname.get(tactic["shortname"], 999)
    kb.tactics.sort(key=lambda t: (t["sort_order"], t["tactic_id"]))

    # дедуп связей
    kb.technique_tactic = sorted(set(kb.technique_tactic))
    kb.technique_mitigation = sorted(set(kb.technique_mitigation))

    kb.meta = {
        "attack_version": collection_version or "unknown",
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tactic_count": str(len(kb.tactics)),
        "technique_count": str(len(kb.techniques)),
        "mitigation_count": str(len(kb.mitigations)),
    }
    return kb


# --------------------------------------------------------------------------- write

_SCHEMA = """
CREATE TABLE mitre_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE mitre_tactic (
    tactic_id   TEXT PRIMARY KEY,
    shortname   TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    sort_order  INTEGER NOT NULL
);

CREATE TABLE mitre_technique (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    description     TEXT NOT NULL DEFAULT '',
    detection       TEXT NOT NULL DEFAULT '',
    platforms       TEXT NOT NULL DEFAULT '[]',
    data_sources    TEXT NOT NULL DEFAULT '[]',
    url             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_mitre_tech_parent ON mitre_technique(parent_id);

CREATE TABLE mitre_technique_tactic (
    technique_id     TEXT NOT NULL,
    tactic_shortname TEXT NOT NULL,
    PRIMARY KEY (technique_id, tactic_shortname)
);
CREATE INDEX idx_mitre_tt_tactic ON mitre_technique_tactic(tactic_shortname);

CREATE TABLE mitre_mitigation (
    mitigation_id TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE mitre_technique_mitigation (
    technique_id  TEXT NOT NULL,
    mitigation_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, mitigation_id)
);
"""


def write_kb_db(path: str, kb: ParsedKb) -> None:
    """Создаёт kb.db с нуля: пишем во временный файл рядом и атомарно подменяем."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    if os.path.exists(tmp):
        os.remove(tmp)

    conn = sqlite3.connect(tmp)
    try:
        conn.executescript(_SCHEMA)
        conn.executemany(
            "INSERT INTO mitre_meta(key, value) VALUES (?, ?)",
            list(kb.meta.items()),
        )
        conn.executemany(
            "INSERT INTO mitre_tactic(tactic_id, shortname, name, description, url, sort_order) "
            "VALUES (:tactic_id, :shortname, :name, :description, :url, :sort_order)",
            kb.tactics,
        )
        conn.executemany(
            "INSERT INTO mitre_technique(technique_id, name, is_subtechnique, parent_id, description, "
            "detection, platforms, data_sources, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    t["technique_id"],
                    t["name"],
                    t["is_subtechnique"],
                    t["parent_id"],
                    t["description"],
                    t["detection"],
                    json.dumps(t["platforms"], ensure_ascii=False),
                    json.dumps(t["data_sources"], ensure_ascii=False),
                    t["url"],
                )
                for t in kb.techniques
            ],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO mitre_technique_tactic(technique_id, tactic_shortname) VALUES (?, ?)",
            kb.technique_tactic,
        )
        conn.executemany(
            "INSERT INTO mitre_mitigation(mitigation_id, name, description, url) "
            "VALUES (:mitigation_id, :name, :description, :url)",
            kb.mitigations,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO mitre_technique_mitigation(technique_id, mitigation_id) VALUES (?, ?)",
            kb.technique_mitigation,
        )
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()

    os.replace(tmp, path)


# --------------------------------------------------------------------------- cli


def _sanity_check(kb: ParsedKb) -> None:
    """Грубая проверка целостности выгрузки - лучше уронить `docker build`, чем вшить битую базу."""
    n_tactics = len(kb.tactics)
    n_techniques = len(kb.techniques)
    if not (12 <= n_tactics <= 16):
        raise SystemExit(f"build_kb: подозрительное число тактик ({n_tactics}), ожидалось 12..16")
    if n_techniques < 500:
        raise SystemExit(f"build_kb: подозрительно мало техник ({n_techniques}), ожидалось >500")
    if not kb.technique_tactic:
        raise SystemExit("build_kb: нет ни одной связи техника->тактика")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Собрать kb.db (MITRE ATT&CK Enterprise) из STIX-бандла")
    ap.add_argument("--out", default="kb/kb.db", help="путь к результирующему SQLite-файлу")
    ap.add_argument("--attack-version", default=None, help="версия ATT&CK, напр. 15.1 (иначе - latest)")
    ap.add_argument("--ref", default=DEFAULT_REF, help="git ref репозитория attack-stix-data")
    ap.add_argument("--source", default=None, help="полный URL STIX-бандла (перекрывает --ref/--attack-version)")
    ap.add_argument("--from-file", default=None, help="читать STIX-бандл из локального файла, без сети")
    args = ap.parse_args(argv)

    if args.from_file:
        print(f"build_kb: читаю {args.from_file}")
        with open(args.from_file, encoding="utf-8") as fh:
            bundle = json.load(fh)
    else:
        url = _resolve_url(args.source, args.ref, args.attack_version)
        print(f"build_kb: скачиваю {url}")
        bundle = fetch_bundle(url)

    kb = parse_bundle(bundle.get("objects", []))
    if args.attack_version:
        kb.meta["attack_version"] = args.attack_version
    kb.meta["source"] = args.from_file or _resolve_url(args.source, args.ref, args.attack_version)

    _sanity_check(kb)
    write_kb_db(args.out, kb)

    size_mb = os.path.getsize(args.out) / (1024 * 1024)
    print(
        f"build_kb: готово -> {args.out} ({size_mb:.1f} МБ) | "
        f"версия {kb.meta['attack_version']}, тактик {kb.meta['tactic_count']}, "
        f"техник {kb.meta['technique_count']}, митигаций {kb.meta['mitigation_count']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
