"""
Каталог Sigma-рулсетов и правил для вкладки "Sigma-правила" в UI.

Две категории рулсетов:
  - builtin - Zircolite/rules/*.json (внешний git-клон, read-only, никогда не редактируем/не удаляем).
  - custom  - custom_rulesets/<ruleset_id>/ - именованные пользовательские рулсеты. Каждый -
              директория: meta.json (id/name/created_at), <rule_id>.yml на обычное правило
              (сырой Sigma YAML - source of truth), <rule_id>{CORRELATION_EXT} на
              correlation-правило (см. ниже, ПОЧЕМУ отдельное расширение) и .manifest.json -
              кэш скомпилированных метаданных ВСЕХ правил директории (тот же формат, что и
              Zircolite/rules/*.json), нужен только для быстрого просмотра списком, никогда не
              участвует в детекте напрямую.

Состав "основного рулсета" (main ruleset, ruleset_path == "main") - НЕ часть этого модуля,
см. app/rules/main_ruleset.py. Он лишь ссылается на рулсеты/правила, каталогизированные здесь
(через load_rules()), поэтому зависимость однонаправленная: main_ruleset.py -> rules_catalog.py.
Этот модуль ничего не знает о main_ruleset - "main" как ruleset_path сюда не пускаем.

Почему custom-рулсет хранится как ДИРЕКТОРИЯ .yml-файлов, а не как один JSON: RulesetHandler
(zircolite.rules.RulesetHandler.ruleset_parsing) для директории глобит только *.yml/*.yaml
(rules.rglob) - .json внутри директории игнорируются. Значит "custom_rulesets/<id>" как путь
уже РАБОТАЕТ как ruleset_path для /ingest/file и /ingest/upload без единой строчки
дополнительной интеграции - и одновременно .manifest.json (не .yml) в той же папке безопасен,
RulesetHandler его не увидит.

Просмотр рулсетов (browsing) НЕ требует pySigma вообще - built-in уже скомпилирован (обычный
json.load), custom читается из готового .manifest.json. Компиляция через RulesetHandler нужна
ТОЛЬКО при добавлении нового кастомного правила/рулсета (save_custom_rule/save_ruleset_yaml).

Sigma correlation-правила (type: event_count/value_count/temporal/temporal_ordered) хранятся
ИНАЧЕ, чем обычные - файлом `<rule_id>{CORRELATION_EXT}` (не `.yml`/`.yaml`!) в той же
директории рулсета. Причина - реальный баг в пинченном pysigma-backend-sqlite (проверено
эмпирически вплоть до последней опубликованной версии 1.2.4): правило, на которое ссылается
`correlation.rules:` (то есть присутствует В ОДНОМ SigmaCollection вместе с корреляцией,
ссылающейся на него), при компиляции этого правила ОТДЕЛЬНО backend возвращает сырую
SQL-строку вместо dict, что валит компиляцию pySigma-стороны совсем (`'str' object has no
attribute 'get'` в Zircolite при попытке отсортировать результат). Наш собственный
correlation-движок (app/detection/correlation.py) при этом вообще не использует SQL, который бы
сгенерировал pySigma для корреляции - ему нужны только структурные поля (type/group-by/
timespan/condition/rules) из raw YAML, которые он читает сам (load_correlation_rules ниже).
Поэтому решение простое и радикальное: correlation-правила физически НИКОГДА не попадают в
тот же RulesetHandler-вызов, что и правило, на которое они ссылаются - расширение файла не
`.yml`/`.yaml`, значит RulesetHandler (rglob("*.yml") + rglob("*.yaml")) их вообще не видит,
`resolve_rule_references()` внутри pySigma никогда не запускается на referenced-правиле, и
оно компилируется как совершенно обычное правило, под своим настоящим именем - никаких
"правил-двойников" в контенте заводить не нужно. compile_custom_rule/compile_ruleset_yaml
ниже сами решают (по наличию ключа `correlation:` в документе), в какую компиляцию отдать
документ - в RulesetHandler (обычные правила) или в собственную лёгкую валидацию без pySigma
(correlation-правила, см. _validate_correlation_doc/_compile_correlation_doc).
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import yaml

from app.rules import value_lists

# файл лежит в app/rules/, до корня проекта — три уровня вверх
BASE_DIR = Path(__file__).resolve().parent.parent.parent

ZIRCOLITE_REPO_PATH = BASE_DIR / "Zircolite"
if str(ZIRCOLITE_REPO_PATH) not in sys.path:
    sys.path.insert(0, str(ZIRCOLITE_REPO_PATH))

from zircolite.config import RulesetConfig  # noqa: E402
from zircolite.rules import RulesetHandler  # noqa: E402

BUILTIN_RULES_DIR = BASE_DIR / "Zircolite" / "rules"
# data/ - общий корень runtime-данных для локального запуска И Docker (см. app/config.py:
# UPLOADS_DIR, docker-compose.yml). BASE_DIR тут - корень проекта локально, /app в контейнере -
# в обоих случаях "data/custom_rulesets" резолвится в ОДИН и тот же физический путь на хосте
# (локально - напрямую, в Docker - через bind-mount ./data/custom_rulesets:/app/data/custom_rulesets),
# без отдельной env-переменной.
CUSTOM_ROOT = BASE_DIR / "data" / "custom_rulesets"

CUSTOM_ROOT.mkdir(parents=True, exist_ok=True)

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# Расширение файлов correlation-правил на диске - НЕ .yml/.yaml, чтобы RulesetHandler
# (Zircolite/pySigma) их вообще не видел при компиляции директории рулсета (см. докстринг
# модуля выше про причину). Содержимое файла при этом - обычный raw Sigma YAML (source of
# truth, как и у .yml-правил), просто с "невидимым" для детект-движка расширением.
CORRELATION_EXT = ".sigmacorr"

_CORR_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}


class CatalogError(Exception):
    """Проблема с рулсетом/правилом на уровне каталога (не найден, невалиден, недопустимый путь) - main.py транслирует в HTTP 400/404."""


class RuleValidationError(Exception):
    """Пользовательский Sigma YAML не прошёл валидацию/компиляцию - main.py транслирует в HTTP 400."""


# ------------------------------------------------------------------ Кэш чтения JSON-рулсетов

# Дорогой json.load() (rules_windows_merged.json - 112k строк / 4291 правило) выполняется один
# раз за время жизни файла - кэш по mtime, дальше просмотр рулсета - это stat() + попадание в
# память (микросекунды). Компиляция через pySigma тут вообще не участвует - только для custom.
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_manifest_lock = threading.Lock()


def _load_json_rules(path: Path) -> list[dict[str, Any]]:
    abs_path = str(path.resolve())
    try:
        mtime = path.stat().st_mtime
    except OSError as exc:
        raise CatalogError(f"Рулсет не найден: {path.name} ({exc})")
    with _cache_lock:
        cached = _cache.get(abs_path)
        if cached and cached[0] == mtime:
            return cached[1]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise CatalogError(f"Не удалось прочитать рулсет '{path.name}': {exc}")
    if not isinstance(data, list):
        raise CatalogError(f"Рулсет '{path.name}' должен быть JSON-массивом правил")
    with _cache_lock:
        _cache[abs_path] = (mtime, data)
    return data


def _invalidate_cache(path: Path) -> None:
    with _cache_lock:
        _cache.pop(str(path.resolve()), None)


def _load_manifest(manifest_path: Path) -> list[dict[str, Any]]:
    """Кэшированное чтение .manifest.json (тем же механизмом, что built-in)."""
    if not manifest_path.exists():
        return []
    return _load_json_rules(manifest_path)


def _load_manifest_uncached(manifest_path: Path) -> list[dict[str, Any]]:
    """Только для read-modify-write под _manifest_lock - не полагаемся на mtime-кэш при записи."""
    if not manifest_path.exists():
        return []
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _write_manifest(manifest_path: Path, rules: list[dict[str, Any]]) -> None:
    manifest_path.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
    _invalidate_cache(manifest_path)


# ------------------------------------------------------------------ Путь -> безопасный резолв

def _safe_resolve(ruleset_path: str) -> Path:
    """Резолвит путь builtin-рулсета и проверяет, что он не убегает за пределы Zircolite/rules/ -
    ruleset приходит как сырая строка в query-параметре, без этой проверки был бы path traversal
    (ruleset=../../../etc/passwd)."""
    path = (BASE_DIR / ruleset_path).resolve()
    root = BUILTIN_RULES_DIR.resolve()
    if not (path == root or path.is_relative_to(root)):
        raise CatalogError(f"Недопустимый путь рулсета: {ruleset_path}")
    return path


def _custom_ruleset_dir(ruleset_path: str) -> Path:
    """"custom_rulesets/<id>" -> резолвленный Path под CUSTOM_ROOT. Валидирует id и требует
    существующий meta.json (иначе это не (валидный) кастомный рулсет) - CatalogError иначе."""
    prefix = "custom_rulesets/"
    if not ruleset_path.startswith(prefix):
        raise CatalogError(f"Не кастомный рулсет: {ruleset_path}")
    ruleset_id = ruleset_path[len(prefix):]
    if not _SAFE_ID_RE.match(ruleset_id):
        raise CatalogError(f"Недопустимый id рулсета: {ruleset_path}")
    path = CUSTOM_ROOT / ruleset_id
    if not (path / "meta.json").is_file():
        raise CatalogError(f"Рулсет не найден: {ruleset_path}")
    return path


def _is_custom_ruleset(ruleset_path: str) -> bool:
    try:
        _custom_ruleset_dir(ruleset_path)
        return True
    except CatalogError:
        return False


def _find_rule_file(target_dir: Path, rule_id: str) -> Path | None:
    """Находит файл правила по id независимо от того, обычное это правило (`.yml`) или
    correlation (CORRELATION_EXT, см. докстринг модуля) - оба хранятся под одним и тем же
    rule_id, различается только расширение. Возвращает None, если правила с таким id нет ни
    в каком виде."""
    plain = target_dir / f"{rule_id}.yml"
    if plain.is_file():
        return plain
    corr = target_dir / f"{rule_id}{CORRELATION_EXT}"
    if corr.is_file():
        return corr
    return None


def load_rules(ruleset_path: str) -> list[dict[str, Any]]:
    """Список правил рулсета по пути/id - тот же 'ruleset', что уже принимают /ingest/*."""
    if _is_custom_ruleset(ruleset_path):
        manifest_path = _custom_ruleset_dir(ruleset_path) / ".manifest.json"
        return _load_manifest(manifest_path)
    path = _safe_resolve(ruleset_path)
    if not path.is_file():
        raise CatalogError(f"Рулсет не найден: {ruleset_path}")
    return _load_json_rules(path)


def paginate_rules(
    rules: list[dict[str, Any]],
    q: str | None,
    sort_by: str | None,
    sort_dir: str,
    limit: int,
    offset: int,
    only_ids: set[str] | None = None,
    in_main_fn: Callable[[str], bool] | None = None,
    level: list[str] | None = None,
    status: list[str] | None = None,
) -> dict[str, Any]:
    """Подстрока по title/description (регистронезависимо) + сортировка + пагинация над УЖЕ
    готовым списком правил - переиспользуется search_rules (по ruleset_path) и main.py напрямую
    для просмотра "Основного рулсета" (виртуальный список из main_ruleset.resolve_with_sources,
    не привязан к одному ruleset_path, поэтому не проходит через load_rules). level сортируется
    по рангу серьёзности (LEVEL_ORDER), не по алфавиту.

    level/status - фильтр по метадате правила (мультиселект в UI): непустой список значений,
    правило проходит, если его level/status (регистронезависимо) входит в список. None/пустой
    список - фильтр не применяется.

    only_ids/in_main_fn - точки интеграции с "основным рулсетом" (app/rules/main_ruleset.py),
    передаются СНАРУЖИ (main.py) предикатами/множеством id, а не импортом main_ruleset -
    этот модуль ничего не знает про main ruleset (см. докстринг модуля)."""
    if q:
        needle = q.strip().lower()
        rules = [
            r for r in rules
            if needle in str(r.get("title", "")).lower() or needle in str(r.get("description", "")).lower()
        ]
    if level:
        allowed = {v.lower() for v in level}
        rules = [r for r in rules if str(r.get("level", "")).lower() in allowed]
    if status:
        allowed = {v.lower() for v in status}
        rules = [r for r in rules if str(r.get("status", "")).lower() in allowed]
    if only_ids is not None:
        rules = [r for r in rules if r.get("id") in only_ids]
    reverse = (sort_dir or "asc").lower() == "desc"
    if sort_by == "level":
        rules = sorted(rules, key=lambda r: LEVEL_ORDER.get(r.get("level", "informational"), 99), reverse=reverse)
    elif sort_by in ("title", "author", "status"):
        rules = sorted(rules, key=lambda r: str(r.get(sort_by, "")).lower(), reverse=reverse)
    total = len(rules)
    page = rules[offset:offset + limit]
    if in_main_fn:
        page = [{**r, "in_main": in_main_fn(r.get("id"))} for r in page]
    return {"rules": page, "total": total, "limit": limit, "offset": offset}


def search_rules(
    ruleset_path: str,
    q: str | None,
    sort_by: str | None,
    sort_dir: str,
    limit: int,
    offset: int,
    only_ids: set[str] | None = None,
    in_main_fn: Callable[[str], bool] | None = None,
    level: list[str] | None = None,
    status: list[str] | None = None,
) -> dict[str, Any]:
    return paginate_rules(
        load_rules(ruleset_path), q, sort_by, sort_dir, limit, offset, only_ids, in_main_fn,
        level=level, status=status,
    )


def get_rule(ruleset_path: str, rule_id: str) -> dict[str, Any] | None:
    """Для custom-рулсета дополнительно подмешивает 'yaml_text' - исходный Sigma YAML (source
    of truth, custom_rulesets/<id>/<rule_id>.yml). У builtin-правил исходного YAML нет и никогда
    не было - хранится только уже скомпилированный SQL, поэтому поле не добавляется.
    Копируем dict перед мутацией - rule берётся из закэшированного списка (_load_manifest),
    писать в него напрямую нельзя, иначе yaml_text навсегда осядет в кэше и перестанет
    обновляться при правках файла на диске мимо приложения."""
    for rule in load_rules(ruleset_path):
        if rule.get("id") == rule_id:
            if _is_custom_ruleset(ruleset_path):
                rule = dict(rule)
                yaml_path = _find_rule_file(_custom_ruleset_dir(ruleset_path), rule_id)
                if yaml_path is not None:
                    rule["yaml_text"] = yaml_path.read_text(encoding="utf-8")
            return rule
    return None


def load_correlation_rules(ruleset_path: str) -> list[dict[str, Any]]:
    """Структурированные описания correlation-правил (Sigma type: event_count/value_count/
    temporal/temporal_ordered) одного custom-рулсета - для app/detection/correlation.py (свой движок
    поверх постоянной таблицы events/rule_hits, а не через pysigma-backend-sqlite - см.
    докстринг модуля про причину и CORRELATION_EXT). Builtin-рулсеты никогда не содержат
    correlation-правил (проверено на всех Zircolite/rules/*.json) - для них всегда [].

    Читает *{CORRELATION_EXT} рулсета напрямую (yaml.safe_load, без pySigma/RulesetHandler -
    тот же "дешёвый browsing"-принцип, что и у остального модуля) - нужны структурные поля
    Sigma YAML (type/group-by/timespan/condition/rules) как есть, не готовый SQL.

    correlation.rules ссылается на соседние правила по их Sigma 'name' (короткий идентификатор)
    ИЛИ 'id' (uuid) - оба формата валидны по спеке; индекс name/id -> title строится по ВСЕМ
    обычным *.yml/*.yaml рулсета (они теперь компилируются независимо от корреляции, см.
    CORRELATION_EXT - никаких "правил-двойников" не требуется, base_rule_titles указывает
    прямо на настоящий title референсируемого правила, ровно то, что реально попадёт в
    events.matched_rules/rule_hits.rule_title, см. app/main.py:_build_matched_row_map).
    Правило с хотя бы одной неразрешённой ссылкой пропускается защитно - каталог не должен
    падать на кривом/неполном YAML (например пока сохраняется только часть файла)."""
    if not _is_custom_ruleset(ruleset_path):
        return []
    target_dir = _custom_ruleset_dir(ruleset_path)

    name_to_title: dict[str, str] = {}
    for yml_path in list(target_dir.glob("*.yml")) + list(target_dir.glob("*.yaml")):
        try:
            text = yml_path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for doc in docs:
            title = doc.get("title")
            if not title:
                continue
            if doc.get("name"):
                name_to_title[str(doc["name"])] = title
            if doc.get("id"):
                name_to_title[str(doc["id"])] = title

    results: list[dict[str, Any]] = []
    for corr_path in target_dir.glob(f"*{CORRELATION_EXT}"):
        try:
            text = corr_path.read_text(encoding="utf-8")
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except (OSError, yaml.YAMLError):
            continue
        for doc in docs:
            corr = doc.get("correlation")
            title = doc.get("title")
            if not title or not isinstance(corr, dict):
                continue
            refs = corr.get("rules") or []
            base_titles: list[str] = []
            unresolved = False
            for ref in refs:
                title_for_ref = name_to_title.get(str(ref))
                if title_for_ref is None:
                    unresolved = True
                    break
                base_titles.append(title_for_ref)
            if unresolved:
                continue
            results.append({
                "id": doc.get("id"),
                "title": title,
                "level": doc.get("level", "informational"),
                "description": doc.get("description", ""),
                "tags": doc.get("tags", []),
                "type": corr.get("type"),
                "group_by": corr.get("group-by") or [],
                "timespan": corr.get("timespan"),
                "condition": corr.get("condition") or {},
                "base_rule_titles": base_titles,
            })
    return results


# ------------------------------------------------------------------ Рулсеты (список/upload/delete)

def _ruleset_info(path: Path, category: str, deletable: bool) -> dict[str, Any]:
    try:
        rule_count = len(_load_json_rules(path))
    except CatalogError:
        rule_count = 0
    rel_path = str(path.relative_to(BASE_DIR)).replace("\\", "/")
    return {
        "path": rel_path,
        "category": category,
        "name": path.stem,
        "rule_count": rule_count,
        "size_bytes": path.stat().st_size,
        "deletable": deletable,
    }


def _custom_ruleset_info(meta_path: Path) -> dict[str, Any]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CatalogError(f"Не удалось прочитать meta.json рулсета: {exc}")
    ruleset_dir = meta_path.parent
    manifest_path = ruleset_dir / ".manifest.json"
    rules = _load_manifest(manifest_path)
    size = sum(f.stat().st_size for f in ruleset_dir.glob("*") if f.is_file())
    return {
        "path": f"custom_rulesets/{meta['id']}",
        "category": "custom",
        "name": meta.get("name") or meta["id"],
        "rule_count": len(rules),
        "size_bytes": size,
        "deletable": True,
    }


def list_rulesets() -> list[dict[str, Any]]:
    """built-in + все именованные custom-рулсеты. Виртуальная запись "основного рулсета"
    (main) сюда НЕ входит - её добавляет main.py (единственное место со знанием об обоих
    модулях), см. докстринг модуля."""
    entries = [_ruleset_info(p, "builtin", deletable=False) for p in sorted(BUILTIN_RULES_DIR.glob("*.json"))]
    for meta_path in sorted(CUSTOM_ROOT.glob("*/meta.json")):
        try:
            entries.append(_custom_ruleset_info(meta_path))
        except CatalogError:
            continue  # битый meta.json - пропускаем, не роняем весь каталог
    return entries


def create_custom_ruleset(name: str) -> str:
    """Создаёт новый именованный пустой custom-рулсет, возвращает его ruleset_path."""
    name = (name or "").strip()
    if not name:
        raise CatalogError("Имя рулсета не может быть пустым")
    ruleset_id = uuid4().hex
    ruleset_dir = CUSTOM_ROOT / ruleset_id
    ruleset_dir.mkdir(parents=True, exist_ok=False)
    meta = {"id": ruleset_id, "name": name, "created_at": datetime.now(timezone.utc).isoformat()}
    (ruleset_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return f"custom_rulesets/{ruleset_id}"


def _resolve_target_ruleset(ruleset: str | None, new_ruleset_name: str | None) -> str:
    """Общая валидация "существующий рулсет ИЛИ новый" для создания правила/загрузки рулсета -
    ровно один из двух должен быть задан; builtin как existing-цель отклоняется (read-only)."""
    ruleset = (ruleset or "").strip()
    new_ruleset_name = (new_ruleset_name or "").strip()
    if ruleset and new_ruleset_name:
        raise CatalogError("Укажи либо существующий рулсет, либо имя нового - не оба сразу")
    if new_ruleset_name:
        return create_custom_ruleset(new_ruleset_name)
    if not ruleset:
        raise CatalogError("Нужно выбрать существующий рулсет или указать имя нового")
    if not _is_custom_ruleset(ruleset):
        raise CatalogError("Правила можно добавлять только в свои (не встроенные) рулсеты")
    return ruleset


def delete_custom_ruleset(ruleset_path: str) -> None:
    """Удаляет именованный custom-рулсет целиком (встроенные отклоняются автоматически -
    не матчат префикс custom_rulesets/)."""
    target_dir = _custom_ruleset_dir(ruleset_path)
    for f in target_dir.iterdir():
        if f.is_file():
            _invalidate_cache(f)
    shutil.rmtree(target_dir)


# ------------------------------------------------------------------ Кастомные правила (YAML)

def _looks_like_correlation_doc(doc: dict[str, Any]) -> bool:
    return "title" in doc and "correlation" in doc


def _validate_correlation_doc(doc: dict[str, Any]) -> None:
    """Лёгкая структурная валидация correlation-документа БЕЗ pySigma (см. докстринг модуля
    про CORRELATION_EXT/почему pySigma тут не участвует вообще). Не полный валидатор Sigma-
    спеки - ловит только очевидные ошибки, чтобы автор правила увидел понятную причину отказа
    при сохранении, а не тихо получил корреляцию, которая никогда не сработает (app/
    correlation.py и так защитно пропускает неподдерживаемые/некорректные записи молча -
    здесь, наоборот, хотим громко предупредить на этапе сохранения)."""
    if not doc.get("title"):
        raise RuleValidationError("Correlation-правило должно содержать 'title'")
    corr = doc.get("correlation")
    if not isinstance(corr, dict):
        raise RuleValidationError("Отсутствует блок 'correlation'")
    corr_type = corr.get("type")
    if corr_type not in _CORR_TYPES:
        raise RuleValidationError(
            f"correlation.type должен быть одним из {sorted(_CORR_TYPES)}, получено: {corr_type!r}"
        )
    refs = corr.get("rules")
    if not refs or not isinstance(refs, list):
        raise RuleValidationError("correlation.rules должен быть непустым списком ссылок на правила")
    if corr_type in ("event_count", "value_count"):
        if not corr.get("timespan"):
            raise RuleValidationError(f"correlation.timespan обязателен для типа '{corr_type}'")
        if not corr.get("condition"):
            raise RuleValidationError(f"correlation.condition обязателен для типа '{corr_type}'")
        if corr_type == "value_count" and not (corr.get("condition") or {}).get("field"):
            raise RuleValidationError("correlation.condition.field обязателен для value_count")


def _compile_correlation_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """"Псевдо-скомпилированная" запись correlation-правила для .manifest.json (просмотр/
    main-ruleset toggle в UI - те же поля, что и у обычных compiled-словарей из RulesetHandler,
    но без 'rule' (SQL, тут неоткуда взять и не нужен - см. докстринг модуля) и без обращения
    к pySigma вообще. Структурные поля (type/group-by/timespan/condition/rules) сюда
    сознательно НЕ дублируются - их заново читает load_correlation_rules из raw YAML при
    каждом использовании (дёшево, correlation-правил в рулсете единицы)."""
    return {
        "id": doc.get("id") or "",
        "title": doc["title"],
        "status": doc.get("status", "experimental"),
        "description": doc.get("description", ""),
        "author": doc.get("author", ""),
        "tags": doc.get("tags", []),
        "falsepositives": doc.get("falsepositives", []),
        "level": doc.get("level", "informational"),
        "correlation": True,
        "rule": [],
        "filename": "",
        "channel": [],
        "eventid": [],
    }


def _looks_like_sigma_rule(yaml_text: str) -> bool:
    """Структурная пре-проверка без обращения к Zircolite/pySigma - эквивалент
    RulesetHandler.is_valid_sigma_rule (title+logsource+detection, либо title+correlation),
    но работает прямо со строкой (не требует ни временного файла, ни RulesetHandler-инстанса
    только чтобы дёрнуть у него один не использующий self метод)."""
    try:
        for doc in yaml.safe_load_all(yaml_text):
            if not isinstance(doc, dict):
                continue
            if all(f in doc for f in ("title", "logsource", "detection")):
                return True
            if "title" in doc and "correlation" in doc:
                return True
    except yaml.YAMLError:
        return False
    return False


def _split_yaml_documents(text: str) -> list[str]:
    """Разбиение multi-document YAML (несколько правил в одном файле, разделены '---' в начале
    строки) на отдельные документы - сырьё для _match_yaml_by_title (см. save_ruleset_yaml)."""
    parts = re.split(r"(?m)^---\s*$", text)
    return [p.strip() for p in parts if p.strip()]


def _match_yaml_by_title(docs: list[str]) -> dict[str, str]:
    """Сопоставляет каждый YAML-документ с его 'title' - чтобы сохранить исходный YAML каждого
    правила по отдельности (см. save_ruleset_yaml). НЕ позиционное: RulesetHandler сортирует
    скомпилированные правила по уровню серьёзности (critical первым, level_order в rules.py),
    поэтому порядок compiled_rules почти никогда не совпадает с порядком документов в файле -
    зип по индексу молча приписывал бы каждому правилу ЧУЖОЙ yaml_text. Сопоставление по title
    устойчиво к переупорядочиванию; title - обязательное поле Sigma, есть всегда. При дубликате
    title внутри одного файла - оба документа исключаются (нет способа надёжно различить, какой
    SQL к какому относится), их yaml_text просто не будет приложен - на детект (уже
    скомпилированный SQL) это не влияет, только на отображение исходника в детейл-панели."""
    by_title: dict[str, list[str]] = {}
    for doc in docs:
        try:
            parsed = yaml.safe_load(doc)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        title = parsed.get("title")
        if title:
            by_title.setdefault(title, []).append(doc)
    return {title: variants[0] for title, variants in by_title.items() if len(variants) == 1}


def _safe_rule_id(candidate: str | None) -> str:
    """id из скомпилированного правила уходит прямо в имя файла (<id>.yml) - candidate это
    содержимое ПОЛЬЗОВАТЕЛЬСКОГО YAML (Sigma 'id:'), поэтому валидируем строго, при
    малейшем сомнении просто генерируем новый - это безопаснее, чем пытаться экранировать."""
    if candidate and _SAFE_ID_RE.match(candidate):
        return candidate
    return uuid4().hex


def _find_rule_id_owner(rule_id: str) -> tuple[str, str] | None:
    """Ищет rule_id среди ВСЕХ рулсетов (builtin + все custom). Возвращает (ruleset_path,
    title) владельца или None, если id свободен. Нужно для save_custom_rule/save_ruleset_yaml:
    там rule_id уходит прямо в имя файла ВНУТРИ целевого рулсета (совпадение = тихая
    перезапись чужого правила), а совпадение с id в ДРУГОМ рулсете отдельно ломает dedup_key
    алертов (rule_id:host:main_entity, см. normalize._dedup_key) - два логически разных
    правила схлопнулись бы в один алерт (инкремент event_count вместо новой записи)."""
    for entry in list_rulesets():
        for rule in load_rules(entry["path"]):
            if rule.get("id") == rule_id:
                return entry["path"], str(rule.get("title") or "")
    return None


def compile_custom_rule(
    yaml_text: str, *, target_dir: Path | None = None, exclude_filename: str | None = None
) -> dict[str, Any]:
    """Валидация + компиляция ОДНОГО правила БЕЗ сохранения на диск (переиспользуется в
    save_custom_rule/update_custom_rule).

    RulesetHandler глотает ошибки конвертации отдельных правил (convert_sigma_rules /
    sigma_rules_to_ruleset ловят исключение и только логируют debug, наружу не поднимают) -
    поэтому голый try/except вокруг конструктора почти никогда не поймает реальную ошибку
    компиляции конкретного правила; после конструктора отдельно проверяем, что
    handler.rulesets непустой.

    target_dir - если задан, компиляция обычного (не-correlation, см. ниже) правила идёт в
    контексте ВСЕХ уже сохранённых там .yml-соседей, а не изолированно во временном файле -
    чтобы поймать коллизию title внутри ОДНОГО рулсета (если после компиляции нашлось больше
    одного правила с таким title - значит в рулсете уже есть тёзка, неоднозначность, см. ниже
    по коду). Соседние .yml копируются в одноразовую scratch-директорию вместе с новым/
    редактируемым правилом, компилируем ТАМ (не реальную директорию рулсета) - надёжнее
    переименования файлов на месте: если процесс упадёт посреди компиляции, в целевом рулсете
    ничего не потеряется и не окажется временно скрытым под чужим расширением. Итог компиляции
    директории - N скомпилированных правил (по числу .yml внутри), нужно выбрать ИМЕННО наше
    среди них; сопоставление - по title (обязательное поле Sigma, тот же приём, что и в
    save_ruleset_yaml/_match_yaml_by_title).

    ВАЖНО: correlation-правила (в т.ч. те, на которые где-то ссылается correlation.rules
    соседнего файла) сюда не попадают вообще - они хранятся под CORRELATION_EXT (не .yml/
    .yaml), поэтому глоб ниже их физически не видит, и pySigma никогда не узнаёт о связи
    correlation-правило/referenced-правило (см. докстринг модуля). Раньше (до перехода на
    CORRELATION_EXT) referenced-only правило не попадало в handler.rulesets из-за
    `_output=False`, выставляемого pySigma при виде correlation-ссылки в ТОЙ ЖЕ загрузке -
    сейчас этот сценарий просто не наступает: обычные правила НИКОГДА не делят SigmaCollection
    с correlation-документами.

    exclude_filename - при редактировании существующего правила (update_custom_rule) не копировать
    его СТАРУЮ версию в scratch-директорию: иначе там на момент компиляции окажутся одновременно
    старый и новый (temp) вариант одного и того же правила, и сопоставление по title становится
    неоднозначным (два кандидата вместо одного).

    Correlation-документы (есть ключ 'correlation') сюда НЕ доходят до RulesetHandler вовсе -
    отдельная ветка ниже, своя лёгкая валидация без pySigma (см. докстринг модуля/
    CORRELATION_EXT про причину: pySigma ломает компиляцию правила, на которое ссылается
    корреляция, если они оба в одном SigmaCollection)."""
    if not yaml_text or not yaml_text.strip():
        raise RuleValidationError("Пустой YAML")
    if not _looks_like_sigma_rule(yaml_text):
        raise RuleValidationError(
            "YAML должен содержать title, logsource и detection (или title и correlation)."
        )

    try:
        first_doc = next((d for d in yaml.safe_load_all(yaml_text) if isinstance(d, dict)), None)
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Некорректный YAML: {exc}")
    if first_doc is not None and _looks_like_correlation_doc(first_doc):
        _validate_correlation_doc(first_doc)
        return _compile_correlation_doc(first_doc)

    # Разворот именованных списков значений (%name% / |expand, см. app/rules/value_lists.py) ДО
    # компиляции - дальше pySigma/Zircolite плейсхолдер не видят. На диск пишется исходный
    # yaml_text с %name% (source of truth), это - только для компиляции.
    try:
        yaml_text = value_lists.expand_placeholders(yaml_text)
    except value_lists.ValueListError as exc:
        raise RuleValidationError(str(exc))

    if target_dir is None:
        tmp_path = Path(tempfile.gettempdir()) / f"sigma-custom-{uuid4().hex}.yml"
        tmp_path.write_text(yaml_text, encoding="utf-8")
        try:
            try:
                handler = RulesetHandler(RulesetConfig(ruleset=[str(tmp_path)]))
            except Exception as exc:  # noqa: BLE001 - реальные SigmaError от pySigma при некорректном detection/logsource
                raise RuleValidationError(f"Ошибка компиляции: {exc}")
            if not handler.rulesets:
                raise RuleValidationError("Правило не скомпилировалось в SQL - проверь detection/logsource.")
            return handler.rulesets[0]
        finally:
            tmp_path.unlink(missing_ok=True)

    try:
        docs = [d for d in yaml.safe_load_all(yaml_text) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Некорректный YAML: {exc}")
    title = docs[0].get("title") if docs else None

    scratch_dir = Path(tempfile.mkdtemp(prefix="sigma-compile-"))
    try:
        for sibling in list(target_dir.glob("*.yml")) + list(target_dir.glob("*.yaml")):
            if exclude_filename and sibling.name == exclude_filename:
                continue
            try:
                sib_text = value_lists.expand_placeholders(sibling.read_text(encoding="utf-8"))
            except (OSError, value_lists.ValueListError):
                continue  # сосед с неразрешимым %placeholder% не должен ронять компиляцию текущего правила
            (scratch_dir / sibling.name).write_text(sib_text, encoding="utf-8")
        (scratch_dir / f"__new_{uuid4().hex}.yml").write_text(yaml_text, encoding="utf-8")
        try:
            handler = RulesetHandler(RulesetConfig(ruleset=[str(scratch_dir)]))
        except Exception as exc:  # noqa: BLE001
            raise RuleValidationError(f"Ошибка компиляции: {exc}")
        if not handler.rulesets:
            raise RuleValidationError("Правило не скомпилировалось в SQL - проверь detection/logsource.")
        candidates = [r for r in handler.rulesets if r.get("title") == title] if title else handler.rulesets
        if not candidates:
            candidates = handler.rulesets
        if len(candidates) > 1:
            raise RuleValidationError(
                f"В этом рулсете уже есть другое правило с заголовком '{title}' - результат "
                "компиляции неоднозначен, переименуй правило (title) и попробуй снова."
            )
        return candidates[0]
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


def compile_ruleset_yaml(yaml_text: str) -> list[dict[str, Any]]:
    """Валидация + компиляция ВСЕХ правил multi-document YAML (одна или несколько Sigma-rule
    документов в одном файле - SigmaCollection.load_ruleset поддерживает это нативно).

    Документы с ключом 'correlation' компилируются ОТДЕЛЬНО от обычных - собственной лёгкой
    валидацией без pySigma (см. докстринг модуля/CORRELATION_EXT). Обычные документы отдаются
    в RulesetHandler ОДНИМ файлом БЕЗ correlation-документов вовсе - именно их совместное
    присутствие в одном SigmaCollection и ломает компиляцию referenced-правила (см. докстринг
    модуля), поэтому исключаем эту ситуацию физически, а не боремся с её последствиями."""
    if not yaml_text or not yaml_text.strip():
        raise RuleValidationError("Пустой YAML")
    try:
        list(yaml.safe_load_all(yaml_text))  # ранний фейл на невалидном YAML целиком
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Некорректный YAML: {exc}")

    corr_results: list[dict[str, Any]] = []
    plain_docs: list[str] = []
    for doc_text in _split_yaml_documents(yaml_text):
        try:
            parsed = yaml.safe_load(doc_text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        if _looks_like_correlation_doc(parsed):
            _validate_correlation_doc(parsed)
            corr_results.append(_compile_correlation_doc(parsed))
        else:
            try:
                plain_docs.append(value_lists.expand_placeholders(doc_text))
            except value_lists.ValueListError as exc:
                raise RuleValidationError(str(exc))

    compiled_plain: list[dict[str, Any]] = []
    if plain_docs:
        tmp_path = Path(tempfile.gettempdir()) / f"sigma-ruleset-{uuid4().hex}.yml"
        tmp_path.write_text("\n---\n".join(plain_docs), encoding="utf-8")
        try:
            try:
                handler = RulesetHandler(RulesetConfig(ruleset=[str(tmp_path)]))
            except Exception as exc:  # noqa: BLE001
                raise RuleValidationError(f"Ошибка компиляции: {exc}")
            compiled_plain = handler.rulesets
        finally:
            tmp_path.unlink(missing_ok=True)

    if not compiled_plain and not corr_results:
        raise RuleValidationError("Ни одно правило не скомпилировалось - проверь YAML.")
    return compiled_plain + corr_results


def save_custom_rule(
    yaml_text: str, ruleset: str | None = None, new_ruleset_name: str | None = None
) -> tuple[dict[str, Any], str]:
    """Компилирует и сохраняет ОДНО правило в существующий (ruleset) или новый
    (new_ruleset_name) именованный custom-рулсет. Возвращает (скомпилированное правило,
    ruleset_path, куда оно попало)."""
    target = _resolve_target_ruleset(ruleset, new_ruleset_name)
    target_dir = _custom_ruleset_dir(target)
    compiled = compile_custom_rule(yaml_text, target_dir=target_dir)
    candidate = compiled.get("id")
    rule_id = _safe_rule_id(candidate)
    if candidate and rule_id == candidate:
        owner = _find_rule_id_owner(rule_id)
        if owner is not None:
            owner_ruleset, owner_title = owner
            raise RuleValidationError(
                f"id '{rule_id}' уже используется правилом '{owner_title}' в рулсете "
                f"'{owner_ruleset}' - укажи другой id или убери поле 'id' из YAML, чтобы он "
                "сгенерировался автоматически."
            )
    compiled["id"] = rule_id
    ext = CORRELATION_EXT if compiled.get("correlation") else ".yml"
    (target_dir / f"{rule_id}{ext}").write_text(yaml_text, encoding="utf-8")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        manifest.append(compiled)
        _write_manifest(manifest_path, manifest)
    return compiled, target


def _peel_value_list_docs(yaml_text: str) -> tuple[list[Any], str]:
    """Из multi-document YAML '+ Загрузить рулсет' вынимает документы-определения списков
    значений (СТРОГО: Sigma pipeline с value_placeholders ИЛИ наш {name, values} - см.
    value_lists.is_list_document). Возвращает (parsed_lists, YAML только правил/корреляций)."""
    list_texts: list[str] = []
    rule_texts: list[str] = []
    for doc_text in _split_yaml_documents(yaml_text):
        try:
            parsed = yaml.safe_load(doc_text)
        except yaml.YAMLError:
            rule_texts.append(doc_text)  # пусть на этом споткнётся компилятор правил, не мы
            continue
        if isinstance(parsed, dict) and value_lists.is_list_document(parsed):
            list_texts.append(doc_text)
        else:
            rule_texts.append(doc_text)
    parsed_lists = value_lists.parse_list_file("\n---\n".join(list_texts)) if list_texts else []
    return parsed_lists, "\n---\n".join(rule_texts)


def save_ruleset_yaml(
    yaml_text: str, ruleset: str | None = None, new_ruleset_name: str | None = None
) -> tuple[dict[str, Any] | None, str | None, list[dict[str, Any]], dict[str, list[str]]]:
    """Компилирует и сохраняет ЦЕЛЫЙ рулсет (одно или несколько Sigma-правил в одном YAML-
    файле) в существующий или новый именованный custom-рулсет. Возвращает
    (сводка рулсета|None, ruleset_path|None, collisions, value_lists_imported).

    Multi-document файл может, кроме правил, содержать документы-определения списков значений
    (Sigma pipeline с value_placeholders.mapping или наш {name, values}) - они вынимаются
    ПЕРВЫМИ, пишутся на диск (mode=replace), и только потом компилируются правила (разворот
    %name% в compile_ruleset_yaml уже видит новые списки). Если в файле ТОЛЬКО списки -
    рулсет не создаётся, возвращается (None, None, [], imported).

    Правило с явным id, который уже занят - ГДЕ УГОДНО (в любом другом рулсете, в этом же
    целевом рулсете от предыдущей загрузки, или дубликат внутри ЭТОГО ЖЕ multi-document
    файла) - НЕ добавляется; уже существующий владелец id не трогается. Это частичный успех:
    остальные правила файла без коллизий сохраняются как обычно, ошибка не поднимается на
    весь запрос. collisions - список {title, id, conflict_ruleset, conflict_title} для UI
    (что именно и с чем не добавилось) - см. app/main.py:upload_ruleset."""
    parsed_lists, rule_yaml = _peel_value_list_docs(yaml_text)
    imported = value_lists.import_lists(parsed_lists, mode="replace") if parsed_lists else {
        "created": [], "replaced": [], "merged": [], "skipped": [], "recompile_needed": [],
    }
    if not rule_yaml.strip():
        return None, None, [], imported

    target = _resolve_target_ruleset(ruleset, new_ruleset_name)
    target_dir = _custom_ruleset_dir(target)
    compiled_rules = compile_ruleset_yaml(rule_yaml)
    doc_by_title = _match_yaml_by_title(_split_yaml_documents(rule_yaml))
    manifest_path = target_dir / ".manifest.json"
    collisions: list[dict[str, Any]] = []
    with _manifest_lock:
        manifest_by_id = {r.get("id"): r for r in _load_manifest_uncached(manifest_path)}
        for compiled in compiled_rules:
            candidate = compiled.get("id")
            rule_id = _safe_rule_id(candidate)
            if candidate and rule_id == candidate:
                # Сначала целевой рулсет (уже загруженные ранее + добавленные чуть раньше в
                # ЭТОМ ЖЕ цикле, manifest_by_id пополняется по ходу) - дешевле и ловит
                # внутрифайловый дубль, который _find_rule_id_owner (читает с диска) не
                # увидит, пока манифест не записан.
                existing = manifest_by_id.get(rule_id)
                owner = (target, str(existing.get("title") or "")) if existing else _find_rule_id_owner(rule_id)
                if owner is not None:
                    owner_ruleset, owner_title = owner
                    collisions.append({
                        "title": compiled.get("title"),
                        "id": rule_id,
                        "conflict_ruleset": owner_ruleset,
                        "conflict_title": owner_title,
                    })
                    continue
            compiled["id"] = rule_id
            manifest_by_id[rule_id] = compiled
            source_doc = doc_by_title.get(compiled.get("title"))
            if source_doc is not None:
                ext = CORRELATION_EXT if compiled.get("correlation") else ".yml"
                (target_dir / f"{rule_id}{ext}").write_text(source_doc, encoding="utf-8")
        _write_manifest(manifest_path, list(manifest_by_id.values()))
    return _custom_ruleset_info(target_dir / "meta.json"), target, collisions, imported


def update_custom_rule(ruleset_path: str, rule_id: str, yaml_text: str) -> dict[str, Any]:
    """Пересобирает СУЩЕСТВУЮЩЕЕ правило на месте - id всегда остаётся ИСХОДНЫМ (rule_id из
    URL). Если новый YAML явно содержит ДРУГОЙ id - это RuleValidationError (400), не тихая
    перезапись: пользователь должен явно увидеть, что id менять нельзя, а не молча получить
    сохранённое правило с незаметно отброшенным id (для настоящего переименования нужно
    удалить старое правило и создать новое явно - осознанно не поддерживается одной кнопкой).
    Пустой/отсутствующий 'id:' в новом YAML - не ошибка, просто подставляется исходный.

    Тип правила (обычное <-> correlation, см. CORRELATION_EXT) может смениться при
    редактировании - файл при этом переписывается под НОВЫМ расширением, старый удаляется
    (rule_id/id в URL остаются теми же, меняется только физическое расширение файла на диске -
    невидимо снаружи API, main_ruleset ссылается на rule_id, не на путь файла)."""
    target_dir = _custom_ruleset_dir(ruleset_path)
    rule_path = _find_rule_file(target_dir, rule_id)
    if rule_path is None:
        raise CatalogError(f"Правило не найдено: {rule_id}")
    compiled = compile_custom_rule(yaml_text, target_dir=target_dir, exclude_filename=rule_path.name)
    candidate = compiled.get("id")
    if candidate and candidate != rule_id:
        raise RuleValidationError(
            f"Менять id при редактировании нельзя - оставь 'id: {rule_id}' (или убери строку "
            "'id:' вовсе, исходный id подставится автоматически)."
        )
    compiled["id"] = rule_id
    new_ext = CORRELATION_EXT if compiled.get("correlation") else ".yml"
    new_path = target_dir / f"{rule_id}{new_ext}"
    if new_path != rule_path:
        rule_path.unlink(missing_ok=True)
    new_path.write_text(yaml_text, encoding="utf-8")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        manifest.append(compiled)
        _write_manifest(manifest_path, manifest)
    return compiled


def delete_custom_rule(ruleset_path: str, rule_id: str) -> None:
    target_dir = _custom_ruleset_dir(ruleset_path)
    rule_path = _find_rule_file(target_dir, rule_id)
    if rule_path is None:
        raise CatalogError(f"Правило не найдено: {rule_id}")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        _write_manifest(manifest_path, manifest)
    rule_path.unlink()


# ------------------------------------------------------------------ Value lists <-> правила

def _iter_custom_rule_files():
    """(ruleset_path, Path к *.yml/*.yaml) по всем именованным custom-рулсетам. Correlation-
    правила (*{CORRELATION_EXT}) сюда не попадают - у них нет detection, плейсхолдеров быть
    не может."""
    for meta_path in sorted(CUSTOM_ROOT.glob("*/meta.json")):
        ruleset_dir = meta_path.parent
        ruleset_path = f"custom_rulesets/{ruleset_dir.name}"
        for yml in list(ruleset_dir.glob("*.yml")) + list(ruleset_dir.glob("*.yaml")):
            yield ruleset_path, yml


def _rule_title_from_file(path: Path) -> str:
    try:
        first = next((d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)), None)
    except (OSError, yaml.YAMLError):
        return ""
    return str((first or {}).get("title") or "")


def rules_using_value_list(list_name: str) -> list[dict[str, Any]]:
    """Кастомные правила, чей detection ссылается на плейсхолдер %list_name% (через |expand).
    Для GET /value-lists/{name}.used_by и защиты при удалении списка."""
    out: list[dict[str, Any]] = []
    for ruleset_path, yml in _iter_custom_rule_files():
        try:
            text = yml.read_text(encoding="utf-8")
        except OSError:
            continue
        if list_name in value_lists.placeholders_used(text):
            out.append({"ruleset": ruleset_path, "rule_id": yml.stem, "title": _rule_title_from_file(yml)})
    return out


def value_list_usage_counts() -> dict[str, int]:
    """{имя списка: сколько кастом-правил на него ссылаются} - одним проходом по всем правилам
    (для колонки "исп. в N правилах" во вкладке "Списки", дешевле N вызовов rules_using_value_list)."""
    counts: dict[str, int] = {}
    for _ruleset_path, yml in _iter_custom_rule_files():
        try:
            names = value_lists.placeholders_used(yml.read_text(encoding="utf-8"))
        except OSError:
            continue
        for n in names:
            counts[n] = counts.get(n, 0) + 1
    return counts


def recompile_rules_for_value_list(list_name: str) -> dict[str, Any]:
    """Пересобирает все кастом-правила, ссылающиеся на %list_name%, и переписывает их записи
    в .manifest.json соответствующих рулсетов. Возвращает
    {recompiled: [...], errors: [{..., error}], affected_rulesets: [...]}.

    Вызывается из main.py после value_lists.update_list. engine.invalidate(...) для
    affected_rulesets делает main.py (у rules_catalog нет ссылки на engine). Правило, которое
    не пересобралось (напр. в нём же есть второй, теперь битый плейсхолдер), сохраняет прежний
    SQL в манифесте - ошибка возвращается наверх для показа пользователю, но save списка не
    откатывается (сам список валиден)."""
    recompiled: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    affected: set[str] = set()
    for ref in rules_using_value_list(list_name):
        ruleset_path, rule_id = ref["ruleset"], ref["rule_id"]
        try:
            target_dir = _custom_ruleset_dir(ruleset_path)
            rule_path = _find_rule_file(target_dir, rule_id)
            if rule_path is None:
                continue
            compiled = compile_custom_rule(
                rule_path.read_text(encoding="utf-8"),
                target_dir=target_dir, exclude_filename=rule_path.name,
            )
            compiled["id"] = rule_id
            manifest_path = target_dir / ".manifest.json"
            with _manifest_lock:
                manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
                manifest.append(compiled)
                _write_manifest(manifest_path, manifest)
            recompiled.append(dict(ref))
            affected.add(ruleset_path)
        except (RuleValidationError, CatalogError) as exc:
            errors.append({**ref, "error": str(exc)})
    return {"recompiled": recompiled, "errors": errors, "affected_rulesets": sorted(affected)}


# ------------------------------------------------------------------ Миграция старой раскладки

def _migrate_legacy_layout() -> None:
    """Одноразовая идемпотентная миграция дособиранной раскладки одного безымянного
    custom_rulesets/my_rules/ (до введения именованных custom-рулсетов) в новую: достаточно
    дописать meta.json в ТУ ЖЕ папку - custom_rulesets/my_rules уже валидная директория с
    *.yml + .manifest.json, ничего перемещать не нужно. custom_rulesets/uploaded/ (старая
    JSON-загрузка) просто перестаёт использоваться, не трогаем."""
    legacy_dir = CUSTOM_ROOT / "my_rules"
    if not legacy_dir.is_dir() or (legacy_dir / "meta.json").exists():
        return
    if not any(legacy_dir.glob("*.yml")) and not (legacy_dir / ".manifest.json").exists():
        return
    meta = {"id": "my_rules", "name": "Мои правила", "created_at": datetime.now(timezone.utc).isoformat()}
    (legacy_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")


_migrate_legacy_layout()
