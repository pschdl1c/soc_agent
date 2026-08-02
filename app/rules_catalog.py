"""
Каталог Sigma-рулсетов и правил для вкладки "Sigma-правила" в UI.

Две категории рулсетов:
  - builtin - Zircolite/rules/*.json (внешний git-клон, read-only, никогда не редактируем/не удаляем).
  - custom  - custom_rulesets/<ruleset_id>/ - именованные пользовательские рулсеты. Каждый -
              директория: meta.json (id/name/created_at), <rule_id>.yml на правило (сырой Sigma
              YAML - source of truth) и .manifest.json - кэш скомпилированных метаданных ВСЕХ
              правил директории (тот же формат, что и Zircolite/rules/*.json), нужен только для
              быстрого просмотра списком, никогда не участвует в детекте напрямую.

Состав "основного рулсета" (main ruleset, ruleset_path == "main") - НЕ часть этого модуля,
см. app/main_ruleset.py. Он лишь ссылается на рулсеты/правила, каталогизированные здесь
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

BASE_DIR = Path(__file__).resolve().parent.parent

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

    only_ids/in_main_fn - точки интеграции с "основным рулсетом" (app/main_ruleset.py),
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
                yaml_path = _custom_ruleset_dir(ruleset_path) / f"{rule_id}.yml"
                if yaml_path.is_file():
                    rule["yaml_text"] = yaml_path.read_text(encoding="utf-8")
            return rule
    return None


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

    target_dir - если задан, компиляция идёт в контексте ВСЕГО целевого custom-рулсета (все
    уже сохранённые там .yml), а не изолированно во временном файле. Нужно для
    correlation-правил: `correlation.rules` ссылается на СОСЕДНЕЕ detection-правило по имени, а
    pySigma (SigmaCollection.load_ruleset) резолвит такие ссылки только внутри ОДНОЙ загрузки -
    при компиляции временного файла в одиночку компилятор соседних правил рулсета просто не
    видит, и ссылка не резолвится (SigmaRuleNotFoundError). Zircolite уже трактует
    custom_rulesets/<id> как одну директорию-рулсет при обычном детекте (RulesetHandler globs
    *.yml всей папки) - тут воспроизводим ту же область видимости, просто на момент сохранения
    одного правила. Реальную директорию рулсета при этом НЕ трогаем - соседние .yml копируются
    в одноразовую scratch-директорию вместе с новым/редактируемым правилом, компилируем ТАМ.
    Так надёжнее переименования файлов на месте: если процесс упадёт посреди компиляции, в
    целевом рулсете ничего не потеряется и не окажется временно скрытым под чужим расширением.
    Итог компиляции директории - N скомпилированных правил (по числу .yml внутри), нужно
    выбрать ИМЕННО наше среди них; сопоставление - по title (обязательное поле Sigma, тот же
    приём, что и в save_ruleset_yaml/_match_yaml_by_title). Referenced-only detection-правило
    (используется только чтобы дать SQL для correlation, `generate: true` не указан) не
    попадает в handler.rulesets вовсе (см. Zircolite rules.py - "referenced only" пропускается)
    - так что даже если title совпадёт с ним, он не будет кандидатом.

    exclude_filename - при редактировании существующего правила (update_custom_rule) не копировать
    его СТАРУЮ версию в scratch-директорию: иначе там на момент компиляции окажутся одновременно
    старый и новый (temp) вариант одного и того же правила, и сопоставление по title становится
    неоднозначным (два кандидата вместо одного)."""
    if not yaml_text or not yaml_text.strip():
        raise RuleValidationError("Пустой YAML")
    if not _looks_like_sigma_rule(yaml_text):
        raise RuleValidationError(
            "YAML должен содержать title, logsource и detection (или title и correlation)."
        )

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
            shutil.copy2(sibling, scratch_dir / sibling.name)
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
    документов в одном файле - SigmaCollection.load_ruleset поддерживает это нативно)."""
    if not yaml_text or not yaml_text.strip():
        raise RuleValidationError("Пустой YAML")
    tmp_path = Path(tempfile.gettempdir()) / f"sigma-ruleset-{uuid4().hex}.yml"
    tmp_path.write_text(yaml_text, encoding="utf-8")
    try:
        try:
            handler = RulesetHandler(RulesetConfig(ruleset=[str(tmp_path)]))
        except Exception as exc:  # noqa: BLE001
            raise RuleValidationError(f"Ошибка компиляции: {exc}")
        if not handler.rulesets:
            raise RuleValidationError("Ни одно правило не скомпилировалось - проверь YAML.")
        return handler.rulesets
    finally:
        tmp_path.unlink(missing_ok=True)


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
    (target_dir / f"{rule_id}.yml").write_text(yaml_text, encoding="utf-8")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        manifest.append(compiled)
        _write_manifest(manifest_path, manifest)
    return compiled, target


def save_ruleset_yaml(
    yaml_text: str, ruleset: str | None = None, new_ruleset_name: str | None = None
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Компилирует и сохраняет ЦЕЛЫЙ рулсет (один или несколько Sigma-правил в одном YAML-
    файле) в существующий или новый именованный custom-рулсет. Возвращает (обновлённая
    сводка рулсета, ruleset_path, collisions).

    Правило с явным id, который уже занят - ГДЕ УГОДНО (в любом другом рулсете, в этом же
    целевом рулсете от предыдущей загрузки, или дубликат внутри ЭТОГО ЖЕ multi-document
    файла) - НЕ добавляется; уже существующий владелец id не трогается. Это частичный успех:
    остальные правила файла без коллизий сохраняются как обычно, ошибка не поднимается на
    весь запрос. collisions - список {title, id, conflict_ruleset, conflict_title} для UI
    (что именно и с чем не добавилось) - см. app/main.py:upload_ruleset."""
    target = _resolve_target_ruleset(ruleset, new_ruleset_name)
    target_dir = _custom_ruleset_dir(target)
    compiled_rules = compile_ruleset_yaml(yaml_text)
    doc_by_title = _match_yaml_by_title(_split_yaml_documents(yaml_text))
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
                (target_dir / f"{rule_id}.yml").write_text(source_doc, encoding="utf-8")
        _write_manifest(manifest_path, list(manifest_by_id.values()))
    return _custom_ruleset_info(target_dir / "meta.json"), target, collisions


def update_custom_rule(ruleset_path: str, rule_id: str, yaml_text: str) -> dict[str, Any]:
    """Пересобирает СУЩЕСТВУЮЩЕЕ правило на месте - id всегда остаётся ИСХОДНЫМ (rule_id из
    URL). Если новый YAML явно содержит ДРУГОЙ id - это RuleValidationError (400), не тихая
    перезапись: пользователь должен явно увидеть, что id менять нельзя, а не молча получить
    сохранённое правило с незаметно отброшенным id (для настоящего переименования нужно
    удалить старое правило и создать новое явно - осознанно не поддерживается одной кнопкой).
    Пустой/отсутствующий 'id:' в новом YAML - не ошибка, просто подставляется исходный."""
    target_dir = _custom_ruleset_dir(ruleset_path)
    rule_path = (target_dir / f"{rule_id}.yml").resolve()
    if not rule_path.is_relative_to(target_dir.resolve()) or not rule_path.is_file():
        raise CatalogError(f"Правило не найдено: {rule_id}")
    compiled = compile_custom_rule(yaml_text, target_dir=target_dir, exclude_filename=rule_path.name)
    candidate = compiled.get("id")
    if candidate and candidate != rule_id:
        raise RuleValidationError(
            f"Менять id при редактировании нельзя - оставь 'id: {rule_id}' (или убери строку "
            "'id:' вовсе, исходный id подставится автоматически)."
        )
    compiled["id"] = rule_id
    rule_path.write_text(yaml_text, encoding="utf-8")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        manifest.append(compiled)
        _write_manifest(manifest_path, manifest)
    return compiled


def delete_custom_rule(ruleset_path: str, rule_id: str) -> None:
    target_dir = _custom_ruleset_dir(ruleset_path)
    rule_path = (target_dir / f"{rule_id}.yml").resolve()
    if not rule_path.is_relative_to(target_dir.resolve()) or not rule_path.is_file():
        raise CatalogError(f"Правило не найдено: {rule_id}")
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        _write_manifest(manifest_path, manifest)
    rule_path.unlink()


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
