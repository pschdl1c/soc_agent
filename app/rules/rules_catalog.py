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
директории рулсета. Причина - реальный баг в ПИНЧЕННОМ (сток, не пропатченный - проверено по
sha256 файла против RECORD в dist-info) pysigma-backend-sqlite==1.2.0 (воспроизведено и на
1.2.4, актуальной опубликованной): правило, на которое ссылается `correlation.rules:` (то есть
присутствует В ОДНОМ SigmaCollection вместе с корреляцией, ссылающейся на него), при
компиляции этого правила ОТДЕЛЬНО ломается ОДНИМ ИЗ ДВУХ способов в зависимости от
`correlation.generate:`. Механизм - `finalize_correlation_subqueries = False`
(`pysigma/conversion/base.py`, не переопределён sqlite-бэкендом) отключает `finalize_query`
для любого правила с backreference. Без `generate:` referenced-правило получает `_output =
False` и просто МОЛЧА ВЫПАДАЕТ из скомпилированного рулсета (перестаёт детектить само по
себе) - тише первого варианта, но не лучше. С `generate: true` `_output` остаётся `True`, и
наружу уходит НЕ финализированная сырая SQL-строка вместо dict, что валит компиляцию
pySigma-стороны совсем (`'str' object has no attribute 'get'` в Zircolite при попытке
отсортировать результат). Наш собственный correlation-движок (app/detection/correlation.py) при
этом вообще не использует SQL, который бы сгенерировал pySigma для корреляции - ему нужны
только структурные поля (type/group-by/timespan/condition/rules) из raw YAML, которые он
читает сам (load_correlation_rules ниже). Поэтому решение простое и радикальное:
correlation-правила физически НИКОГДА не попадают в тот же RulesetHandler-вызов, что и
правило, на которое они ссылаются - расширение файла не `.yml`/`.yaml`, значит RulesetHandler
(rglob("*.yml") + rglob("*.yaml")) их вообще не видит, `resolve_rule_references()` внутри
pySigma никогда не запускается на referenced-правиле, и оно компилируется как совершенно
обычное правило, под своим настоящим именем - никаких
"правил-двойников" в контенте заводить не нужно. compile_custom_rule/compile_ruleset_yaml
ниже сами решают (по наличию ключа `correlation:` в документе), в какую компиляцию отдать
документ - в RulesetHandler (обычные правила) или в собственную лёгкую валидацию без pySigma
(correlation-правила, см. _validate_correlation_doc/_compile_correlation_doc).
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

import yaml

from app import config
from app.models import Severity
from app.rules import value_lists
from app.timespan import parse_timespan as timespan_parse

# файл лежит в app/rules/, до корня проекта — три уровня вверх
BASE_DIR = Path(__file__).resolve().parent.parent.parent

ZIRCOLITE_REPO_PATH = BASE_DIR / "Zircolite"
if str(ZIRCOLITE_REPO_PATH) not in sys.path:
    sys.path.insert(0, str(ZIRCOLITE_REPO_PATH))

from zircolite.config import RulesetConfig  # noqa: E402
from zircolite.rules import RulesetHandler  # noqa: E402

_log = logging.getLogger(__name__)

BUILTIN_RULES_DIR = BASE_DIR / "Zircolite" / "rules"
# data/ - общий корень runtime-данных для локального запуска И Docker (см. app/config.py:
# UPLOADS_DIR, docker-compose.yml). BASE_DIR тут - корень проекта локально, /app в контейнере -
# в обоих случаях "data/custom_rulesets" резолвится в ОДИН и тот же физический путь на хосте
# (локально - напрямую, в Docker - через bind-mount ./data/custom_rulesets:/app/data/custom_rulesets),
# без отдельной env-переменной.
CUSTOM_ROOT = config.CUSTOM_RULESETS_DIR

CUSTOM_ROOT.mkdir(parents=True, exist_ok=True)

# Префикс ruleset_path кастомного рулсета - "custom_rulesets/<id>". Один литерал на модуль:
# по нему И только по нему решается, кастомный это путь или встроенный (в т.ч. когда рулсета с
# таким id вообще нет - иначе несуществующий кастомный путь уходил бы в builtin-ветку и получал
# сообщение про "недопустимый путь"/"встроенные рулсеты" вместо честного "не найден").
CUSTOM_PREFIX = "custom_rulesets/"

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# Расширение файлов correlation-правил на диске - НЕ .yml/.yaml, чтобы RulesetHandler
# (Zircolite/pySigma) их вообще не видел при компиляции директории рулсета (см. докстринг
# модуля выше про причину). Содержимое файла при этом - обычный raw Sigma YAML (source of
# truth, как и у .yml-правил), просто с "невидимым" для детект-движка расширением.
CORRELATION_EXT = ".sigmacorr"

_CORR_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}

# slug типа инцидента (correlation.incident.type) - lowercase, для incidents.incident_type и
# параметризации типа инцидента (см. CLAUDE.md §7 Этап 4). В духе value_lists._NAME_RE, но
# только нижний регистр.
_INCIDENT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
_SEVERITY_VALUES = {s.value for s in Severity}


class CatalogError(Exception):
    """Проблема с рулсетом/правилом на уровне каталога, из-за которой ДЕЙСТВИЕ невозможно, хотя
    объект существует: встроенный рулсет как цель записи/удаления, недопустимый путь, взаимно
    исключающие параметры. main.py транслирует в HTTP 400 (см. _catalog_http)."""


class CatalogNotFound(CatalogError):
    """Частный случай: запрошенного рулсета/правила просто НЕТ - main.py транслирует в 404.

    Отдельный подкласс, потому что раньше оба случая были одним CatalogError и на всех ручках
    каталога отдавались как 404: попытка добавить встроенный рулсет в основной или удалить его
    отвечала «не найден» про существующий рулсет, а запрос к несуществующему кастомному пути -
    наоборот, сообщением про встроенность. Наследование от CatalogError оставлено намеренно:
    старые `except CatalogError` (напр. в main_ruleset.resolve_with_sources, где осиротевшая
    ссылка просто пропускается) продолжают ловить оба вида."""


class CatalogConflict(CatalogError):
    """Действие сломало бы ДРУГИЕ правила: удаляемое/переименовываемое правило (или рулсет)
    указано в correlation.rules корреляций, которые остаются. main.py транслирует в 409; повтор с
    force=true удаляет всё равно. references - [{ruleset, rule_id, title, refs}] для ответа."""

    def __init__(self, message: str, references: list[dict[str, Any]]):
        super().__init__(message)
        self.references = references


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
        raise CatalogNotFound(f"Рулсет не найден: {path.name} ({exc})")
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
    invalidate_scan_cache()


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
    существующий meta.json. Не кастомный путь/кривой id - CatalogError (действие недопустимо,
    400), нет такого рулсета - CatalogNotFound (404)."""
    if not ruleset_path.startswith(CUSTOM_PREFIX):
        raise CatalogError(f"Не кастомный рулсет: {ruleset_path}")
    ruleset_id = ruleset_path[len(CUSTOM_PREFIX):]
    if not _SAFE_ID_RE.match(ruleset_id):
        raise CatalogError(f"Недопустимый id рулсета: {ruleset_path}")
    path = CUSTOM_ROOT / ruleset_id
    if not (path / "meta.json").is_file():
        raise CatalogNotFound(f"Рулсет не найден: {ruleset_path}")
    return path


def _is_custom_ruleset(ruleset_path: str) -> bool:
    try:
        _custom_ruleset_dir(ruleset_path)
        return True
    except CatalogError:
        return False


def is_custom_ruleset(ruleset_path: str) -> bool:
    """Публичная обёртка над _is_custom_ruleset - для модулей вне этого файла
    (app/rules/main_ruleset.py: запрет built-in в основном рулсете; app/main.py: выбор режима
    дедупа алертов, см. app/detection/normalize.py)."""
    return _is_custom_ruleset(ruleset_path)


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
    """Список правил рулсета по пути/id - тот же 'ruleset', что уже принимают /ingest/*.

    Путь с префиксом custom_rulesets/ разбирается ТОЛЬКО как кастомный - даже если такого
    рулсета нет: иначе несуществующий кастомный путь проваливался в ветку builtin и получал
    "Недопустимый путь рулсета" (400) вместо честного "Рулсет не найден" (404)."""
    if ruleset_path.startswith(CUSTOM_PREFIX):
        manifest_path = _custom_ruleset_dir(ruleset_path) / ".manifest.json"
        return _load_manifest(manifest_path)
    path = _safe_resolve(ruleset_path)
    if not path.is_file():
        raise CatalogNotFound(f"Рулсет не найден: {ruleset_path}")
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
    ruleset_path: str | None = None,
    kind: list[str] | None = None,
) -> dict[str, Any]:
    """Подстрока по title/description/name (регистронезависимо) + сортировка + пагинация над УЖЕ
    готовым списком правил - переиспользуется search_rules (по ruleset_path) и main.py напрямую
    для просмотра "Основного рулсета" (виртуальный список из main_ruleset.resolve_with_sources,
    не привязан к одному ruleset_path, поэтому не проходит через load_rules). level сортируется
    по рангу серьёзности (LEVEL_ORDER), не по алфавиту.

    name (Sigma `name`, ключ ссылок correlation.rules) в .manifest.json не хранится - строки
    дополняются им из скана YAML (_rule_names) по паре (рулсет строки, id). Рулсет строки -
    source_ruleset (просмотр main), иначе ruleset_path. У builtin name нет.

    kind - фильтр по виду правила (мультиселект «Тип» в UI, как level/status): "base"
    (обычное Sigma-правило), "correlation" (корреляция БЕЗ инцидента - промежуточные звенья
    и агрегаторы), "incident" (сценарное правило, блок correlation.incident). None/пустой
    список - фильтр не применяется. Виды НЕ вложены друг в друга: сценарное правило в
    "correlation" не попадает (бейдж у него один - inc).

    level/status - фильтр по метадате правила (мультиселект в UI): непустой список значений,
    правило проходит, если его level/status (регистронезависимо) входит в список. None/пустой
    список - фильтр не применяется.

    only_ids/in_main_fn - точки интеграции с "основным рулсетом" (app/rules/main_ruleset.py),
    передаются СНАРУЖИ (main.py) предикатами/множеством id, а не импортом main_ruleset -
    этот модуль ничего не знает про main ruleset (см. докстринг модуля)."""
    names = _rule_names()
    if names:
        rules = [_with_name(r, names, ruleset_path) for r in rules]
    if q:
        needle = q.strip().lower()
        rules = [
            r for r in rules
            if needle in str(r.get("title", "")).lower()
            or needle in str(r.get("description", "")).lower()
            or needle in str(r.get("name") or "").lower()
        ]
    if level:
        allowed = {v.lower() for v in level}
        rules = [r for r in rules if str(r.get("level", "")).lower() in allowed]
    if status:
        allowed = {v.lower() for v in status}
        rules = [r for r in rules if str(r.get("status", "")).lower() in allowed]
    if kind:
        allowed = set(kind)
        rules = [r for r in rules if _rule_kind(r) in allowed]
    if only_ids is not None:
        rules = [r for r in rules if r.get("id") in only_ids]
    reverse = (sort_dir or "asc").lower() == "desc"
    if sort_by == "level":
        rules = sorted(rules, key=lambda r: LEVEL_ORDER.get(r.get("level", "informational"), 99), reverse=reverse)
    elif sort_by in ("title", "name", "author", "status"):
        rules = sorted(rules, key=lambda r: str(r.get(sort_by) or "").lower(), reverse=reverse)
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
    kind: list[str] | None = None,
) -> dict[str, Any]:
    return paginate_rules(
        load_rules(ruleset_path), q, sort_by, sort_dir, limit, offset, only_ids, in_main_fn,
        level=level, status=status, ruleset_path=ruleset_path, kind=kind,
    )


def _rule_kind(rule: dict[str, Any]) -> str:
    """Вид правила для фильтра «Тип» - те же три взаимоисключающих значения, что и бейджи в UI."""
    if rule.get("incident"):
        return "incident"
    if rule.get("correlation"):
        return "correlation"
    return "base"


def _rule_names() -> dict[tuple[str, str], str]:
    """(ruleset_path, id) -> Sigma name по всем своим правилам. Ключ - пара, а не голый id:
    неизменённое правило SigmaHQ может носить тот же id, что и запись встроенного рулсета.
    Id записи манифеста - это id из YAML, у correlation без id: - имя файла, поэтому
    кладутся оба."""
    names: dict[tuple[str, str], str] = {}
    for entry in _scan_custom_rules()[1]:
        if not entry["name"]:
            continue
        for key in (entry["id"], entry["rule_id"]):
            if key:
                names[(entry["ruleset_path"], key)] = entry["name"]
    return names


def _with_name(
    rule: dict[str, Any], names: dict[tuple[str, str], str], ruleset_path: str | None
) -> dict[str, Any]:
    """Копия строки с name - строки берутся из кэша манифеста, мутировать их нельзя."""
    name = names.get((rule.get("source_ruleset") or ruleset_path or "", rule.get("id") or ""))
    return {**rule, "name": name} if name else rule


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


# ------------------------------------------------------------------ Общий индекс своих правил
#
# Ссылки correlation.rules резолвятся по ВСЕМ custom-рулсетам сразу, а не только внутри своего:
# контент раскладывается по доменам (auth/recon/persistence/...), и сценарий одного домена
# законно опирается на базовое правило другого (входящий WMI-exec в lateral - на сетевой вход из
# auth; killchain - на агрегаторы всех доменов). Раньше ссылка за пределы рулсета отклонялась, и
# контент приходилось либо сваливать в один рулсет, либо копировать базовые правила - а копия это
# другой title, т.е. лишний алерт и лишние строки rule_hits на то же событие.
#
# Цена глобального резолва - ГЛОБАЛЬНАЯ уникальность того, по чему резолвим и что пишем в леджер:
# name (ключ ссылки) и title (ключ rule_hits.rule_title) проверяются на сохранении
# (_check_global_uniqueness). Ключ, который всё же оказался неоднозначным (файлы правили мимо
# API), в рантайме считается НЕразрешённым - тише не бывает, но и чужое правило не подставится.
#
# Кэш - по сигнатуре ВСЕХ файлов правил (число + макс. mtime): правка в чужом рулсете меняет
# резолв ссылок этого, поэтому посдиректорная сигнатура тут больше не годится.
_scan_cache_lock = threading.Lock()
_scan_cache: tuple[tuple[int, float], list[dict[str, Any]]] | None = None
# Сама сигнатура - glob + stat всех файлов всех рулсетов (~10 мс на полторы сотни правил), а
# зовётся скан внутри резолва по разу на каждую активную корреляцию (сам резолв main_ruleset.resolve_for
# считается один раз на флаш, app/main.py:_process_batch). Без паузы между проверками резолв main
# стоил ~0.5 с и флаш с десятком источников не укладывался в свой интервал. Поэтому сигнатура
# перепроверяется не чаще раза в _SCAN_RECHECK_SECONDS; запись через этот модуль сбрасывает кэш
# сразу (invalidate_scan_cache), правка файлов мимо API подхватывается с этой задержкой.
_SCAN_RECHECK_SECONDS = 2.0
_scan_checked_at = 0.0
_scan_root: Path | None = None


def invalidate_scan_cache() -> None:
    global _scan_cache, _scan_checked_at
    with _scan_cache_lock:
        _scan_cache = None
        _scan_checked_at = 0.0
_correlation_cache_lock = threading.Lock()
_correlation_cache: dict[str, tuple[tuple[int, float], list[dict[str, Any]]]] = {}


def _custom_rule_files() -> list[tuple[str, Path, str]]:
    """(ruleset_path, файл, kind) по всем именованным custom-рулсетам: *.yml/*.yaml - "base",
    *{CORRELATION_EXT} - "correlation"."""
    out: list[tuple[str, Path, str]] = []
    for meta_path in sorted(CUSTOM_ROOT.glob("*/meta.json")):
        ruleset_dir = meta_path.parent
        ruleset_path = f"{CUSTOM_PREFIX}{ruleset_dir.name}"
        for p in sorted(list(ruleset_dir.glob("*.yml")) + list(ruleset_dir.glob("*.yaml"))):
            out.append((ruleset_path, p, "base"))
        for p in sorted(ruleset_dir.glob(f"*{CORRELATION_EXT}")):
            out.append((ruleset_path, p, "correlation"))
    return out


def _files_signature(paths: list[Path]) -> tuple[int, float]:
    mtimes = []
    for f in paths:
        try:
            mtimes.append(f.stat().st_mtime)
        except OSError:
            continue
    return (len(paths), max(mtimes) if mtimes else 0.0)


def _scan_custom_rules() -> tuple[tuple[int, float], list[dict[str, Any]]]:
    """(сигнатура, записи) - по записи на КАЖДЫЙ документ-правило всех custom-рулсетов:
    {ruleset_path, path, rule_id (имя файла), kind, title, name, id, doc}. Читается напрямую
    yaml.safe_load (без pySigma), кэшируется по сигнатуре всех файлов."""
    global _scan_cache, _scan_checked_at, _scan_root
    now = time.monotonic()
    with _scan_cache_lock:
        if _scan_root != CUSTOM_ROOT:  # тесты подменяют корень - чужой кэш не годится
            _scan_cache, _scan_root = None, CUSTOM_ROOT
        if _scan_cache is not None and now - _scan_checked_at < _SCAN_RECHECK_SECONDS:
            return _scan_cache
    files = _custom_rule_files()
    signature = _files_signature([p for _, p, _ in files])
    with _scan_cache_lock:
        if _scan_cache is not None and _scan_cache[0] == signature:
            _scan_checked_at = now
            return _scan_cache
    entries: list[dict[str, Any]] = []
    for ruleset_path, path, kind in files:
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
        except (OSError, yaml.YAMLError):
            continue
        for doc in docs:
            title = doc.get("title")
            if not title:
                continue
            if kind == "correlation" and not isinstance(doc.get("correlation"), dict):
                continue
            entries.append({
                "ruleset_path": ruleset_path,
                "path": path,
                "rule_id": path.stem,
                "kind": kind,
                "title": str(title),
                "name": str(doc["name"]) if doc.get("name") else None,
                "id": str(doc["id"]) if doc.get("id") else None,
                "doc": doc,
            })
    result = (signature, entries)
    with _scan_cache_lock:
        _scan_cache = result
        _scan_checked_at = now
    return result


def _same_file(a: Path, b: Path | None) -> bool:
    return b is not None and a.resolve() == b.resolve()


def _ref_entry_index(exclude_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Sigma name/id -> запись _scan_custom_rules. Неоднозначный ключ (два РАЗНЫХ правила)
    выкидывается целиком - резолвить его в «какое-нибудь из двух» хуже, чем не резолвить."""
    index: dict[str, dict[str, Any]] = {}
    ambiguous: set[str] = set()
    for entry in _scan_custom_rules()[1]:
        if _same_file(entry["path"], exclude_path):
            continue
        for key in (entry["name"], entry["id"]):
            if not key:
                continue
            prev = index.get(key)
            if prev is not None and not _same_file(prev["path"], entry["path"]):
                ambiguous.add(key)
            index[key] = entry
    for key in ambiguous:
        index.pop(key, None)
    if ambiguous:
        _log.warning("неоднозначные ссылки правил (name/id у нескольких правил): %s", sorted(ambiguous))
    return index


def load_correlation_rules(ruleset_path: str) -> list[dict[str, Any]]:
    """Структурированные описания correlation-правил (Sigma type: event_count/value_count/
    temporal/temporal_ordered) одного custom-рулсета - для app/detection/correlation.py (свой движок
    поверх постоянной таблицы events/rule_hits, а не через pysigma-backend-sqlite - см.
    докстринг модуля про причину и CORRELATION_EXT). Builtin-рулсеты никогда не содержат
    correlation-правил (проверено на всех Zircolite/rules/*.json) - для них всегда [].

    Кэш по сигнатуре ВСЕХ файлов правил (см. _scan_custom_rules): ссылки резолвятся по всем
    custom-рулсетам, так что правка соседнего рулсета тоже меняет результат. Без кэша YAML
    перепарсивался бы на каждый вызов, а вызывается это минимум дважды за батч (active_hit_spec
    ДО store_events + evaluate_batch ПОСЛЕ, для каждого source_batch отдельно)."""
    if not _is_custom_ruleset(ruleset_path):
        return []
    signature, entries = _scan_custom_rules()
    with _correlation_cache_lock:
        cached = _correlation_cache.get(ruleset_path)
        if cached is not None and cached[0] == signature:
            return cached[1]
    result = _load_correlation_rules_uncached(ruleset_path, entries)
    with _correlation_cache_lock:
        _correlation_cache[ruleset_path] = (signature, result)
    return result


def build_ref_index(*, exclude_path: Path | None = None) -> dict[str, dict[str, str]]:
    """Индекс Sigma 'name'/'id' -> {"title", "kind", "ruleset_path"} по ВСЕМ правилам ВСЕХ
    custom-рулсетов: *.yml/*.yaml дают kind="base", *{CORRELATION_EXT} - kind="correlation" (без
    второй категории ссылка correlation -> correlation, т.е. цепочка, никогда бы не резолвилась).
    Это ровно тот словарь, по которому резолвится correlation.rules - и в рантайме
    (_load_correlation_rules_uncached), и при валидации на сохранении
    (_validate_correlation_doc), поэтому он ОДИН на оба пути: разъехавшись, они дали бы
    "сохранилось, но не работает".

    exclude_path - не учитывать конкретный файл (редактирование существующего правила: его
    старая версия на диске не должна участвовать в резолве ссылок новой).

    Межрулсетные ссылки поддержаны (см. комментарий к _scan_custom_rules): ruleset_path в записи -
    где лежит правило, на которое указывает ссылка, по нему исполнение подтягивает зависимости
    (with_dependencies)."""
    return {
        key: {"title": e["title"], "kind": e["kind"], "ruleset_path": e["ruleset_path"]}
        for key, e in _ref_entry_index(exclude_path).items()
    }


def _check_global_uniqueness(docs: list[dict[str, Any]], *, exclude_path: Path | None = None) -> None:
    """title и name своих правил уникальны среди ВСЕХ custom-рулсетов, а не только внутри одного.

    title - ключ леджера rule_hits.rule_title и значение events.matched_rules: два разных правила
    с одним title смешали бы свои попадания в одних и тех же строках, и корреляция по одному
    считала бы события другого. name - ключ ссылки correlation.rules: при межрулсетном резолве
    дубль сделал бы ссылку неоднозначной. Раньше хватало проверки внутри рулсета, пока ссылки
    туда не выходили.

    Исключение - документ с тем же id, что у владельца title/name: это то же самое правило
    (повторная загрузка пака), его обработает логика коллизий по id в save_ruleset_yaml, а не
    отказ всего файла. Дубль title внутри ОДНОГО загружаемого файла - всегда ошибка: раньше такой
    документ молча терял исходный YAML (_match_yaml_by_title), а правило оставалось в манифесте."""
    owners_by_title: dict[str, dict[str, Any]] = {}
    owners_by_name: dict[str, dict[str, Any]] = {}
    for entry in _scan_custom_rules()[1]:
        if _same_file(entry["path"], exclude_path):
            continue
        owners_by_title.setdefault(entry["title"], entry)
        if entry["name"]:
            owners_by_name.setdefault(entry["name"], entry)

    seen_titles: set[str] = set()
    seen_names: set[str] = set()
    for doc in docs:
        title = str(doc.get("title") or "")
        name = str(doc["name"]) if doc.get("name") else None
        doc_id = str(doc["id"]) if doc.get("id") else None
        if title:
            if title in seen_titles:
                raise RuleValidationError(f"title '{title}' встречается в файле больше одного раза")
            seen_titles.add(title)
            owner = owners_by_title.get(title)
            if owner is not None and not (doc_id and owner["id"] == doc_id):
                raise RuleValidationError(
                    f"title '{title}' уже занят правилом в рулсете '{owner['ruleset_path']}'. title - "
                    "ключ попаданий правила (rule_hits) и должен быть уникален среди всех своих "
                    "рулсетов - переименуй правило."
                )
        if name:
            if name in seen_names:
                raise RuleValidationError(f"name '{name}' встречается в файле больше одного раза")
            seen_names.add(name)
            owner = owners_by_name.get(name)
            if owner is not None and not (doc_id and owner["id"] == doc_id):
                raise RuleValidationError(
                    f"name '{name}' уже занят правилом '{owner['title']}' в рулсете "
                    f"'{owner['ruleset_path']}'. По name резолвятся ссылки correlation.rules, он "
                    "должен быть уникален среди всех своих рулсетов."
                )


def with_dependencies(pairs: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, dict[str, Any]]]:
    """Дополняет набор активных правил [(ruleset_path, скомпилированное правило)] тем, на что
    ссылаются активные корреляции из ДРУГИХ рулсетов (транзитивно: ссылка на корреляцию тянет и
    её собственные ссылки).

    Зачем не требовать, чтобы пользователь сам включил зависимость в main: корреляция без своего
    базового правила молча мертва - базовое правило не исполняется движком, в rule_hits ему
    нечего писать. Проверка «зависимость не в main -> 400» на каждом тоггле плодила бы запреты в
    обе стороны (выключить базовое, удалить рулсет, добавить корреляцию раньше базы), а итог один
    и тот же. Подтянутые правила - копии с via_dependency=True (не мутируем кэш манифестов): их
    можно показать отдельно в составе main. Их собственные алерты при этом появляются как у любого
    исполняемого правила - это цена работающей корреляции. required_by - названия корреляций,
    которые потянули правило (подсказка к бейджу «зависимость» в UI)."""
    present = {(src, rule.get("id")) for src, rule in pairs}
    deps: dict[tuple[str, Any], dict[str, Any]] = {}
    out = list(pairs)
    queue = [(src, rule) for src, rule in pairs if rule.get("correlation")]
    # По одному чтению на рулсет за вызов: корреляций и ссылок десятки, а load_* на каждой итерации
    # перепроверяли кэши (stat/скан) заново - это и было основной ценой резолва main.
    corr_by_src: dict[str, dict[str, dict[str, Any]]] = {}
    rules_by_src: dict[str, dict[str, list[dict[str, Any]]]] = {}
    while queue:
        src, rule = queue.pop()
        if src not in corr_by_src:
            corr_by_src[src] = {c["id"]: c for c in load_correlation_rules(src)}
        corr = corr_by_src[src].get(rule.get("id"))
        if corr is None:
            continue
        for ref in corr.get("base_rule_refs") or []:
            dep_src = ref.get("ruleset_path")
            if not dep_src:
                continue
            if dep_src not in rules_by_src:
                by_title: dict[str, list[dict[str, Any]]] = {}
                try:
                    for r in load_rules(dep_src):
                        by_title.setdefault(str(r.get("title")), []).append(r)
                except CatalogError:
                    pass
                rules_by_src[dep_src] = by_title
            for dep in rules_by_src[dep_src].get(ref["title"], []):
                key = (dep_src, dep.get("id"))
                if key in deps:
                    if corr.get("title") not in deps[key]["required_by"]:
                        deps[key]["required_by"].append(corr.get("title"))
                    continue
                if key in present:
                    continue
                present.add(key)
                dep_rule = {**dep, "via_dependency": True, "required_by": [corr.get("title")]}
                deps[key] = dep_rule
                out.append((dep_src, dep_rule))
                if dep.get("correlation"):
                    queue.append((dep_src, dep_rule))
    return out


def find_rules_by_titles(titles: set[str]) -> list[tuple[str, dict[str, Any]]]:
    """[(ruleset_path, скомпилированное правило)] по title среди всех custom-рулсетов - member-
    правила инцидента (GET /incidents/{id}/context) могут лежать не в рулсете корреляции."""
    out: list[tuple[str, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()
    for entry in _scan_custom_rules()[1]:
        key = (entry["ruleset_path"], entry["rule_id"])
        if entry["title"] not in titles or key in seen:
            continue
        seen.add(key)
        try:
            rules = load_rules(entry["ruleset_path"])
        except CatalogError:
            continue
        rule = next((r for r in rules if r.get("id") == entry["rule_id"]), None)
        if rule is not None:
            out.append((entry["ruleset_path"], rule))
    return out


def find_referencing_correlations(
    ruleset_path: str, rule_id: str | None = None, *, only_refs: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Корреляции ВНЕ удаляемого набора, чьи correlation.rules резолвятся в правило rule_id
    рулсета ruleset_path (или в любое правило рулсета, если rule_id=None). only_refs - учитывать
    только ссылки с этими ключами (переименование name: ссылки по id не рвутся)."""
    entries = _scan_custom_rules()[1]
    targets = {
        e["path"].resolve() for e in entries
        if e["ruleset_path"] == ruleset_path and (rule_id is None or e["rule_id"] == rule_id)
    }
    if not targets:
        return []
    index = _ref_entry_index()
    out: list[dict[str, Any]] = []
    for e in entries:
        if e["kind"] != "correlation" or e["path"].resolve() in targets:
            continue
        hits = []
        for ref in e["doc"]["correlation"].get("rules") or []:
            key = str(ref)
            if only_refs is not None and key not in only_refs:
                continue
            target = index.get(key)
            if target is not None and target["path"].resolve() in targets:
                hits.append(key)
        if hits:
            out.append({"ruleset": e["ruleset_path"], "rule_id": e["rule_id"], "title": e["title"], "refs": hits})
    return out


def _conflict_message(what: str, refs: list[dict[str, Any]]) -> str:
    listed = ", ".join(f"'{r['title']}' ({r['ruleset']})" for r in refs[:10])
    more = f" и ещё {len(refs) - 10}" if len(refs) > 10 else ""
    return (
        f"{what}: на него ссылаются корреляции {listed}{more} - они перестанут срабатывать. "
        "Сначала поправь или удали их, либо повтори с force=true."
    )


def _load_correlation_rules_uncached(ruleset_path: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Тело load_correlation_rules без кэша - см. его докстринг.

    Читает *.yml/*.yaml (обычные правила) И *{CORRELATION_EXT} (correlation-правила, в т.ч.
    друг на друга - цепочки вроде auth_after_brutforce_by_account -> ...failures_by_account,
    см. artifacts/content/auth_after_brutforce.yml) напрямую (yaml.safe_load, без pySigma/
    RulesetHandler - тот же "дешёвый browsing"-принцип, что и у остального модуля) - нужны
    структурные поля Sigma YAML (type/group-by/timespan/condition/rules) как есть, не готовый SQL.

    correlation.rules ссылается на соседние правила ЛИБО обычные, ЛИБО correlation - по их
    Sigma 'name' (короткий идентификатор) ИЛИ 'id' (uuid), оба формата валидны по спеке. Индекс
    name/id -> {"title", "kind"} строится по ВСЕМ *.yml/*.yaml ("kind"="base") И ВСЕМ
    *{CORRELATION_EXT} ("kind"="correlation") рулсета - без второй категории ссылки на другую
    корреляцию (цепочки) никогда бы не резолвились, а именно это раньше молча ронялo ВСЕ
    temporal_ordered-правила auth_after_brutforce.yml (см. CLAUDE.md/план Этапа A).
    base_rule_titles - плоский список title'ов (обратная совместимость, используется как OR-
    список в SQL); base_rule_refs - {"title","kind"} на каждую ссылку, нужен app/detection/
    correlation.py (active_hit_spec различает, куда писать hit: store_events - для "base",
    сама корреляция при срабатывании - для "correlation", см. insert_correlation_hits).
    Правило с хотя бы одной неразрешённой ссылкой пропускается защитно - каталог не должен
    падать на кривом/неполном YAML (например пока сохраняется только часть файла). На
    СОХРАНЕНИИ такая ссылка теперь отклоняется громко (_validate_correlation_doc с ref_index),
    так что тихий пропуск здесь остаётся только страховкой для правки файлов мимо API.

    Ссылка может указывать в ДРУГОЙ custom-рулсет - base_rule_refs несёт его ruleset_path."""
    ref_index = build_ref_index()

    # Имя файла - это rule_id, под которым правило лежит в .manifest.json (см.
    # save_custom_rule/_safe_rule_id): в САМОМ YAML поля 'id:' может не быть - Sigma его не
    # требует, и мы его в файл не дописываем. Фолбэк обязателен: по id correlation-запись
    # сопоставляется с манифестом в correlation._active_correlation_rules для "основного
    # рулсета", и с id=None правило молча выпадало из main - сохранялось, показывалось в UI и
    # никогда не срабатывало (тот же класс тихого отказа, что и неразрешимая ссылка).
    corr_docs = [
        (e["doc"], e["rule_id"]) for e in entries
        if e["ruleset_path"] == ruleset_path and e["kind"] == "correlation"
    ]

    results: list[dict[str, Any]] = []
    for doc, file_rule_id in corr_docs:
        corr = doc["correlation"]
        title = doc["title"]
        refs = corr.get("rules") or []
        base_refs: list[dict[str, str]] = []
        unresolved = False
        for ref in refs:
            resolved = ref_index.get(str(ref))
            if resolved is None:
                unresolved = True
                break
            base_refs.append(resolved)
        if unresolved:
            _log.warning("correlation '%s' (%s) пропущена: неразрешимая ссылка", title, ruleset_path)
            continue
        results.append({
            "id": doc.get("id") or file_rule_id,
            "title": title,
            "level": doc.get("level", "informational"),
            "description": doc.get("description", ""),
            "tags": doc.get("tags", []),
            "type": corr.get("type"),
            "group_by": corr.get("group-by") or [],
            "timespan": corr.get("timespan"),
            "condition": corr.get("condition") or {},
            "base_rule_titles": [r["title"] for r in base_refs],
            "base_rule_refs": base_refs,
            "incident": _parse_incident_spec(corr.get("incident")),
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


def _resolve_existing_target(
    ruleset: str | None, new_ruleset_name: str | None
) -> tuple[str | None, Path | None]:
    """Проверка "существующий рулсет ИЛИ новый" (ровно один из двух; builtin как existing-цель
    отклоняется), НИЧЕГО при этом не создающая: для существующего рулсета возвращает
    (ruleset_path, директория), для нового - (None, None).

    Создание нового рулсета откладывает вызывающий (save_custom_rule/save_ruleset_yaml) - до
    момента, когда известно, что в него реально что-то ляжет. Иначе любая ошибка компиляции
    оставляла бы в каталоге пустой рулсет с rule_count: 0."""
    ruleset = (ruleset or "").strip()
    new_ruleset_name = (new_ruleset_name or "").strip()
    if ruleset and new_ruleset_name:
        raise CatalogError("Укажи либо существующий рулсет, либо имя нового - не оба сразу")
    if new_ruleset_name:
        return None, None
    if not ruleset:
        raise CatalogError("Нужно выбрать существующий рулсет или указать имя нового")
    if ruleset.startswith(CUSTOM_PREFIX):
        return ruleset, _custom_ruleset_dir(ruleset)
    raise CatalogError(
        f"Правила можно добавлять только в свои (не встроенные) рулсеты - '{ruleset}' встроенный"
    )


def delete_custom_ruleset(ruleset_path: str, *, force: bool = False) -> None:
    """Удаляет именованный custom-рулсет целиком. Встроенный рулсет - осмысленный отказ
    (CatalogError -> 400), а не "не найден": файл существует, удалять его просто нельзя.
    Если на правила рулсета ссылаются корреляции ДРУГИХ рулсетов - CatalogConflict (409),
    force=True удаляет всё равно."""
    if not ruleset_path.startswith(CUSTOM_PREFIX):
        raise CatalogError(f"Встроенный рулсет удалить нельзя: {ruleset_path}")
    target_dir = _custom_ruleset_dir(ruleset_path)
    if not force:
        refs = find_referencing_correlations(ruleset_path)
        if refs:
            raise CatalogConflict(_conflict_message(f"Рулсет {ruleset_path} нельзя удалить", refs), refs)
    for f in target_dir.iterdir():
        if f.is_file():
            _invalidate_cache(f)
    shutil.rmtree(target_dir)
    invalidate_scan_cache()


# ------------------------------------------------------------------ Кастомные правила (YAML)

def _looks_like_correlation_doc(doc: dict[str, Any]) -> bool:
    return "title" in doc and "correlation" in doc


# Операторы простого (не extended) correlation.condition - см. _validate_correlation_doc и
# app/detection/correlation.py:_COND_OPS (та же семантика, сознательно продублирован список
# ключей, а не импортирован оттуда - rules_catalog не должен зависеть от detection-модуля,
# см. докстринг про однонаправленную зависимость main_ruleset.py -> rules_catalog.py выше).
_CORR_CONDITION_OPS = {"gt", "gte", "lt", "lte", "eq", "neq"}


def _is_simple_correlation_condition(condition: Any) -> bool:
    """True, если condition - словарь ТОЛЬКО из простых операторов (+ 'field' у value_count) -
    та единственная форма, которую умеет считать app/detection/correlation.py. False - для
    "расширенных" condition-выражений Sigma-спеки (temporal_extended/temporal_ordered_extended,
    напр. condition: {expression: "rule_a and rule_b"}) - они НЕ поддержаны (см. CLAUDE.md/
    план Этапа A: ни один SQL-бэкенд Sigma их толком не считает, а нашему движку это отдельная,
    более сложная задача, не входящая в этот этап)."""
    if not isinstance(condition, dict):
        return False
    keys = set(condition.keys()) - {"field"}
    return bool(keys) and keys.issubset(_CORR_CONDITION_OPS)


def _parse_incident_spec(raw: Any) -> dict[str, Any] | None:
    """Нормализует блок correlation.incident в {type, severity?, title?} для
    load_correlation_rules. None, если блока нет или type кривой - молча (валидацию с громкими
    ошибками делает _validate_correlation_doc на СОХРАНЕНИИ; здесь - защитное чтение уже
    лежащего на диске правила, как и всё в _load_correlation_rules_uncached)."""
    if not isinstance(raw, dict):
        return None
    itype = raw.get("type")
    if not itype or not _INCIDENT_TYPE_RE.match(str(itype)):
        return None
    return {
        "type": str(itype),
        "severity": str(raw["severity"]) if raw.get("severity") else None,
        "title": str(raw["title"]).strip() if raw.get("title") else None,
    }


def _validate_correlation_doc(
    doc: dict[str, Any], *, ref_index: dict[str, dict[str, str]] | None = None
) -> None:
    """Лёгкая структурная валидация correlation-документа БЕЗ pySigma (см. докстринг модуля
    про CORRELATION_EXT/почему pySigma тут не участвует вообще). Не полный валидатор Sigma-
    спеки - ловит только очевидные ошибки, чтобы автор правила увидел понятную причину отказа
    при сохранении, а не тихо получил корреляцию, которая никогда не сработает (app/
    correlation.py и так защитно пропускает неподдерживаемые/некорректные записи молча -
    здесь, наоборот, хотим громко предупредить на этапе сохранения).

    Дополнено относительно первой версии (см. CLAUDE.md/план Этапа A - раньше эти три
    ошибки проходили валидацию и потом молча были неактивны): обязательный непустой
    group-by (без него app/detection/correlation.py:evaluate_batch пропускает правило -
    "по всей выборке" корреляция не поддерживается), формат timespan через тот же парсер,
    что и в рантайме (app/timespan.parse_timespan - раньше валидация принимала любую
    непустую строку, включая 'M'/'y', которые рантайм не понимает), и явный отказ
    "расширенных" condition-выражений вместо тихой инертности.

    ref_index (build_ref_index целевого рулсета + документы того же загружаемого файла) -
    если передан, КАЖДАЯ ссылка correlation.rules проверяется на разрешимость. Раньше правило
    с опечаткой в ссылке сохранялось с 201 и молча исчезало из load_correlation_rules (оно
    пропускает записи с неразрешёнными ссылками целиком) - корреляция никогда не срабатывала,
    и в UI это ничем не отличалось от рабочего правила. None - валидация без контекста
    рулсета (прямой вызов compile_custom_rule без target_dir, тесты), ссылки не проверяются."""
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
    if ref_index is not None:
        unresolved = [str(r) for r in refs if str(r) not in ref_index]
        if unresolved:
            known = sorted(ref_index)
            hint = (
                f" Доступные: {', '.join(known[:12])}"
                + ("..." if len(known) > 12 else "")
            ) if known else " Пока нет ни одного своего правила, на которое можно сослаться."
            raise RuleValidationError(
                "correlation.rules ссылается на правила, которых нет ни в одном своём рулсете: "
                + ", ".join(unresolved)
                + ". Ссылка резолвится по Sigma 'name' или 'id' правила любого custom-рулсета "
                "(встроенные не участвуют); сначала сохрани базовое правило." + hint
            )
    group_by = corr.get("group-by")
    if not group_by or not isinstance(group_by, list):
        raise RuleValidationError(
            "correlation.group-by обязателен и должен быть непустым списком полей - "
            "корреляция 'по всей выборке' (без group-by) не поддержана"
        )
    timespan = corr.get("timespan")
    timespan_seconds = timespan_parse(timespan) if timespan else None
    if timespan_seconds is None:
        raise RuleValidationError(
            f"correlation.timespan должен быть числом с единицей s/m/h/d/w (например '5m'), "
            f"получено: {timespan!r}"
        )
    # timespan не должен превышать срок хранения events: ретеншн (app/store.py:
    # delete_events_older_than) удаляет старые events И осиротевшие rule_hits, поэтому окно
    # длиннее ретеншна систематически недосчитывало бы - старая часть окна физически удалена
    # раньше, чем правило успеет её увидеть (см. docs/spec/correlation.md). 0 - ретеншн
    # выключен (храним вечно), проверка не нужна.
    retention_days = getattr(config, "EVENTS_RETENTION_DAYS", 0) or 0
    if retention_days > 0 and timespan_seconds > retention_days * 86400:
        raise RuleValidationError(
            f"correlation.timespan ({timespan}) больше срока хранения событий "
            f"(SIEM_EVENTS_RETENTION_DAYS={retention_days}д) - окно корреляции недосчитывало бы: "
            f"часть окна старше ретеншна физически удаляется вместе с events и rule_hits. "
            f"Уменьши timespan или увеличь SIEM_EVENTS_RETENTION_DAYS."
        )
    condition = corr.get("condition")
    if corr_type in ("event_count", "value_count"):
        if not condition or not _is_simple_correlation_condition(condition):
            raise RuleValidationError(
                f"correlation.condition обязателен для типа '{corr_type}' и должен содержать "
                f"один из операторов: {sorted(_CORR_CONDITION_OPS)}"
            )
        if corr_type == "value_count" and not condition.get("field"):
            raise RuleValidationError("correlation.condition.field обязателен для value_count")
    elif condition is not None and not _is_simple_correlation_condition(condition):
        raise RuleValidationError(
            "Расширенные correlation.condition-выражения (temporal_extended/"
            "temporal_ordered_extended) не поддержаны - condition должен быть словарём из "
            f"операторов {sorted(_CORR_CONDITION_OPS)} или отсутствовать"
        )

    # correlation.incident - помечает правило как ИНЦИДЕНТНОЕ (см. app/detection/correlation.py:
    # evaluate_batch, CLAUDE.md §7 Этап 4). Срабатывание такого правила поднимает инцидент, а
    # НЕ обычный correlation-алерт. Блок необязателен; если задан - валидируем громко.
    incident = corr.get("incident")
    if incident is not None:
        if not isinstance(incident, dict):
            raise RuleValidationError("correlation.incident должен быть словарём {type, severity?, title?}")
        itype = incident.get("type")
        if not itype or not _INCIDENT_TYPE_RE.match(str(itype)):
            raise RuleValidationError(
                "correlation.incident.type обязателен и должен быть slug'ом "
                "[a-z0-9][a-z0-9_]{0,63} (например 'brute_force_success')"
            )
        sev = incident.get("severity")
        if sev is not None and str(sev) not in _SEVERITY_VALUES:
            raise RuleValidationError(
                f"correlation.incident.severity должен быть одним из {sorted(_SEVERITY_VALUES)}, "
                f"получено: {sev!r}"
            )
        title = incident.get("title")
        if title is not None and not str(title).strip():
            raise RuleValidationError("correlation.incident.title, если задан, не может быть пустым")


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
        # Булев бейдж "это правило поднимает инцидент" для UI/браузинга - сам slug/severity/title
        # в манифест не дублируем, их читает load_correlation_rules из raw YAML (как type/group-by).
        "incident": bool(
            isinstance(doc.get("correlation"), dict) and doc["correlation"].get("incident")
        ),
        "rule": [],
        "filename": "",
        "channel": [],
        "eventid": [],
    }


def _docs_look_like_sigma_rule(docs: list[dict[str, Any]]) -> bool:
    """Структурная пре-проверка УЖЕ РАЗОБРАННЫХ документов без обращения к Zircolite/pySigma -
    эквивалент RulesetHandler.is_valid_sigma_rule (title+logsource+detection, либо
    title+correlation).

    Принимает разобранные документы, а не текст, специально: прежняя версия парсила YAML сама
    и на yaml.YAMLError возвращала False, из-за чего вызывающий отвечал общим "должен
    содержать title, logsource и detection" на ЛЮБУЮ синтаксическую ошибку, а ветка с
    реальной позицией ошибки парсера ниже по коду была недостижима."""
    for doc in docs:
        if all(f in doc for f in ("title", "logsource", "detection")):
            return True
        if "title" in doc and "correlation" in doc:
            return True
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


def _validate_rule_id(doc: dict[str, Any]) -> None:
    """Sigma требует, чтобы 'id:' (если он вообще указан) был UUID. Проверяем ЭТО САМИ и ДО
    компиляции, ровно тем же способом, что и pySigma (`UUID(value)`, см. sigma/rule/base.py) -
    иначе пользователь получает сообщение не про ту строку файла.

    Почему нельзя положиться на ошибку снизу: pySigma действительно бросает внятное
    `SigmaIdentifierError: Sigma rule identifier must be an UUID`, но до нас оно не доходит -
    Zircolite (внешний клон, не правим) заранее отсеивает невалидные правила в
    `RulesetHandler` (`is_valid_sigma_rule`, rules.py) и МОЛЧА их выбрасывает, отдавая пустой
    рулсет. Наверх остаётся только факт «правил не получилось», и compile_custom_rule
    вынужденно печатает догадку «проверь detection/logsource» - при формально безупречных
    detection и logsource. Ловили вживую на 'id' с лишними символами в последней группе.

    Нестроковое значение (YAML отдаёт int/float/bool для `id: 12345`) отклоняем тем же
    сообщением: pySigma ловит только ValueError, а `UUID(12345)` бросает TypeError - он ушёл
    бы наружу как ещё менее внятная ошибка компиляции.

    Отсутствующий 'id:' (или `id:` с пустым значением - YAML разбирает его в None) - НЕ
    ошибка: поле необязательное, id сгенерируется автоматически (см. _safe_rule_id)."""
    if "id" not in doc:
        return
    raw = doc.get("id")
    if raw is None:
        return
    try:
        UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise RuleValidationError(
            f"Поле 'id' должно быть UUID (сейчас: '{raw}'). Исправь его или убери строку "
            "'id:' вовсе - тогда id сгенерируется автоматически."
        )


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
    yaml_text: str,
    *,
    target_dir: Path | None = None,
    exclude_filename: str | None = None,
    ref_index: dict[str, dict[str, str]] | None = None,
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

    ref_index - чем резолвить ссылки correlation.rules. None (по умолчанию) - взять из
    target_dir; если и его нет (прямой вызов без контекста рулсета), ссылки не проверяются.
    ПУСТОЙ словарь - осмысленное значение "сослаться не на что" (правило сохраняется ПЕРВЫМ в
    ещё не созданный рулсет, см. save_custom_rule): корреляция в таком рулсете заведомо
    мертва, и это надо сказать сразу, а не молчать.

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
    # YAML разбирается ОДИН раз и до всех проверок - структурная проверка идёт уже по
    # разобранным документам, поэтому синтаксическая ошибка доезжает до пользователя со своей
    # позицией, а не маскируется общим "должен содержать title, logsource и detection".
    try:
        docs = [d for d in yaml.safe_load_all(yaml_text) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Некорректный YAML: {exc}")
    if not _docs_look_like_sigma_rule(docs):
        raise RuleValidationError(
            "YAML должен содержать title, logsource и detection (или title и correlation)."
        )
    # Формат 'id' проверяем ДО компиляции: ошибку про него Zircolite глушит, и до пользователя
    # доезжало сообщение про detection/logsource (см. _validate_rule_id).
    for doc in docs:
        _validate_rule_id(doc)
    exclude_path = (target_dir / exclude_filename) if (target_dir is not None and exclude_filename) else None
    _check_global_uniqueness(docs, exclude_path=exclude_path)

    first_doc = docs[0] if docs else None
    if first_doc is not None and _looks_like_correlation_doc(first_doc):
        # Ссылки correlation.rules проверяем по всем своим рулсетам - неразрешимая ссылка
        # означает правило, которое сохранится, но никогда не сработает. Без target_dir и без
        # явного ref_index (прямой вызов, тесты валидации документа) ссылки не проверяются.
        if ref_index is None and target_dir is not None:
            ref_index = build_ref_index(exclude_path=exclude_path)
        _validate_correlation_doc(first_doc, ref_index=ref_index)
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

    # title берём из разобранных ВЫШЕ документов: expand_placeholders трогает только detection,
    # заголовок он изменить не может - повторно парсить развёрнутый текст незачем.
    title = first_doc.get("title") if first_doc else None

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


def compile_ruleset_yaml(yaml_text: str, *, target_dir: Path | None = None) -> list[dict[str, Any]]:
    """Валидация + компиляция ВСЕХ правил multi-document YAML (одна или несколько Sigma-rule
    документов в одном файле - SigmaCollection.load_ruleset поддерживает это нативно).

    Документы с ключом 'correlation' компилируются ОТДЕЛЬНО от обычных - собственной лёгкой
    валидацией без pySigma (см. докстринг модуля/CORRELATION_EXT). Обычные документы отдаются
    в RulesetHandler ОДНИМ файлом БЕЗ correlation-документов вовсе - именно их совместное
    присутствие в одном SigmaCollection и ломает компиляцию referenced-правила (см. докстринг
    модуля), поэтому исключаем эту ситуацию физически, а не боремся с её последствиями.

    target_dir - директория целевого рулсета, если он уже существует: её правила участвуют в
    резолве correlation.rules наравне с документами самого файла (корреляция в паке может
    ссылаться и на правило из того же файла, и на уже лежащее в рулсете). None - новый рулсет,
    ссылаться можно только внутри файла."""
    if not yaml_text or not yaml_text.strip():
        raise RuleValidationError("Пустой YAML")
    try:
        list(yaml.safe_load_all(yaml_text))  # ранний фейл на невалидном YAML целиком
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Некорректный YAML: {exc}")

    ref_index = build_ref_index()
    file_docs: list[dict[str, Any]] = []
    for doc_text in _split_yaml_documents(yaml_text):
        try:
            parsed = yaml.safe_load(doc_text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict) or not parsed.get("title"):
            continue
        file_docs.append(parsed)
        kind = "correlation" if _looks_like_correlation_doc(parsed) else "base"
        for key in ("name", "id"):
            if parsed.get(key):
                ref_index[str(parsed[key])] = {"title": str(parsed["title"]), "kind": kind, "ruleset_path": ""}
    _check_global_uniqueness(file_docs)

    corr_results: list[dict[str, Any]] = []
    plain_docs: list[str] = []
    for doc_text in _split_yaml_documents(yaml_text):
        try:
            parsed = yaml.safe_load(doc_text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        # Как и в compile_custom_rule: формат 'id' проверяем сами, иначе один документ пака с
        # кривым id молча выпадет из компиляции, а сообщение уведёт к detection/logsource.
        _validate_rule_id(parsed)
        if _looks_like_correlation_doc(parsed):
            _validate_correlation_doc(parsed, ref_index=ref_index)
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
    ruleset_path, куда оно попало).

    Новый рулсет создаётся на диске ТОЛЬКО после успешной компиляции и проверки id: иначе
    любая ошибка в правиле (битый YAML, неразрешимая ссылка корреляции, занятый id) оставляла
    бы в каталоге пустой рулсет с rule_count: 0 - то же, что и у пака в save_ruleset_yaml."""
    target, target_dir = _resolve_existing_target(ruleset, new_ruleset_name)
    # Ссылки correlation.rules резолвятся по всем своим рулсетам - корреляция в ещё не
    # созданном рулсете тоже может опираться на базовые правила других.
    compiled = compile_custom_rule(yaml_text, target_dir=target_dir, ref_index=build_ref_index())
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
    if target_dir is None:
        target = create_custom_ruleset(new_ruleset_name or "")
        target_dir = _custom_ruleset_dir(target)
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
    (что именно и с чем не добавилось) - см. app/main.py:upload_ruleset.

    Новый рулсет (new_ruleset_name) создаётся на диске ТОЛЬКО когда известно, что в него
    реально ляжет хотя бы одно правило: пак, все правила которого столкнулись по id с уже
    существующими, раньше оставлял в каталоге пустую директорию с rule_count: 0."""
    parsed_lists, rule_yaml = _peel_value_list_docs(yaml_text)
    imported = value_lists.import_lists(parsed_lists, mode="replace") if parsed_lists else {
        "created": [], "replaced": [], "merged": [], "skipped": [], "recompile_needed": [],
    }
    if not rule_yaml.strip():
        return None, None, [], imported

    # Цель проверяем ДО компиляции (чтобы не компилировать пак впустую при кривой цели), но
    # создание нового рулсета откладываем до момента, когда есть что писать.
    target, target_dir = _resolve_existing_target(ruleset, new_ruleset_name)
    compiled_rules = compile_ruleset_yaml(rule_yaml, target_dir=target_dir)
    doc_by_title = _match_yaml_by_title(_split_yaml_documents(rule_yaml))
    collisions: list[dict[str, Any]] = []
    with _manifest_lock:
        manifest_path = (target_dir / ".manifest.json") if target_dir is not None else None
        manifest_by_id = (
            {r.get("id"): r for r in _load_manifest_uncached(manifest_path)}
            if manifest_path is not None else {}
        )
        accepted: list[tuple[str, dict[str, Any]]] = []
        for compiled in compiled_rules:
            candidate = compiled.get("id")
            rule_id = _safe_rule_id(candidate)
            if candidate and rule_id == candidate:
                # Сначала целевой рулсет (уже загруженные ранее + добавленные чуть раньше в
                # ЭТОМ ЖЕ цикле, manifest_by_id пополняется по ходу) - дешевле и ловит
                # внутрифайловый дубль, который _find_rule_id_owner (читает с диска) не
                # увидит, пока манифест не записан.
                existing = manifest_by_id.get(rule_id)
                owner = (
                    (target or (new_ruleset_name or ""), str(existing.get("title") or ""))
                    if existing else _find_rule_id_owner(rule_id)
                )
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
            accepted.append((rule_id, compiled))

        if not accepted:
            # Ни одно правило не прошло - на диск не пишем ничего. Нового рулсета не появится
            # вовсе, существующий остаётся как был (манифест не переписываем).
            info = _custom_ruleset_info(target_dir / "meta.json") if target_dir is not None else None
            return info, target, collisions, imported

        if target_dir is None:
            target = create_custom_ruleset(new_ruleset_name or "")
            target_dir = _custom_ruleset_dir(target)
            manifest_path = target_dir / ".manifest.json"
        for rule_id, compiled in accepted:
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
        raise CatalogNotFound(f"Правило не найдено: {rule_id}")
    compiled = compile_custom_rule(yaml_text, target_dir=target_dir, exclude_filename=rule_path.name)
    candidate = compiled.get("id")
    if candidate and candidate != rule_id:
        raise RuleValidationError(
            f"Менять id при редактировании нельзя - оставь 'id: {rule_id}' (или убери строку "
            "'id:' вовсе, исходный id подставится автоматически)."
        )
    # Смена name рвёт ссылки correlation.rules, сделанные по этому name (ссылки по id - нет).
    old_name = _doc_name(rule_path)
    new_name = _doc_name_from_text(yaml_text)
    if old_name and new_name != old_name:
        refs = find_referencing_correlations(ruleset_path, rule_id, only_refs={old_name})
        if refs:
            raise CatalogConflict(_conflict_message(f"Нельзя сменить name '{old_name}'", refs), refs)
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


def _doc_name_from_text(yaml_text: str) -> str | None:
    try:
        first = next((d for d in yaml.safe_load_all(yaml_text) if isinstance(d, dict)), None)
    except yaml.YAMLError:
        return None
    return str(first["name"]) if first and first.get("name") else None


def _doc_name(path: Path) -> str | None:
    try:
        return _doc_name_from_text(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def delete_custom_rule(ruleset_path: str, rule_id: str, *, force: bool = False) -> None:
    """Удаляет своё правило. Если на него ссылаются корреляции (в любом рулсете, кроме самого
    удаляемого файла) - CatalogConflict (409), force=True удаляет всё равно: ссылающиеся
    корреляции дальше молча пропускаются load_correlation_rules."""
    target_dir = _custom_ruleset_dir(ruleset_path)
    rule_path = _find_rule_file(target_dir, rule_id)
    if rule_path is None:
        raise CatalogNotFound(f"Правило не найдено: {rule_id}")
    if not force:
        refs = find_referencing_correlations(ruleset_path, rule_id)
        if refs:
            raise CatalogConflict(_conflict_message(f"Правило {rule_id} нельзя удалить", refs), refs)
    manifest_path = target_dir / ".manifest.json"
    with _manifest_lock:
        manifest = [r for r in _load_manifest_uncached(manifest_path) if r.get("id") != rule_id]
        _write_manifest(manifest_path, manifest)
    rule_path.unlink()
    invalidate_scan_cache()


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
