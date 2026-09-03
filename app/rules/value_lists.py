"""
Именованные списки значений (value lists) для Sigma-правил - реализация штатного
Sigma-плейсхолдера `%name%` + модификатора `|expand`.

Идея: в правиле пишется
    detection:
      selection:
        Image|endswith|expand:
          - '%hacktool_binaries%'
а сам список утилит хранится ОТДЕЛЬНО (data/value_lists/hacktool_binaries.yml) и правится
через вкладку "Списки" в UI. Перед компиляцией правила плейсхолдер разворачивается в обычный
Sigma-список значений (OR-семантика), модификатор `expand` убирается - дальше правило
компилируется штатным путём, pySigma/Zircolite плейсхолдер вообще не видят (см.
app/rules/rules_catalog.py:compile_custom_rule/compile_ruleset_yaml).

Почему разворачиваем САМИ, а не через pysigma ValuePlaceholderTransformation: Zircolite
(RulesetHandler.sigma_rules_to_ruleset) жёстко собирает ProcessingPipeline из имён
установленных pipeline-плагинов, воткнуть свой ProcessingPipeline с динамическим mapping в
его публичный API нельзя без форка. Разворот текста ДО компиляции - тот же принцип "свой
маленький парсер без внешней зависимости", что и у app/filter_lang.py / app/detection/correlation.py.

На диске правило хранится с `%name%` (source of truth) - списки "живые": правка списка
влечёт пересборку зависимых правил (см. rules_catalog.recompile_rules_for_value_list,
вызывается из main.py после update_list).

Модуль намеренно НЕ импортирует rules_catalog (чтобы не заводить цикл: rules_catalog ->
value_lists). Всё, что требует знания про правила/рулсеты (rules_using / recompile), живёт
в rules_catalog и оркестрируется из main.py.
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

import yaml

# файл лежит в app/rules/, до корня проекта — три уровня вверх
BASE_DIR = Path(__file__).resolve().parent.parent.parent
# data/ - тот же общий корень runtime-данных, что и custom_rulesets/uploads (см.
# app/rules/rules_catalog.py:CUSTOM_ROOT, docker-compose.yml). Под Docker монтируется volume-ом.
VALUE_LISTS_ROOT = BASE_DIR / "data" / "value_lists"
VALUE_LISTS_ROOT.mkdir(parents=True, exist_ok=True)

# Имя списка = имя плейсхолдера = имя файла (<name>.yml). Отдельный индекс не нужен.
_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
# Значение-запись, которая ЦЕЛИКОМ является плейсхолдером. Встроенные (foo%name%bar) в v1
# не поддержаны - только запись целиком.
_PLACEHOLDER_RE = re.compile(r"^%([A-Za-z0-9_]+)%$")
# Для defensive-фолбэка, когда YAML не парсится (см. placeholders_used).
_PLACEHOLDER_ANY_RE = re.compile(r"%([A-Za-z0-9_]+)%")

_MAX_VALUES = 20_000
_MAX_DESCRIPTION = 2000

_lock = threading.Lock()


class ValueListError(Exception):
    """Проблема со списком значений (не найден, пуст, недопустимое имя, уже существует) -
    main.py транслирует в HTTP 400/404/409, rules_catalog - в RuleValidationError при компиляции."""


# ------------------------------------------------------------------ файловое хранилище

def _list_path(name: str) -> Path:
    return VALUE_LISTS_ROOT / f"{name}.yml"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_values(values: Any) -> list[str]:
    """Список непустых строк: trim, выкидываем пустые, дедуп с сохранением порядка."""
    if not isinstance(values, list):
        raise ValueListError("'values' должен быть списком строк")
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    if len(out) > _MAX_VALUES:
        raise ValueListError(f"слишком много значений в списке (> {_MAX_VALUES})")
    return out


def _load_raw(name: str) -> dict[str, Any] | None:
    path = _list_path(name)
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueListError(f"не удалось прочитать список '{name}': {exc}")
    if not isinstance(data, dict):
        raise ValueListError(f"файл списка '{name}' повреждён (ожидался YAML-словарь)")
    return data


def _write(name: str, description: str, values: list[str], created_at: str) -> dict[str, Any]:
    doc = {
        "name": name,
        "description": description,
        "created_at": created_at,
        "updated_at": _now_iso(),
        "values": values,
    }
    _list_path(name).write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8"
    )
    return doc


# ------------------------------------------------------------------ CRUD

def list_lists() -> list[dict[str, Any]]:
    """Сводка всех списков для вкладки "Списки" (без самих значений)."""
    out: list[dict[str, Any]] = []
    for path in sorted(VALUE_LISTS_ROOT.glob("*.yml")):
        name = path.stem
        try:
            raw = _load_raw(name) or {}
        except ValueListError:
            continue  # повреждённый файл - пропускаем, не роняем весь список (как list_rulesets)
        values = raw.get("values") or []
        out.append({
            "name": name,
            "description": raw.get("description", ""),
            "value_count": len(values) if isinstance(values, list) else 0,
            "updated_at": raw.get("updated_at", ""),
        })
    return out


def get_list(name: str) -> dict[str, Any] | None:
    raw = _load_raw(name)
    if raw is None:
        return None
    values = raw.get("values") or []
    return {
        "name": name,
        "description": raw.get("description", ""),
        "created_at": raw.get("created_at", ""),
        "updated_at": raw.get("updated_at", ""),
        "values": list(values) if isinstance(values, list) else [],
    }


def create_list(name: str, description: str, values: list[str]) -> dict[str, Any]:
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise ValueListError(
            "Имя списка: 1-64 символа A-Z a-z 0-9 _ (оно же имя плейсхолдера %имя%)"
        )
    description = (description or "").strip()[:_MAX_DESCRIPTION]
    values = _normalize_values(values)
    with _lock:
        if _list_path(name).exists():
            raise ValueListError(f"Список '{name}' уже существует")
        return _write(name, description, values, created_at=_now_iso())


def update_list(name: str, description: str, values: list[str]) -> dict[str, Any] | None:
    """Имя неизменяемо (переименование порвало бы ссылки в правилах). None - списка нет."""
    description = (description or "").strip()[:_MAX_DESCRIPTION]
    values = _normalize_values(values)
    with _lock:
        raw = _load_raw(name)
        if raw is None:
            return None
        created_at = raw.get("created_at") or _now_iso()
        return _write(name, description, values, created_at=created_at)


def delete_list(name: str) -> bool:
    """False - списка не было. Проверку "используется в правилах" делает вызывающая сторона
    (main.py через rules_catalog.rules_using_value_list) - здесь только файловая операция."""
    with _lock:
        path = _list_path(name)
        if not path.is_file():
            return False
        path.unlink()
        return True


# ------------------------------------------------------------------ раскрытие плейсхолдеров

def _resolve_placeholder_values(placeholder_name: str) -> list[str]:
    raw = _load_raw(placeholder_name)
    if raw is None:
        raise ValueListError(
            f"плейсхолдер %{placeholder_name}% не найден - создай список во вкладке «Списки»"
        )
    values = raw.get("values") or []
    if not isinstance(values, list) or not values:
        raise ValueListError(f"список '{placeholder_name}' пуст - добавь значения")
    return [str(v) for v in values]


def _key_has_expand(key: str) -> bool:
    return any(seg.strip().lower() == "expand" for seg in str(key).split("|"))


def _key_without_expand(key: str) -> str:
    return "|".join(seg for seg in str(key).split("|") if seg.strip().lower() != "expand")


def _expand_map(node: dict[str, Any]) -> bool:
    """Разворачивает ключи с `|expand` внутри одной field:value-мапы detection. Возвращает
    True, если что-то изменилось."""
    changed = False
    for key in list(node.keys()):
        if not _key_has_expand(key):
            continue
        raw = node[key]
        values = raw if isinstance(raw, list) else [raw]
        expanded: list[Any] = []
        for v in values:
            m = _PLACEHOLDER_RE.match(v.strip()) if isinstance(v, str) else None
            if m is None:
                expanded.append(v)
                continue
            expanded.extend(_resolve_placeholder_values(m.group(1)))
        # дедуп с сохранением порядка (значения из списка могут пересечься с явными)
        seen: set[Any] = set()
        deduped: list[Any] = []
        for x in expanded:
            k = x if isinstance(x, (str, int, float, bool)) else repr(x)
            if k in seen:
                continue
            seen.add(k)
            deduped.append(x)

        new_key = _key_without_expand(key)
        if new_key in node and new_key != key:
            prev = node[new_key]
            prev = prev if isinstance(prev, list) else [prev]
            deduped = prev + [x for x in deduped if x not in prev]
        node[new_key] = deduped
        if new_key != key:
            del node[key]
        changed = True
    return changed


def _iter_detection_maps(det: dict[str, Any]):
    for sid, sub in det.items():
        if sid == "condition":
            continue
        if isinstance(sub, dict):
            yield sub
        elif isinstance(sub, list):
            for item in sub:
                if isinstance(item, dict):
                    yield item


def expand_placeholders(yaml_text: str) -> str:
    """Разворачивает `%name%` под ключами с `|expand` в detection всех документов YAML.

    Быстрый путь: если подстроки 'expand' в тексте нет вовсе - возвращаем исходный текст
    как есть (не пересериализуем -> сохраняются комментарии/форматирование правила). Результат
    пересериализации нужен только компилятору, на диск он не пишется (см. докстринг модуля).

    Бросает ValueListError, если плейсхолдер не найден или ссылается на пустой список.
    Невалидный YAML не наша забота - возвращаем как есть, дальше упадёт компилятор с внятной
    YAML-ошибкой."""
    if "expand" not in yaml_text:
        return yaml_text
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return yaml_text
    changed = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        det = doc.get("detection")
        if not isinstance(det, dict):
            continue
        for sub_map in _iter_detection_maps(det):
            if _expand_map(sub_map):
                changed = True
    if not changed:
        return yaml_text
    # width=4096: не даём safe_dump сворачивать длинные значения переносом (при загрузке YAML
    # свернёт обратно в пробел, но для значений со значимыми пробелами это был бы риск).
    return yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, width=4096)


def placeholders_used(yaml_text: str) -> set[str]:
    """Имена плейсхолдеров, на которые ссылается detection (через ключи с `|expand`).
    Для GET /value-lists/{name}.used_by, счётчиков и пересборки при правке списка."""
    names: set[str] = set()
    if "expand" not in yaml_text:
        return names
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return set(_PLACEHOLDER_ANY_RE.findall(yaml_text))  # defensive: правило пока недописано
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        det = doc.get("detection")
        if not isinstance(det, dict):
            continue
        for sub_map in _iter_detection_maps(det):
            for key, raw in sub_map.items():
                if not _key_has_expand(key):
                    continue
                for v in (raw if isinstance(raw, list) else [raw]):
                    m = _PLACEHOLDER_RE.match(v.strip()) if isinstance(v, str) else None
                    if m:
                        names.add(m.group(1))
    return names


# ------------------------------------------------------------------ загрузка файлом

# Sigma processing-pipeline: значения плейсхолдеров задаются трансформацией value_placeholders
# (или query_expansion_placeholders) с блоком mapping: {имя: [значения]}. Это и есть "формат
# Sigma для плейсхолдеров" - отдельного файла-списка спецификация не определяет.
_PIPELINE_PLACEHOLDER_TYPES = {"value_placeholders", "query_expansion_placeholders"}
# Ключи, наличие которых означает "это документ-правило/пайплайн-инструкция, НЕ определение списка".
_RULE_MARKER_KEYS = ("logsource", "detection", "correlation", "title")


class ParsedList(NamedTuple):
    name: str
    description: str
    values: list[str]


def _mapping_from_pipeline(doc: dict[str, Any]) -> dict[str, list[Any]]:
    """{имя плейсхолдера: [значения]} из transformations[].mapping пайплайн-документа Sigma.
    Несколько подходящих трансформаций в одном документе - маппинги объединяются."""
    out: dict[str, list[Any]] = {}
    trs = doc.get("transformations")
    if not isinstance(trs, list):
        return out
    for tr in trs:
        if not isinstance(tr, dict) or str(tr.get("type", "")).strip() not in _PIPELINE_PLACEHOLDER_TYPES:
            continue
        mapping = tr.get("mapping")
        if isinstance(mapping, dict):
            for key, val in mapping.items():
                out.setdefault(str(key), []).extend(val if isinstance(val, list) else [val])
    return out


def _is_native_list_doc(doc: dict[str, Any]) -> bool:
    """Наш формат выгрузки: {name, description?, values: [...]} и никаких признаков правила."""
    return (
        isinstance(doc.get("name"), str)
        and isinstance(doc.get("values"), list)
        and not any(k in doc for k in _RULE_MARKER_KEYS)
    )


def is_list_document(doc: dict[str, Any]) -> bool:
    """СТРОГАЯ проверка "документ - определение списка" для '+ Загрузить рулсет' (rules_catalog):
    только явный pipeline с value_placeholders ИЛИ наш {name, values}. "Голый" mapping
    {имя: [...]} здесь НЕ распознаётся (в контексте загрузки рулсета его легко спутать с
    кривым правилом) - он принимается только явной загрузкой списков (parse_list_file)."""
    if not isinstance(doc, dict):
        return False
    return bool(_mapping_from_pipeline(doc)) or _is_native_list_doc(doc)


def parse_list_file(text: str) -> list[ParsedList]:
    """Разбирает файл со списками (вкладка «Списки» → «+ Загрузить список»). Форматы:
      - Sigma pipeline YAML: transformations с type: value_placeholders /
        query_expansion_placeholders и mapping: {имя: [значения]} (один файл → много списков);
      - наш формат: {name, description?, values: [...]}, в т.ч. multi-document;
      - «голый» YAML-словарь {имя: [значения], ...} (тот же mapping, но без обёртки pipeline).
    Имена валидируются _NAME_RE, значения нормализуются (_normalize_values). Одно имя,
    встреченное в файле дважды, объединяется по значениям."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ValueListError(f"Некорректный YAML: {exc}")
    if not docs:
        raise ValueListError("Пустой файл")

    collected: dict[str, ParsedList] = {}

    def _add(name: Any, description: str, values: Any) -> None:
        name = str(name).strip()
        if not _NAME_RE.match(name):
            raise ValueListError(
                f"Недопустимое имя списка '{name}' - нужно [A-Za-z0-9_] длиной 1..64"
            )
        vals = _normalize_values(list(values) if isinstance(values, (list, tuple)) else [values])
        if name in collected:
            prev = collected[name]
            merged = prev.values + [v for v in vals if v not in prev.values]
            collected[name] = ParsedList(name, prev.description or description, merged)
        else:
            collected[name] = ParsedList(name, description, vals)

    for doc in docs:
        if not isinstance(doc, dict):
            raise ValueListError("Каждый документ файла должен быть YAML-словарём")
        pmap = _mapping_from_pipeline(doc)
        if pmap:
            pipeline_desc = str(doc.get("name") or "")
            for key, val in pmap.items():
                _add(key, pipeline_desc, val)
            continue
        if _is_native_list_doc(doc):
            _add(doc["name"], str(doc.get("description") or ""), doc["values"])
            continue
        # «голый» mapping {имя: [значения], ...} - принимаем, только если ни одного ключа-маркера
        # правила и все значения похожи на значения списка (список/скаляр).
        if doc and not any(k in doc for k in (*_RULE_MARKER_KEYS, "transformations")) and all(
            isinstance(v, (list, str, int, float)) for v in doc.values()
        ):
            for key, val in doc.items():
                _add(key, "", val)
            continue
        raise ValueListError(
            "Документ не распознан как определение списка: ожидается Sigma pipeline с "
            "value_placeholders.mapping, формат {name, values} или {имя: [значения]}"
        )

    return list(collected.values())


def import_lists(parsed: list[ParsedList], mode: str) -> dict[str, list[str]]:
    """Пишет разобранные списки на диск. mode:
      - create  - существующие не трогать (в skipped);
      - replace - перезаписать целиком (в replaced + recompile_needed);
      - merge   - объединить значения с текущими (в merged + recompile_needed).
    recompile_needed - имена, по которым надо пересобрать зависимые правила (делает вызывающая
    сторона через rules_catalog.recompile_rules_for_value_list). Сам fan-out тут не делаем -
    модуль не знает про rules_catalog."""
    if mode not in ("create", "replace", "merge"):
        raise ValueListError("mode: create | replace | merge")
    res: dict[str, list[str]] = {"created": [], "replaced": [], "merged": [], "skipped": [], "recompile_needed": []}
    for pl in parsed:
        existing = get_list(pl.name)
        if existing is None:
            create_list(pl.name, pl.description, pl.values)
            res["created"].append(pl.name)
        elif mode == "create":
            res["skipped"].append(pl.name)
        elif mode == "replace":
            update_list(pl.name, pl.description or existing["description"], pl.values)
            res["replaced"].append(pl.name)
            res["recompile_needed"].append(pl.name)
        else:  # merge
            merged = existing["values"] + [v for v in pl.values if v not in existing["values"]]
            update_list(pl.name, existing["description"] or pl.description, merged)
            res["merged"].append(pl.name)
            res["recompile_needed"].append(pl.name)
    return res
