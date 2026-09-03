"""
Состав "основного рулсета" (main ruleset) - виртуальная композиция правил из ЛЮБЫХ других
рулсетов (built-in и custom, см. app/rules/rules_catalog.py), используемая по умолчанию потоковым
ingest (/ingest/stream) и /ingest/events, где сейчас вообще нет способа выбрать ruleset.

Хранит НЕ копии правил, а только ссылки: какие рулсеты добавлены целиком (included_rulesets) +
точечные исключения внутри них (excluded_rules) + точечные добавления отдельных правил из
рулсетов, которые целиком не добавлены (included_rules). Файл custom_rulesets/main_ruleset.json.

Зависимость однонаправленная: этот модуль импортирует rules_catalog (чтобы читать/валидировать
правила через load_rules), rules_catalog про main ruleset ничего не знает - см. его докстринг.
"""
from __future__ import annotations

import json
import threading
from typing import Any

from app.rules import rules_catalog

STATE_PATH = rules_catalog.CUSTOM_ROOT / "main_ruleset.json"
MAIN_RULESET_ID = "main"

_lock = threading.Lock()


def _default_state() -> dict[str, Any]:
    return {"included_rulesets": [], "excluded_rules": {}, "included_rules": {}}


def load_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return _default_state()
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return _default_state()
    state = _default_state()
    state.update({k: v for k, v in data.items() if k in state})
    return state


def _save_state(state: dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def is_rule_included(state: dict[str, Any], ruleset_path: str, rule_id: str) -> bool:
    if ruleset_path in state["included_rulesets"]:
        return rule_id not in state["excluded_rules"].get(ruleset_path, [])
    return rule_id in state["included_rules"].get(ruleset_path, [])


def ruleset_status(state: dict[str, Any], ruleset_path: str) -> str:
    """"full" - весь рулсет в main (без точечных исключений), "partial" - частично
    (либо целиком добавлен, но с исключениями, либо не добавлен, но есть отдельные правила),
    "none" - совсем не участвует."""
    if ruleset_path in state["included_rulesets"]:
        return "full" if not state["excluded_rules"].get(ruleset_path) else "partial"
    return "partial" if state["included_rules"].get(ruleset_path) else "none"


def resolve_with_sources() -> list[tuple[str, dict[str, Any]]]:
    """Как resolve(), но сохраняет для каждого правила его настоящий ruleset_path -
    нужно вкладке Sigma-правила при просмотре "Основного рулсета" как отдельного пункта в
    селекторе: клик по правилу/кнопка исключения должны бить по НАСТОЯЩЕМУ источнику
    (get_rule/toggle_rule), а не по виртуальному "main". Дёшево по той же причине, что и
    resolve() - см. его докстринг.

    НЕ дедуплицирует по 'id' правила - у скомпилированных Zircolite-рулсетов (в т.ч. built-in
    rules_windows_merged.json) ОДНО Sigma-правило легитимно превращается в НЕСКОЛЬКО записей
    с ОДИНАКОВЫМ id, но разным SQL (разные pipeline-варианты полей под разные источники, напр.
    'HackTool - Mimikatz Execution - Generic' на Security/EventID=4688 и '... - Sysmon' на
    Sysmon/EventID=1 - оба с id=a642964e-...). Дедуп по (ruleset_path, id) здесь стоял раньше
    и молча выкидывал ~37% правил rules_windows_merged.json при добавлении рулсета целиком
    (2680 уникальных id на 4291 запись) - бага, не защита: структура state (included_rulesets -
    список без повторов, included_rules - dict по уникальным путям, каждый src_rules
    проходится ровно один раз) и так гарантирует, что один и тот же элемент списка не
    попадёт в pairs дважды, доп. дедуп не нужен вообще."""
    state = load_state()
    pairs: list[tuple[str, dict[str, Any]]] = []

    for ruleset_path in state["included_rulesets"]:
        try:
            src_rules = rules_catalog.load_rules(ruleset_path)
        except rules_catalog.CatalogError:
            continue  # рулсет удалён с диска мимо on_ruleset_deleted - осиротевшая ссылка, не падаем
        excluded = set(state["excluded_rules"].get(ruleset_path, []))
        for rule in src_rules:
            if rule.get("id") not in excluded:
                pairs.append((ruleset_path, rule))

    for ruleset_path, rule_ids in state["included_rules"].items():
        if ruleset_path in state["included_rulesets"] or not rule_ids:
            continue
        try:
            src_rules = rules_catalog.load_rules(ruleset_path)
        except rules_catalog.CatalogError:
            continue
        wanted = set(rule_ids)
        for rule in src_rules:
            if rule.get("id") in wanted:
                pairs.append((ruleset_path, rule))

    return pairs


def resolve() -> list[dict[str, Any]]:
    """Плоский список скомпилированных правил для движка (app/detection/engine.py:run_batch_with_rules).
    Дёшево: load_rules() для builtin/custom читает уже СКОМПИЛИРОВАННЫЕ правила через
    mtime-кэш rules_catalog._load_json_rules - pySigma тут не участвует вообще, поэтому
    пересчитывать resolve() на каждый батч (без доп. кэша) нормально."""
    return [rule for _src, rule in resolve_with_sources()]


def rule_count() -> int:
    return len(resolve_with_sources())


def toggle_rule(ruleset_path: str, rule_id: str, include: bool) -> bool:
    """Включает/выключает одно правило в main. Бросает CatalogError, если ruleset_path/rule_id
    не существуют (валидация через rules_catalog.load_rules)."""
    rules_catalog.load_rules(ruleset_path)
    with _lock:
        state = load_state()
        if ruleset_path in state["included_rulesets"]:
            excl = set(state["excluded_rules"].get(ruleset_path, []))
            if include:
                excl.discard(rule_id)
            else:
                excl.add(rule_id)
            if excl:
                state["excluded_rules"][ruleset_path] = sorted(excl)
            else:
                state["excluded_rules"].pop(ruleset_path, None)
        else:
            incl = set(state["included_rules"].get(ruleset_path, []))
            if include:
                incl.add(rule_id)
            else:
                incl.discard(rule_id)
            if incl:
                state["included_rules"][ruleset_path] = sorted(incl)
            else:
                state["included_rules"].pop(ruleset_path, None)
        _save_state(state)
        return is_rule_included(state, ruleset_path, rule_id)


def toggle_ruleset(ruleset_path: str, include: bool) -> str:
    """Добавляет/убирает рулсет ЦЕЛИКОМ из main (сбрасывает точечные исключения/добавления по
    нему - они теряют смысл при явном переключении на уровне всего рулсета)."""
    rules_catalog.load_rules(ruleset_path)
    with _lock:
        state = load_state()
        if include:
            if ruleset_path not in state["included_rulesets"]:
                state["included_rulesets"].append(ruleset_path)
        else:
            if ruleset_path in state["included_rulesets"]:
                state["included_rulesets"].remove(ruleset_path)
        state["excluded_rules"].pop(ruleset_path, None)
        state["included_rules"].pop(ruleset_path, None)
        _save_state(state)
        return ruleset_status(state, ruleset_path)


def on_ruleset_deleted(ruleset_path: str) -> None:
    """Чистит ссылки на рулсет, который был удалён из каталога (DELETE /rulesets) - иначе
    resolve() продолжал бы молча его пропускать, но state бы копил осиротевшие записи."""
    with _lock:
        state = load_state()
        changed = False
        if ruleset_path in state["included_rulesets"]:
            state["included_rulesets"].remove(ruleset_path)
            changed = True
        if state["excluded_rules"].pop(ruleset_path, None) is not None:
            changed = True
        if state["included_rules"].pop(ruleset_path, None) is not None:
            changed = True
        if changed:
            _save_state(state)
