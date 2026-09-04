"""
Стейтфул-корреляция поверх постоянной таблицы events/rule_hits (app/store.py).

Почему отдельный модуль, а не pysigma-backend-sqlite/Zircolite (полный разбор - CLAUDE.md §8,
docs/spec/correlation.md): (1) ZircoliteCore создаётся заново на каждый micro-batch flush
ingest-воркера с пустой in-memory БД - между вызовами никакого state вообще нет; (2) даже
НЕЗАВИСИМО от этого - сток (не пропатченный) backend pysigma-backend-sqlite==1.2.0 для
event_count/value_count генерирует SQL БЕЗ единого упоминания timespan (окно вычисляется и
выбрасывается - `str.format` молча игнорирует лишний kwarg), а temporal/temporal_ordered хоть
и накладывают окно, но как "весь срок жизни группы уложился в timespan" (не скользящее окно) -
и temporal_ordered при этом вообще не проверяет порядок появления событий (GROUP_CONCAT
считается и никогда не сравнивается). То же самое воспроизведено и в единственном другом
SQL-совместимом Sigma-бэкенде (pysigma-backend-clickhouse) - это не баг одного бэкенда, а
следствие того, что Sigma-бэкенд генерирует один statement, а скользящее окно с анкером и
переоценкой на каждый flush - свойство движка исполнения, которого у Sigma-бэкендов нет
в принципе. Здесь - свой маленький компилятор по образцу app/filter_lang.py: bound-параметры,
json_extract(...) через app/store.py (без JOIN к events на счётном пути, см. ниже).

Поддержаны correlation type: event_count/value_count/temporal/temporal_ordered, включая
ЦЕПОЧКИ (correlation ссылается на другую correlation, напр. auth_after_brutforce_by_account в
artifacts/content/auth_after_brutforce.yml). "Расширенные" condition-выражения
(temporal_extended/temporal_ordered_extended) не поддержаны - см.
app/rules/rules_catalog.py:_validate_correlation_doc (отклоняются при сохранении, громко).

Триггер - вызывается из app/main.py:_process_batch ПОСЛЕ каждого store.store_events(...), т.е.
после каждого flush ingest-воркера, с коротким замыканием: если ни одно активное
correlation-правило (и ни одна корреляция, реально сработавшая ВЫШЕ по цепочке В ЭТОМ ЖЕ
flush'е) не даёт новых попаданий - до БД дело не доходит вовсе.

Требование к производительности (обязательное, см. CLAUDE.md/docs/spec/correlation.md):
скорость не должна зависеть от размера БД. Достигается ДВУХФАЗНЫМ счётом (см.
_evaluate_correlation_rule): фаза 1 - ОДИН GROUP BY-запрос по rule_hits сразу по ВСЕМ
кандидатным ключам объединённого окна (store.evaluate_correlation_windows, без JOIN к events -
O(H), H = число попаданий в окне, не размер БД); фаза 2 - точная перепроверка ТОЛЬКО
кандидатов, прошедших грубый порог фазы 1 (обычно 0-2 ключа за flush), в их СОБСТВЕННОМ узком
окне (store.evaluate_correlation_window). Ключ к этому - rule_hits.group_json: денормализованные
значения нужных полей пишутся ПРЯМО В rule_hits на store_events (см. active_hit_spec ниже), а
не достаются через JOIN/json_extract(raw_json,...) на events - что и убирает зависимость от
размера events/БД в целом.

ЦЕПОЧКИ без отдельной таблицы: сработавшая корреляция пишется в rule_hits КАК ОБЫЧНОЕ
попадание (store.insert_correlation_hits) - синтетический event_id якоря, rule_title = title
самой корреляции, group_json = её СОБСТВЕННЫЕ group-by значения. Родительская корреляция видит
потомка ТЕМ ЖЕ запросом, что и обычное базовое правило (temporal_ordered/temporal-код не
различает "kind" ссылки при СЧЁТЕ - только active_hit_spec различает его при РЕШЕНИИ, писать
ли hit из store_events). Это работает благодаря ограничению Sigma-спеки для цепочек: связанные
correlation-правила используют один и тот же список group-by полей (иначе имена полей
разошлись бы и родитель не нашёл бы значения в group_json потомка) - _topo_order гарантирует,
что потомки обрабатываются РАНЬШЕ родителей В ОДНОМ И ТОМ ЖЕ проходе evaluate_batch.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from app.rules import main_ruleset, rules_catalog
from app.fields import (
    DST_IP_FIELDS,
    HOST_FIELDS,
    PROCESS_FIELDS,
    SRC_IP_FIELDS,
    TIME_FIELDS,
    USER_FIELDS,
    first_present,
)
from app.models import Alert, Entities, Severity, SigmaRuleRef
from app.store import Store
from app.timespan import parse_timespan

# Типы, которые этот модуль реально эвалуирует - "расширенные" условия (temporal_extended/
# temporal_ordered_extended) сюда не входят и не могут попасть валидацией на сохранении
# (rules_catalog._validate_correlation_doc), но лишняя защита здесь дешёвая.
_EVAL_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}

_COND_OPS: dict[str, Any] = {
    "gte": lambda c, n: c >= n,
    "gt": lambda c, n: c > n,
    "lte": lambda c, n: c <= n,
    "lt": lambda c, n: c < n,
    "eq": lambda c, n: c == n,
}


def _condition_met(condition: dict[str, Any], count: int) -> bool:
    """condition - {"gte": 10} (event_count) или {"field": "Image", "gte": 5} (value_count,
    'field' - имя поля для distinct, обрабатывается отдельно store.evaluate_correlation_window,
    здесь просто пропускается как не-оператор). Пустое/без единого распознанного оператора
    условие - НЕ считается выполненным (иначе пустая condition молча пропускала бы всё)."""
    checked = False
    for op, threshold in condition.items():
        if op == "field":
            continue
        fn = _COND_OPS.get(op)
        if fn is None:
            continue
        try:
            threshold_num = float(threshold)
        except (TypeError, ValueError):
            continue
        checked = True
        if not fn(count, threshold_num):
            return False
    return checked


def _temporal_required_met(condition: dict[str, Any], count: int, n_refs: int) -> bool:
    """temporal/temporal_ordered по спеке не требуют condition - "все ссылки должны появиться
    в окне" (count = distinct-rules >= число ссылок). Если автор правила ВСЁ ЖЕ указал простой
    condition (валидация rules_catalog это допускает) - уважаем его вместо дефолта."""
    if condition and any(op in _COND_OPS for op in condition):
        return _condition_met(condition, count)
    return count >= n_refs


def _normalize_event_time(event_time: str | None) -> str | None:
    """Дублирует store._normalize_event_time (та же 1-строчная трансформация) - окно, которое
    здесь считается, должно быть в ТОЙ ЖЕ нормализованной форме, что и rule_hits.event_time
    (см. app/store.py), иначе BETWEEN в store.evaluate_correlation_window(s) сравнивал бы
    разные форматы. Не импортируется напрямую из store.py (private-имя, отдельный модуль) -
    сознательно небольшое дублирование вместо кросс-модульной завязки на чужую приватную
    функцию (тот же принцип, что уже был здесь до этого изменения)."""
    if event_time is None:
        return None
    return event_time.replace(" ", "T").replace("Z", "")


def _shift_iso(normalized_time: str, delta_seconds: int) -> str | None:
    try:
        dt = datetime.fromisoformat(normalized_time)
    except ValueError:
        return None
    return (dt + timedelta(seconds=delta_seconds)).isoformat()


def _extract_entities(events: list[dict[str, Any]]) -> Entities:
    """Минимальный локальный аналог normalize._extract_entities - не импортируется оттуда
    (приватная функция другого модуля, normalize.py сознательно не трогаем, см. план)."""
    users, hosts, src_ips, dst_ips, processes = set(), set(), set(), set(), set()
    for event in events:
        if v := first_present(event, USER_FIELDS):
            users.add(v)
        if v := first_present(event, HOST_FIELDS):
            hosts.add(v)
        if v := first_present(event, SRC_IP_FIELDS):
            src_ips.add(v)
        if v := first_present(event, DST_IP_FIELDS):
            dst_ips.add(v)
        if v := first_present(event, PROCESS_FIELDS):
            processes.add(v)
    return Entities(
        users=sorted(users), hosts=sorted(hosts), src_ips=sorted(src_ips),
        dst_ips=sorted(dst_ips), processes=sorted(processes),
    )


def _dedup_key(rule_id: str, key_values: tuple[Any, ...]) -> str:
    """Независимая от normalize._dedup_key функция - другая семантика ключа (group-by значения
    корреляции, не (host, main_entity) одного алерта)."""
    raw = f"{rule_id}:" + ":".join(str(v) for v in key_values)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _active_correlation_rules(ruleset_path: str | None) -> list[dict[str, Any]]:
    """Активные correlation-правила ЛЮБОГО типа (фильтрация по типу - дело вызывающей стороны,
    см. _EVAL_TYPES) для ruleset_path: для "main" - объединение из всех custom-рулсетов,
    реально включённых в основной рулсет (main_ruleset.resolve_with_sources, та же логика
    видимости, что уже использует остальной проект); для обычного custom ruleset_path -
    напрямую; для builtin/None - пусто (builtin корреляций не содержит)."""
    if not ruleset_path:
        return []
    if ruleset_path == main_ruleset.MAIN_RULESET_ID:
        active_ids_by_ruleset: dict[str, set[str]] = {}
        for src, rule in main_ruleset.resolve_with_sources():
            if rule.get("correlation"):
                active_ids_by_ruleset.setdefault(src, set()).add(rule.get("id"))
        result: list[dict[str, Any]] = []
        for src, ids in active_ids_by_ruleset.items():
            result += [c for c in rules_catalog.load_correlation_rules(src) if c["id"] in ids]
        return result
    return rules_catalog.load_correlation_rules(ruleset_path)


def active_hit_spec(ruleset_path: str | None) -> dict[str, set[str]]:
    """Названия БАЗОВЫХ (не-correlation) Sigma-правил -> набор полей, которые нужно
    денормализовать в rule_hits.group_json для срабатываний этих правил (см.
    app/store.py:store_events, вызывается app/main.py ДО store_events). Поле = объединение
    group-by ВСЕХ активных correlation-записей, ссылающихся на это правило, плюс
    condition.field у value_count-ссылающихся.

    Ссылки на ДРУГИЕ correlation-правила (цепочки, "kind"="correlation") сюда НЕ попадают -
    когда сама корреляция срабатывает, evaluate_batch пишет её rule_hits-запись НАПРЯМУЮ
    (store.insert_correlation_hits) со ВСЕМИ её собственными group-by полями, hit_spec для
    этого не нужен (см. докстринг модуля про цепочки)."""
    spec: dict[str, set[str]] = {}
    for corr in _active_correlation_rules(ruleset_path):
        if corr.get("type") not in _EVAL_TYPES:
            continue
        group_by = corr.get("group_by") or []
        if not group_by:
            continue
        fields = set(group_by)
        if corr.get("type") == "value_count":
            distinct_field = (corr.get("condition") or {}).get("field")
            if distinct_field:
                fields.add(distinct_field)
        for ref in corr.get("base_rule_refs") or []:
            if ref.get("kind") != "base":
                continue
            spec.setdefault(ref["title"], set()).update(fields)
    return spec


def _topo_order(corr_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Топологический порядок: корреляции, на которые ссылаются ДРУГИЕ активные корреляции
    (цепочки, напр. auth_after_brutforce_by_account -> auth_after_brutforce_failures_by_account
    в artifacts/content/auth_after_brutforce.yml), обрабатываются РАНЬШЕ родителей - иначе
    родитель не увидел бы свежее срабатывание потомка в ЭТОМ ЖЕ flush'е (см. evaluate_batch).
    Стандартный DFS-топосорт; правило, участвующее в цикле ссылок, не роняет весь проход -
    обрабатывается best-effort в исходном порядке (лучше сработать не в оптимальном порядке
    -возможно, на flush позже, когда обе стороны цикла уже видны в rule_hits- чем не
    сработать вовсе)."""
    by_title = {c["title"]: c for c in corr_rules}
    children_of: dict[str, set[str]] = {c["title"]: set() for c in corr_rules}
    for c in corr_rules:
        for ref in c.get("base_rule_refs") or []:
            if ref.get("kind") == "correlation" and ref["title"] in by_title:
                children_of[c["title"]].add(ref["title"])

    ordered: list[dict[str, Any]] = []
    visited: set[str] = set()
    in_progress: set[str] = set()

    def visit(title: str) -> None:
        if title in visited or title not in by_title:
            return
        if title in in_progress:
            return  # цикл - не падаем, оставляем best-effort порядок
        in_progress.add(title)
        for child_title in children_of.get(title, ()):
            visit(child_title)
        in_progress.discard(title)
        visited.add(title)
        ordered.append(by_title[title])

    for c in corr_rules:
        visit(c["title"])
    return ordered


def _sequence_matches_order(sequence: list[tuple[str, str]], expected_titles: list[str]) -> bool:
    """Жадное сопоставление подпоследовательности (стандартный алгоритм "is B a subsequence of
    A"): expected_titles - порядок ссылок Sigma correlation.rules, temporal_ordered требует
    ИМЕННО этот порядок появления. sequence - (rule_title, event_time) по возрастанию времени
    внутри уже отфильтрованного по ключу окна (см. store.fetch_correlation_hit_sequence) - все
    строки уже принадлежат ОДНОМУ group-by-ключу, строк мало (окно узкое), поэтому линейный
    проход дёшев. Апстрим-бэкенды (pysigma-backend-sqlite/-clickhouse) считают такую же
    GROUP_CONCAT-последовательность, но НИКОГДА её не сравнивают - см. докстринг модуля."""
    if not expected_titles:
        return False
    idx = 0
    for title, _ in sequence:
        if title == expected_titles[idx]:
            idx += 1
            if idx == len(expected_titles):
                return True
    return False


def _build_alert(
    corr: dict[str, Any],
    key: tuple[Any, ...],
    count: int,
    sample_events: list[dict[str, Any]],
    source_batch: str,
) -> Alert:
    rule_ref = SigmaRuleRef(
        rule_id=corr.get("id") or "",
        title=corr["title"],
        level=Severity.from_zircolite(corr.get("level")),
        mitre_techniques=[t for t in (corr.get("tags") or []) if str(t).startswith("attack.t")],
        description=corr.get("description", ""),
    )
    entities = _extract_entities(sample_events)
    host = first_present(sample_events[0], HOST_FIELDS) if sample_events else None
    if not host:
        host = "-".join(str(v) for v in key) or "unknown-host"
    return Alert(
        dedup_key=_dedup_key(rule_ref.rule_id, key),
        engine="correlation",
        source_batch=source_batch,
        host=host,
        rule=rule_ref,
        entities=entities,
        event_count=count,
        sample_events=sample_events,
    )


def _evaluate_correlation_rule(
    store: Store,
    corr: dict[str, Any],
    corr_type: str,
    group_by: list[str],
    base_titles: list[str],
    source_batch: str,
    anchors: dict[tuple[Any, ...], str],
    timespan_seconds: int,
    distinct_field: str | None,
) -> dict[tuple[Any, ...], tuple[int, list[dict[str, Any]], str]]:
    """Двухфазный счёт одного correlation-правила по всем кандидатным ключам сразу (см.
    докстринг модуля). anchors - {group-by-ключ: нормализованный anchor_time} из НОВЫХ
    попаданий этого flush'а (вычисляет evaluate_batch). Возвращает ТОЛЬКО ключи, для которых
    условие реально выполнено: {ключ: (count, sample_events, anchor_time)}."""
    windows: dict[tuple[Any, ...], tuple[str, str]] = {}
    for key, anchor_time in anchors.items():
        window_start = _shift_iso(anchor_time, -timespan_seconds)
        if window_start:
            windows[key] = (window_start, anchor_time)
    if not windows:
        return {}

    combined_from = min(ws for ws, _ in windows.values())
    combined_to = max(at for _, at in windows.values())

    if corr_type == "value_count":
        coarse_mode = "distinct_values"
    elif corr_type in ("temporal", "temporal_ordered"):
        coarse_mode = "distinct_rules"
    else:
        coarse_mode = "events"

    coarse = store.evaluate_correlation_windows(
        rule_titles=base_titles, source_batch=source_batch,
        time_from=combined_from, time_to=combined_to,
        group_by=group_by, mode=coarse_mode, distinct_field=distinct_field,
    )

    condition = corr.get("condition") or {}
    n_refs = len(base_titles)
    result: dict[tuple[Any, ...], tuple[int, list[dict[str, Any]], str]] = {}

    for key, (window_start, anchor_time) in windows.items():
        coarse_count = coarse.get(key, 0)
        # Короткое замыкание фазы 2 по грубому порогу фазы 1: окно фазы 1 (объединённое)
        # шире-или-равно индивидуальному окну ключа -> coarse_count никогда не занижен
        # относительно точного - пропуск здесь безопасен, не даёт ложноотрицательных.
        if corr_type in ("temporal", "temporal_ordered"):
            if not _temporal_required_met(condition, coarse_count, n_refs):
                continue
        elif not _condition_met(condition, coarse_count):
            continue

        if corr_type == "temporal_ordered":
            sequence = store.fetch_correlation_hit_sequence(
                rule_titles=base_titles, source_batch=source_batch,
                time_from=window_start, time_to=anchor_time,
                group_by=group_by, key_values=key,
            )
            if not _sequence_matches_order(sequence, base_titles):
                continue
            precise = store.evaluate_correlation_window(
                base_rule_titles=base_titles, group_by=group_by, key_values=key,
                source_batch=source_batch, time_from=window_start, time_to=anchor_time,
                mode="distinct_rules",
            )
            count = precise["count"]
        elif corr_type == "temporal":
            precise = store.evaluate_correlation_window(
                base_rule_titles=base_titles, group_by=group_by, key_values=key,
                source_batch=source_batch, time_from=window_start, time_to=anchor_time,
                mode="distinct_rules",
            )
            if not _temporal_required_met(condition, precise["count"], n_refs):
                continue
            count = precise["count"]
        else:
            precise = store.evaluate_correlation_window(
                base_rule_titles=base_titles, group_by=group_by, key_values=key,
                source_batch=source_batch, time_from=window_start, time_to=anchor_time,
                distinct_field=distinct_field,
            )
            count = precise["count"]
            if not _condition_met(condition, count):
                continue

        result[key] = (count, precise["sample_events"], anchor_time)
    return result


def evaluate_batch(
    store: Store,
    ruleset_path: str | None,
    source_batch: str,
    matched_events_by_title: dict[str, list[dict[str, Any]]],
) -> int:
    """Точка входа, зовётся из app/main.py:_process_batch после каждого store.store_events(...)
    (т.е. после каждого flush ingest-воркера). matched_events_by_title - {rule_title: [сырые
    dict событий, сматченных В ЭТОМ батче под этим source_batch]}. Возвращает число
    созданных/обновлённых correlation-алертов."""
    if not ruleset_path or not matched_events_by_title:
        return 0
    corr_rules = [c for c in _active_correlation_rules(ruleset_path) if c.get("type") in _EVAL_TYPES]
    if not corr_rules:
        return 0
    corr_rules = _topo_order(corr_rules)

    # Копия входного словаря - пополняется синтетическими "попаданиями" срабатывающих
    # correlation-правил ЭТОГО ЖЕ прохода (см. докстринг модуля про цепочки), не мутируем
    # аргумент вызывающей стороны.
    fired_by_title: dict[str, list[dict[str, Any]]] = {
        title: list(events) for title, events in matched_events_by_title.items()
    }

    alerts: list[Alert] = []

    for corr in corr_rules:
        if Severity.from_zircolite(corr.get("level")) == Severity.informational:
            continue  # informational - шум, алерты по нему не заводим (см. normalize.py/UI)
        group_by = corr.get("group_by") or []
        if not group_by:
            continue  # без group-by корреляция была бы "по всей выборке" - не поддерживаем
        base_titles = corr.get("base_rule_titles") or []
        if not base_titles:
            continue

        new_matches: list[dict[str, Any]] = []
        for title in base_titles:
            new_matches += fired_by_title.get(title, [])
        if not new_matches:
            continue  # короткое замыкание - ни одна ссылка не "горела" в этом батче

        timespan_seconds = parse_timespan(corr.get("timespan"))
        if timespan_seconds is None:
            continue

        corr_type = corr["type"]
        distinct_field = None
        if corr_type == "value_count":
            distinct_field = (corr.get("condition") or {}).get("field")
            if not distinct_field:
                continue

        # Один кандидатный ключ на набор значений group-by полей; якорь конца окна - event_time
        # САМОГО ПОЗДНЕГО из новых попаданий с этим ключом (НЕ datetime.now() - иначе
        # корреляции никогда бы не срабатывали при replay исторических датасетов, напр. OTRF
        # Security-Datasets, где все event_time уже в прошлом).
        anchors: dict[tuple[Any, ...], str] = {}
        for event in new_matches:
            raw_key = tuple(event.get(f) for f in group_by)
            if any(v is None for v in raw_key):
                continue
            # str(...) на КАЖДОЕ значение - group_json на записи (store_events/
            # insert_correlation_hits) хранит значения ИСКЛЮЧИТЕЛЬНО строками (см. store.py),
            # а store.evaluate_correlation_windows возвращает ключи ИЗ group_json (тоже
            # строки). Без этой нормализации числовое/булево поле в group-by (напр. EventID)
            # давало бы Python-ключ (4625,) (int), который никогда не совпал бы со строковым
            # ("4625",) из фазы 1 - корреляция молча не срабатывала бы.
            key = tuple(str(v) for v in raw_key)
            normalized = _normalize_event_time(first_present(event, TIME_FIELDS))
            if not normalized:
                continue
            if key not in anchors or normalized > anchors[key]:
                anchors[key] = normalized
        if not anchors:
            continue

        fired = _evaluate_correlation_rule(
            store, corr, corr_type, group_by, base_titles, source_batch,
            anchors, timespan_seconds, distinct_field,
        )
        if not fired:
            continue

        corr_hit_rows: list[tuple[str, str, str, str, str | None]] = []
        for key, (count, sample_events, anchor_time) in fired.items():
            alert = _build_alert(corr, key, count, sample_events, source_batch)
            alerts.append(alert)
            group_values = {f: str(v) for f, v in zip(group_by, key)}
            corr_hit_rows.append((
                f"corr:{corr['title']}:{alert.dedup_key}:{anchor_time}",
                corr["title"], source_batch, anchor_time, json.dumps(group_values),
            ))
            # Синтетическое "попадание" видно родительским correlation-правилам ЭТОГО ЖЕ
            # прохода (см. _topo_order) - те же имена полей, что у group_by ЭТОЙ корреляции
            # (по Sigma-спеке цепочки используют одинаковый group-by у всех звеньев), плюс
            # синтетическое SystemTime - anchor родителя вычисляется ТЕМ ЖЕ кодом чуть выше
            # (first_present(event, TIME_FIELDS)), без отдельной ветки под "источник попадания".
            fired_by_title.setdefault(corr["title"], []).append({**group_values, "SystemTime": anchor_time})
        # Пишем СРАЗУ (не батчим до конца прохода) - родительская correlation, обрабатываемая
        # НИЖЕ по topo-порядку в ЭТОМ ЖЕ вызове, считает свой count запросом К БД
        # (store.evaluate_correlation_window(s)), а не по fired_by_title - если отложить
        # запись, родитель не увидел бы только что сработавшего потомка вообще (fired_by_title
        # даёт лишь "новое попадание есть" + anchor для короткого замыкания/окна, реальный СЧЁТ
        # всегда идёт через rule_hits в БД, см. докстринг модуля).
        if corr_hit_rows:
            store.insert_correlation_hits(corr_hit_rows)

    if not alerts:
        return 0
    return store.upsert_correlation_alerts(alerts)
