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
скорость не должна зависеть от размера БД. Достигается A3-оценкой (_evaluate_correlation_rule):
на каждое активное правило за flush - ОДИН range-scan по rule_hits
(store.fetch_correlation_hits), СУЖЕННЫЙ до тех group-by-ключей, у которых в этом flush'е были
новые попадания, в диапазоне [min(new) - timespan, max(new) + timespan]; дальше - проход
СКОЛЬЗЯЩИМ окном в памяти (_best_anchor, O(H), H = число попаданий в окне для этих ключей, не
размер БД) по ВСЕМ точкам-якорям конца окна. Проверять все точки-якоря, а не одну на
max(event_time), нужно из-за перемешанного порядка прихода (форвардер выгрузил буфер,
разъехались часы, replay): «позднее» событие со старой меткой раньше сдвигало якорь назад, и
окно переставало накрывать уже сохранённые свежие хиты - правило молча не взводилось (краевой
эффект, см. docs/spec/correlation.md). На найденное окно - один store.evaluate_correlation_window
за авторитетным счётом и sample_events (единственное место с JOIN к events - ради контента
события, не для счёта). Ключ к независимости от размера БД - rule_hits.group_json:
денормализованные значения нужных полей пишутся ПРЯМО В rule_hits на store_events (см.
active_hit_spec ниже), а не достаются через JOIN/json_extract(raw_json,...) на events.

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

from app import updates
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
from app.models import Alert, Entities, Incident, Severity, SigmaRuleRef
from app.store import Store
from app.timespan import parse_timespan
from app.timeutil import normalize_event_time

# Типы, которые этот модуль реально эвалуирует - "расширенные" условия (temporal_extended/
# temporal_ordered_extended) сюда не входят и не могут попасть валидацией на сохранении
# (rules_catalog._validate_correlation_doc), но лишняя защита здесь дешёвая.
_EVAL_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}

# Префикс синтетического event_id, под которым сработавшая корреляция пишет своё попадание в
# rule_hits (цепочки, см. evaluate_batch/_split_synthetic_hit). Настоящие events.event_id -
# uuid4, двоеточий не содержат вовсе, так что пересечения быть не может.
_SYNTHETIC_HIT_PREFIX = "corr:"
# Предел рекурсии разворота цепочки в реальные события (_expand_synthetic_samples). Цикл
# невозможен (_topo_order отвергает его раньше), это защита от аномально длинной цепочки.
_MAX_EXPAND_DEPTH = 4
# Потолок sample_events у корреляции/инцидента. Больше дефолтного sample_limit=10 у
# store.evaluate_correlation_window: у цепочки в список идут и сэмплы её собственного окна,
# и развёрнутые события предков (напр. успешный вход ПЛЮС предшествующие неудачи).
_MAX_SAMPLE_EVENTS = 20

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


def _shift_iso(normalized_time: str, delta_seconds: int) -> str | None:
    try:
        dt = datetime.fromisoformat(normalized_time)
    except ValueError:
        return None
    return (dt + timedelta(seconds=delta_seconds)).isoformat()


def _split_synthetic_hit(event_id: str, known_titles: list[str]) -> tuple[str, str] | None:
    """Разбирает синтетический event_id попадания корреляции "corr:{dedup}:{title}:{anchor}"
    (формат задаётся в evaluate_batch) в (title, anchor_time). None - если это обычный
    event_id настоящего события или title не принадлежит ни одному известному правилу.

    Позиционно надёжны только первые два сегмента (dedup - hex без ':'), а title и anchor_time
    оба могут содержать ':' - поэтому title не "вырезается", а СОПОСТАВЛЯЕТСЯ с реальными
    названиями активных correlation-правил (самое длинное совпадение - на случай, когда одно
    название является префиксом другого)."""
    if not event_id.startswith(_SYNTHETIC_HIT_PREFIX):
        return None
    parts = event_id.split(":", 2)
    if len(parts) < 3:
        return None
    rest = parts[2]
    for title in sorted(known_titles, key=len, reverse=True):
        if rest.startswith(title + ":"):
            return title, rest[len(title) + 1:]
    return None


def _expand_synthetic_samples(
    store: Store,
    corr_index: dict[str, dict[str, Any]],
    source_batch: str,
    event_ids: list[str],
    limit: int,
    depth: int = 0,
) -> list[dict[str, Any]]:
    """Разворачивает синтетические попадания ЦЕПОЧКИ в РЕАЛЬНЫЕ события правила-предка.

    Зачем: попадание сработавшей корреляции живёт в rule_hits с синтетическим event_id, которому
    в events не соответствует ничего - JOIN в store.evaluate_correlation_window его молча
    пропускает. Из-за этого у корреляции НАД корреляцией sample_events приходили пустыми, а
    вместе с ними пустыми были и entities (они извлекаются из сэмплов) - то есть карточка
    инцидента и контекст агента для самых интересных сценариев (brute-force -> успешный вход,
    повторяющиеся всплески разведки) не содержали ни одного события. Для агента Этапа 5 это
    отсутствие входных данных, а не косметика.

    Как: по синтетическому id узнаём title предка и anchor его окна, по rule_hits.group_json -
    ключ, по которому он тогда сработал (store.fetch_hit_group_values), дальше берём сэмплы
    ЕГО собственного окна [anchor - timespan, anchor] тем же store.evaluate_correlation_window.
    Если предок сам ссылался на корреляцию - рекурсия (ограничена _MAX_EXPAND_DEPTH, хотя цикл
    невозможен: _topo_order отвергает циклы ещё на этапе построения порядка).

    Стоимость платится ТОЛЬКО в момент реального срабатывания цепочки и только на контент
    событий - счётный путь (см. докстринг модуля) не затрагивается вообще."""
    if depth >= _MAX_EXPAND_DEPTH or limit <= 0 or not corr_index:
        return []
    collected: list[dict[str, Any]] = []
    for event_id in event_ids:
        if len(collected) >= limit:
            break
        parsed = _split_synthetic_hit(event_id, list(corr_index))
        if parsed is None:
            continue
        title, anchor_time = parsed
        child = corr_index.get(title)
        if child is None:
            continue
        group_by = child.get("group_by") or []
        base_titles = child.get("base_rule_titles") or []
        timespan_seconds = parse_timespan(child.get("timespan"))
        if not group_by or not base_titles or timespan_seconds is None:
            continue
        group_values = store.fetch_hit_group_values(event_id, title)
        if not group_values or any(f not in group_values for f in group_by):
            continue
        window_start = _shift_iso(anchor_time, -timespan_seconds)
        if not window_start:
            continue
        child_type = child.get("type")
        inner = store.evaluate_correlation_window(
            base_rule_titles=base_titles,
            group_by=group_by,
            key_values=tuple(group_values[f] for f in group_by),
            source_batch=source_batch,
            time_from=window_start,
            time_to=anchor_time,
            mode=("distinct_rules" if child_type in ("temporal", "temporal_ordered") else None),
            distinct_field=(child.get("condition") or {}).get("field") if child_type == "value_count" else None,
            sample_limit=limit - len(collected),
        )
        collected += inner["sample_events"]
        if len(collected) < limit:
            collected += _expand_synthetic_samples(
                store, corr_index, source_batch, inner["event_ids"], limit - len(collected), depth + 1,
            )
    return collected[:limit]


def _merge_samples(
    direct: list[dict[str, Any]], expanded: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    """Сводит сэмплы окна самой корреляции и развёрнутые события предков в один хронологический
    список без повторов (одно и то же событие может прийти обоими путями, если его зацепили и
    базовое правило родителя, и базовое правило потомка). Порядок - по нормализованному времени
    события; событий без распознаваемого времени немного, они уходят в конец."""
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []
    for event in direct + expanded:
        try:
            fingerprint = json.dumps(event, sort_keys=True, default=str)
        except (TypeError, ValueError):
            fingerprint = repr(event)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        merged.append(event)
    merged.sort(key=lambda e: normalize_event_time(first_present(e, TIME_FIELDS)) or "9999")
    return merged[:limit]


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
            # {**c, ...} - НЕ мутируем dict'ы из кэша rules_catalog. ruleset_path (реальный
            # custom-рулсет-источник, не "main") нужен инцидентам для GET /incidents/{id}/context.
            result += [
                {**c, "ruleset_path": src}
                for c in rules_catalog.load_correlation_rules(src) if c["id"] in ids
            ]
        return result
    return [
        {**c, "ruleset_path": ruleset_path}
        for c in rules_catalog.load_correlation_rules(ruleset_path)
    ]


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


def _build_incident(
    corr: dict[str, Any],
    incident_spec: dict[str, Any],
    key: tuple[Any, ...],
    group_values: dict[str, str],
    sample_events: list[dict[str, Any]],
    anchor_time: str,
    timespan_seconds: int,
    base_titles: list[str],
    source_batch: str,
) -> Incident | None:
    """Строит Incident для сработавшего инцидентного correlation-правила (см. evaluate_batch).
    Идентичность - ИСТОЧНИК + фиксированный бакет по timespan: window_bucket = anchor,
    округлённый вниз до кратности timespan в секундах;
    dedup_key = sha256(source_batch:type:group_values:window_bucket)[:16].
    Повтор в том же бакете -> UPDATE строки (store.upsert_incidents). None, если anchor_time не
    парсится (бакет не посчитать) - ключ пропускается.

    source_batch в ключе ОБЯЗАТЕЛЕН: всё остальное в инциденте живёт в рамках одного источника -
    счёт корреляции сужен по source_batch (store.fetch_correlation_hits), колонка incidents.
    source_batch одна, DELETE /batches/{источник} чистит инциденты по ней. Без источника в
    ключе два разных источника, увидевшие ту же сущность в том же бакете (обычное дело: один
    IP атакует два сервера, у каждого свой форвардер), схлопывались в ОДНУ строку: UPDATE
    перезаписывал окно/sample_events/entities данными второго источника, а метка source_batch
    оставалась от первого - карточка показывала события B под ярлыком A, member-алерты
    приезжали из обоих (link_alerts_to_incident фильтрует по ТЕКУЩЕМУ батчу, не по батчу
    инцидента), а /incidents/{id}/context собирал related_events по источнику A, где сэмплов
    из B нет вовсе. Удаление батча довершало расхождение с обеих сторон."""
    try:
        epoch = int(datetime.fromisoformat(anchor_time).timestamp())
    except ValueError:
        return None
    bucket_start = datetime.fromtimestamp((epoch // timespan_seconds) * timespan_seconds)
    window_bucket = bucket_start.isoformat()

    raw = (
        f"{source_batch}:{incident_spec['type']}:"
        + ":".join(str(v) for v in key)
        + f":{window_bucket}"
    )
    dedup_key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    window_start = _shift_iso(anchor_time, -timespan_seconds) or anchor_time
    sev = incident_spec.get("severity") or corr.get("level") or "medium"
    techniques = [t for t in (corr.get("tags") or []) if str(t).startswith("attack.t")]

    return Incident(
        dedup_key=dedup_key,
        incident_type=incident_spec["type"],
        title=incident_spec.get("title") or corr["title"],
        severity=Severity.from_zircolite(sev),
        source_batch=source_batch,
        ruleset_path=corr.get("ruleset_path", ""),
        correlation_rule_id=corr.get("id") or "",
        correlation_rule_title=corr["title"],
        group_key=dict(group_values),
        member_rule_titles=list(base_titles),
        window_start=window_start,
        window_end=anchor_time,
        window_bucket=window_bucket,
        mitre_techniques=techniques,
        entities=_extract_entities(sample_events),
        sample_events=sample_events,
    )


def _best_anchor(
    hits: list[tuple[str, str, str | None]],
    corr_type: str,
    timespan_seconds: int,
    condition: dict[str, Any],
    n_refs: int,
    anchor_lo: str,
    anchor_hi: str,
) -> str | None:
    """A3: ищет САМУЮ ПОЗДНЮЮ точку-якорь e (= event_time какого-то попадания), для которой окно
    [e - timespan, e] удовлетворяет условию правила. None, если такой нет.

    Зачем не один якорь на max(event_time), как раньше: при перемешанном порядке прихода
    (форвардер выгрузил буфер, разъехались часы, replay) «позднее» событие со старой меткой
    времени сдвигало бы якорь назад, и окно [anchor - timespan, anchor] переставало бы
    накрывать уже сохранённые более свежие хиты - правило молча не взводилось (краевой эффект,
    см. docs/spec/correlation.md). Здесь проверяются ВСЕ точки-якоря в интересном диапазоне.

    hits: [(event_time, rule_title, distinct_value)] по возрастанию времени, ВСЕ для одного
    group-by-ключа. anchor_lo/anchor_hi ограничивают якоря диапазоном [min(new), max(new) +
    timespan]: окно может ВПЕРВЫЕ сработать в этом flush'е только если содержит хотя бы одно
    из новых событий - окна без новых событий уже оценивались на прошлых проходах.

    Скользящее окно двумя указателями: O(H) для event_count; O(H) для temporal[_ordered]
    (мультимножество rule_title); O(H) для value_count (мультимножество distinct-значений).
    Порядок для temporal_ordered здесь НЕ проверяется (только достижимость порога по числу
    разных правил) - его точно перепроверяет вызывающая сторона через
    store.fetch_correlation_hit_sequence в найденном окне."""
    n = len(hits)
    if n == 0:
        return None
    lo = 0
    rule_counts: dict[str, int] = {}
    val_counts: dict[str, int] = {}
    best: str | None = None
    for hi in range(n):
        et_hi, rt_hi, dv_hi = hits[hi]
        rule_counts[rt_hi] = rule_counts.get(rt_hi, 0) + 1
        if dv_hi is not None:
            val_counts[dv_hi] = val_counts.get(dv_hi, 0) + 1

        lo_bound = _shift_iso(et_hi, -timespan_seconds)
        if lo_bound is None:
            continue  # не смогли посчитать окно - эту точку-якорь пропускаем
        while lo < hi and hits[lo][0] < lo_bound:
            et_lo, rt_lo, dv_lo = hits[lo]
            rule_counts[rt_lo] -= 1
            if rule_counts[rt_lo] == 0:
                del rule_counts[rt_lo]
            if dv_lo is not None:
                val_counts[dv_lo] -= 1
                if val_counts[dv_lo] == 0:
                    del val_counts[dv_lo]
            lo += 1

        if not (anchor_lo <= et_hi <= anchor_hi):
            continue  # окно [et_hi - timespan, et_hi] не содержит ни одного НОВОГО события

        if corr_type == "value_count":
            ok = _condition_met(condition, len(val_counts))
        elif corr_type in ("temporal", "temporal_ordered"):
            ok = _temporal_required_met(condition, len(rule_counts), n_refs)
        else:
            ok = _condition_met(condition, hi - lo + 1)
        if ok:
            best = et_hi  # берём самую позднюю подходящую (цикл идёт по возрастанию времени)
    return best


def _evaluate_correlation_rule(
    store: Store,
    corr: dict[str, Any],
    corr_type: str,
    group_by: list[str],
    base_titles: list[str],
    source_batch: str,
    new_spans: dict[tuple[Any, ...], tuple[str, str]],
    timespan_seconds: int,
    distinct_field: str | None,
    corr_index: dict[str, dict[str, Any]],
) -> dict[tuple[Any, ...], tuple[int, list[dict[str, Any]], str, list[str]]]:
    """A3-оценка одного correlation-правила по всем кандидатным ключам сразу (см. докстринг
    модуля / _best_anchor). new_spans - {group-by-ключ: (min, max нормализованного event_time
    среди НОВЫХ попаданий этого flush'а)} (вычисляет evaluate_batch). Возвращает ТОЛЬКО ключи,
    для которых условие реально выполнено: {ключ: (count, sample_events, anchor_time,
    event_ids)} - event_ids (новое, см. store.evaluate_correlation_window) нужны для
    store.link_alerts_to_incident (цепочка event -> alert -> incident без "сущностей")."""
    if not new_spans:
        return {}

    # Диапазон точек-якорей: окно [e - timespan, e] может ВПЕРВЫЕ сработать только если содержит
    # хотя бы одно новое событие -> e in [min(new), max(new) + timespan]. Данные для скользящего
    # окна нужны от (самый ранний якорь) - timespan.
    min_new = min(lo for lo, _ in new_spans.values())
    max_new = max(hi for _, hi in new_spans.values())
    fetch_from = _shift_iso(min_new, -timespan_seconds)
    anchor_hi = _shift_iso(max_new, timespan_seconds)
    if not fetch_from or not anchor_hi:
        return {}

    rows = store.fetch_correlation_hits(
        rule_titles=base_titles, source_batch=source_batch,
        time_from=fetch_from, time_to=anchor_hi,
        group_by=group_by, keys=list(new_spans.keys()), distinct_field=distinct_field,
    )
    by_key: dict[tuple[str, ...], list[tuple[str, str, str | None]]] = {}
    for key, et, rt, dv in rows:
        by_key.setdefault(key, []).append((et, rt, dv))

    condition = corr.get("condition") or {}
    n_refs = len(base_titles)
    result: dict[tuple[Any, ...], tuple[int, list[dict[str, Any]], str]] = {}

    for key, hits in by_key.items():
        # Дешёвый гейт: грубая оценка по ВСЕМ вытащенным хитам ключа (диапазон шире любого
        # под-окна ширины timespan -> оценка сверху). Не прошёл здесь - не пройдёт нигде.
        if corr_type == "value_count":
            coarse = len({dv for _, _, dv in hits if dv is not None})
            gate = _condition_met(condition, coarse)
        elif corr_type in ("temporal", "temporal_ordered"):
            coarse = len({rt for _, rt, _ in hits})
            gate = _temporal_required_met(condition, coarse, n_refs)
        else:
            gate = _condition_met(condition, len(hits))
        if not gate:
            continue

        anchor_time = _best_anchor(
            hits, corr_type, timespan_seconds, condition, n_refs, min_new, anchor_hi
        )
        if anchor_time is None:
            continue
        window_start = _shift_iso(anchor_time, -timespan_seconds)
        if not window_start:
            continue

        # Авторитетный счёт + sample_events по найденному окну через тот же store-метод, что и
        # раньше (единственное место с JOIN к events - ради контента событий, не для счёта).
        precise = store.evaluate_correlation_window(
            base_rule_titles=base_titles, group_by=group_by, key_values=key,
            source_batch=source_batch, time_from=window_start, time_to=anchor_time,
            mode=("distinct_rules" if corr_type in ("temporal", "temporal_ordered") else None),
            distinct_field=distinct_field,
        )
        count = precise["count"]
        if corr_type in ("temporal", "temporal_ordered"):
            if not _temporal_required_met(condition, count, n_refs):
                continue
        elif not _condition_met(condition, count):
            continue

        if corr_type == "temporal_ordered":
            sequence = store.fetch_correlation_hit_sequence(
                rule_titles=base_titles, source_batch=source_batch,
                time_from=window_start, time_to=anchor_time,
                group_by=group_by, key_values=key,
            )
            if not _sequence_matches_order(sequence, base_titles):
                continue

        # Синтетические попадания предков (цепочка) не джойнятся к events - разворачиваем их в
        # реальные события, иначе sample_events (а с ними и entities) у корреляции НАД
        # корреляцией остались бы пустыми, см. _expand_synthetic_samples.
        sample_events = precise["sample_events"]
        expanded = _expand_synthetic_samples(
            store, corr_index, source_batch, precise["event_ids"],
            limit=_MAX_SAMPLE_EVENTS - len(sample_events),
        )
        if expanded:
            sample_events = _merge_samples(sample_events, expanded, _MAX_SAMPLE_EVENTS)

        result[key] = (count, sample_events, anchor_time, precise["event_ids"])
    return result


def evaluate_batch(
    store: Store,
    ruleset_path: str | None,
    source_batch: str,
    matched_events_by_title: dict[str, list[dict[str, Any]]],
    link_specs_out: list[dict[str, Any]] | None = None,
) -> int:
    """Точка входа, зовётся из app/main.py:_process_batch после каждого store.store_events(...)
    (т.е. после каждого flush ingest-воркера). matched_events_by_title - {rule_title: [сырые
    dict событий, сматченных В ЭТОМ батче под этим source_batch]}. Возвращает число
    созданных/обновлённых correlation-алертов + инцидентов.

    link_specs_out (Этап 4, необязателен) - если передан список, evaluate_batch дописывает в
    него по одной записи на КАЖДЫЙ созданный/обновлённый инцидент:
    {dedup_key, incident_id, source_batch, event_ids, window_start, window_end}. event_ids -
    ВСЕ event_id (реальные и синтетические "corr:...", см. store.evaluate_correlation_window),
    реально вошедшие в выигрышное окно - цепочка event -> alert -> incident, БЕЗ сопоставления
    по значению "сущности" (см. store.link_alerts_to_incident, docs/spec/incidents.md).
    app/main.py:_process_batch по этим записям ПОСЛЕ store.upsert_alerts (и после
    store.link_events_to_alerts - события этого же батча уже должны знать свой alert_id)
    привязывает уже сохранённые алерты к инциденту - раньше, внутри evaluate_batch, алертов
    zircolite текущего flush ещё нет в БД."""
    if not ruleset_path or not matched_events_by_title:
        return 0
    corr_rules = [c for c in _active_correlation_rules(ruleset_path) if c.get("type") in _EVAL_TYPES]
    if not corr_rules:
        return 0
    corr_rules = _topo_order(corr_rules)
    # Индекс по названию - им _expand_synthetic_samples узнаёт окно/ключ правила-предка по
    # синтетическому попаданию цепочки (title в rule_hits - это именно title correlation-правила).
    corr_index = {c["title"]: c for c in corr_rules if c.get("title")}

    # Копия входного словаря - пополняется синтетическими "попаданиями" срабатывающих
    # correlation-правил ЭТОГО ЖЕ прохода (см. докстринг модуля про цепочки), не мутируем
    # аргумент вызывающей стороны.
    fired_by_title: dict[str, list[dict[str, Any]]] = {
        title: list(events) for title, events in matched_events_by_title.items()
    }

    alerts: list[Alert] = []
    incidents: list[Incident] = []

    for corr in corr_rules:
        incident_spec = corr.get("incident")
        # informational - шум, алертов по нему не заводим (см. normalize.py/UI). НО помеченное
        # инцидентное правило пропускаем сквозь эту отсечку: у него severity инцидента берётся
        # из incident.severity (или дефолт medium), а не из level correlation-правила.
        if not incident_spec and Severity.from_zircolite(corr.get("level")) == Severity.informational:
            continue
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

        # Один кандидатный ключ на набор значений group-by полей. Для КАЖДОГО ключа собираем
        # (min, max) нормализованного event_time среди НОВЫХ попаданий этого flush'а - это
        # диапазон, в котором A3-оценка ищет точку-якорь конца окна (см. _best_anchor). НЕ
        # datetime.now() - иначе корреляции никогда бы не срабатывали при replay исторических
        # датасетов (напр. OTRF Security-Datasets, где все event_time уже в прошлом).
        new_spans: dict[tuple[Any, ...], tuple[str, str]] = {}
        for event in new_matches:
            raw_key = tuple(event.get(f) for f in group_by)
            if any(v is None for v in raw_key):
                continue
            # str(...) на КАЖДОЕ значение - group_json на записи (store_events/
            # insert_correlation_hits) хранит значения ИСКЛЮЧИТЕЛЬНО строками (см. store.py),
            # а store-методы корреляции возвращают ключи ИЗ group_json (тоже строки). Без этой
            # нормализации числовое/булево поле в group-by (напр. EventID) давало бы Python-ключ
            # (4625,) (int), который никогда не совпал бы со строковым ("4625",) - корреляция
            # молча не срабатывала бы.
            key = tuple(str(v) for v in raw_key)
            normalized = normalize_event_time(first_present(event, TIME_FIELDS))
            if not normalized:
                continue
            if key not in new_spans:
                new_spans[key] = (normalized, normalized)
            else:
                lo, hi = new_spans[key]
                new_spans[key] = (min(lo, normalized), max(hi, normalized))
        if not new_spans:
            continue

        fired = _evaluate_correlation_rule(
            store, corr, corr_type, group_by, base_titles, source_batch,
            new_spans, timespan_seconds, distinct_field, corr_index,
        )
        if not fired:
            continue

        corr_hit_rows: list[tuple[str, str, str, str, str | None]] = []
        for key, (count, sample_events, anchor_time, event_ids) in fired.items():
            group_values = {f: str(v) for f, v in zip(group_by, key)}
            if incident_spec:
                built = _build_incident(
                    corr, incident_spec, key, group_values, sample_events,
                    anchor_time, timespan_seconds, base_titles, source_batch,
                )
                if built is None:
                    continue  # anchor_time не распарсился - бакет не посчитать
                incidents.append(built)
                hit_dedup = built.dedup_key
                if link_specs_out is not None:
                    link_specs_out.append({
                        "dedup_key": built.dedup_key,
                        "source_batch": source_batch,
                        "event_ids": event_ids,
                        "window_start": built.window_start,
                        "window_end": built.window_end,
                    })
            else:
                alert = _build_alert(corr, key, count, sample_events, source_batch)
                alerts.append(alert)
                hit_dedup = alert.dedup_key
            # dedup_key ВСЕГДА второй ":"-сегмент (split(":", 2)) - формат гарантирован именно
            # этим порядком (не зависит от того, что title/anchor_time сами могут содержать
            # ":"): store.link_alerts_to_incident парсит его отсюда для цепочек (сработка ДРУГОЙ
            # correlation-записи среди event_ids родителя) БЕЗ похода в БД - dedup_key сам себя
            # несёт. Раньше было f"corr:{title}:{dedup}:{anchor}" - dedup оказывался НЕ на
            # фиксированной позиции, распарсить его надёжно было нельзя.
            corr_hit_rows.append((
                f"corr:{hit_dedup}:{corr['title']}:{anchor_time}",
                corr["title"], source_batch, anchor_time, json.dumps(group_values),
            ))
            # Синтетическое "попадание" видно родительским correlation-правилам ЭТОГО ЖЕ
            # прохода (см. _topo_order) - те же имена полей, что у group_by ЭТОЙ корреляции
            # (по Sigma-спеке цепочки используют одинаковый group-by у всех звеньев), плюс
            # синтетическое SystemTime - anchor родителя вычисляется ТЕМ ЖЕ кодом чуть выше
            # (first_present(event, TIME_FIELDS)), без отдельной ветки под "источник попадания".
            # Пишется и для инцидентных правил - на случай цепочки, где инцидентное правило
            # само является звеном другой корреляции (единообразие, лишним не бывает).
            fired_by_title.setdefault(corr["title"], []).append({**group_values, "SystemTime": anchor_time})
        # Пишем СРАЗУ (не батчим до конца прохода) - родительская correlation, обрабатываемая
        # НИЖЕ по topo-порядку в ЭТОМ ЖЕ вызове, считает свой count запросом К БД
        # (store.evaluate_correlation_window(s)), а не по fired_by_title - если отложить
        # запись, родитель не увидел бы только что сработавшего потомка вообще (fired_by_title
        # даёт лишь "новое попадание есть" + anchor для короткого замыкания/окна, реальный СЧЁТ
        # всегда идёт через rule_hits в БД, см. докстринг модуля).
        if corr_hit_rows:
            store.insert_correlation_hits(corr_hit_rows)

    n = 0
    if alerts:
        n += store.upsert_correlation_alerts(alerts)
        # Автообновление списков в UI (app/updates.py) - бампим тут, а не в main.py: запись
        # correlation-алертов/инцидентов идёт отсюда напрямую, и возвращаемое наружу число (n)
        # смешивает алерты с инцидентами - по нему вызывающий не восстановит, какой список
        # реально поменялся. created=0 намеренно: upsert_correlation_alerts возвращает ВСЕ
        # обработанные строки, а не только созданные, и пока окно живо, одна и та же корреляция
        # переписывается на каждом flush - "N новых алертов" в бейдже росло бы на ровном месте.
        # Список всё равно перечитается (version бампнулась), просто без числа.
        updates.bump("alerts")
    if incidents:
        upserted = store.upsert_incidents(incidents)
        updates.bump("incidents", created=sum(1 for _, was_new in upserted if was_new))
        for (incident_id, was_new), inc in zip(upserted, incidents):
            # Повтор в том же бакете (was_new=False) с уже завершённым расследованием -> ре-энкью
            # в queued (новый контекст для агента); queued/running не трогается (store.enqueue_*).
            store.enqueue_investigation(incident_id, requeue_terminal=not was_new)
            if link_specs_out is not None:
                for spec in link_specs_out:
                    if spec.get("dedup_key") == inc.dedup_key:
                        spec["incident_id"] = incident_id
        n += len(incidents)
    return n
