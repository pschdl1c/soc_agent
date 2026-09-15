"""
FastAPI-сервис мини-SIEM поверх Zircolite.

Запуск: uvicorn app.main:app --reload --port 8000 (порт/хост переопределяются
        через SIEM_HOST/SIEM_PORT в .env, см. app/config.py) - либо python -m app.main.
Swagger: http://localhost:8000/docs
UI аналитика: http://localhost:8000/
"""
from __future__ import annotations

import json
import logging
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

try:
    # Единственный источник правды — [project].version в pyproject.toml (пакет ставится
    # `pip install -e .` / `pip install .`). Фолбэк — на случай запуска из исходников без установки.
    __version__ = _pkg_version("soc-agent")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.5.0"

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from app import config, incidents, kb, logging_setup, updates
from app.detection import correlation
from app.detection.engine import ZircoliteEngine
from app.detection.normalize import zircolite_results_to_alerts
from app.fields import INGEST_SOURCE_FIELD
from app.filter_lang import FILTER_OPS, FilterSyntaxError, compile_filter_query
from app.ingest_queue import IngestQueueFull, IngestWorker
from app.models import (
    CustomRuleSubmit,
    CustomRuleUpdate,
    IncidentStatusUpdate,
    IngestEventsRequest,
    IngestFileRequest,
    IngestResponse,
    MainRulesetRuleToggle,
    MainRulesetToggle,
    SourceCreate,
    SourceUpdate,
    ValueListCreate,
    ValueListUpdate,
)
from app.rules import main_ruleset, rules_catalog, value_lists
from app.rules.rules_catalog import CatalogConflict, CatalogError, CatalogNotFound, RuleValidationError
from app.rules.value_lists import ValueListError
from app.store import Store

BASE_DIR = config.BASE_DIR
CONFIG_PATH = config.ZIRCOLITE_CONFIG_PATH
DEFAULT_RULESET_PATH = config.DEFAULT_RULESET_PATH
DB_PATH = config.DB_PATH
STATIC_DIR = Path(__file__).resolve().parent / "static"
UPLOADS_DIR = config.UPLOADS_DIR
UPLOADS_DIR.mkdir(exist_ok=True)

_EXTENSION_TO_INPUT_TYPE = {
    ".evtx": "evtx",
    ".json": "json",
    ".jsonl": "json",
    ".ndjson": "json",
    ".xml": "xml",
    ".csv": "csv",
    ".log": "auditd",  # частый случай для auditd/syslog-подобных текстовых логов
}


def _guess_input_type(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return _EXTENSION_TO_INPUT_TYPE.get(suffix, "json")

# Логирование настраивается ДО создания движка/хранилища - первое же сообщение (загрузка
# рулсета) должно уйти уже в UTF-8-хендлер, а не в print с кодировкой консоли Windows.
logging_setup.configure(config.LOG_LEVEL)
logger = logging.getLogger(__name__)

engine = ZircoliteEngine(config_path=CONFIG_PATH, default_ruleset_path=DEFAULT_RULESET_PATH)
store = Store(db_path=DB_PATH)


def _build_matched_row_map(raw_results: list[dict]) -> dict[int, list[str]]:
    """Из сырых результатов Zircolite строит {row_id: [названия правил]} для одного батча."""
    mapping: dict[int, list[str]] = {}
    for rule in raw_results:
        for event in rule.get("matches", []):
            row_id = event.get("row_id")
            if row_id is None:
                continue
            mapping.setdefault(row_id, []).append(rule.get("title", "Unnamed Rule"))
    return mapping


def _split_events_by_source(events: list[dict], default_label: str) -> dict[str, list[dict]]:
    """Разбивает УЖЕ обработанные движком события обратно по их реальному источнику - метка
    едет внутри каждого события через INGEST_SOURCE_FIELD (проставляется в _process_events
    ПЕРЕД прогоном движка) и снимается (pop) здесь, чтобы не утечь в raw_json, который увидит
    аналитик. Если маркера нет (события пришли из /ingest/file・/ingest/upload - там пишется
    сырой файл с диска как есть, без маркеров), все события просто попадают в одну группу под
    default_label - поведение для одноисточниковых путей не меняется."""
    groups: dict[str, list[dict]] = {}
    for event in events:
        label = event.pop(INGEST_SOURCE_FIELD, default_label)
        groups.setdefault(label, []).append(event)
    return groups


def _catalog_http(exc: CatalogError) -> HTTPException:
    """Единая трансляция ошибок каталога правил в HTTP: 404 - объекта нет (CatalogNotFound),
    400 - объект есть, но действие над ним недопустимо (встроенный рулсет как цель записи/
    удаления/добавления в main, кривой путь, взаимоисключающие параметры).

    Раньше ручки каталога отдавали 404 на любую CatalogError, и отказ по смыслу выглядел как
    «не найден» на заведомо существующий встроенный рулсет - см. app/rules/rules_catalog.py:
    CatalogNotFound. 409 - действие сломало бы ссылки корреляций (CatalogConflict), повтор с
    force=true проходит."""
    if isinstance(exc, CatalogNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, CatalogConflict):
        return HTTPException(status_code=409, detail={"message": str(exc), "references": exc.references})
    return HTTPException(status_code=400, detail=str(exc))


MAX_PAGE_LIMIT = 500


def _check_paging(limit: int, offset: int = 0, max_limit: int = MAX_PAGE_LIMIT) -> None:
    """Единая проверка пагинации для ВСЕХ листинговых ручек: limit в 1..max_limit, offset >= 0.

    Одна точка вместо разнобоя по ручкам: раньше /events и /rulesets/rules отдавали 400,
    /incidents молча зажимал значение, а /alerts и /events/group не проверяли ничего - limit=0
    возвращал пустой список при total>0 (UI рисовал пустую страницу с непустым пейджером), а
    limit без верхней границы вытягивал таблицу целиком одним запросом. Отрицательный offset
    SQLite молча трактует как 0 - тоже отклоняем, чтобы опечатка не выглядела как успех."""
    if not (1 <= limit <= max_limit):
        raise HTTPException(status_code=400, detail=f"limit: 1..{max_limit}")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset: >= 0")


def _process_batch(events_path: str, input_type: str, ruleset_path: str | None, source_label: str) -> IngestResponse:
    # dedup_by_content выбирает режим дедупа алертов (app/detection/normalize.py): True - хэш
    # содержимого события (custom-рулсеты и "main" - тот теперь СОБИРАЕТСЯ только из custom, см.
    # app/rules/main_ruleset.py), False - грубее, только (rule_id, host) (built-in, только
    # batch-прогоны файлов). Путь пуст/None у /ingest/file без явного ruleset - там движковый
    # дефолт engine.default_ruleset_path, а он built-in.
    # Состав правил резолвится ОДИН раз на флаш и отдаётся и движку, и корреляциям
    # (active_hit_spec/evaluate_batch через corr_rules): раньше резолв повторялся 3 + N раз
    # (N - источников во флаше), и при правке контента посреди флаша движок и корреляции могли
    # увидеть разный набор правил.
    if ruleset_path == main_ruleset.MAIN_RULESET_ID or (
        ruleset_path and ruleset_path.startswith("custom_rulesets/")
    ):
        # "main" - состав основного рулсета; custom - все правила рулсета. Оба - по УЖЕ
        # скомпилированному .manifest.json (rules_catalog.load_rules), а не пересборкой сырых .yml
        # в RulesetHandler: только в манифесте плейсхолдеры value lists (%name% / |expand, см.
        # app/rules/value_lists.py) уже развёрнуты - RulesetHandler, глядя на сырой .yml с
        # %name%, молча уронил бы такое правило. Вместе с межрулсетными зависимостями корреляций
        # (main_ruleset.resolve_for) - иначе корреляция, опирающаяся на базовое правило другого
        # рулсета, была бы мертва.
        try:
            pairs = main_ruleset.resolve_for(ruleset_path)
        except CatalogError as exc:
            raise _catalog_http(exc)
        raw_results, all_events, total_events, elapsed = engine.run_batch_with_rules(
            events_path=events_path, rules=[rule for _src, rule in pairs], input_type=input_type,
        )
        corr_rules = correlation.correlation_rules_from_pairs(pairs)
        dedup_by_content = True
    else:
        raw_results, all_events, total_events, elapsed = engine.run_batch(
            events_path=events_path, input_type=input_type, ruleset_path=ruleset_path,
        )
        corr_rules = []  # builtin корреляций не содержит
        dedup_by_content = False

    matched_map = _build_matched_row_map(raw_results)
    # Названия БАЗОВЫХ правил + поля, которые нужно денормализовать в rule_hits.group_json,
    # хотя бы для одной активной correlation-записи этого ruleset_path, передаётся в
    # store_events (см. app/detection/correlation.py:active_hit_spec).
    hit_spec = correlation.active_hit_spec(ruleset_path, corr_rules=corr_rules)
    correlation_created = 0
    # link_specs (Этап 4) - evaluate_batch дописывает сюда по записи на каждый созданный/
    # обновлённый инцидент; привязка member-алертов идёт ПОСЛЕ store.upsert_alerts ниже
    # (раньше алертов zircolite текущего flush ещё нет в БД).
    link_specs: list[dict] = []
    # row_id (Zircolite-локальный id ЭТОГО батча) -> настоящий events.event_id - единственное
    # место, где эта связка вообще существует (row_id нигде не персистится). Копится по ВСЕМ
    # label'ам флаша в один общий словарь - zircolite_results_to_alerts ниже работает по ПОЛНОМУ
    # raw_results батча, не по отдельным label'ам. Нужна для events.alert_id (см. ниже) - основы
    # цепочки event -> alert -> incident (store.link_alerts_to_incident), без "сущностей".
    row_id_to_event_id: dict[Any, str] = {}
    # Один прогон движка мог объединять НЕСКОЛЬКО реальных источников (см. _process_events) -
    # события возвращаются в БД под их СОБСТВЕННОЙ меткой, не под source_label всего прогона.
    for label, events_subset in _split_events_by_source(all_events, source_label).items():
        row_id_to_event_id.update(store.store_events(
            events_subset, source_batch=label, matched_row_to_rules=matched_map,
            hit_spec=hit_spec,
        ))
        # Стейтфул-корреляция (app/detection/correlation.py) - переоценивается ПОСЛЕ каждого flush для
        # (правило, group-by-ключ) пар, реально затронутых ЭТИМ батчем (короткое замыкание
        # внутри evaluate_batch, если ни одно активное correlation-правило не ссылается на
        # сработавшее здесь правило - до БД дело не доходит вовсе). Окно считается по постоянной
        # таблице events/rule_hits, а не по содержимому текущего батча - см. CLAUDE.md.
        matched_events_by_title: dict[str, list[dict]] = {}
        for event in events_subset:
            for title in matched_map.get(event.get("row_id"), []):
                matched_events_by_title.setdefault(title, []).append(event)
        correlation_created += correlation.evaluate_batch(
            store, ruleset_path=ruleset_path, source_batch=label,
            matched_events_by_title=matched_events_by_title, link_specs_out=link_specs,
            corr_rules=corr_rules,
        )

    alerts = zircolite_results_to_alerts(
        raw_results, default_source_batch=source_label, dedup_by_content=dedup_by_content,
    )
    # Какие dedup_key УЖЕ были в БД до записи - только для бейджа "N новых алертов" в UI
    # (app/updates.py). upsert_alerts возвращает число ОБРАБОТАННЫХ строк, новые от
    # дедуплицированных по нему не отличить, а менять её контракт нельзя: то же число уходит в
    # IngestResponse.alerts_created и печатается в UI/скриптах. Отдельный SELECT по индексу
    # dedup_key на батч - на фоне прогона движка (~0.25с фиксированного оверхеда) незаметен.
    known_before = set(store.get_alert_ids_by_dedup_keys([a.dedup_key for a in alerts]))
    created = store.upsert_alerts(alerts)
    if alerts:
        # Бампим по ФАКТУ upsert-а, а не только когда появились новые строки: повторное
        # срабатывание правила инкрементит event_count существующего алерта - в списке это
        # видимое изменение, просто без "новых" (UI покажет нейтральное "данные обновились").
        updates.bump("alerts", created=len({a.dedup_key for a in alerts} - known_before))

    # events.alert_id - проставляем СРАЗУ после upsert_alerts (настоящие alert_id уже известны -
    # и вновь созданные, и переиспользованные по dedup_key), ДО обработки link_specs ниже: та
    # линковка резолвит event_id -> alert_id именно через эту колонку (store.link_alerts_to_incident).
    # alert.source_row_ids - row_id ЭТОГО батча (см. normalize.py); события, чей row_id сюда не
    # попал (ручные тесты без row_id, либо built-in-режим, где events.alert_id не нужен вовсе -
    # built-in в main не допускается) просто пропускаются.
    if alerts:
        dedup_key_to_alert_id = store.get_alert_ids_by_dedup_keys([a.dedup_key for a in alerts])
        event_id_to_alert_id: dict[str, str] = {}
        for alert in alerts:
            alert_id = dedup_key_to_alert_id.get(alert.dedup_key)
            if not alert_id:
                continue
            for row_id in alert.source_row_ids:
                event_id = row_id_to_event_id.get(row_id)
                if event_id:
                    event_id_to_alert_id[event_id] = alert_id
        store.link_events_to_alerts(event_id_to_alert_id)

    # Привязка уже сохранённых алертов к инцидентам этого flush'а (см. link_specs выше и
    # store.link_alerts_to_incident) - цепочкой event_id -> alert_id -> incident_id, без
    # сопоставления по значению "сущности" (см. docs/spec/incidents.md). Инцидентные правила
    # базовых алертов обычно informational, но алерт всё равно заводится (см. normalize.py) -
    # так что event_ids сценария почти всегда находят member-алерт(ы).
    for spec in link_specs:
        if spec.get("incident_id"):
            store.link_alerts_to_incident(spec["incident_id"], spec["source_batch"], spec["event_ids"])

    return IngestResponse(
        source_batch=source_label,
        events_processed=total_events,
        rules_matched=len(raw_results),
        alerts_created=created + correlation_created,
        duration_seconds=round(elapsed, 2),
    )


def _process_events(tagged_events: list[tuple[dict, str]], ruleset_path: str | None = None) -> IngestResponse:
    """Общий путь для батча уже-распарсенных событий (из /ingest/events и потокового воркера
    ingest_queue.IngestWorker): сбрасывает во временный jsonl и переиспользует _process_batch.

    tagged_events - (событие, source_label) для КАЖДОГО события отдельно, а не один общий label
    на весь вызов - потоковый воркер теперь флашит ВЕСЬ буфер (возможно, вперемешку из разных
    источников) ОДНИМ вызовом вместо отдельного прогона движка на каждый источник (см. докстринг
    app/ingest_queue.py про амортизацию фиксированного оверхеда движка). Чтобы события/алерты
    после прогона всё равно попали в БД под правильным source_batch, метка временно дописывается
    В КАЖДОЕ событие (INGEST_SOURCE_FIELD) перед прогоном и снимается после - см.
    _split_events_by_source (для events) и normalize.zircolite_results_to_alerts (для alerts).

    Ни /ingest/events, ни IngestWorker (потоковый /ingest/stream) не передают ruleset_path - оба
    по умолчанию используют "основной рулсет" (main), собираемый во вкладке Sigma-правила."""
    ruleset_path = ruleset_path or main_ruleset.MAIN_RULESET_ID
    distinct_labels = {label for _, label in tagged_events}
    batch_label = next(iter(distinct_labels)) if len(distinct_labels) == 1 else f"mixed:{len(distinct_labels)}-sources"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tmp:
        for event, label in tagged_events:
            # Страховка второго уровня к проверке в _parse_stream_body: ЛЮБАЯ не-dict запись,
            # добравшаяся сюда любым путём, отбрасывается поштучно. Исключение на этой строке
            # обрабатывается ingest_queue._flush как ошибка ВСЕГО буфера - то есть одна битая
            # запись стоила бы всего флаша (см. докстринг _parse_stream_body).
            if not isinstance(event, dict):
                continue
            tagged = {**event, INGEST_SOURCE_FIELD: label}
            tmp.write(json.dumps(tagged, default=str) + "\n")
        tmp_path = tmp.name
    try:
        return _process_batch(tmp_path, "json", ruleset_path, batch_label)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _run_retention() -> None:
    """Ретеншн events (см. app/store.py:delete_events_older_than, docs/spec/storage.md) -
    периодически зовётся тем же фоновым потоком, что и flush ingest-воркера (см.
    IngestWorker.retention_fn ниже), не отдельным потоком. cutoff в ТОМ ЖЕ формате, что и
    events.ingested_at (`datetime.now(timezone.utc).isoformat()`, см. store.store_events) -
    обязательно, иначе строковое сравнение в SQL сравнивало бы разные форматы."""
    if config.EVENTS_RETENTION_DAYS <= 0:
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(days=config.EVENTS_RETENTION_DAYS)).isoformat()
    deleted = store.delete_events_older_than(cutoff)
    if deleted:
        logger.info("ретеншн: удалено %s событий старше %sд", deleted, config.EVENTS_RETENTION_DAYS)


def _run_incident_verdicts() -> None:
    """Заглушка обработки расследований инцидентов (Этап 4, см. app/incidents.py:run_pending) -
    периодически зовётся тем же фоновым потоком, что и ретеншн. Настоящий агент - Этап 5."""
    if not config.INCIDENT_VERDICT_ENABLED:
        return
    processed = incidents.run_pending(store)
    if processed:
        logger.info("обработано расследований: %s", processed)


# Потоковый ingest: воркер зовёт _process_events ОДИН РАЗ на весь флаш (может мешать несколько
# источников сразу, см. докстринг _process_events). retention_fn - None при
# EVENTS_RETENTION_DAYS<=0 (ретеншн выключен) - не заводим лишний таймаут ожидания в воркере,
# если он всё равно ничего бы не делал (см. IngestWorker._run). periodic_tasks - прочие
# фоновые задачи того же потока (Этап 4: заглушка вердиктов инцидентов).
ingest_worker = IngestWorker(
    process_fn=_process_events,
    retention_fn=_run_retention if config.EVENTS_RETENTION_DAYS > 0 else None,
    periodic_tasks=(
        [(_run_incident_verdicts, config.INCIDENT_VERDICT_INTERVAL)]
        if config.INCIDENT_VERDICT_ENABLED else None
    ),
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ingest_worker.start()
    try:
        yield
    finally:
        ingest_worker.stop()


app = FastAPI(title="Mini-SIEM Engine", version=__version__, lifespan=lifespan)


@app.get("/health")
def health(detailed: bool = False) -> dict:
    """
    Реальная проверка живости (не просто "процесс отвечает"): SELECT 1 по БД, состояние
    фонового потока очереди ingest, наличие скомпилированного Zircolite-ruleset-а. Все три
    дешёвые, поэтому выполняются всегда - подходит для частого поллинга из UI (см. checkHealth
    в index.html). detailed=true добавляет к проверке БД счётчики строк и размер файла
    (полный COUNT(*) по обеим таблицам - дороже, вызывается только по клику на светофор).
    """
    checks = {
        "db": store.health(detailed=detailed),
        "zircolite": engine.health(),
        "ingest_queue": ingest_worker.health(),
    }
    overall = "ok" if all(c.get("status") == "ok" for c in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}


@app.get("/updates")
def get_updates() -> dict:
    """Счётчики изменений списков для автообновления UI (см. app/updates.py и pollUpdates в
    index.html): {"epoch": ..., "alerts": {"version": N, "created": M}, "incidents": {...}}.

    Считается ПОЛНОСТЬЮ В ПАМЯТИ, без похода в БД - ручку опрашивает каждая открытая вкладка
    раз в несколько секунд, поэтому она обязана быть дешевле самого списка (иначе автообновление
    стоило бы дороже ручного «Обновить»). Отдельная ручка, а не поле в /health: у них разный
    ритм опроса (7с против 20с) и разная семантика - /health про живость сервиса, эта про
    свежесть данных."""
    return updates.snapshot()


def _authenticate_ingest(request: Request) -> dict:
    """Токен из заголовка 'Authorization: Bearer <token>' ЛИБО 'X-Ingest-Token: <token>'.
    Возвращает dict активного источника (его name - метка source_batch). Иначе 401 - события
    НЕ попадают в очередь ("остальные события без токена игнорируются", см. постановку).

    Токен принимается ТОЛЬКО из заголовка, не из query-параметра: query светится в логах
    reverse-proxy / веб-сервера (см. правило про секреты в URL в CLAUDE.md). Гейтом закрыты
    /ingest/stream и /ingest/events - "безголовые" пути приёма событий с форвардеров;
    /ingest/file и /ingest/upload остаются открытыми (их дёргают из локального UI)."""
    token: str | None = None
    auth = request.headers.get("authorization") or ""
    if auth[:7].lower() == "bearer ":
        token = auth[7:].strip() or None
    if not token:
        token = (request.headers.get("x-ingest-token") or "").strip() or None
    source = store.authenticate_source(token)
    if source is None:
        raise HTTPException(
            status_code=401,
            detail=("Нужен токен зарегистрированного источника. Создайте источник во вкладке "
                    "«Источник данных» и передавайте его токен в заголовке "
                    "'Authorization: Bearer <token>' (или 'X-Ingest-Token')."),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return source


@app.post("/ingest/file", response_model=IngestResponse)
def ingest_file(request: IngestFileRequest) -> IngestResponse:
    events_path = Path(request.events_path)
    if not events_path.exists():
        raise HTTPException(status_code=404, detail=f"Файл не найден: {events_path}")
    source_label = request.source_label or events_path.stem
    return _process_batch(str(events_path), request.input_type, request.ruleset, source_label)


@app.post("/ingest/events", response_model=IngestResponse)
def ingest_events(request: Request, body: IngestEventsRequest) -> IngestResponse:
    """Приём порции сырых событий в теле (синхронный прогон). Как и /ingest/stream, требует
    токен зарегистрированного источника - метку source_batch задаёт САМ источник (его имя),
    поле source_label в теле игнорируется."""
    source = _authenticate_ingest(request)
    if not body.events:
        raise HTTPException(status_code=400, detail="Пустой список событий")
    return _process_events([(e, source["name"]) for e in body.events])


def _parse_stream_body(raw: bytes) -> tuple[list[dict], int]:
    """Принимает NDJSON (по событию на строку) или JSON-массив. Пустые строки пропускаем.
    Возвращает (события, сколько записей отброшено как не-объекты).

    Событием считается ТОЛЬКО JSON-объект: голая строка/число/массив в потоке отбрасывается
    здесь, а не уезжает дальше в очередь. Иначе одна такая запись роняла бы `{**event, ...}`
    в _process_events, а ingest_queue._flush ловит исключение на ВЕСЬ буфер разом - и вместе с
    битой записью молча терялся весь флаш (до INGEST_BATCH_SIZE событий, в т.ч. от других
    источников), при том что форвардер уже получил 202 и повторять не станет. /ingest/events
    ту же проверку делает через Pydantic (422), тут её раньше не было вовсе."""
    text = raw.decode("utf-8").strip()
    if not text:
        return [], 0
    if text[0] == "[":  # цельный JSON-массив
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("ожидался JSON-массив событий")
        raw_items: list = data
    else:
        raw_items = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                raw_items.append(json.loads(line))
    events = [item for item in raw_items if isinstance(item, dict)]
    return events, len(raw_items) - len(events)


@app.post("/ingest/stream")
async def ingest_stream(request: Request) -> JSONResponse:
    """
    Потоковый приём событий с форвардеров (Fluent Bit / NXLog / curl и т.п.).
    Тело - NDJSON (application/x-ndjson) или JSON-массив.

    ТРЕБУЕТ токен зарегистрированного источника: заголовок 'Authorization: Bearer <token>'
    (или 'X-Ingest-Token: <token>'). Запросы без валидного токена активного источника
    отклоняются 401, события в очередь не попадают. Метку source_batch задаёт САМ источник
    (его имя, заданное при создании во вкладке «Источник данных») - query-параметр ?source=
    больше не используется.

    Не запускает детект синхронно: кладёт события в очередь и сразу отвечает 202,
    чтобы форвардер не ждал прогона Zircolite. Реальный прогон - в фоновом воркере
    батчами (см. app/ingest_queue.py).
    """
    source = _authenticate_ingest(request)
    label = source["name"]
    raw = await request.body()
    try:
        events, skipped = _parse_stream_body(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Не удалось разобрать тело запроса: {exc}")

    # skipped отдаём в ответе (а не только пишем в лог) - иначе форвардер, шлющий мусор,
    # никак не узнал бы, что часть записей не принята: код ответа тут всегда 202.
    if not events:
        return JSONResponse(status_code=202, content={"queued": 0, "skipped": skipped, "source": label})

    try:
        queued = ingest_worker.enqueue(events, source_label=label)
    except IngestQueueFull as exc:  # очередь заполнена - часть событий (exc.queued) уже принята
        raise HTTPException(
            status_code=503,
            detail=f"Очередь ingest переполнена: {exc}. Повтори запрос позже.",
        )
    except RuntimeError as exc:  # воркер не запущен
        raise HTTPException(status_code=503, detail=f"Очередь ingest недоступна: {exc}")

    return JSONResponse(status_code=202, content={"queued": queued, "skipped": skipped, "source": label})


@app.post("/ingest/upload", response_model=IngestResponse)
async def ingest_upload(
    file: UploadFile = File(...),
    input_type: str = Form("auto"),
    ruleset: str | None = Form(None),
    source_label: str | None = Form(None),
) -> IngestResponse:
    """
    Приём файла, выбранного пользователем через файловый диалог браузера
    (input type=file). В отличие от /ingest/file,
    здесь путь на сервере не нужен - файл целиком передаётся в теле запроса.
    """
    resolved_type = _guess_input_type(file.filename) if input_type == "auto" else input_type
    label = source_label or Path(file.filename).stem

    saved_path = UPLOADS_DIR / f"{uuid4().hex}_{file.filename}"
    with saved_path.open("wb") as out:
        out.write(await file.read())

    try:
        return _process_batch(str(saved_path), resolved_type, ruleset, label)
    finally:
        # Сам файл оставляем в uploads/ - пригодится для повторного прогона другим ruleset-ом
        # без повторной загрузки. Если место на диске важнее - можно раскомментировать удаление:
        # saved_path.unlink(missing_ok=True)
        pass


@app.get("/batches")
def list_batches() -> list[dict]:
    return store.list_batches()


@app.delete("/batches/{source_batch}")
def delete_batch(source_batch: str) -> dict:
    """Удаляет источник целиком: все его события И алерты (source_batch - не отдельная
    сущность, просто общая метка на обеих таблицах)."""
    result = store.delete_batch(source_batch)
    if result["events_deleted"] == 0 and result["alerts_deleted"] == 0:
        raise HTTPException(status_code=404, detail=f"Источник не найден: {source_batch}")
    # Строки ИСЧЕЗЛИ - для открытого UI это такое же изменение списка, как появление новых
    # (created не растёт, UI покажет нейтральное "данные обновились").
    updates.bump("alerts")
    updates.bump("incidents")
    return {"source_batch": source_batch, **result}


# ------------------------------------------------------------------ Registered sources (потоковые источники)

@app.get("/sources")
def list_sources() -> list[dict]:
    """Зарегистрированные потоковые источники (вкладка «Источник данных»). Токен НЕ отдаётся -
    только token_hint (последние 4 символа). Счётчики событий/алертов и время последнего
    события подтягиваются из /batches по совпадению name == source_batch (регистрация и
    накопленные данные - независимые вещи, у только что созданного источника счётчики нулевые)."""
    batch_stats = {b["source_batch"]: b for b in store.list_batches()}
    result = []
    for s in store.list_sources():
        b = batch_stats.get(s["name"])
        result.append({
            **s,
            "event_count": b["event_count"] if b else 0,
            "alert_count": b["alert_count"] if b else 0,
            "last_event_at": b["last_ingested_at"] if b else None,
        })
    return result


@app.post("/sources", status_code=201)
def create_source(body: SourceCreate) -> dict:
    """Регистрирует источник и возвращает ОДНОРАЗОВЫЙ токен (поле "token"). Повторно токен не
    посмотреть - только POST /sources/{id}/rotate. Имя обязательно, уникально, оно же метка
    source_batch всех событий/алертов источника."""
    try:
        return store.create_source(body.name, body.description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/sources/{source_id}/rotate")
def rotate_source_token(source_id: str) -> dict:
    """Перевыпуск токена: старый перестаёт работать немедленно. Ответ несёт новый одноразовый
    токен в поле "token"."""
    token = store.rotate_source_token(source_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    return {"source_id": source_id, "token": token}


@app.patch("/sources/{source_id}")
def update_source(source_id: str, body: SourceUpdate) -> dict:
    """Включить/выключить приём по токену источника и/или поменять описание. Выключенный
    источник сразу перестаёт приниматься на /ingest/stream и /ingest/events (401)."""
    updated = store.update_source(source_id, body.enabled, body.description)
    if updated is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    return updated


@app.delete("/sources/{source_id}")
def delete_source(source_id: str) -> dict:
    """Снимает регистрацию (токен отзывается сразу). Уже принятые события и алерты этого
    источника ОСТАЮТСЯ - их отдельно удаляет DELETE /batches/{имя}."""
    if not store.delete_source(source_id):
        raise HTTPException(status_code=404, detail="Источник не найден")
    return {"deleted": source_id}


AlertIncidentFilter = Literal["all", "in", "none"]


@app.get("/alerts")
def list_alerts(
    source_batch: str | None = None,
    rule_level: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    incident: AlertIncidentFilter = "all",
    q: str | None = None,
    rule_title: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Ответ - обёртка {alerts, total, limit, offset} (как у /events и /incidents): без total
    UI не мог нарисовать пейджер и молча показывал первые 100 алертов из скольких угодно.
    incident - all/in/none (участие в инцидентах), q - поиск по правилу/хосту/сущностям,
    rule_title - точное название (раскрытие группы "по правилу"). Строка несёт incident_ids."""
    _check_paging(limit, offset)
    filters = dict(
        source_batch=source_batch, rule_level=rule_level, time_from=time_from, time_to=time_to,
        incident=incident, q=q, rule_title=rule_title,
    )
    return {
        "alerts": store.list_alerts(**filters, sort_by=sort_by, sort_dir=sort_dir, limit=limit, offset=offset),
        "total": store.count_alerts(**filters),
        "limit": limit,
        "offset": offset,
    }


@app.get("/alerts/groups")
def list_alert_groups(
    source_batch: str | None = None,
    rule_level: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    incident: AlertIncidentFilter = "all",
    q: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Режим "Группировать по правилу" вкладки Алерты - отображение, не дедуп: строка на
    rule_title {rule_title, rule_level (макс.), alert_count, event_count, in_incident_count,
    last_created_at}. Фильтры - как у /alerts; sort_by = rule|alert_count|event_count|created_at.
    Объявлена ДО /alerts/{alert_id}, иначе "groups" съелся бы как alert_id."""
    _check_paging(limit, offset)
    groups, total = store.group_alerts_by_rule(
        source_batch=source_batch, rule_level=rule_level, time_from=time_from, time_to=time_to,
        incident=incident, q=q, sort_by=sort_by, sort_dir=sort_dir, limit=limit, offset=offset,
    )
    return {"groups": groups, "total": total, "limit": limit, "offset": offset}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Алерт не найден")
    # Обогащение MITRE только в КАРТОЧКЕ (не в списке): сырой mitre_techniques (list[str]) не
    # трогаем ради обратной совместимости, добавляем отдельный ключ mitre - гибрид, где техника
    # без совпадения в KB помечена matched=false (UI покажет её как сырой тег).
    alert["mitre"] = kb.enrich_techniques(alert.get("mitre_techniques", []))
    return alert


# ------------------------------------------------------------------ Incidents (Этап 4)

def _incident_entity_filter(group_key: dict) -> str | None:
    """Строит строку мини-языка фильтра (app/filter_lang.py) по значениям group-by инцидента:
    `Field1 = "v1" and Field2 = "v2"`. Имена полей - те же сырые имена события, что были в
    group-by правила (они есть в raw_json), значения экранируются под строковый литерал."""
    parts: list[str] = []
    for field, value in (group_key or {}).items():
        if not field or value is None:
            continue
        v = str(value).replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'{field} = "{v}"')
    return " and ".join(parts) if parts else None


@app.get("/incidents")
def list_incidents(
    status: str | None = None,
    incident_type: str | None = None,
    source_batch: str | None = None,
    severity: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    q: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    _check_paging(limit, offset)
    filters = dict(
        status=status, incident_type=incident_type, source_batch=source_batch,
        severity=severity, time_from=time_from, time_to=time_to, q=q,
    )
    return {
        "incidents": store.list_incidents(sort_by=sort_by, sort_dir=sort_dir, limit=limit, offset=offset, **filters),
        "total": store.count_incidents(**filters),
        "limit": limit,
        "offset": offset,
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    inc = store.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    # Обогащение MITRE в карточке (как у /alerts/{id}) - объединение тегов правила и member-алертов.
    tags = list(inc.get("mitre_techniques", []))
    for ma in inc.get("member_alerts", []):
        full = store.get_alert(ma["alert_id"])
        if full:
            tags += full.get("mitre_techniques", [])
    inc["mitre"] = kb.enrich_techniques(sorted(set(tags)))
    return inc


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, body: IncidentStatusUpdate) -> dict:
    if not store.update_incident_status(incident_id, body.status):
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    updates.bump("incidents")
    return {"incident_id": incident_id, "status": body.status}


@app.get("/incidents/{incident_id}/context")
def get_incident_context(incident_id: str) -> dict:
    """Полный контекст инцидента одним ответом - под будущего агента (Этап 5) и ручной триаж.
    Обязан переживать вычищенные ретеншном events (related_events тогда пустой)."""
    inc = store.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")

    ruleset_path = inc.get("ruleset_path") or ""
    notes: list[str] = []

    correlation_rule = None
    if ruleset_path:
        try:
            for c in rules_catalog.load_correlation_rules(ruleset_path):
                if c.get("id") == inc.get("correlation_rule_id") or c.get("title") == inc.get("correlation_rule_title"):
                    correlation_rule = {
                        k: c.get(k) for k in
                        ("id", "title", "type", "group_by", "timespan", "condition", "level", "description")
                    }
                    break
        except CatalogError:
            pass
    if correlation_rule is None:
        notes.append("correlation-правило инцидента не найдено (удалено или сменило рулсет)")

    member_rules: list[dict] = []
    member_titles = set(inc.get("member_rule_titles") or [])
    if member_titles:
        # По title среди ВСЕХ своих рулсетов: ссылки correlation.rules межрулсетные, member-
        # правило может лежать в другом домене, чем сама корреляция.
        try:
            for src, r in rules_catalog.find_rules_by_titles(member_titles):
                entry = {
                    "rule_id": r.get("id"), "title": r.get("title"), "level": r.get("level"),
                    "description": r.get("description", ""), "rule": r.get("rule", []),
                    "ruleset_path": src,
                }
                got = rules_catalog.get_rule(src, r.get("id"))
                if got and got.get("yaml_text"):
                    entry["yaml_text"] = got["yaml_text"]
                member_rules.append(entry)
        except CatalogError:
            pass

    related = {"events": [], "total": 0, "query": None}
    filter_text = _incident_entity_filter(inc.get("group_key") or {})
    if filter_text:
        try:
            qf = compile_filter_query(filter_text)
            related = {
                "events": store.list_events(source_batch=inc["source_batch"], query_filter=qf, limit=100),
                "total": store.count_events(source_batch=inc["source_batch"], query_filter=qf),
                "query": filter_text,
            }
        except FilterSyntaxError as exc:
            notes.append(f"фильтр событий по сущности не собрался: {exc}")

    # История СУЩНОСТИ, а не источника: раньше сюда уходили просто последние 50 алертов
    # source_batch без всякой привязки к group_key - на живом потоке это шум, который агент
    # принял бы за релевантный контекст. Теперь ищем алерты, где реально встречаются значения
    # group-by инцидента (host + любое значение внутри entities, см.
    # store.list_alerts_by_entity). Если group-by не про "сущность" (напр. DNS QueryName) -
    # совпадений просто не будет, и это честный пустой результат, а не подмена шумом.
    entity_values = [
        str(v).strip() for v in (inc.get("group_key") or {}).values() if str(v or "").strip()
    ]
    if entity_values:
        entity_history = {
            "scope": "entity",
            "values": entity_values,
            "alerts": store.list_alerts_by_entity(
                entity_values, source_batch=inc["source_batch"], limit=50
            ),
        }
    else:
        entity_history = {
            "scope": "source",
            "values": [],
            "alerts": store.list_alerts(source_batch=inc["source_batch"], limit=50),
        }
        notes.append("у инцидента пустой group_key - в истории последние алерты источника, не сущности")

    result = {
        "incident": inc,
        "correlation_rule": correlation_rule,
        "member_rules": member_rules,
        "sample_events": inc.get("sample_events", []),
        "related_events": related,
        "entity_history": entity_history,
    }
    if notes:
        result["note"] = "; ".join(notes)
    return result


def _parse_filters(filters: str | None) -> list[dict] | None:
    """filters приходит как JSON-массив условий [{field, op, value}, ...] в query-параметре.
    Используется только для group_cond (drill-in по выбранной группе) - свободный текстовый
    фильтр разбирается отдельно, см. _parse_query_filter."""
    if not filters:
        return None
    try:
        parsed = json.loads(filters)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"filters: невалидный JSON ({exc})")
    if not isinstance(parsed, list):
        raise HTTPException(status_code=400, detail="filters: ожидался JSON-массив условий")
    # Нераспознанное условие - 400 здесь и сейчас, а не молчаливый пропуск при сборке WHERE:
    # drill-in по группе обязан только СУЖАТЬ выборку, а условие, которое некуда скомпилировать,
    # раньше просто выбрасывалось - и запрос отдавал всё подряд (fail-open). Store на этот же
    # случай бросает FilterSyntaxError (см. store._build_extra_filter_clause) - тут ошибка
    # ловится раньше и с указанием, какое именно условие не разобрано.
    for cond in parsed:
        if not isinstance(cond, dict):
            raise HTTPException(status_code=400, detail=f"filters: условие должно быть объектом, а не {type(cond).__name__}")
        field = str(cond.get("field") or "").strip()
        op = str(cond.get("op") or "eq").lower()
        if not field:
            raise HTTPException(status_code=400, detail="filters: условие без поля")
        if op not in FILTER_OPS:
            raise HTTPException(
                status_code=400,
                detail=f"filters: неизвестный оператор '{op}' (допустимы: {', '.join(sorted(FILTER_OPS))})",
            )
    return parsed


def _parse_query_filter(query: str | None) -> tuple[str, list] | None:
    """Разбирает строку фильтра (мини-язык в духе MaxPatrol, см. app/filter_lang.py) и сразу
    компилирует её в parametrized SQL - если синтаксис некорректен, отдаём 400 с человеко-
    читаемым текстом ошибки, чтобы UI показал его пользователю рядом со строкой фильтра."""
    if not query or not query.strip():
        return None
    try:
        return compile_filter_query(query)
    except FilterSyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"Ошибка синтаксиса фильтра: {exc}")


@app.get("/events")
def list_events(
    source_batch: str | None = None,
    only_matched: bool | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    fields: str | None = None,
    query: str | None = None,
    group_cond: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    _check_paging(limit, offset)
    field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields else None
    query_filter = _parse_query_filter(query)
    # group_cond - одиночное условие drill-in по выбранной группе; всегда сужает (AND).
    extra_list = _parse_filters(f"[{group_cond}]") if group_cond else None
    events = store.list_events(
        source_batch=source_batch, only_matched=only_matched,
        time_from=time_from, time_to=time_to, sort_by=sort_by, sort_dir=sort_dir,
        fields=field_list, query_filter=query_filter,
        extra_filters=extra_list, limit=limit, offset=offset,
    )
    total = store.count_events(
        source_batch=source_batch, only_matched=only_matched,
        time_from=time_from, time_to=time_to, query_filter=query_filter,
        extra_filters=extra_list,
    )
    return {"events": events, "total": total, "limit": limit, "offset": offset}


@app.get("/events/group")
def group_events(
    group_by: str,
    source_batch: str | None = None,
    only_matched: bool | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    query: str | None = None,
    limit: int = 200,
) -> dict:
    """Агрегаторы для панели группировки: значения выбранного поля + счётчики (фильтр применён до),
    плюс total_groups - общее число уникальных значений (может быть больше limit)."""
    _check_paging(limit)  # offset у группировки нет - выдача всегда с начала, топ-N по счётчику
    query_filter = _parse_query_filter(query)
    result = store.group_events(
        group_by=group_by, source_batch=source_batch, only_matched=only_matched,
        time_from=time_from, time_to=time_to, query_filter=query_filter,
        limit=limit,
    )
    return {"group_by": group_by, "groups": result["groups"], "total_groups": result["total_groups"]}


@app.get("/events/{event_id}")
def get_event(event_id: str) -> dict:
    event = store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Событие не найдено")
    return event


@app.get("/rulesets")
def get_rulesets() -> list[dict]:
    entries = rules_catalog.list_rulesets()
    state = main_ruleset.load_state()
    for entry in entries:
        entry["main_status"] = main_ruleset.ruleset_status(state, entry["path"])
    entries.append({
        "path": main_ruleset.MAIN_RULESET_ID,
        "category": "main",
        "name": "Основной рулсет",
        "rule_count": main_ruleset.rule_count(),
        "size_bytes": 0,
        "deletable": False,
        "main_status": "full",
    })
    return entries


# Виды правил для мультиселекта «Тип» вкладки «Sigma-правила»: обычное / корреляция без
# инцидента / сценарное (correlation.incident). Приезжает CSV в одном параметре, как level
# и status; неизвестное значение - 400, а не молчаливый показ всех правил.
RULE_KINDS = {"base", "correlation", "incident"}


@app.get("/rulesets/rules")
def get_ruleset_rules(
    ruleset: str,
    q: str | None = None,
    sort_by: str | None = None,
    sort_dir: str = "asc",
    limit: int = 50,
    offset: int = 0,
    only_main: bool = False,
    level: str | None = None,
    status: str | None = None,
    kind: str | None = None,
) -> dict:
    _check_paging(limit, offset)
    # Мультиселект фильтра приезжает как CSV в одном query-параметре (level=critical,high),
    # а не повторяющимся ключом - проще на фронте собирать из чекбоксов в поповере.
    level_list = [v for v in level.split(",") if v] if level else None
    status_list = [v for v in status.split(",") if v] if status else None
    kind_list = [v for v in kind.split(",") if v] if kind else None
    if kind_list and not RULE_KINDS.issuperset(kind_list):
        raise HTTPException(
            status_code=400,
            detail=f"Недопустимый kind: {kind}. Допустимо: {', '.join(sorted(RULE_KINDS))}",
        )
    if ruleset == main_ruleset.MAIN_RULESET_ID:
        # Просмотр "Основного рулсета" как отдельного пункта селектора - виртуальный список,
        # собранный из НЕСКОЛЬКИХ реальных рулсетов сразу (не проходит через load_rules).
        # Каждая строка несёт source_ruleset - настоящий ruleset_path, по которому фронт
        # должен бить в /rulesets/rule и /main-ruleset/rules при клике/снятии с main.
        # Правило, подтянутое как зависимость корреляции (via_dependency), в main явно не
        # включено - in_main=False, чтобы кнопка тоггла не врала.
        rules = [
            {**rule, "source_ruleset": src, "in_main": not rule.get("via_dependency")}
            for src, rule in main_ruleset.resolve_with_sources()
        ]
        return rules_catalog.paginate_rules(
            rules, q, sort_by, sort_dir, limit, offset, level=level_list, status=status_list,
            kind=kind_list,
        )
    try:
        base_rules = rules_catalog.load_rules(ruleset)
        state = main_ruleset.load_state()
        in_main_fn = lambda rid: main_ruleset.is_rule_included(state, ruleset, rid)  # noqa: E731
        only_ids = {r.get("id") for r in base_rules if in_main_fn(r.get("id"))} if only_main else None
        return rules_catalog.search_rules(
            ruleset, q, sort_by, sort_dir, limit, offset, only_ids=only_ids, in_main_fn=in_main_fn,
            level=level_list, status=status_list, kind=kind_list,
        )
    except CatalogError as exc:
        raise _catalog_http(exc)


@app.get("/rulesets/rule")
def get_ruleset_rule(ruleset: str, rule_id: str) -> dict:
    try:
        rule = rules_catalog.get_rule(ruleset, rule_id)
    except CatalogError as exc:
        raise _catalog_http(exc)
    if rule is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    return rule


@app.post("/rulesets/upload")
async def upload_ruleset(
    file: UploadFile = File(...),
    ruleset: str | None = Form(None),
    new_ruleset_name: str | None = Form(None),
) -> dict:
    if not file.filename or not file.filename.lower().endswith((".yml", ".yaml")):
        raise HTTPException(status_code=400, detail="Ожидается файл Sigma YAML (.yml/.yaml)")
    raw = await file.read()
    try:
        yaml_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Не удалось прочитать файл как UTF-8: {exc}")
    try:
        info, _target_path, collisions, imported = rules_catalog.save_ruleset_yaml(
            yaml_text, ruleset, new_ruleset_name,
        )
    except CatalogError as exc:
        raise _catalog_http(exc)
    except (RuleValidationError, ValueListError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Файл мог нести документы-определения списков (Sigma pipeline value_placeholders и т.п.) -
    # они уже записаны; пересобираем правила ДРУГИХ рулсетов, если те списки изменились.
    recompile = _recompile_for_value_lists(imported["recompile_needed"])
    base = info if info is not None else {"rules": 0, "note": "в файле только определения списков - рулсет не создан"}
    return {**base, "collisions": collisions, "value_lists_imported": imported, **recompile}


@app.delete("/rulesets")
def delete_ruleset(ruleset: str, force: bool = False) -> dict:
    try:
        rules_catalog.delete_custom_ruleset(ruleset, force=force)
    except CatalogError as exc:
        raise _catalog_http(exc)
    engine.invalidate(ruleset)
    main_ruleset.on_ruleset_deleted(ruleset)
    return {"deleted": ruleset}


@app.post("/rules/custom", status_code=201)
def create_custom_rule(body: CustomRuleSubmit) -> dict:
    try:
        compiled, target_path = rules_catalog.save_custom_rule(body.yaml_text, body.ruleset, body.new_ruleset_name)
    except CatalogError as exc:
        raise _catalog_http(exc)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    engine.invalidate(target_path)
    return {**compiled, "ruleset_path": target_path}


@app.put("/rules/custom/{rule_id}")
def update_custom_rule(rule_id: str, ruleset: str, body: CustomRuleUpdate) -> dict:
    try:
        compiled = rules_catalog.update_custom_rule(ruleset, rule_id, body.yaml_text)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except CatalogError as exc:
        raise _catalog_http(exc)
    engine.invalidate(ruleset)
    return compiled


@app.delete("/rules/custom/{rule_id}")
def delete_custom_rule(rule_id: str, ruleset: str, force: bool = False) -> dict:
    try:
        rules_catalog.delete_custom_rule(ruleset, rule_id, force=force)
    except CatalogError as exc:
        raise _catalog_http(exc)
    engine.invalidate(ruleset)
    # Ссылку на удалённое правило в составе основного рулсета убираем ТУТ же (как это делает
    # on_ruleset_deleted для удаления рулсета целиком) - иначе main_ruleset.json копит
    # осиротевшие id, а удалённое правило продолжает числиться включённым в main.
    main_ruleset.on_rule_deleted(ruleset, rule_id)
    return {"deleted": rule_id}


@app.post("/main-ruleset/rules")
def toggle_main_ruleset_rule(body: MainRulesetRuleToggle) -> dict:
    try:
        in_main = main_ruleset.toggle_rule(body.ruleset, body.rule_id, body.include)
    except CatalogError as exc:
        raise _catalog_http(exc)
    return {"ruleset": body.ruleset, "rule_id": body.rule_id, "in_main": in_main}


@app.post("/main-ruleset/rulesets")
def toggle_main_ruleset_ruleset(body: MainRulesetToggle) -> dict:
    try:
        status = main_ruleset.toggle_ruleset(body.ruleset, body.include)
    except CatalogError as exc:
        raise _catalog_http(exc)
    return {"ruleset": body.ruleset, "main_status": status}


def _recompile_for_value_lists(names: list[str]) -> dict:
    """Пересобирает правила, ссылающиеся на изменённые списки значений, + invalidate кэша
    движка по затронутым рулсетам. Общий хвост для PUT /value-lists/{name},
    POST /value-lists/upload и POST /rulesets/upload (когда в файле были документы-списки)."""
    recompiled: list[dict] = []
    errors: list[dict] = []
    affected: set[str] = set()
    for name in names:
        r = rules_catalog.recompile_rules_for_value_list(name)
        recompiled += r["recompiled"]
        errors += r["errors"]
        affected.update(r["affected_rulesets"])
    for ruleset_path in affected:
        engine.invalidate(ruleset_path)
    return {"recompiled": recompiled, "errors": errors}


@app.get("/value-lists")
def list_value_lists() -> list[dict]:
    """Именованные списки значений (плейсхолдеры %name% / |expand для Sigma-правил,
    см. app/rules/value_lists.py) - для вкладки «Списки». used_by_count считается одним проходом."""
    counts = rules_catalog.value_list_usage_counts()
    entries = value_lists.list_lists()
    for entry in entries:
        entry["used_by_count"] = counts.get(entry["name"], 0)
    return entries


@app.get("/value-lists/{name}")
def get_value_list(name: str) -> dict:
    data = value_lists.get_list(name)
    if data is None:
        raise HTTPException(status_code=404, detail="Список не найден")
    data["used_by"] = rules_catalog.rules_using_value_list(name)
    return data


@app.post("/value-lists", status_code=201)
def create_value_list(body: ValueListCreate) -> dict:
    try:
        return value_lists.create_list(body.name, body.description, body.values)
    except ValueListError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/value-lists/{name}")
def update_value_list(name: str, body: ValueListUpdate) -> dict:
    """Правка списка -> СРАЗУ пересобирает все правила, которые на него ссылаются (переписывает
    их .manifest.json + invalidate кэша движка по затронутым рулсетам). Ответ несёт recompiled/
    errors - список сохраняется всегда, правила с ошибкой компиляции остаются на прежнем SQL."""
    try:
        updated = value_lists.update_list(name, body.description, body.values)
    except ValueListError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="Список не найден")
    return {**updated, **_recompile_for_value_lists([name])}


@app.post("/value-lists/upload")
async def upload_value_lists(
    file: UploadFile = File(...),
    mode: str = Form("create"),
) -> dict:
    """Загрузка списков значений файлом (вкладка «Списки» → «+ Загрузить список»). Форматы -
    см. value_lists.parse_list_file: Sigma processing-pipeline YAML с value_placeholders.mapping
    (один файл → много списков), наш {name, description?, values}, или «голый» {имя: [значения]}.
    mode: create (не трогать существующие) | replace (перезаписать) | merge (объединить значения).
    replace/merge пересобирают правила, ссылающиеся на изменённые списки (recompiled/errors)."""
    if not file.filename or not file.filename.lower().endswith((".yml", ".yaml")):
        raise HTTPException(status_code=400, detail="Ожидается YAML-файл (.yml/.yaml)")
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Не удалось прочитать файл как UTF-8: {exc}")
    try:
        parsed = value_lists.parse_list_file(text)
        result = value_lists.import_lists(parsed, mode)
    except ValueListError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {**result, **_recompile_for_value_lists(result["recompile_needed"])}


@app.delete("/value-lists/{name}")
def delete_value_list(name: str, force: bool = False) -> dict:
    used_by = rules_catalog.rules_using_value_list(name)
    if used_by and not force:
        raise HTTPException(
            status_code=409,
            detail=(f"Список используется в {len(used_by)} правилах - повтори с ?force=true, "
                    "чтобы удалить (эти правила перестанут компилироваться)."),
        )
    if not value_lists.delete_list(name):
        raise HTTPException(status_code=404, detail="Список не найден")
    return {"deleted": name, "was_used_by": used_by}


# ----------------- База знаний (вкладка «База знаний»): матрица MITRE ATT&CK -----------------
# Read-only, данные в отдельном kb.db (см. app/kb.py, scripts/build_kb.py). Если база не собрана,
# ручки отдают валидную форму с "available": false (не 5xx) - так проще UI.


@app.get("/kb/mitre/meta")
def kb_mitre_meta() -> dict:
    return kb.meta()


@app.get("/kb/mitre/matrix")
def kb_mitre_matrix() -> dict:
    return kb.matrix()


@app.get("/kb/mitre/techniques")
def kb_mitre_techniques(
    tactic: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    _check_paging(limit, offset)
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset: >= 0")
    return kb.list_techniques(tactic=tactic, q=q, limit=limit, offset=offset)


@app.get("/kb/mitre/techniques/{technique_id}")
def kb_mitre_technique(technique_id: str) -> dict:
    tech = kb.get_technique(technique_id.upper())
    if tech is None:
        raise HTTPException(status_code=404, detail="Техника не найдена в базе знаний")
    return tech


@app.get("/", response_class=HTMLResponse)
def analyst_ui() -> HTMLResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="UI не найден - ожидается app/static/index.html")
    # no-store: файл активно меняется при разработке, а без явного Cache-Control браузер
    # может отдать эвристически закэшированную (устаревшую) копию даже на обычный F5 -
    # так однажды уже словили "фикс не применился" при живом сервере с актуальным файлом.
    return HTMLResponse(
        content=index_file.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-store"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=True)
