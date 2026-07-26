"""
FastAPI-сервис мини-SIEM поверх Zircolite.

Запуск: uvicorn app.main:app --reload --port 8000 (порт/хост переопределяются
        через SIEM_HOST/SIEM_PORT в .env, см. app/config.py) - либо python -m app.main.
Swagger: http://localhost:8000/docs
UI аналитика: http://localhost:8000/
"""
from __future__ import annotations

import json
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from app import config
from app.engine import ZircoliteEngine
from app.fields import INGEST_SOURCE_FIELD
from app.filter_lang import FilterSyntaxError, compile_filter_query
from app.ingest_queue import IngestWorker
from app.models import (
    AlertStatusUpdate,
    CustomRuleSubmit,
    CustomRuleUpdate,
    IngestEventsRequest,
    IngestFileRequest,
    IngestResponse,
    MainRulesetRuleToggle,
    MainRulesetToggle,
)
from app.normalize import zircolite_results_to_alerts
from app import main_ruleset
from app import rules_catalog
from app.rules_catalog import CatalogError, RuleValidationError
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


def _process_batch(events_path: str, input_type: str, ruleset_path: str | None, source_label: str) -> IngestResponse:
    if ruleset_path == main_ruleset.MAIN_RULESET_ID:
        rules = main_ruleset.resolve()
        raw_results, all_events, total_events, elapsed = engine.run_batch_with_rules(
            events_path=events_path, rules=rules, input_type=input_type,
        )
    else:
        raw_results, all_events, total_events, elapsed = engine.run_batch(
            events_path=events_path, input_type=input_type, ruleset_path=ruleset_path,
        )

    matched_map = _build_matched_row_map(raw_results)
    # Один прогон движка мог объединять НЕСКОЛЬКО реальных источников (см. _process_events) -
    # события возвращаются в БД под их СОБСТВЕННОЙ меткой, не под source_label всего прогона.
    for label, events_subset in _split_events_by_source(all_events, source_label).items():
        store.store_events(events_subset, source_batch=label, matched_row_to_rules=matched_map)

    alerts = zircolite_results_to_alerts(raw_results, default_source_batch=source_label)
    created = store.upsert_alerts(alerts)

    return IngestResponse(
        source_batch=source_label,
        events_processed=total_events,
        rules_matched=len(raw_results),
        alerts_created=created,
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
            tagged = {**event, INGEST_SOURCE_FIELD: label}
            tmp.write(json.dumps(tagged, default=str) + "\n")
        tmp_path = tmp.name
    try:
        return _process_batch(tmp_path, "json", ruleset_path, batch_label)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# Потоковый ingest: воркер зовёт _process_events ОДИН РАЗ на весь флаш (может мешать несколько
# источников сразу, см. докстринг _process_events).
ingest_worker = IngestWorker(process_fn=_process_events)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ingest_worker.start()
    try:
        yield
    finally:
        ingest_worker.stop()


app = FastAPI(title="Mini-SIEM Engine", version="0.3.0", lifespan=lifespan)


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


@app.post("/ingest/file", response_model=IngestResponse)
def ingest_file(request: IngestFileRequest) -> IngestResponse:
    events_path = Path(request.events_path)
    if not events_path.exists():
        raise HTTPException(status_code=404, detail=f"Файл не найден: {events_path}")
    source_label = request.source_label or events_path.stem
    return _process_batch(str(events_path), request.input_type, request.ruleset, source_label)


@app.post("/ingest/events", response_model=IngestResponse)
def ingest_events(request: IngestEventsRequest) -> IngestResponse:
    if not request.events:
        raise HTTPException(status_code=400, detail="Пустой список событий")
    return _process_events([(e, request.source_label) for e in request.events])


def _parse_stream_body(raw: bytes) -> list[dict]:
    """Принимает NDJSON (по событию на строку) или JSON-массив. Пустые строки пропускаем."""
    text = raw.decode("utf-8").strip()
    if not text:
        return []
    if text[0] == "[":  # цельный JSON-массив
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("ожидался JSON-массив событий")
        return data
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


@app.post("/ingest/stream")
async def ingest_stream(request: Request, source: str = "live-stream") -> JSONResponse:
    """
    Потоковый приём событий с форвардеров (Fluent Bit / NXLog / curl и т.п.).
    Тело - NDJSON (application/x-ndjson) или JSON-массив. Параметр ?source=<label>
    задаёт источник (обычно имя хоста) - под ним события группируются в хранилище.

    Не запускает детект синхронно: кладёт события в очередь и сразу отвечает 202,
    чтобы форвардер не ждал прогона Zircolite. Реальный прогон - в фоновом воркере
    батчами (см. app/ingest_queue.py).
    """
    raw = await request.body()
    try:
        events = _parse_stream_body(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Не удалось разобрать тело запроса: {exc}")

    if not events:
        return JSONResponse(status_code=202, content={"queued": 0, "source": source})

    try:
        queued = ingest_worker.enqueue(events, source_label=source)
    except Exception as exc:  # очередь переполнена / воркер не запущен
        raise HTTPException(status_code=503, detail=f"Очередь ingest недоступна: {exc}")

    return JSONResponse(status_code=202, content={"queued": queued, "source": source})


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
    return {"source_batch": source_batch, **result}


@app.get("/alerts")
def list_alerts(
    source_batch: str | None = None,
    status: str | None = None,
    rule_level: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    return store.list_alerts(
        source_batch=source_batch, status=status, rule_level=rule_level,
        time_from=time_from, time_to=time_to, sort_by=sort_by, sort_dir=sort_dir,
        limit=limit, offset=offset,
    )


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Алерт не найден")
    return alert


@app.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, body: AlertStatusUpdate) -> dict:
    ok = store.update_alert_status(alert_id, body.status)
    if not ok:
        raise HTTPException(status_code=404, detail="Алерт не найден")
    return {"alert_id": alert_id, "status": body.status}


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
    if not (1 <= limit <= 500):
        raise HTTPException(status_code=400, detail="limit: 1..500")
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
) -> dict:
    if not (1 <= limit <= 500):
        raise HTTPException(status_code=400, detail="limit: 1..500")
    # Мультиселект фильтра приезжает как CSV в одном query-параметре (level=critical,high),
    # а не повторяющимся ключом - проще на фронте собирать из чекбоксов в поповере.
    level_list = [v for v in level.split(",") if v] if level else None
    status_list = [v for v in status.split(",") if v] if status else None
    if ruleset == main_ruleset.MAIN_RULESET_ID:
        # Просмотр "Основного рулсета" как отдельного пункта селектора - виртуальный список,
        # собранный из НЕСКОЛЬКИХ реальных рулсетов сразу (не проходит через load_rules).
        # Каждая строка несёт source_ruleset - настоящий ruleset_path, по которому фронт
        # должен бить в /rulesets/rule и /main-ruleset/rules при клике/снятии с main.
        rules = [
            {**rule, "source_ruleset": src, "in_main": True}
            for src, rule in main_ruleset.resolve_with_sources()
        ]
        return rules_catalog.paginate_rules(
            rules, q, sort_by, sort_dir, limit, offset, level=level_list, status=status_list,
        )
    try:
        base_rules = rules_catalog.load_rules(ruleset)
        state = main_ruleset.load_state()
        in_main_fn = lambda rid: main_ruleset.is_rule_included(state, ruleset, rid)  # noqa: E731
        only_ids = {r.get("id") for r in base_rules if in_main_fn(r.get("id"))} if only_main else None
        return rules_catalog.search_rules(
            ruleset, q, sort_by, sort_dir, limit, offset, only_ids=only_ids, in_main_fn=in_main_fn,
            level=level_list, status=status_list,
        )
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/rulesets/rule")
def get_ruleset_rule(ruleset: str, rule_id: str) -> dict:
    try:
        rule = rules_catalog.get_rule(ruleset, rule_id)
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
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
        info, _target_path, collisions = rules_catalog.save_ruleset_yaml(yaml_text, ruleset, new_ruleset_name)
    except (CatalogError, RuleValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {**info, "collisions": collisions}


@app.delete("/rulesets")
def delete_ruleset(ruleset: str) -> dict:
    try:
        rules_catalog.delete_custom_ruleset(ruleset)
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    engine.invalidate(ruleset)
    main_ruleset.on_ruleset_deleted(ruleset)
    return {"deleted": ruleset}


@app.post("/rules/custom", status_code=201)
def create_custom_rule(body: CustomRuleSubmit) -> dict:
    try:
        compiled, target_path = rules_catalog.save_custom_rule(body.yaml_text, body.ruleset, body.new_ruleset_name)
    except (RuleValidationError, CatalogError) as exc:
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
        raise HTTPException(status_code=404, detail=str(exc))
    engine.invalidate(ruleset)
    return compiled


@app.delete("/rules/custom/{rule_id}")
def delete_custom_rule(rule_id: str, ruleset: str) -> dict:
    try:
        rules_catalog.delete_custom_rule(ruleset, rule_id)
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    engine.invalidate(ruleset)
    return {"deleted": rule_id}


@app.post("/main-ruleset/rules")
def toggle_main_ruleset_rule(body: MainRulesetRuleToggle) -> dict:
    try:
        in_main = main_ruleset.toggle_rule(body.ruleset, body.rule_id, body.include)
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ruleset": body.ruleset, "rule_id": body.rule_id, "in_main": in_main}


@app.post("/main-ruleset/rulesets")
def toggle_main_ruleset_ruleset(body: MainRulesetToggle) -> dict:
    try:
        status = main_ruleset.toggle_ruleset(body.ruleset, body.include)
    except CatalogError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ruleset": body.ruleset, "main_status": status}


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
