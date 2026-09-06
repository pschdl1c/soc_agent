"""
Pydantic-модели: нормализованный Alert (то, что видит агент/UI) и модели запросов к API.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional, get_args
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow_naive() -> datetime:
    """Наивный (без tzinfo) datetime по UTC - замена deprecated (в 3.12) datetime.utcnow().

    Именно наивный, а не datetime.now(timezone.utc): Alert.created_at уходит в БД строкой
    через .isoformat(), а store.list_alerts фильтрует/сортирует его СТРОКОВЫМ сравнением с
    наивными границами из UI (см. timeParams() в index.html - специально без 'Z'/offset) и с
    уже накопленными в alerts строками того же формата. Aware-вариант дал бы суффикс '+00:00'
    -> сломанное сравнение диапазонов и колонка смешанного формата. Формат на диске остаётся
    ровно тем же, что и был при datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Числовой ранг серьёзности - для roll-up инцидента (max среди member-алертов) и сортировки.
# Держим ОТДЕЛЬНО от порядка объявления enum: rule_level из разных источников иногда приходит
# как 'unknown'/None, а не как валидный литерал - .rank() должен это пережить без исключения.
_SEVERITY_RANK: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


# Жизненный цикл триаж-статуса инцидента - ЕДИНСТВЕННОЕ определение на проект: им типизировано
# тело PATCH /incidents/{id}/status (422 на всё остальное), им же проверяет запись Store
# (update_incident_status) и чинит мусор, записанный до появления проверки (store._migrate).
IncidentStatus = Literal["new", "investigating", "closed"]
INCIDENT_STATUSES: tuple[str, ...] = get_args(IncidentStatus)


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @classmethod
    def from_zircolite(cls, rule_level: str | None) -> "Severity":
        """rule_level из Zircolite иногда 'unknown' или отсутствует - подстраховка."""
        try:
            return cls(rule_level)
        except ValueError:
            return cls.informational

    @classmethod
    def rank(cls, value: "Severity | str | None") -> int:
        """Числовой ранг (critical=5 ... informational=1). Неизвестное/пустое значение -> 1."""
        key = value.value if isinstance(value, cls) else str(value or "")
        return _SEVERITY_RANK.get(key, 1)

    @classmethod
    def roll_up(cls, values: "list[Severity | str | None]") -> "Severity":
        """Максимальная серьёзность из набора - severity инцидента как roll-up member-алертов
        (см. app/store.py:link_alerts_to_incident). Пустой набор -> informational."""
        best = cls.informational
        for v in values:
            cand = v if isinstance(v, cls) else cls.from_zircolite(str(v) if v else None)
            if cls.rank(cand) > cls.rank(best):
                best = cand
        return best


class Entities(BaseModel):
    """Сущности, извлечённые из событий - для пивота и будущих RAG-запросов агента."""
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)


class SigmaRuleRef(BaseModel):
    rule_id: str
    title: str
    level: Severity
    mitre_techniques: list[str] = Field(default_factory=list)
    description: str = ""


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    dedup_key: str
    created_at: datetime = Field(default_factory=utcnow_naive)
    engine: str = "zircolite"
    source_batch: str  # имя датасета/источника, из которого пришёл алерт
    host: str
    rule: SigmaRuleRef
    entities: Entities
    event_count: int
    sample_events: list[dict[str, Any]]
    # Статуса тут больше нет - триаж-статус (new -> investigating -> closed) существует только
    # у Incident. Алерт - сырое срабатывание, статус ему не нужен (см. CLAUDE.md/docs/spec).
    # Транзитное поле - НЕ персистится как колонка (store.py пишет INSERT явным списком
    # колонок, этого поля среди них нет). row_id событий ЭТОГО батча (Zircolite-локальный id,
    # см. normalize.py), из которых собран алерт - app/main.py:_process_batch использует их
    # (после перевода в настоящий events.event_id через store_events) для events.alert_id -
    # основа цепочки event -> alert -> incident без всяких "сущностей" (см. store.py:
    # link_alerts_to_incident, docs/spec/incidents.md). У correlation-алертов (app/detection/
    # correlation.py:_build_alert) всегда пусто - у них своя, отдельная схема dedup/резолва
    # через rule_hits (см. докстринг correlation.py про цепочки).
    source_row_ids: list[Any] = Field(default_factory=list)


class Incident(BaseModel):
    """Инцидент - агрегат алертов, ЕДИНИЦА РАБОТЫ АГЕНТА (Этап 5). Заводится ТОЛЬКО при
    срабатывании correlation-правила, помеченного блоком `correlation.incident` (см.
    app/detection/correlation.py:evaluate_batch, app/rules/rules_catalog.py). Обычные алерты в
    инциденты сами не собираются (catch-all прохода нет - осознанное ограничение Этапа 4).

    Идентичность - фиксированный бакет по timespan правила: dedup_key =
    sha256(f"{incident_type}:{':'.join(group_values)}:{window_bucket}")[:16], где window_bucket -
    anchor окна, округлённый вниз до кратности timespan в секундах. Повтор в том же бакете ->
    UPDATE строки (см. store.upsert_incidents), разрыв > timespan -> новый бакет -> новый инцидент.
    """
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    dedup_key: str
    incident_type: str  # slug из correlation.incident.type
    title: str
    severity: Severity
    status: IncidentStatus = "new"  # см. IncidentStatus - единственный источник правды
    source_batch: str
    ruleset_path: str = ""
    correlation_rule_id: str = ""
    correlation_rule_title: str
    group_key: dict[str, str] = Field(default_factory=dict)  # {group_by_field: value}
    member_rule_titles: list[str] = Field(default_factory=list)  # base_rule_titles правила
    window_start: str  # нормализованный ISO (anchor - timespan)
    window_end: str  # нормализованный ISO (anchor)
    window_bucket: str  # ISO начала бакета - часть dedup_key
    alert_count: int = 0  # привязанных строк alerts (досчитывается в link_alerts_to_incident)
    mitre_techniques: list[str] = Field(default_factory=list)
    entities: Entities = Field(default_factory=Entities)
    sample_events: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow_naive)
    updated_at: datetime = Field(default_factory=utcnow_naive)


class Investigation(BaseModel):
    """Расследование инцидента: очередь + результат работы агента (Этап 5). На Этапе 4 -
    только каркас: строка заводится `queued` при создании инцидента, фоновая заглушка
    (app/incidents.py:run_pending) переводит queued -> running -> done с placeholder-вердиктом."""
    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    status: str = "queued"  # queued -> running -> done -> error
    verdict: Optional[str] = None  # TP | FP | needs-review
    rationale: str = ""
    confidence: Optional[float] = None
    steps: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""
    created_at: datetime = Field(default_factory=utcnow_naive)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class IngestFileRequest(BaseModel):
    """Запуск на уже лежащем на диске файле датасета (batch-режим, для тестов/OTRF)."""
    events_path: str
    input_type: str = "json"  # json | evtx | auditd | sysmon_linux | xml | csv
    ruleset: Optional[str] = None  # если не задан - берётся ruleset по умолчанию из engine
    source_label: Optional[str] = None


class IngestEventsRequest(BaseModel):
    """Приём порции сырых событий напрямую (micro-batch из очереди, например от форвардера)."""
    events: list[dict[str, Any]]
    source_label: str = "live-queue"


class IngestResponse(BaseModel):
    source_batch: str
    events_processed: int
    rules_matched: int
    alerts_created: int
    duration_seconds: float


class IncidentStatusUpdate(BaseModel):
    """Тело PATCH /incidents/{id}/status - жизненный цикл new -> investigating -> closed.

    Именно Literal, а не str: раньше сюда проходило любое значение ({"status": "bogus"} -> 200
    и запись в БД), после чего инцидент не находился ни одним фильтром /incidents?status=... .
    С Literal FastAPI сам отвечает 422 со списком допустимых значений, до Store дело не доходит
    (там на этот же случай остался ValueError - Store зовут и мимо HTTP)."""
    status: IncidentStatus


class CustomRuleSubmit(BaseModel):
    """Тело POST /rules/custom - сырой Sigma YAML одного правила (валидация/компиляция
    в app/rules/rules_catalog.py). ruleset - существующий именованный custom-рулсет, куда добавить
    правило; new_ruleset_name - создать новый custom-рулсет с этим именем. Ровно один из двух."""
    yaml_text: str
    ruleset: Optional[str] = None
    new_ruleset_name: Optional[str] = None


class CustomRuleUpdate(BaseModel):
    """Тело PUT /rules/custom/{rule_id} - новый YAML для существующего правила (id не меняется)."""
    yaml_text: str


class MainRulesetRuleToggle(BaseModel):
    """Тело POST /main-ruleset/rules - включить/выключить одно правило в основном рулсете."""
    ruleset: str
    rule_id: str
    include: bool


class MainRulesetToggle(BaseModel):
    """Тело POST /main-ruleset/rulesets - добавить/убрать рулсет ЦЕЛИКОМ в основной рулсет."""
    ruleset: str
    include: bool


SOURCE_DESCRIPTION_MAX = 64


class SourceCreate(BaseModel):
    """Тело POST /sources - регистрация потокового источника (вкладка «Источник данных»).
    name ОБЯЗАТЕЛЕН и уникален: он же становится меткой source_batch для всех событий и
    алертов этого источника. После создания name неизменяем (можно только удалить/пересоздать)."""
    name: str
    description: str = Field(default="", max_length=SOURCE_DESCRIPTION_MAX)


class SourceUpdate(BaseModel):
    """Тело PATCH /sources/{source_id} - что разрешено менять после создания (name и токен - нет;
    токен меняется только через POST /sources/{source_id}/rotate)."""
    enabled: Optional[bool] = None
    description: Optional[str] = Field(default=None, max_length=SOURCE_DESCRIPTION_MAX)


class ValueListCreate(BaseModel):
    """Тело POST /value-lists - новый именованный список значений (см. app/rules/value_lists.py).
    name - оно же имя плейсхолдера %name% в правилах, после создания неизменяемо."""
    name: str
    description: str = ""
    values: list[str] = Field(default_factory=list)


class ValueListUpdate(BaseModel):
    """Тело PUT /value-lists/{name} - описание + значения (name берётся из URL, не меняется)."""
    description: str = ""
    values: list[str] = Field(default_factory=list)
