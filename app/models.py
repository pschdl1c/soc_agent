"""
Pydantic-модели: нормализованный Alert (то, что видит агент/UI) и модели запросов к API.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


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
    created_at: datetime = Field(default_factory=datetime.utcnow)
    engine: str = "zircolite"
    source_batch: str  # имя датасета/источника, из которого пришёл алерт
    host: str
    rule: SigmaRuleRef
    entities: Entities
    event_count: int
    sample_events: list[dict[str, Any]]
    status: str = "new"  # new -> investigating -> closed


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


class AlertStatusUpdate(BaseModel):
    status: str


class CustomRuleSubmit(BaseModel):
    """Тело POST /rules/custom - сырой Sigma YAML одного правила (валидация/компиляция
    в app/rules_catalog.py). ruleset - существующий именованный custom-рулсет, куда добавить
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
