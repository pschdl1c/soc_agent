# Модели данных

**Модуль:** `app/models.py`
**Назначение:** Pydantic v2-модели нормализованного алерта, вложенных структур и тел
HTTP-запросов.

## Область ответственности

- Определение доменных моделей (`Alert`, `SigmaRuleRef`, `Entities`, `Severity`).
- Определение моделей тел запросов для эндпоинтов `app/main.py`.
- Утилита `utcnow_naive()` для получения времени создания алерта.

## `utcnow_naive() -> datetime`

Возвращает `datetime.now(timezone.utc).replace(tzinfo=None)` — наивный datetime по UTC.

Обоснование наивной формы: `Alert.created_at` сериализуется в БД строкой через `.isoformat()`
и сравнивается строково с наивными границами интервала из UI (без суффикса `Z`/offset).
Aware-форма дала бы суффикс `+00:00` и сломала бы строковое сравнение диапазонов.

## `Severity(str, Enum)`

Значения: `informational`, `low`, `medium`, `high`, `critical`.

`Severity.from_zircolite(rule_level: str | None) -> Severity` — конструктор с подстраховкой:
неизвестное или отсутствующее значение (`None`, `"unknown"`, произвольная строка) отображается
в `Severity.informational`.

`Severity.rank(value) -> int` — числовой ранг (`critical` = 5 … `informational` = 1; неизвестное
→ 1). `Severity.roll_up(values) -> Severity` — максимальная серьёзность из набора (severity
инцидента как roll-up member-алертов, см. `app/store.py:link_alerts_to_incident`).

## `Entities(BaseModel)`

Сущности, извлечённые из событий алерта.

| Поле | Тип | По умолчанию |
|---|---|---|
| `users` | `list[str]` | `[]` |
| `hosts` | `list[str]` | `[]` |
| `src_ips` | `list[str]` | `[]` |
| `dst_ips` | `list[str]` | `[]` |
| `processes` | `list[str]` | `[]` |

## `SigmaRuleRef(BaseModel)`

Ссылка на сработавшее правило внутри алерта.

| Поле | Тип | По умолчанию |
|---|---|---|
| `rule_id` | `str` | — |
| `title` | `str` | — |
| `level` | `Severity` | — |
| `mitre_techniques` | `list[str]` | `[]` |
| `description` | `str` | `""` |

## `Alert(BaseModel)`

Нормализованный алерт — единица хранения таблицы `alerts` и элемент ответов `/alerts`.

| Поле | Тип | По умолчанию | Примечание |
|---|---|---|---|
| `alert_id` | `str` | `str(uuid4())` | первичный ключ |
| `dedup_key` | `str` | — | ключ дедупликации |
| `created_at` | `datetime` | `utcnow_naive()` | наивный UTC |
| `engine` | `str` | `"zircolite"` | `"zircolite"` или `"correlation"` |
| `source_batch` | `str` | — | метка источника/датасета |
| `host` | `str` | — | хост алерта |
| `rule` | `SigmaRuleRef` | — | — |
| `entities` | `Entities` | — | — |
| `event_count` | `int` | — | число событий (или размер окна для корреляции) |
| `sample_events` | `list[dict[str, Any]]` | — | сэмпл событий |
| `source_row_ids` | `list[Any]` | `[]` | транзитное, НЕ персистится как колонка — row_id событий этого батча (см. `normalize.py`), нужны `main.py` для `events.alert_id` |

Статуса у алерта нет (был `new`/`investigating`/`closed`, убран) — триаж-статус есть только у
`Incident.status`.

## `Incident(BaseModel)` (Этап 4)

Единица хранения таблицы `incidents`. Заводится помеченным `correlation.incident` correlation-правилом
(см. `docs/spec/incidents.md`).

| Поле | Тип | По умолчанию | Примечание |
|---|---|---|---|
| `incident_id` | `str` | `str(uuid4())` | PK |
| `dedup_key` | `str` | — | `sha256(source_batch:incident_type:group_values:window_bucket)[:16]` |
| `incident_type` | `str` | — | slug из `incident.type` |
| `title` | `str` | — | `incident.title` или title правила |
| `severity` | `Severity` | — | явная / `level` правила / `medium`; далее roll-up member-алертов |
| `status` | `str` | `"new"` | `new` → `investigating` → `closed` |
| `source_batch` | `str` | — | один источник |
| `ruleset_path` | `str` | `""` | для `/context` |
| `correlation_rule_id` / `correlation_rule_title` | `str` | `""` / — | правило-триггер |
| `group_key` | `dict[str, str]` | `{}` | значения group-by |
| `member_rule_titles` | `list[str]` | `[]` | `base_rule_titles` правила |
| `window_start` / `window_end` / `window_bucket` | `str` | — | нормализованное ISO; бакет — часть `dedup_key` |
| `alert_count` | `int` | `0` | привязанных алертов |
| `mitre_techniques` | `list[str]` | `[]` | union тегов правила + member-алертов |
| `entities` | `Entities` | `Entities()` | из `sample_events` |
| `sample_events` | `list[dict]` | `[]` | из фазы 2 корреляции |
| `created_at` / `updated_at` | `datetime` | `utcnow_naive()` | наивный UTC |

## `Investigation(BaseModel)` (Этап 4)

Строка таблицы `investigations` — очередь и результат расследования инцидента.

| Поле | Тип | По умолчанию |
|---|---|---|
| `investigation_id` | `str` | `str(uuid4())` |
| `incident_id` | `str` | — |
| `status` | `str` | `"queued"` (`queued` → `running` → `done` → `error`) |
| `verdict` | `str \| None` | `None` (`TP` / `FP` / `needs-review`) |
| `rationale` | `str` | `""` |
| `confidence` | `float \| None` | `None` |
| `steps` | `list[dict]` | `[]` |
| `error` | `str` | `""` |
| `created_at` | `datetime` | `utcnow_naive()` |
| `started_at` / `finished_at` | `datetime \| None` | `None` |

## Модели тел запросов

| Модель | Эндпоинт | Поля |
|---|---|---|
| `IngestFileRequest` | `POST /ingest/file` | `events_path: str`; `input_type: str = "json"`; `ruleset: str \| None = None`; `source_label: str \| None = None` |
| `IngestEventsRequest` | `POST /ingest/events` | `events: list[dict]`; `source_label: str = "live-queue"` (игнорируется, метку задаёт источник) |
| `IngestResponse` | ответ `/ingest/*` | `source_batch: str`; `events_processed: int`; `rules_matched: int`; `alerts_created: int`; `duration_seconds: float` |
| `IncidentStatusUpdate` | `PATCH /incidents/{id}/status` | `status: IncidentStatus` = `Literal["new", "investigating", "closed"]` — любое другое значение отбивает FastAPI (422). Набор значений живёт в `INCIDENT_STATUSES` и переиспользуется `store.update_incident_status`/`store._migrate` |
| `CustomRuleSubmit` | `POST /rules/custom` | `yaml_text: str`; `ruleset: str \| None = None`; `new_ruleset_name: str \| None = None` (ровно один из двух) |
| `CustomRuleUpdate` | `PUT /rules/custom/{rule_id}` | `yaml_text: str` |
| `MainRulesetRuleToggle` | `POST /main-ruleset/rules` | `ruleset: str`; `rule_id: str`; `include: bool` |
| `MainRulesetToggle` | `POST /main-ruleset/rulesets` | `ruleset: str`; `include: bool` |
| `SourceCreate` | `POST /sources` | `name: str`; `description: str = ""` (`max_length` = `SOURCE_DESCRIPTION_MAX`) |
| `SourceUpdate` | `PATCH /sources/{id}` | `enabled: bool \| None = None`; `description: str \| None = None` (`max_length` = `SOURCE_DESCRIPTION_MAX`) |
| `ValueListCreate` | `POST /value-lists` | `name: str`; `description: str = ""`; `values: list[str] = []` |
| `ValueListUpdate` | `PUT /value-lists/{name}` | `description: str = ""`; `values: list[str] = []` |

## Константы

- `SOURCE_DESCRIPTION_MAX = 64` — максимальная длина описания источника.

## Зависимости

- Импортирует: `pydantic`, `datetime`, `enum`, `uuid`.
- Импортируется: `app/detection/normalize.py`, `app/detection/correlation.py`, `app/store.py`
  (`Alert`, `SOURCE_DESCRIPTION_MAX`), `app/main.py`.
