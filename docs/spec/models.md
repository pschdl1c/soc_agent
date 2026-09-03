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
| `status` | `str` | `"new"` | `new` → `investigating` → `closed` |

## Модели тел запросов

| Модель | Эндпоинт | Поля |
|---|---|---|
| `IngestFileRequest` | `POST /ingest/file` | `events_path: str`; `input_type: str = "json"`; `ruleset: str \| None = None`; `source_label: str \| None = None` |
| `IngestEventsRequest` | `POST /ingest/events` | `events: list[dict]`; `source_label: str = "live-queue"` (игнорируется, метку задаёт источник) |
| `IngestResponse` | ответ `/ingest/*` | `source_batch: str`; `events_processed: int`; `rules_matched: int`; `alerts_created: int`; `duration_seconds: float` |
| `AlertStatusUpdate` | `PATCH /alerts/{id}/status` | `status: str` |
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
