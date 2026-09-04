# Инциденты и расследования (Этап 4)

Компоненты: таблицы `incidents` / `investigations` в `siem.db` (см. [`storage.md`](storage.md)),
ветка `incident` в `app/detection/correlation.py:evaluate_batch` (см. [`correlation.md`](correlation.md)),
модуль `app/incidents.py` (заглушка фоновой обработки), ручки `/incidents*` в `app/main.py`
(см. [`http-api.md`](http-api.md)).

**Инцидент** — агрегат срабатываний, будущая единица работы AI-агента расследования (Этап 5).
Не сырое срабатывание правила: N алертов → M инцидентов, M ≪ N.

## Как заводится инцидент

Инцидент создаётся ТОЛЬКО когда срабатывает correlation-правило (`.sigmacorr`), помеченное
блоком `correlation.incident`:

```yaml
correlation:
  type: temporal_ordered
  rules: [many_failures_by_account, win_successful_logon]
  group-by: [TargetDomainName, TargetUserName]
  timespan: 15m
  incident:
    type: brute_force_success   # обязателен, slug ^[a-z0-9][a-z0-9_]{0,63}$ -> incidents.incident_type
    severity: high              # опц., informational|low|medium|high|critical
    title: "..."                # опц., иначе берётся title правила
```

- Помеченное правило создаёт инцидент **вместо** обычного `engine="correlation"` алерта.
  Непомеченные correlation-правила ведут себя как раньше.
- Помеченное правило пробивает отсечку `level: informational` (severity инцидента — из
  `incident.severity`, иначе из `level`, иначе `medium`).
- Валидация блока — `rules_catalog._validate_correlation_doc` (громко, на сохранении):
  `type` обязателен и slug, `severity` из допустимого набора, `title` непуст.
- В `.manifest.json` кладётся только булев бейдж `incident: true`; сам slug/severity/title
  читает `load_correlation_rules` из raw YAML (как `type`/`group-by`).

**Catch-all прохода по таблице `alerts` НЕТ.** Одиночный критичный алерт, не покрытый ни одним
помеченным correlation-правилом (пример — единичный `HackTool - Mimikatz Execution`), инцидентом
не становится и агенту Этапа 5 не виден. Осознанное ограничение этапа; вариант «авто-инцидент на
любой `critical` без сценария» — вне Этапа 4.

## Идентичность — фиксированный бакет по `timespan`

```
window_bucket = anchor_time, округлённое ВНИЗ до кратности timespan (в секундах)
dedup_key = sha256(f"{incident_type}:{':'.join(group_by_values)}:{window_bucket}")[:16]
```

- Повтор того же ключа в том же бакете → **UPDATE** строки инцидента (`store.upsert_incidents`):
  `severity = roll_up([старое, новое])`, `window_start = min`, `window_end = max`, обновляются
  `sample_events` / `entities` / `mitre_techniques` / `member_rule_titles` / `title`.
- Разрыв активности больше `timespan` → другой `window_bucket` → другой `dedup_key` → **новый
  инцидент**.
- Это отличает инцидент от correlation-алерта, который дедупится по значениям group-by без учёта
  времени (см. [`correlation.md`](correlation.md), `upsert_correlation_alerts`).

## Привязка member-алертов

После `store.upsert_alerts` в `main.py:_process_batch` вызывается
`store.link_alerts_to_incident(...)` — проставляет `alerts.incident_id` и досчитывает
`incidents.alert_count` + roll-up severity.

Выборка сужена `source_batch` + `rule_title IN (member_rule_titles)` + совпадение значения
сущности (`alerts.host` или подстрока в `alerts.entities`) + `incident_id IS NULL`. **`events` не
трогается** (требование производительности — см. [`correlation.md`](correlation.md)).

**Ограничение (неточность по времени):** временнóго сужения по `created_at` нет — `alerts.created_at`
это наивный wall-clock приёма, а окно корреляции считается по `event_time` источника; при replay
исторических датасетов шкалы расходятся, и алерт того же правила/сущности из соседнего окна может
быть привязан к инциденту. Приемлемо: базовые правила сценариев обычно `level: informational` и
алертов вообще не заводят — привязывать часто нечего.

## Инварианты

- Инцидент привязан к ОДНОМУ `source_batch` (как и корреляция). `Store.delete_batch` чистит
  `incidents` и `investigations` вместе с `events`/`alerts`/`rule_hits`.
- Инцидент **переживает свои `events`**: ретеншн (`delete_events_older_than`) чистит `events` и
  осиротевшие `rule_hits`, но не `alerts`/`incidents`. `GET /incidents/{id}/context` обязан
  работать при пустом `related_events`.
- Таймстампы (`created_at`/`updated_at`) — наивный UTC (`models.utcnow_naive().isoformat()`),
  строкосравнимый с границами времени из UI и с `alerts.created_at`.

## Расследования (`investigations`)

Одна строка на инцидент, жизненный цикл `queued → running → done → error`. Заводится `queued`
при создании инцидента (`store.enqueue_investigation`). Повтор в том же бакете, если расследование
уже терминальное (`done`/`error`), ре-энкьюит его в `queued` (новый контекст); `queued`/`running`
не трогаются.

`app/incidents.py:run_pending(store, batch=20)` — **заглушка Этапа 4**: берёт до `batch`
`queued`-строк (FIFO), переводит `queued → running → done` с вердиктом `needs-review` и
placeholder-обоснованием, без какого-либо анализа. Ошибка на одной строке → её статус `error`,
проход не падает. Настоящий агент (`app/agent/`, LangGraph + OpenAI-совместимый провайдер) —
Этап 5, он заменит тело `run_pending`; формат строки, жизненный цикл статуса и точка вызова
остаются.

Вызывается периодически тем же фоновым потоком `IngestWorker`, что и ретеншн `events` (параметр
`periodic_tasks`, см. [`ingest-queue.md`](ingest-queue.md)); интервал —
`SIEM_INCIDENT_VERDICT_INTERVAL` (дефолт 30с), `SIEM_INCIDENT_VERDICT_ENABLED=0` выключает.

## HTTP

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/incidents` | Список. Фильтры `status`/`incident_type`/`source_batch`/`severity`/`time_from`/`time_to`, сортировка `sort_by` (`created_at`\|`updated_at`\|`alert_count`\|`status`\|`severity`)/`sort_dir`, `limit` (1..500)/`offset`. Ответ `{incidents, total, limit, offset}`; каждая строка несёт `investigation_status`. |
| GET | `/incidents/{id}` | Карточка: строка инцидента + `member_alerts` + `investigation` + `mitre` (обогащение тегов через `app/kb.py`, объединение правила и member-алертов). |
| GET | `/incidents/{id}/context` | Полный контекст: `correlation_rule` (структурные поля), `member_rules` (+ `yaml_text`/SQL), `sample_events`, `related_events` (события по сущности через `store.list_events` + `compile_filter_query`), `entity_history` (последние алерты источника). Удалённое правило/вычищенные события → пустые секции + `note`, не 5xx. |
| PATCH | `/incidents/{id}/status` | `new → investigating → closed`. |
