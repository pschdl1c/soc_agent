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

### `correlation.incident` — только на ПОСЛЕДНЕМ звене цепочки

Если правило A (например `event_count`) помечено `correlation.incident`, а правило B ссылается
на A в своём `rules:` (эскалация «то же самое случилось ещё раз») — **не помечай A**, помечай
только B (терминальное звено). Иначе на одну и ту же историю заведутся ДВА разных инцидента
(A — сам по себе, B — поверх него) вместо одного финального, а `incidents` не умеет ссылаться на
`incidents` (связи есть только инцидент → алерт, таблица `incident_alerts`) — U-образной иерархии не
получится, получится дублирование. Непомеченное A при этом ведёт себя как обычная correlation:
пишет `Alert` — тот и станет member-алертом финального инцидента B (см. ниже, цепочка по
`event_id` резолвит такую ссылку через `alerts.dedup_key`, без похода в `events`).

## Идентичность — источник + фиксированный бакет по `timespan`

```
window_bucket = anchor_time, округлённое ВНИЗ до кратности timespan (в секундах)
dedup_key = sha256(f"{source_batch}:{incident_type}:{':'.join(group_by_values)}:{window_bucket}")[:16]
```

`source_batch` в ключе обязателен: инцидент живёт в рамках ОДНОГО источника — счёт корреляции
сужен по `source_batch` (`store.fetch_correlation_hits`), колонка `incidents.source_batch` одна,
`DELETE /batches/{источник}` чистит инциденты по ней. Без источника в ключе два разных источника,
увидевшие ту же сущность в том же бакете (обычный случай: один IP по двум серверам, у каждого
свой форвардер), схлопывались в одну строку: `UPDATE` перезаписывал окно/`sample_events`/
`entities` данными второго источника, метка `source_batch` оставалась от первого, member-алерты
приезжали из обоих (`link_alerts_to_incident` фильтрует по ТЕКУЩЕМУ батчу, не по батчу
инцидента), а `GET /incidents/{id}/context` собирал `related_events`/`entity_history` по
источнику из колонки — то есть по тому, чьих сэмплов в карточке уже не было.

- Повтор того же ключа в том же бакете → **UPDATE** строки инцидента (`store.upsert_incidents`):
  `severity = roll_up([старое, новое])`, `window_start = min`, `window_end = max`, обновляются
  `sample_events` / `entities` / `mitre_techniques` / `member_rule_titles` / `title`.
- Разрыв активности больше `timespan` → другой `window_bucket` → другой `dedup_key` → **новый
  инцидент**.
- Это отличает инцидент от correlation-алерта, который дедупится по значениям group-by без учёта
  времени (см. [`correlation.md`](correlation.md), `upsert_correlation_alerts`).

## Привязка member-алертов — цепочкой event → alert → incident, БЕЗ сущностей

`app/detection/correlation.py` знает точно, какие `event_id` реально вошли в выигрышное окно
correlation-правила (`store.evaluate_correlation_window` отдаёт их наравне со `sample_events` —
без доп. JOIN, `event_id` уже есть прямо в `rule_hits`). Именно эти `event_id`
(`link_specs_out[i]["event_ids"]`) и есть основа связи, а не значение какой-либо "сущности".

`event_id` бывает двух видов:

- **настоящий** — `events.event_id` (сработка БАЗОВОГО Sigma-правила). Резолвится через колонку
  `events.alert_id`, которую `main.py:_process_batch` проставляет СРАЗУ после `store.upsert_alerts`
  (`store.link_events_to_alerts`): для каждого построенного `Alert` берётся полный список
  `row_id` его событий ЭТОГО батча (`Alert.source_row_ids`, см. `normalize.py`), переводится в
  настоящие `event_id` через словарь, который возвращает `store.store_events` (единственное
  место, где связка `row_id → event_id` вообще существует), и пишется в `events.alert_id`.
- **синтетический** — `"corr:{dedup_key}:{title}:{anchor_time}"` (сработка ДРУГОЙ
  correlation-записи, см. цепочки в [`correlation.md`](correlation.md)). `dedup_key` — ВСЕГДА
  второй `":"`-сегмент (`split(":", 2)`, формат гарантирован кодом, который его строит) — тот же
  `dedup_key`, что достаётся `Alert.dedup_key` при постройке алерта этой correlation-записи
  (`correlation._dedup_key`). Резолвится прямым поиском `alerts.dedup_key`, без похода в
  `events` вообще. Если та correlation-запись сама была инцидентной (не рекомендуется — см.
  §"Только последнее звено..." выше), её `dedup_key` живёт в `incidents`, не в `alerts` — просто
  не находится, без падения.

`store.link_alerts_to_incident(incident_id, source_batch, event_ids)` резолвит оба вида в набор
`alert_id`, затем одним `INSERT OR IGNORE INTO incident_alerts ... WHERE source_batch = ? AND
alert_id IN (...)` пишет связи и досчитывает `incidents.alert_count` + roll-up severity по таблице
связей. `events` (кроме уже упомянутой колонки `alert_id`) не трогается.

Связь **many-to-many**: один алерт законно входит в несколько инцидентов — разные сценарии на одних
событиях (напр. `SCE_Recon_Scripted_Discovery` и `SCE_TH_Recon_Discovery_Burst`). Раньше связь была
колонкой `alerts.incident_id` с условием `incident_id IS NULL` — второй инцидент получал 0
member-алертов. Старые БД не мигрируются — `siem.db` пересоздаётся. `delete_batch` чистит `incident_alerts` и по
инцидентам источника, и по его алертам.

Это заменило более раннюю версию (сопоставление по значению "сущности": `alerts.host IN (...)
OR alerts.entities LIKE '%...%'`) — та работала, только пока `group-by` correlation-правила был
по хосту или одной из пяти жёстко зашитых категорий `_extract_entities` (user/host/src_ip/
dst_ip/process). Для `group-by` вне этих категорий (например DNS `QueryName`, путь ключа
реестра) она молча не находила ничего — `entities` этих категорий не знает, а по значению домена
`alerts.host` не совпадает. Цепочка по `event_id` не зависит от того, что такое group-by-поле —
работает для любого правила.

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
| GET | `/incidents/{id}/context` | Полный контекст: `correlation_rule` (структурные поля), `member_rules` (+ `yaml_text`/SQL), `sample_events`, `related_events` (события по сущности через `store.list_events` + `compile_filter_query`), `entity_history` (алерты, где встречаются значения `group_key` — `store.list_alerts_by_entity`; `scope: "entity"`, либо `scope: "source"` + `note`, если `group_key` пуст). Удалённое правило/вычищенные события → пустые секции + `note`, не 5xx. |
| PATCH | `/incidents/{id}/status` | `new → investigating → closed`. |
