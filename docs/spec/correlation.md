# Стейтфул-корреляция

**Модуль:** `app/detection/correlation.py`
**Назначение:** оценка Sigma correlation-правил всех эвалуируемых типов (`event_count`,
`value_count`, `temporal`, `temporal_ordered`, включая ЦЕПОЧКИ — correlation ссылается на
другую correlation) поверх постоянных таблиц `events`/`rule_hits`, независимо от размера
micro-batch И независимо от размера БД.

## Область ответственности

- Определение активных correlation-правил для рулсета и полей, которые нужно денормализовать
  в `rule_hits.group_json` (`active_hit_spec`).
- Оценка окна после каждого flush ingest-воркера с коротким замыканием.
- Топологический порядок обработки корреляций внутри одного прохода — цепочки корректно видят
  срабатывание потомка в ТОМ ЖЕ flush'е.
- Формирование correlation-алертов (`engine="correlation"`).

## Причина отдельной реализации (не `pysigma-backend-sqlite`/Zircolite)

- `ZircoliteCore` создаётся заново на каждый flush с пустой in-memory БД — между вызовами
  состояния нет в принципе.
- Установленный **сток** (не пропатченный — сверено по sha256 файла против RECORD в dist-info)
  `pysigma-backend-sqlite==1.2.0` для `event_count`/`value_count` генерирует SQL БЕЗ единого
  упоминания `timespan` — `convert_timespan` вызывается, но в шаблоне нет плейсхолдера
  `{timespan}`, а `str.format` молча игнорирует лишний kwarg. Окно вычисляется и выбрасывается,
  без ошибки/предупреждения.
- `temporal`/`temporal_ordered` у того же бэкенда окно накладывают, но как
  `(julianday(last_event) - julianday(first_event)) <= timespan` — «весь срок жизни группы
  уложился в timespan», а НЕ скользящее окно. На накопленной БД группа, где активность была в
  январе и в июне, не сработает никогда, даже если внутри был всплеск за 5 минут.
- `temporal_ordered` того же бэкенда считает `GROUP_CONCAT(sigma_rule_id ORDER BY timestamp)`
  и **никогда её не сравнивает** — `HAVING` условие идентично `temporal` (`rule_count {op}
  {count}`). Реальный порядок появления событий не проверяется вообще.
- То же самое воспроизведено в единственном другом SQL-совместимом Sigma-бэкенде
  (`pysigma-backend-clickhouse`, `clicksiem/pySigma-backend-clickhouse`) — построчный порт тех
  же трёх дефектов (`{timespan}` отсутствует у `event_count`/`value_count`, `temporal` считает
  по всей истории группы, `temporal_ordered` не сравнивает порядок). Это не баг одного
  бэкенда — Sigma-бэкенд генерирует один SQL statement, а скользящее окно с анкером и
  переоценкой на каждый flush — свойство движка исполнения, которого у Sigma-бэкендов нет
  в принципе. DuckDB-бэкенда для Sigma не существует вовсе.

Модуль использует собственный компилятор с bound-параметрами и `json_extract` через
`app/store.py` (без `JOIN` к `events` на счётном пути — см. «Производительность» ниже).

## Поддержанные типы

`event_count`, `value_count`, `temporal`, `temporal_ordered` — включая цепочки (correlation
ссылается на другую correlation, форма `artifacts/content/auth_after_brutforce.yml`).
«Расширенные» condition-выражения (`temporal_extended`/`temporal_ordered_extended`, напр.
`condition: {expression: "rule_a and rule_b"}`) не поддержаны — отклоняются явной ошибкой при
сохранении правила (`app/rules/rules_catalog.py:_validate_correlation_doc`), не тихой
инертностью.

## Производительность: двухфазный счёт

**Обязательное требование:** скорость коррелятора не должна зависеть от размера БД. Проверяется
`scripts/bench_correlation.py` (десятикратный рост `rule_hits` даёт единицы процентов роста
времени счёта, не десятикратный).

Достигается двумя изменениями относительно наивной реализации «запрос на каждый ключ с `JOIN`
к `events`»:

1. **`rule_hits.group_json`** — значения нужных полей (group-by ∪ `condition.field` у
   `value_count`) денормализуются ПРЯМО в леджер на запись (`store.store_events(...,
   hit_spec=...)` для обычных Sigma-попаданий, `store.insert_correlation_hits(...)` для
   попаданий самих correlation-правил — см. «Цепочки» ниже). Счёт больше НЕ обращается к
   `events`/`raw_json` вообще — только к `rule_hits`, который проиндексирован именно под этот
   доступ (`idx_rule_hits_lookup(rule_title, source_batch, event_time)`).
2. **Двухфазный запрос** (`_evaluate_correlation_rule`):
   - **Фаза 1** — `store.evaluate_correlation_windows(...)` — ОДИН `GROUP BY`-запрос по ВСЕМ
     кандидатным ключам объединённого окна `[min(anchor) − timespan, max(anchor)]` сразу.
     `O(H)`, где `H` — число попаданий базового правила внутри окна, НЕ размер БД. Грубая
     оценка (окно шире индивидуального может завысить счёт отдельных ключей) — служит
     коротким замыканием: ключи, не прошедшие порог здесь, дальше не проверяются.
   - **Фаза 2** — `store.evaluate_correlation_window(...)` — точная перепроверка ТОЛЬКО
     кандидатов, прошедших фазу 1 (обычно 0–2 ключа за flush), в их СОБСТВЕННОМ узком окне.
     Здесь же достаются `sample_events` (единственное место, где есть `JOIN` к `events` — не
     влияет на стоимость счёта, `LIMIT 10`).

`JOIN` к `events` больше не участвует в подсчёте `count` вообще — заменён на `json_extract` по
`rule_hits.group_json`. `EXPLAIN QUERY PLAN` на обоих запросах даёт `SEARCH rule_hits USING
INDEX idx_rule_hits_lookup (...)`, без `SCAN`.

## Цепочки (correlation → correlation) без отдельной таблицы

Сработавшая correlation-запись пишется в `rule_hits` КАК ОБЫЧНОЕ попадание
(`store.insert_correlation_hits`): синтетический `event_id` (`corr:<title>:<dedup_key>:
<anchor_time>`), `rule_title` = title самой корреляции, `event_time` = anchor окна,
`group_json` = ЕЁ СОБСТВЕННЫЕ значения group-by. Родительская корреляция видит потомка ТЕМ ЖЕ
запросом, что и обычное базовое правило — код `temporal`/`event_count`/etc. не различает
происхождение попадания.

Это работает благодаря ограничению Sigma-спеки для цепочек: связанные correlation-правила
используют ОДИН И ТОТ ЖЕ список group-by полей (иначе имена полей разошлись бы, и родитель не
нашёл бы нужные значения в `group_json` потомка).

Запись в `rule_hits` для только что сработавшей корреляции происходит СРАЗУ (не батчится до
конца прохода `evaluate_batch`) — родительская корреляция, обрабатываемая ниже по
топологическому порядку в ЭТОМ ЖЕ вызове, считает свой count запросом К БД, а не по
внутрипроцессным данным; если бы запись откладывалась, родитель не увидел бы только что
сработавшего потомка вообще.

### `_topo_order` — порядок обработки

Корреляции, на которые ссылаются ДРУГИЕ активные корреляции, обрабатываются РАНЬШЕ родителей
(стандартный DFS-топосорт по графу ссылок `kind="correlation"`). Правило, участвующее в цикле
ссылок (некорректный, но возможный контент), не роняет весь проход — обрабатывается
best-effort в исходном порядке.

### `active_hit_spec` и разделение "base"/"correlation"

`app/rules/rules_catalog.py:load_correlation_rules` резолвит `correlation.rules:` по ОБЩЕМУ
индексу `name`/`id` → `{title, kind}`, построенному и по `*.yml`/`*.yaml` (`kind="base"`), и по
`*.sigmacorr` (`kind="correlation"`) — раньше индекс строился ТОЛЬКО по `*.yml`/`*.yaml`, из-за
чего ссылка correlation → correlation никогда не резолвилась, и вся correlation-запись
(включая её собственные корректные base-ссылки) молча пропускалась целиком (это ровно то, что
раньше «глушило» все три `temporal_ordered`-правила `auth_after_brutforce.yml`).

`active_hit_spec(ruleset_path) -> dict[str, set[str]]` — названия БАЗОВЫХ (`kind="base"`)
правил → набор полей для `group_json`. Ссылки `kind="correlation"` сюда НЕ попадают — когда
сама корреляция срабатывает, `evaluate_batch` пишет её `rule_hits`-запись напрямую
(`insert_correlation_hits`) со ВСЕМИ её собственными group-by полями, `hit_spec` для этого не
нужен.

## Публичный интерфейс

### `evaluate_batch(store, ruleset_path, source_batch, matched_events_by_title) -> int`

Точка входа, вызывается из `app/main.py:_process_batch` после каждого `store.store_events(...)`.

- `matched_events_by_title` — `{rule_title: [сырые события, сматченные в этом батче под этим
  source_batch]}` — и для БАЗОВЫХ правил, и (после первого срабатывания в том же проходе) для
  correlation-правил через внутренний `fired_by_title` (копия аргумента, дополняемая
  синтетическими попаданиями сработавших корреляций — см. «Цепочки»).
- Возвращает число созданных/обновлённых correlation-алертов.
- Ранний выход `0`, если `ruleset_path` пуст, `matched_events_by_title` пуст или активных
  correlation-правил нет.

Для каждого активного correlation-правила (в топологическом порядке):

1. Пропуск, если уровень `informational`.
2. Пропуск, если `group_by` пуст (корреляция «по всей выборке» не поддерживается).
3. `new_matches` — объединение попаданий по всем `base_rule_titles` (включая синтетические от
   уже сработавших в этом проходе потомков); пропуск, если пусто (короткое замыкание).
4. `timespan_seconds` = `app.timespan.parse_timespan(timespan)`; пропуск, если `None`.
5. Для `value_count`: `distinct_field` = `condition["field"]`; пропуск, если не задан.
6. Якорь конца окна на КАЖДЫЙ кандидатный ключ = максимальный нормализованный `event_time`
   среди новых попаданий этого батча с этим ключом. Значения ключа приводятся к строкам
   (`str(v)`) — `group_json` на записи хранит их строками, несогласованность типов (напр.
   Python `int` из числового поля вроде `EventID` против строки из `group_json`) раньше давала
   ложноотрицательный результат фазы 1 (ключ просто не находился в ответе).
7. `_evaluate_correlation_rule(...)` — двухфазный счёт (см. выше), с типоспецифичной логикой:
   - `event_count`/`value_count` — обычное сравнение `condition` со счётом;
   - `temporal` — `mode="distinct_rules"`, порог по умолчанию — все ссылки должны
     присутствовать (`count >= len(base_titles)`); явный простой `condition` (если указан)
     уважается вместо дефолта (`_temporal_required_met`);
   - `temporal_ordered` — тот же порог, ПЛЮС `store.fetch_correlation_hit_sequence(...)` +
     `_sequence_matches_order(...)` (жадное сопоставление подпоследовательности) — РЕАЛЬНАЯ
     проверка порядка появления, которой нет ни у одного апстрим Sigma-бэкенда.
8. Сработавшие ключи → `Alert` (`_build_alert`) + `store.insert_correlation_hits(...)` СРАЗУ.
9. `store.upsert_correlation_alerts(alerts)` — один раз в конце по всем правилам батча.

### `active_hit_spec(ruleset_path: str | None) -> dict[str, set[str]]`

См. «`active_hit_spec` и разделение "base"/"correlation"» выше. Вызывается `app/main.py` до
`store.store_events`, чтобы построить аргумент `hit_spec`.

## Разбор `timespan`

`app/timespan.py:parse_timespan` (отдельный лист-модуль без импортов, симметрично видимый и
`app/detection/correlation.py` (рантайм), и `app/rules/rules_catalog.py` (валидация при
сохранении правила)). `_TIMESPAN_RE = ^(\d+)\s*([smhdw])$` (регистронезависимо). Единицы:
`s=1`, `m=60`, `h=3600`, `d=86400`, `w=604800` секунд. `M` (месяц) и `y` (год) не поддержаны.
Невалидная строка → `None`.

## Проверка условия (`_condition_met`, `_temporal_required_met`)

`condition` — словарь вида `{"gte": 10}` (`event_count`) или `{"field": "Image", "gte": 5}`
(`value_count`; `field` обрабатывается отдельно). Операторы: `gte`, `gt`, `lte`, `lt`, `eq`.
Условие без единого распознанного оператора считается **невыполненным**. Для `temporal`/
`temporal_ordered` дефолт — «все ссылки присутствуют» (`count >= len(base_titles)`), явный
простой `condition` (если автор правила его указал) уважается вместо дефолта.

## Определение активных правил (`_active_correlation_rules`)

- `ruleset_path` пуст или builtin → `[]`.
- `ruleset_path == "main"` → объединение correlation-правил из всех custom-рулсетов,
  включённых в основной рулсет (`main_ruleset.resolve_with_sources()` +
  `rules_catalog.load_correlation_rules(src)`).
- Обычный custom `ruleset_path` → `rules_catalog.load_correlation_rules(ruleset_path)`.

Возвращает записи ЛЮБОГО типа (в т.ч. непригодные к эвалуации) — фильтрация по
поддерживаемым типам (`event_count`/`value_count`/`temporal`/`temporal_ordered`) выполняется
вызывающей стороной (`evaluate_batch`, `active_hit_spec`).

## Формирование алерта (`_build_alert`)

- `SigmaRuleRef` из полей correlation-правила (`id`, `title`, `level`, `tags` c префиксом
  `attack.t`, `description`).
- `entities` = локальный `_extract_entities(sample_events)`.
- `host` = `first_present(sample_events[0], HOST_FIELDS)`; при отсутствии —
  `"-".join(key)` или `"unknown-host"`.
- `dedup_key` = `sha256(f"{rule_id}:" + ":".join(key_values))[:16]` — семантика ключа —
  набор значений group-by, не (host, main_entity).
- `engine="correlation"`, `event_count = count`.

## Инварианты

- Якорь окна — `event_time` самого позднего нового события с ключом, не `datetime.now()`
  (корректная работа при replay исторических датасетов).
- Нормализация времени (`_normalize_event_time`) дублирует `app/store._normalize_event_time`:
  `" "` → `"T"`, удаление `"Z"`. Форма должна совпадать с `rule_hits.event_time`.
- Корреляция считается в пределах одного `source_batch`.
- Скорость счёта не зависит от размера `events`/БД — только от плотности попаданий внутри
  окна (`docs/spec/storage.md`, `scripts/bench_correlation.py`).

## Ограничения

Технически correlation-правила источник-агностичны: движок работает с любыми именами полей,
пережившими flatten Zircolite, вне зависимости от `logsource`/продукта. Но есть жёсткие
структурные и функциональные границы (практическая версия — `docs/guide/correlation-rules-guide.md`
§«Ограничения»):

- **Ссылка `correlation.rules` резолвится ТОЛЬКО внутри одной директории custom-рулсета.**
  `rules_catalog._load_correlation_rules_uncached` строит индекс `name`/`id` → `title` через
  `target_dir.glob(...)` — только файлы САМОЙ этой директории. На builtin-правила (`Zircolite/
  rules/*.json`, другая директория) сослаться нельзя вообще; на правило из ДРУГОГО
  custom-рулсета — тоже нельзя, даже если оба включены в основной рулсет. Нужный селектор
  приходится продублировать как свой `.yml` в той же папке, что и корреляция (см. `windows_
  bruteforce.yml`/`auth_after_brutforce.yml` — они заводят собственные базовые правила, а не
  ссылаются на built-in).
- **Одна корреляция — один `source_batch`.** Все запросы к `rule_hits` в `store.py` фильтруют
  по конкретному `source_batch`; корреляция между событиями двух РАЗНЫХ зарегистрированных
  источников невозможна (вынесено в план Этапа B).
- **`group-by` должен буквально совпадать по именам полей между звеньями цепочки** — иначе
  родитель не найдёт значений в `group_json` потомка (см. «Цепочки» выше).
- **Только 4 из 8 типов Sigma-корреляций.** `value_sum`/`value_avg`/`value_percentile`/
  `value_median` не поддержаны — такой `type:` отклоняется `_validate_correlation_doc`.
  "Расширенные" condition-выражения (`*_extended`) — тоже.
- **Нет детекта отсутствия события** ("нет логина 24ч после...") — ограничение самой
  Sigma-спеки, все типы считают присутствие/количество, не тишину.
- **Обрезка не-алфанумерических символов в именах полей** (`Zircolite/zircolite/streaming.py:
  _NON_ALNUM_RE`) — если для поля нет явного маппинга в `Zircolite/config/config.yaml`, любое
  имя (не только вложенные пути) теряет все символы вне `[A-Za-z0-9]`: `src_ip` → `srcip`,
  `dst-port` → `dstport`. Для CamelCase-полей Windows/Sysmon это прозрачно, для `snake_case`/
  `kebab-case` источников (JSON/ECS/облако) — нет: `group-by`/`condition.field` с такими
  именами не найдут поле в событии, пока маппинг не добавлен явно.
- **Edge-triggered, не level-triggered.** Переоценка идёт только при НОВОМ попадании базового
  правила в текущем flush'е (`evaluate_batch` вызывается из `_process_batch` после каждого
  `store_events`). Порог, формально достигнутый исключительно течением времени без новых
  событий, сам по себе не «дозревает».
- **Нет ретроактивного пересчёта.** `hit_spec` (какие поля писать в `group_json`) вычисляется
  из АКТИВНЫХ на момент батча correlation-правил (`active_hit_spec`) — события, принятые ДО
  того, как правило попало в основной рулсет, в `rule_hits` не переписываются задним числом.
- **Ретеншн `events` подрезает и `rule_hits`.** `store.delete_events_older_than` чистит
  осиротевшие `rule_hits` вместе со старыми `events` — если `timespan` корреляции длиннее
  `SIEM_EVENTS_RETENTION_DAYS`, окно будет систематически недосчитывать (старая часть окна
  физически удалена раньше, чем корреляция успеет её увидеть).
- **Дедуп по значениям `group-by`, не по времени.** Повторное срабатывание того же ключа
  перезаписывает `event_count`/`sample_events` уже существующей строки алерта (см.
  `upsert_correlation_alerts`), не создаёт отдельную запись — разделение «новый инцидент» /
  «продолжение старого» появится только с сущностью Инцидента (Этап B).

## Зависимости

- Импортирует: `hashlib`, `json`, `datetime`; `app/rules/{main_ruleset, rules_catalog}`;
  `app/fields.py`; `app/models.py`; `app/store.py` (`Store`); `app/timespan.py`
  (`parse_timespan`).
- Импортируется: `app/main.py` (`evaluate_batch`, `active_hit_spec`).
