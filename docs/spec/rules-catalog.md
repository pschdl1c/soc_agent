# Каталог Sigma-рулсетов и правил

**Модуль:** `app/rules/rules_catalog.py`
**Назначение:** каталогизация builtin и custom рулсетов, чтение и пагинация правил, компиляция
пользовательского Sigma YAML, хранение custom-рулсетов на диске, интеграция со списками значений.

## Область ответственности

- Перечисление рулсетов (builtin `Zircolite/rules/*.json` + custom `data/custom_rulesets/<id>/`).
- Кэшированное чтение JSON-рулсетов и манифестов по mtime.
- Компиляция одного правила и целого рулсета через `RulesetHandler` (только при сохранении).
- Отдельная лёгкая валидация correlation-документов без pySigma.
- CRUD custom-правил и custom-рулсетов.
- Связь «список значений ↔ правила» (поиск использований, пересборка).

## Хранение custom-рулсета

`data/custom_rulesets/<ruleset_id>/`:

| Файл | Содержание |
|---|---|
| `meta.json` | `{id, name, created_at}` |
| `<rule_id>.yml` | сырой Sigma YAML обычного правила (source of truth) |
| `<rule_id>.sigmacorr` | сырой Sigma YAML correlation-правила (`CORRELATION_EXT`) |
| `.manifest.json` | кэш скомпилированных метаданных всех правил каталога |

`ruleset_id` — `uuid4().hex`, кроме зарезервированного `my_rules` (миграция старой раскладки).

`CUSTOM_ROOT = <BASE_DIR>/data/custom_rulesets` (в Docker — `/app/data/custom_rulesets`).

### Расширение correlation-правил

`CORRELATION_EXT = ".sigmacorr"`. `RulesetHandler` глобит только `*.yml`/`*.yaml`, поэтому
correlation-файлы не попадают в компиляцию вместе с правилом, на которое они ссылаются. Это
обходит баг стокового (не пропатченного — сверено по sha256 файла) `pysigma-backend-sqlite==
1.2.0` (воспроизведено и на 1.2.4): `finalize_correlation_subqueries = False`
(`pysigma/conversion/base.py`, не переопределён sqlite-бэкендом) отключает `finalize_query`
для правила с backreference из `correlation.rules` в том же `SigmaCollection`. Без
`correlation.generate:` referenced-правило молча выпадает из скомпилированного рулсета
(перестаёт детектить само по себе); с `generate: true` наружу уходит НЕ финализированная сырая
SQL-строка вместо dict, что валит компиляцию Zircolite-стороны совсем.

`_CORR_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}`.

## Исключения

| Класс | Смысл | HTTP |
|---|---|---|
| `CatalogNotFound` (подкласс `CatalogError`) | запрошенного рулсета/правила нет | 404 |
| `CatalogError` | объект есть, но действие недопустимо: встроенный рулсет как цель записи/удаления/добавления в main, невалидный путь или id, взаимоисключающие параметры | 400 |
| `RuleValidationError` | пользовательский YAML не прошёл валидацию/компиляцию | 400 |

## Кэш чтения

`_load_json_rules(path)` — `json.load` с кэшем `{abs_path: (mtime, list)}` под `_cache_lock`.
Список рулсета должен быть JSON-массивом, иначе `CatalogError`. `_invalidate_cache(path)`
сбрасывает запись. `_write_manifest` пишет манифест и инвалидирует его кэш.

## Резолв путей

### `_safe_resolve(ruleset_path) -> Path`

Для builtin: `(BASE_DIR / ruleset_path).resolve()`, проверка `is_relative_to(Zircolite/rules)`.
Выход за пределы → `CatalogError` (защита от path traversal).

### `_custom_ruleset_dir(ruleset_path) -> Path`

Требует префикс `CUSTOM_PREFIX = "custom_rulesets/"`, id по `_SAFE_ID_RE = ^[A-Za-z0-9_-]{1,128}$`,
существующий `meta.json`. Нет префикса / кривой id → `CatalogError`; нет такого рулсета →
`CatalogNotFound`. Путь с префиксом `CUSTOM_PREFIX` разбирается ТОЛЬКО как кастомный (в т.ч.
несуществующий) — иначе он проваливался бы в builtin-ветку и получал сообщение про
«недопустимый путь»/«встроенные рулсеты» вместо честного «не найден».

### `_find_rule_file(target_dir, rule_id) -> Path | None`

Ищет `<rule_id>.yml`, затем `<rule_id>.sigmacorr`.

## Чтение правил

### `load_rules(ruleset_path) -> list[dict]`

- custom → содержимое `.manifest.json` (через кэш).
- builtin → `_load_json_rules(_safe_resolve(ruleset_path))`.

### `paginate_rules(rules, q, sort_by, sort_dir, limit, offset, only_ids=None, in_main_fn=None, level=None, status=None) -> dict`

Над готовым списком: подстрочный поиск `q` по `title`/`description`; фильтр `level`/`status`
(мультиселект, регистронезависимо); фильтр `only_ids`; сортировка (`level` — по `LEVEL_ORDER`,
`title`/`author`/`status` — по строке); срез `[offset:offset+limit]`. При `in_main_fn` — в
каждую строку добавляется `in_main: bool`.
Возврат: `{"rules": [...], "total": int, "limit": int, "offset": int}`.

`LEVEL_ORDER = {critical: 0, high: 1, medium: 2, low: 3, informational: 4}`.

### `search_rules(ruleset_path, ...)` — `paginate_rules(load_rules(ruleset_path), ...)`.

### `get_rule(ruleset_path, rule_id) -> dict | None`

Правило по `id`. Для custom-рулсета добавляет `yaml_text` — содержимое `<rule_id>.yml`
или `<rule_id>.sigmacorr` (dict копируется перед мутацией). У builtin `yaml_text` отсутствует.

### `load_correlation_rules(ruleset_path) -> list[dict]`

Только для custom. Читает `*.sigmacorr` напрямую (`yaml.safe_load_all`, без pySigma).
Строит общий индекс `name`/`id` → `{"title": <str>, "kind": "base"|"correlation"}` — **и по
`*.yml`/`*.yaml` (`kind="base"`), И по `*.sigmacorr` (`kind="correlation"`)**. Вторая категория
нужна для ЦЕПОЧЕК (`correlation.rules` ссылается на другую correlation, форма
`artifacts/content/auth_after_brutforce.yml`) — без неё ссылка correlation → correlation
никогда не резолвится, и вся зависимая correlation-запись (включая её собственные корректные
base-ссылки) молча пропадает целиком (Этап A дорожной карты — прежде это «глушило» все
`temporal_ordered`-правила в контенте). Для каждого correlation-документа с `title` и словарём
`correlation`:

```
{
  "id": <str|None>, "title": <str>, "level": <str>, "description": <str>, "tags": <list>,
  "type": <str>, "group_by": <list>, "timespan": <str>, "condition": <dict>,
  "base_rule_titles": [<title соседнего правила>, ...],
  "base_rule_refs": [{"title": <str>, "kind": "base"|"correlation"}, ...],
  "incident": <{"type": <slug>, "severity": <str|None>, "title": <str|None>} | None>
}
```

`id` — `id:` из YAML, а при его отсутствии **имя файла** (`<rule_id>.sigmacorr`). Фолбэк
обязателен: Sigma не требует `id:`, в файл он не дописывается, а по `id` correlation-запись
сопоставляется с `.manifest.json` в `correlation._active_correlation_rules` для «основного
рулсета» — с `id=None` правило молча выпадало из main (сохранено, видно в UI, никогда не
срабатывает).

`incident` (Этап 4) — нормализованный блок `correlation.incident` (`_parse_incident_spec`);
`None`, если блока нет. Помечает правило как инцидентное (см. `docs/spec/incidents.md`).
`_compile_correlation_doc` кладёт в `.manifest.json` булев бейдж `incident: true` (без slug —
его читает `load_correlation_rules` из raw YAML).

`_validate_correlation_doc` на сохранении дополнительно проверяет:
- разрешимость КАЖДОЙ ссылки `correlation.rules` по `ref_index` (см. `build_ref_index`):
  неизвестное имя → `RuleValidationError` с перечислением доступных имён рулсета. Ссылки
  резолвятся только внутри своего рулсета; при загрузке пака в индекс дополнительно входят
  документы самого файла. Без этой проверки правило сохранялось успешно и молча выпадало из
  `load_correlation_rules` — корреляция никогда не срабатывала;
- блок `correlation.incident`, если задан: `type` обязателен и slug `^[a-z0-9][a-z0-9_]{0,63}$`,
  `severity` из набора `Severity`, `title` непуст;
- `timespan` не длиннее срока хранения событий: `parse_timespan(timespan) >
  SIEM_EVENTS_RETENTION_DAYS·86400` (при включённом ретеншне) → `RuleValidationError` — иначе
  окно корреляции систематически недосчитывало бы, часть его старше ретеншна физически
  удаляется вместе с `events` и осиротевшими `rule_hits` (см. `docs/spec/correlation.md`).

`base_rule_titles` — плоский список (обратная совместимость, используется как OR-список в
SQL); `base_rule_refs` — параллельный список с `kind`, нужен `app/detection/correlation.py`
(`active_hit_spec` различает, кому писать `rule_hits`-попадание: `store_events` — для "base",
сама сработавшая корреляция — для "correlation", см. `docs/spec/correlation.md`). Правило с
хотя бы одной неразрешённой ссылкой `correlation.rules` пропускается целиком — защитно, для
файлов, отредактированных мимо API (через API такая ссылка отклоняется на сохранении).

### `build_ref_index(target_dir, *, exclude_filename=None) -> dict[str, dict[str, str]]`

Индекс Sigma `name`/`id` → `{"title", "kind"}` по всем файлам одной директории рулсета:
`*.yml`/`*.yaml` → `kind="base"`, `*.sigmacorr` (только документы с блоком `correlation`) →
`kind="correlation"`. Файл `exclude_filename` пропускается (старая версия редактируемого
правила). Один и тот же индекс используют и рантайм-резолв (`load_correlation_rules`), и
валидация на сохранении — иначе они разъехались бы («сохранилось, но не работает»).

**Кэш** — по сигнатуре директории (`_correlation_dir_signature`: число файлов + максимальный
`mtime` среди `*.yml`/`*.yaml`/`*.sigmacorr`), не по одному файлу как `_load_json_rules` —
результат зависит от содержимого ВСЕЙ директории сразу (ссылки резолвятся друг на друга).
Без кэша YAML перепарсивался бы на каждый вызов, а вызывается это минимум дважды за flush
(`active_hit_spec` до `store_events` + `evaluate_batch` после, на каждый `source_batch`).

## Рулсеты: список / создание / удаление

| Функция | Возврат | Поведение |
|---|---|---|
| `list_rulesets()` | `list[dict]` | builtin (`deletable=False`) + custom (`deletable=True`); запись `main` не входит |
| `create_custom_ruleset(name)` | `str` (ruleset_path) | новый пустой каталог с `meta.json` |
| `delete_custom_ruleset(ruleset_path)` | `None` | `shutil.rmtree`; инвалидация кэша файлов |

Строка рулсета: `{path, category, name, rule_count, size_bytes, deletable}`.

`_resolve_existing_target(ruleset, new_ruleset_name) -> tuple[str|None, Path|None]` — ровно
один из двух; builtin как existing-цель отклоняется. Ничего не создаёт: для существующего
рулсета `(ruleset_path, директория)`, для нового `(None, None)`. И `save_custom_rule`, и
`save_ruleset_yaml` создают новый рулсет только после успешной компиляции — иначе ошибка в
правиле оставляла бы в каталоге пустой рулсет с `rule_count: 0`.

## Компиляция

### `compile_custom_rule(yaml_text, *, target_dir=None, exclude_filename=None) -> dict`

Валидация + компиляция одного правила без записи на диск.

1. Пустой YAML → `RuleValidationError`.
2. Разбор YAML (`yaml.safe_load_all`) — ОДИН раз и до всех проверок; `yaml.YAMLError` →
   `RuleValidationError("Некорректный YAML: ...")` с позицией ошибки от парсера.
3. Структурная пре-проверка разобранных документов `_docs_look_like_sigma_rule`
   (title+logsource+detection ЛИБО title+correlation) → иначе `RuleValidationError`.
3a. `_validate_rule_id` по КАЖДОМУ документу: если `id:` задан, он обязан парситься как `UUID`
   (та же проверка, что у pySigma в `sigma/rule/base.py`; принимаются обе формы — с дефисами и
   32 hex; отсутствующий или пустой `id:` — не ошибка). Проверяем САМИ и до компиляции, потому
   что внятное `SigmaIdentifierError` от pySigma наружу не выходит: Zircolite отсеивает
   невалидные правила в `RulesetHandler` (`is_valid_sigma_rule`) молча и отдаёт пустой рулсет,
   после чего п.8 печатал бы догадку «проверь detection/logsource» при исправных detection и
   logsource. Нестроковое значение (`id: 12345`) отклоняется тем же сообщением — `UUID(int)`
   бросает `TypeError`, который pySigma не ловит вовсе.
4. Если первый документ — correlation (`_looks_like_correlation_doc`): `_validate_correlation_doc`
   (с `ref_index=build_ref_index(target_dir, exclude_filename=...)`, если `target_dir` задан)
   + возврат `_compile_correlation_doc` (без обращения к pySigma).
5. Иначе: `value_lists.expand_placeholders(yaml_text)`; `ValueListError` → `RuleValidationError`.
6. `target_dir is None` → компиляция во временном одиночном файле; берётся `handler.rulesets[0]`.
7. `target_dir` задан → соседние `*.yml`/`*.yaml` (кроме `exclude_filename`) с раскрытыми
   плейсхолдерами копируются в scratch-каталог вместе с новым правилом; компиляция каталога;
   среди результатов выбирается запись с совпадающим `title`. Более одного кандидата →
   `RuleValidationError` (коллизия title внутри рулсета).
8. Пустой `handler.rulesets` → `RuleValidationError`.

### `compile_ruleset_yaml(yaml_text, *, target_dir=None) -> list[dict]`

Компиляция всех документов multi-document YAML. Формат `id` каждого документа проверяется
`_validate_rule_id` (как в `compile_custom_rule`) — иначе документ с кривым `id` молча выпадал
из компиляции и пак сохранялся неполным. Correlation-документы валидируются отдельно
(`_validate_correlation_doc` с `ref_index` = правила `target_dir` (если задан) плюс документы
самого файла + `_compile_correlation_doc`), обычные — разворачиваются
(`expand_placeholders`) и компилируются одним файлом **без** correlation-документов. Пустой
результат обоих видов → `RuleValidationError`. Возврат — `compiled_plain + corr_results`.

## Сохранение custom-правил

### `save_custom_rule(yaml_text, ruleset=None, new_ruleset_name=None) -> tuple[dict, str]`

`_resolve_existing_target` → `compile_custom_rule(..., target_dir=...)`. `rule_id` — валидный
Sigma `id:` (`_SAFE_ID_RE`) или новый `uuid4().hex`. Явный `id`, занятый в любом рулсете
(`_find_rule_id_owner`) → `RuleValidationError`. Запись `<rule_id>{.yml|.sigmacorr}`; запись в
`.manifest.json` под `_manifest_lock`. Возврат `(скомпилированное правило, ruleset_path)`.

### `save_ruleset_yaml(yaml_text, ruleset=None, new_ruleset_name=None) -> tuple[dict|None, str|None, list, dict]`

Возврат `(сводка рулсета|None, ruleset_path|None, collisions, value_lists_imported)`.

- `_peel_value_list_docs` извлекает документы-определения списков (строго — `is_list_document`),
  импортирует их `mode="replace"` первыми.
- Если после извлечения правил не осталось → `(None, None, [], imported)`.
- `_resolve_existing_target` — цель проверяется ДО компиляции, но новый рулсет пока не создаётся.
- `compile_ruleset_yaml(..., target_dir=<существующий рулсет|None>)` + сопоставление исходных
  YAML-документов с правилами по `title` (`_match_yaml_by_title`; дубль title — документ
  исключается).
- Правило с занятым явным `id` (в этом рулсете, в другом рулсете или дубль в файле) не
  добавляется; запись — в `collisions` (`{title, id, conflict_ruleset, conflict_title}`).
  Остальные правила сохраняются (частичный успех).
- Если не прошло НИ ОДНО правило: на диск не пишется ничего — новый рулсет не создаётся
  (`(None, None, collisions, imported)`), у существующего манифест не переписывается.
- Иначе (только теперь) создаётся новый рулсет, если целью был `new_ruleset_name`, пишутся
  файлы правил и манифест.

### `update_custom_rule(ruleset_path, rule_id, yaml_text) -> dict`

`id` всегда остаётся исходным (`rule_id` из URL). Явный другой `id` в новом YAML →
`RuleValidationError`. Тип правила (обычное ↔ correlation) может смениться — файл
переписывается под новым расширением, старый удаляется. Обновление `.manifest.json`.

### `delete_custom_rule(ruleset_path, rule_id) -> None`

Удаляет запись из `.manifest.json` и файл правила. Отсутствие правила → `CatalogNotFound`.

## Списки значений ↔ правила

| Функция | Возврат | Поведение |
|---|---|---|
| `rules_using_value_list(list_name)` | `list[{ruleset, rule_id, title}]` | правила, чей `detection` ссылается на `%list_name%` через `|expand` |
| `value_list_usage_counts()` | `dict[str, int]` | `{имя списка: число правил}` одним проходом |
| `recompile_rules_for_value_list(list_name)` | `dict` | пересобирает зависимые правила, переписывает их `.manifest.json`; возврат `{recompiled, errors, affected_rulesets}` |

`engine.invalidate(...)` для `affected_rulesets` выполняет `app/main.py`.

## Компиляция и Zircolite

При импорте модуля в `sys.path` добавляется `<BASE_DIR>/Zircolite`; импортируются
`zircolite.config.RulesetConfig`, `zircolite.rules.RulesetHandler`. `RulesetHandler`
глотает ошибки конвертации отдельных правил — после конструктора отдельно проверяется
непустой `handler.rulesets`.

## Миграция

`_migrate_legacy_layout()` (вызывается при импорте): если `custom_rulesets/my_rules/` содержит
`*.yml`/`.manifest.json`, но нет `meta.json` — дописывает `meta.json` (`id="my_rules"`,
`name="Мои правила"`). Идемпотентно.

## Зависимости

- Импортирует: `json`, `re`, `shutil`, `sys`, `tempfile`, `threading`, `datetime`, `pathlib`,
  `uuid`, `yaml`; `app/rules/value_lists.py`; `zircolite.*`.
- Импортируется: `app/rules/main_ruleset.py`, `app/detection/correlation.py`, `app/main.py`.
- Не импортирует `main_ruleset` (однонаправленная зависимость).
