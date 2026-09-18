# Полный гайд по Sigma-правилам

Sigma — открытый, платформо-независимый формат описания правил обнаружения угроз. Правило
пишется на YAML, конвертер (pySigma) транслирует его в язык запросов конкретной платформы.

Документ описывает формат Sigma и то, как он исполняется **в этом SIEM**. Раздел 1 обязателен к
прочтению до первого правила: модель исполнения здесь отличается от той, что описана в
документации SigmaHQ, и правило, написанное по общим рекомендациям, может скомпилироваться без
ошибок и никогда не сработать.

Соглашения по контенту проекта (именование, авторство, границы доменов, адаптация правил
SigmaHQ) — `CLAUDE.md` §9. Конвейер доставки и проверки — `docs/spec/content-pipeline.md`.

---

## 1. Как правило исполняется в этом SIEM

Правило компилируется в SQL (`pysigma-backend-sqlite` через Zircolite) и выполняется по таблице
событий флаша. Из этого следуют четыре отличия от обычного Sigma-стека.

### 1.1. Pipeline нет — имена полей берутся буквально

Компиляция идёт **без Sigma-пайплайна**. Поле `Image` в правиле означает поле `Image` в событии,
и ничего больше: никакого маппинга `Image → process.executable` или `Image → NewProcessName` не
происходит. Имя поля в правиле обязано совпадать с именем, которое реально приезжает с агента.

Практическое следствие: набор полей задаёт агент (`deploy/windows/vector.toml`), а не сервер.
Сверяйтесь с `artifacts/content/telemetry/event_fields.json` — это выгрузка реальных полей стенда
по ключу `<Channel>|<EventID>`.

### 1.2. `logsource` ни на что не влияет — работает guard

Раз пайплайна нет, `logsource` при компиляции игнорируется полностью. Он остаётся метаданными для
человека. Ограничение правила нужным каналом и типом события делается **явным блоком detection**:

```yaml
detection:
  guard_logsource:
    Channel: Microsoft-Windows-Sysmon/Operational
    EventID: 1
  selection:
    Image|endswith: '\powershell.exe'
  condition: guard_logsource and selection
```

Guard обязателен для каждого правила. Имя блока не должно попадать под маски `selection*` /
`filter*`, которые использует `condition` оригинального правила, — иначе оно изменит смысл
выражений вида `1 of selection*`.

### 1.3. Правило, упоминающее отсутствующее поле, живо — но фильтр по нему гасит правило

Движок досоздаёт колонки полей, упомянутых правилами, но не пришедших ни в одном событии батча,
со значением NULL (`docs/spec/detection-engine.md`). Раньше такое правило падало с `no such
column` и молча не срабатывало; теперь оно отрабатывает.

Остаётся семантика NULL: `NOT (ParentImage LIKE ...)` на отсутствующем поле — **ложь**. Правило,
чей фильтр опирается на поле, которого стек не доставляет, не сработает никогда. Самый частый
случай — `Provider_Name`: агент шлёт `ProviderName`, а Zircolite при flatten вырезает из имён
полей все не-alnum символы, поэтому подчёркивание не доедет ни при каком написании. В правиле
пишется `ProviderName`, если провайдер действительно сужает детект, иначе поле убирается — роль
ограничителя играет guard.

### 1.4. Correlation-правила хранятся отдельным файлом

На диске корреляция и правила, на которые она ссылается, **всегда лежат в разных файлах**:
корреляция — под расширением `.sigmacorr`, обычное правило — под `.yml`. Совместное присутствие
корреляции и referenced-правила в одной единице компиляции ломает сборку (разбор — раздел 5 и
`docs/guide/correlation-rules-guide.md`), поэтому они разведены физически.

Загружать их одним multi-document файлом можно — сервер сам разделит документы и разложит по
нужным расширениям. Речь именно о раскладке на диске, а не об удобстве загрузки.

---

## 2. Базовая структура правила

```yaml
title: Подозрительный запуск PowerShell с закодированной командой
id: 3d2b0c1a-1234-4a5b-9c8d-abcdef123456
status: experimental
description: >
  Обнаруживает запуск powershell.exe с флагом -EncodedCommand,
  что часто используется для обфускации вредоносных команд.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Иван Иванов
date: 2026-07-26
modified: 2026-07-26
tags:
  - attack.execution
  - attack.t1059.001

logsource:
  category: process_creation
  product: windows

detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-e '
  condition: selection

falsepositives:
  - Легитимные административные скрипты
level: high
```

### 2.1. Разбор полей метаданных

| Поле | Обязательно | Назначение |
|---|---|---|
| `title` | да | Короткое, понятное название (до ~100 символов) |
| `id` | да (для публикации) | Уникальный UUID4 правила, не меняется никогда |
| `status` | нет | Жизненный цикл: `stable`, `test`, `experimental`, `deprecated`, `unsupported` |
| `description` | рекомендуется | Что и зачем детектим, человеческим языком |
| `references` | нет | Ссылки на статьи, ATT&CK, блоги, отчёты об инцидентах |
| `author` | нет | Кто написал |
| `date` / `modified` | нет | Даты создания/правки в формате `YYYY-MM-DD` |
| `tags` | рекомендуется | Обычно `attack.<тактика>` и `attack.txxxx` (MITRE ATT&CK) |
| `falsepositives` | рекомендуется | Список legit-сценариев, дающих ложные срабатывания |
| `level` | да | Критичность: `informational`, `low`, `medium`, `high`, `critical` |
| `related` | нет | Связи с другими правилами (см. раздел 7) |

---

## 3. `logsource` — откуда данные

> **В этом SIEM `logsource` не влияет на компиляцию** (раздел 1.2): пайплайна нет, блок остаётся
> метаданными. Источник ограничивается guard-блоком в `detection`. Раздел описывает поле как
> элемент формата Sigma — заполнять его следует корректно, но полагаться на него нельзя.

Указывает источник логов, от которого в стандартном Sigma-стеке зависит выбор pipeline при
конвертации.

```yaml
logsource:
  category: process_creation   # тип события (общая категория)
  product: windows              # ОС/продукт
  service: sysmon               # конкретный сервис/лог в рамках продукта
```

Частые комбинации:

| product | category / service | Пример источника |
|---|---|---|
| `windows` | `process_creation` | Sysmon EID 1 / Security EID 4688 |
| `windows` | `service: security` | Windows Security Event Log |
| `windows` | `category: network_connection` | Sysmon EID 3 |
| `windows` | `category: file_event` | Sysmon EID 11 |
| `linux` | `service: auditd` | auditd |
| `aws` | `service: cloudtrail` | AWS CloudTrail |
| `azure` | `service: signinlogs` | Azure AD Sign-in logs |
| `okta` | `service: okta` | Okta System Log |

В стандартном Sigma-стеке ошибка в `logsource` приводит к «тихой» поломке правила: оно
конвертируется без ошибок, но ищет не то поле. Здесь той же ценой обходится отсутствующий или
неверный guard — правило будет срабатывать на чужих каналах либо не срабатывать вовсе.

---

## 4. `detection` — сердце правила

### 4.1. Именованные блоки (search identifiers)

```yaml
detection:
  selection:
    Image|endswith: '\cmd.exe'
  filter:
    User: 'DOMAIN\admin'
  condition: selection and not filter
```

- Имена блоков (`selection`, `filter`, `keywords`, `selection_1` и т.д.) — произвольные, но по конвенции сообщества:
  - `selection*` — то, что должно совпасть (позитивное условие)
  - `filter*` — то, что нужно исключить (обычно с `not` в condition)
- Внутри блока: **поля через запятую = логическое И**, **список значений одного поля = логическое ИЛИ**.

```yaml
selection:
  Image|endswith: '\powershell.exe'   # И
  CommandLine|contains:                # ИЛИ между элементами списка
    - '-enc'
    - '-EncodedCommand'
```
Значит: `Image заканчивается на powershell.exe` **И** (`CommandLine содержит -enc` **ИЛИ** `содержит -EncodedCommand`).

### 4.2. `condition` — булева логика между блоками

```yaml
condition: selection and not filter
condition: selection1 or selection2
condition: 1 of selection*          # хотя бы один из блоков selection_1, selection_2...
condition: all of selection*        # все блоки, начинающиеся с selection
condition: all of them              # все блоки в detection
condition: 1 of them
```

### 4.3. Модификаторы полей (`|`)

Ставятся после имени поля через `|`, можно комбинировать несколько подряд.

| Модификатор | Что делает |
|---|---|
| `contains` | подстрока где угодно |
| `startswith` / `endswith` | начало/конец строки |
| `re` | регулярное выражение |
| `cased` | учитывать регистр (по умолчанию Sigma регистронезависима) |
| `all` | все элементы списка должны совпасть (а не любой — меняет ИЛИ на И) |
| `gt`, `gte`, `lt`, `lte` | числовое/лексикографическое сравнение |
| `cidr` | сравнение IP с подсетью, напр. `10.0.0.0/8` |
| `base64` | значение закодировано в base64 |
| `base64offset` | то же, но с учётом 3 возможных смещений байт-выравнивания |
| `windash` | автоматически генерирует варианты Windows-флагов (`-enc`, `/enc`, `—enc`) |
| `utf16` / `utf16le` / `utf16be` / `wide` | значение в UTF-16 (частая обфускация в PowerShell) |
| `fieldref` | сравнение с значением ДРУГОГО поля этого же события, а не с константой |
| `expand` | подстановка плейсхолдера из внешнего списка/переменной окружения |
| `exists` | поле просто существует / не существует |

Пример комбинации модификаторов:
```yaml
CommandLine|contains|windash|base64offset:
  - 'FromBase64String'
```

### 4.4. Спецзначения

```yaml
selection:
  ParentImage: null          # поле отсутствует / пусто -> компилируется в `ParentImage IS NULL`
  CommandLine|contains: '*'  # wildcard — обычно не нужен, contains уже подразумевает "где угодно"
```
Wildcards `*` и `?` поддерживаются нативно в значениях без модификаторов (`Image: '*\temp\*.exe'`).

**Проверка отсутствия поля — только `Field: null`.** Модификатор `|exists: false` здесь
непригоден: он компилируется в `NOT Field = Field`, что на NULL не истина, — такая ветка не
срабатывает никогда. `Field|exists: true` (`Field = Field`) работает правильно.

Учтите при этом, что Windows чаще пишет «пусто» не отсутствием поля, а значением `'-'`, поэтому
на практике нужен фильтр по значению:

```yaml
filter_invalid_ip:
  IpAddress: ['-', '']
```

### 4.5. Именованные списки значений (`%name%` + `|expand`)

Длинные перечни (утилиты recon, LOLBIN-бинарники, известные плохие хеши) не нужно копировать
в каждое правило — они выносятся в **именованный список** и подставляются плейсхолдером:

```yaml
detection:
  selection_image:
    Image|endswith|expand:
      - '%recon_binaries%'
  selection_cli:
    CommandLine|windash|contains|expand: '%recon_flags%'
  condition: selection_image and selection_cli
```

- Список создаётся/правится во вкладке **«Списки»** UI (или через `POST/PUT /value-lists`),
  хранится в `data/value_lists/<name>.yml` (`name` = имя плейсхолдера, `[A-Za-z0-9_]{1,64}`).
- **Загрузка файлом** (вкладка «Списки» → «+ Загрузить список», или `POST /value-lists/upload`).
  Форматы YAML:
    - Sigma processing-pipeline — трансформация `value_placeholders` (или
      `query_expansion_placeholders`) с блоком `mapping: {имя: [значения]}`. Один файл может
      задавать несколько списков:
      ```yaml
      name: Recon value lists
      transformations:
        - type: value_placeholders
          mapping:
            recon_binaries: [/usr/bin/whoami, /usr/bin/netstat]
            recon_flags:    ['-a', '-n']
      ```
    - наш формат `{name, description?, values: [...]}` (в т.ч. multi-document через `---`);
    - «голый» словарь `{имя: [значения], ...}`.
  `mode` = `create` (не трогать существующие) | `replace` | `merge` (объединить значения).
  Те же документы-списки можно **подмешать в файл `+ Загрузить рулсет`** (Sigma-правила):
  documents-списки распознаются строго (только pipeline `value_placeholders` или `{name, values}`),
  пишутся ПЕРВЫМИ, правила пака компилируются уже с их значениями.
- `|expand` — последний модификатор в цепочке; значение вида `%name%` (целиком) заменяется
  **при компиляции** на все значения списка с OR-семантикой, `expand` из цепочки убирается.
  Остальные модификаторы (`endswith`, `windash`, …) сохраняются. Можно смешивать плейсхолдер
  с явными значениями в одном списке.
- На диске правило хранится с `%name%` (source of truth) — **списки живые**: правка списка
  сразу пересобирает все правила, которые на него ссылаются.
- Неизвестный плейсхолдер или пустой список → ошибка компиляции правила с внятным текстом.
- **Только кастомные правила.** Встроенные рулсеты (`Zircolite/rules/*.json`) приходят уже
  скомпилированными в SQL — плейсхолдеры в них не работают.
- v1: поддержана только запись целиком `%name%` (встроенные `foo%name%bar` — нет).

Реализация — свой разворот текста до компиляции (`app/rules/value_lists.py`), не через
`pysigma ValuePlaceholderTransformation` (Zircolite не даёт воткнуть свой pipeline).

---

## 5. Correlation rules — корреляция между событиями/правилами

Это отдельный **тип** YAML-документа (не `detection`, а `correlation`), который ссылается на обычные Sigma-правила по их `id` и описывает логику между несколькими событиями во времени. Раньше это делали через костыльный `| count() by ...`, теперь — нормальный формализм.

> Ниже — общий разбор формата по спеке Sigma (backend-агностичный). Как это реализовано
> ИМЕННО в этом проекте (собственный движок поверх `events`/`rule_hits`, куда сохранять,
> ограничения, готовые примеры) — `docs/guide/correlation-rules-guide.md`.
>
> Одно отличие важно знать уже здесь: корреляция и правила, на которые она ссылается, **не могут
> лежать в одном файле** — корреляция хранится под расширением `.sigmacorr` (раздел 1.4).

### 5.1. `event_count` — считает количество срабатываний правила

```yaml
title: Много неудачных логинов с одного IP
correlation:
  type: event_count
  rules:
    - failed_login_rule_id
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
```
"Если правило `failed_login_rule_id` сработало ≥10 раз для одного `IpAddress` за 5 минут — алерт."

### 5.2. `value_count` — считает уникальные значения поля

```yaml
correlation:
  type: value_count
  rules:
    - failed_login_rule_id
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    field: TargetUserName
    gte: 5
```
"С одного IP пытались логиниться под ≥5 разными юзернеймами за 5 минут" — классический password spraying.

### 5.3. `temporal` — несколько разных правил в одном временном окне (порядок неважен)

```yaml
correlation:
  type: temporal
  rules:
    - suspicious_login
    - lateral_movement_smb
  group-by:
    - User
  timespan: 15m
```

### 5.4. `temporal_ordered` — то же самое, но строго по порядку

```yaml
correlation:
  type: temporal_ordered
  rules:
    - initial_access_rule
    - privilege_escalation_rule
    - exfiltration_rule
  group-by:
    - Hostname
  timespan: 1h
```
Моделирует attack chain: события должны произойти именно в указанной последовательности на одном хосте в течение часа.

### 5.5. Ключевые поля корреляции

| Поле | Назначение |
|---|---|
| `type` | `event_count` / `value_count` / `temporal` / `temporal_ordered` |
| `rules` | список `id` (или `name`) правил-источников событий |
| `group-by` | по каким полям группировать (аналог `GROUP BY` в SQL) |
| `timespan` | окно времени: `5m`, `1h`, `1d` |
| `condition` | порог срабатывания (`gte`, `lte`, `eq`, диапазон) |
| `aliases` | если поле называется по-разному в разных правилах-источниках, можно задать общий алиас |

Поддержка корреляций зависит от backend'а — не все таргеты (особенно старые SIEM без нативной агрегации) реализуют это одинаково полно.

---

## 6. Sigma Filters — фильтры без изменения самого правила

Отдельный YAML-объект, который "накладывается" поверх чужого/готового правила (например, из публичного репозитория SigmaHQ), не трогая исходный файл — удобно для исключений под конкретную инфраструктуру.

```yaml
title: Исключение для сервера сборки CI
filter:
  rules:
    - suspicious_powershell_rule_id
  selection:
    Hostname: 'CI-BUILD-01'
  condition: not selection
```
Решает проблему: не нужно форкать чужое правило ради одного false positive в своей среде.

---

## 7. Связи между правилами: `related`

```yaml
related:
  - id: 51e42a95-2f80-4a25-8dc7-1234567890ab
    type: derived
  - id: 9b6a1f3e-aaaa-bbbb-cccc-000000000000
    type: obsolete
```

Типы связи:
- `derived` — это правило создано на основе другого
- `obsolete` — заменяет более старое правило
- `merged` — несколько правил объединены в это
- `renamed` — правило переименовано (тот же смысл, новый `id`/`title`)
- `similar` — концептуально похожее, но не заменяющее

Полезно для управления жизненным циклом детектов в большом репозитории.

---

## 8. Pipelines и Taxonomies (маппинг полей)

Отдельный механизм pySigma (не часть самого правила) — конфиги, описывающие, как поля Sigma
превращаются в реальные имена полей источника:

- `Image` → `process.executable` (ECS/Elastic) или `NewProcessName` (нативный Windows Security Log)
- `CommandLine` → `process.command_line` (ECS) или `CommandLine` (Sysmon как есть)

**В этом SIEM пайплайна нет, и заводить его не планируется.** Имена полей берутся буквально
(раздел 1.1), а формат событий задаёт агент. Практические последствия при переносе правила из
SigmaHQ:

| Что в правиле SigmaHQ | Что делать здесь |
|---|---|
| Абстрактное имя поля (`Image`, `CommandLine`, `User`) | Оставить как есть — Sysmon шлёт эти имена буквально |
| Правило на `process_creation` без привязки к EID | Писать под Sysmon EID 1 (поле `Image`); близнеца на 4688 не заводить |
| `Provider_Name` | Заменить на `ProviderName`, если сужает детект, иначе убрать (раздел 1.3) |
| Опора на `logsource` | Перенести в guard-блок (раздел 1.2) |

Близнец на Security 4688 не заводится намеренно: один запуск процесса пишет и Sysmon 1, и 4688,
поэтому два правила дали бы двойной счёт в корреляциях. То же с установкой службы — правила
пишутся только на Security 4697, не на System 7045.

---

## 9. Практические рекомендации по написанию правил

1. **Отталкивайтесь от конкретного поведения атаки**, а не абстрактной идеи. Возьмите технику из
   MITRE ATT&CK, посмотрите реальные события стенда, найдите уникальные признаки.
2. **Guard обязателен** (раздел 1.2). Правило без ограничения по `Channel`/`EventID` сработает на
   чужом канале — `logsource` от этого не защищает.
3. **Сверяйте имена полей с `telemetry/event_fields.json`.** Поле, которого стек не доставляет,
   делает правило мёртвым молча (раздел 1.3).
4. **Не делайте условия слишком широкими.** Базовое правило даёт свой алерт, а не только питает
   корреляцию: отсечка `informational` в этом SIEM снята намеренно. `SELECT * FROM logs WHERE
   EventID=4624` без фильтров дал на стенде 71 алерт, из которых все 71 — служебные входы SCM.
   Для auth-правил обязательны белый список `LogonType` и отсечка машинных учёток
   (`TargetUserName|endswith: '$'`).
5. **Фильтруйте мусорные значения ключа корреляции.** Windows пишет «пусто» как `'-'`, и это
   полноправное значение group-by: у 4625 при локальном входе `IpAddress` равен `'-'`. Без
   фильтра корреляция сложит все локальные неудачи машины в один бакет.
6. **Всегда заполняйте `falsepositives`** — подсказка аналитику и будущему агенту расследования.
7. **Реалистичный `level`** — от него зависит severity алерта и приоритет разбора.
8. **Тегируйте по ATT&CK** (`attack.txxxx`) — по этим тегам карточка алерта достраивает технику
   из базы знаний (`docs/spec/knowledge-base.md`).
9. **Изучайте готовые правила** в [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma); поиск
   кандидатов и черновик адаптации — `scripts/content/sigma_find.py` и `adapt_sigma.py`.
10. **Для многошаговых атак используйте корреляции**, а не пытайтесь впихнуть всю логику в один
    `detection` — базовое правило остаётся переиспользуемым «кирпичиком» для нескольких сценариев.
11. **Проверяйте правило фикстурой.** Прогон синтетики на изолированном экземпляре —
    `docs/spec/content-pipeline.md`; каждое базовое правило обязано сработать хотя бы в одном
    кейсе (`test_content.py --coverage`).

---

## 10. Мини-шпаргалка условий

```yaml
condition: selection                     # один блок
condition: selection and not filter      # с исключением
condition: sel1 or sel2                  # любой из двух
condition: 1 of selection*               # любой из блоков с префиксом selection
condition: all of selection*             # все блоки с префиксом selection
condition: all of them                   # все блоки detection
condition: 1 of them                     # хотя бы один блок detection
```

## 11. Полный пример с корреляцией (attack chain)

Пример собран по правилам этого SIEM: guard у каждого базового правила, фильтры мусорных
значений, ссылки по `name`, корреляция — **отдельным файлом** (раздел 1.4).

`auth/rules/network_logon_success.yml`:

```yaml
title: Network Logon Success
name: network_logon_success
id: 11111111-1111-1111-1111-111111111111
author: ET, Claude
detection:
  guard_logsource:
    Channel: Security
    EventID: 4624
  selection:
    LogonType: 3
  filter_machine:
    TargetUserName|endswith: '$'
  filter_invalid_ip:
    IpAddress: ['-', '']
  condition: guard_logsource and selection and not 1 of filter_*
level: informational
```

`lateral/rules/admin_share_connection.yml`:

```yaml
title: Admin Share Network Connection
name: admin_share_connection
id: 22222222-2222-2222-2222-222222222222
author: ET, Claude
detection:
  guard_logsource:
    Channel: Security
    EventID: 5140
  selection:
    ShareName|endswith: '\ADMIN$'
  condition: guard_logsource and selection
level: low
```

`lateral/correlations/sce_lateral_admin_share.yml` (на диск ляжет как `.sigmacorr`):

```yaml
title: SCE_Lateral_AdminShare_After_Logon
name: sce_lateral_admin_share
id: 33333333-3333-3333-3333-333333333333
correlation:
  type: temporal_ordered
  rules:
    - network_logon_success
    - admin_share_connection
  group-by:
    - Computer
  timespan: 15m
  incident:
    type: lateral_admin_share
    severity: high
level: high
```

Замечания к примеру:

- Базовые правила лежат в **разных доменах-рулсетах**, и это норма: ссылки `correlation.rules`
  резолвятся по всем своим рулсетам, а копировать правило между доменами нельзя (копия — другой
  `title`, то есть лишний алерт и лишние строки леджера на то же событие).
- Ссылки даны по `name`, а не по `id` — оба варианта работают, но `name` читаемее.
- `group-by: [Computer]` — общее поле обоих событий. Связать поля с разными именами (например
  `TargetSid` ↔ `MemberSid`) нельзя: алиасов полей в движке нет.
- Блок `incident` ставится только на **последнем** звене цепочки. Если пометить и промежуточное,
  на одну историю заведётся два инцидента вместо одного.

Каждое отдельное правило может быть низкой критичности, но их упорядоченная комбинация в коротком
окне — сильный сигнал компрометации.
