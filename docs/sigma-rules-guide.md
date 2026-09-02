# Полный гайд по Sigma-правилам

Sigma — открытый, платформо-независимый формат описания правил обнаружения угроз для SIEM-систем. Правило пишется один раз на YAML, а конвертер (pySigma / sigma-cli) транслирует его в нативный язык запросов конкретной платформы (Splunk SPL, Elastic EQL/Lucene, Microsoft Sentinel KQL, QRadar AQL и т.д.).

---

## 1. Как это работает

1. Аналитик описывает логику обнаружения в YAML-файле.
2. **Backend + pipeline** (часть pySigma) знают, как абстрактные поля Sigma (`Image`, `CommandLine`, `User`) соответствуют реальным полям конкретного источника логов (например, Sysmon, Windows Security Log, ECS в Elastic).
3. Конвертер транслирует правило в целевой язык запросов.
4. Запрос выполняется в SIEM (периодически или в реальном времени), при совпадении — алерт.

```bash
pip install sigma-cli
sigma convert -t splunk -p sysmon my_rule.yml
sigma check my_rule.yml        # валидация синтаксиса
```

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

Указывает источник логов, от которого зависит выбор pipeline при конвертации.

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

Чем точнее `logsource`, тем корректнее конвертер смапит имена полей — это критично, ошибка здесь приводит к "тихой" поломке правила (конвертируется без ошибок, но никогда не сработает).

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
  ParentImage: null          # поле отсутствует / пусто
  CommandLine|contains: '*'  # wildcard — обычно не нужен, contains уже подразумевает "где угодно"
```
Wildcards `*` и `?` поддерживаются нативно в значениях без модификаторов (`Image: '*\temp\*.exe'`).

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

Реализация — свой разворот текста до компиляции (`app/value_lists.py`), не через
`pysigma ValuePlaceholderTransformation` (Zircolite не даёт воткнуть свой pipeline).

---

## 5. Correlation rules — корреляция между событиями/правилами

Это отдельный **тип** YAML-документа (не `detection`, а `correlation`), который ссылается на обычные Sigma-правила по их `id` и описывает логику между несколькими событиями во времени. Раньше это делали через костыльный `| count() by ...`, теперь — нормальный формализм.

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

Отдельный механизм (часть pySigma, не самого правила) — конфиги, описывающие, как поля Sigma превращаются в реальные имена полей источника:

- `Image` → `process.executable` (ECS/Elastic) или `NewProcessName` (нативный Windows Security Log)
- `CommandLine` → `process.command_line` (ECS) или `CommandLine` (Sysmon как есть)

Если пишете правило под нестандартный источник логов (кастомный SIEM-коннектор), может понадобиться свой pipeline — это Python/YAML-конфигурация, отдельная от самого `.yml` правила.

---

## 9. Практические рекомендации по написанию правил

1. **Отталкивайтесь от конкретного поведения атаки**, а не абстрактной идеи. Возьмите технику из MITRE ATT&CK, посмотрите реальные логи (Sysmon EID 1, auditd execve и т.п.), найдите уникальные признаки.
2. **`logsource` должен быть максимально точным** — иначе конвертация "тихо" сломается (сконвертируется без ошибок, но искать будет не то поле).
3. **Не делайте условия слишком широкими.** `CommandLine|contains: 'http'` — гарантированный шквал ложных срабатываний. Комбинируйте несколько условий через `and`.
4. **Всегда заполняйте `falsepositives`** — не формальность, а подсказка аналитику SOC.
5. **Реалистичный `level`** — от этого зависит приоритет алерта в очереди.
6. **Тегируйте по ATT&CK** (`attack.txxxx`) — стандарт де-факто, упрощает картирование покрытия детектов.
7. **Тестируйте конвертацию** под реальный backend перед публикацией (`sigma convert`).
8. **Валидируйте синтаксис** (`sigma check`) — YAML-ошибки легко пропустить глазами.
9. **Изучайте готовые правила** в [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — лучший источник идиом и лучших практик сообщества.
10. **Для многошаговых атак используйте корреляции**, а не пытайтесь впихнуть всю логику в один `detection` — так правило остаётся читаемым и переиспользуемым (базовые правила можно использовать и отдельно, и как "кирпичики" в корреляции).

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

```yaml
# --- Правило 1: подозрительный логин ---
title: Успешный логин после серии неудач
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low

---
# --- Правило 2: подозрительное перемещение по сети ---
title: SMB-соединение к административной шаре
id: 22222222-2222-2222-2222-222222222222
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort: 445
    ShareName|endswith: '\ADMIN$'
  condition: selection
level: medium

---
# --- Корреляция: логин -> lateral movement на одном хосте за 15 минут ---
title: Цепочка "логин -> SMB lateral movement"
correlation:
  type: temporal_ordered
  rules:
    - 11111111-1111-1111-1111-111111111111
    - 22222222-2222-2222-2222-222222222222
  group-by:
    - Hostname
  timespan: 15m
level: high
```

Каждое отдельное правило может быть низкой критичности (шумное само по себе), но их упорядоченная комбинация в коротком окне — сильный сигнал компрометации.
