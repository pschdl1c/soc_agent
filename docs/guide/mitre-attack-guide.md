# Гайд по MITRE ATT&CK

MITRE ATT&CK (**A**dversarial **T**actics, **T**echniques **a**nd **C**ommon **K**nowledge) —
открытая, постоянно обновляемая база знаний о поведении атакующих, основанная на разборе реальных
инцидентов и отчётов threat intelligence. По сути это общий словарь: вместо «хакеры как-то
закрепились в системе» — конкретное «T1547.001 Registry Run Keys / Startup Folder».

ATT&CK нужен, чтобы:

- **описывать угрозы единообразно** — SOC, TI, red team и вендоры говорят на одном языке;
- **измерять покрытие детектов** — «какие техники мы ловим, а какие нет» (ATT&CK Navigator);
- **приоритизировать** — по тому, какие техники реально используют актуальные для вас группы;
- **обогащать алерты** — по технике из сработавшего правила подтянуть контекст: тактику,
  описание, чем детектить, чем митигировать, кто так делал.

Официальный сайт: <https://attack.mitre.org>. Данные в машиночитаемом виде (STIX 2.1):
<https://github.com/mitre-attack/attack-stix-data>.

---

## 1. Модель и матрица

ATT&CK делится на три **домена** (независимые матрицы):

| Домен | Про что | Пример техники |
|---|---|---|
| **Enterprise** | Windows / Linux / macOS / облака / сети / контейнеры / SaaS / Identity | T1059 Command and Scripting Interpreter |
| **Mobile** | Android / iOS | T1417 Input Capture |
| **ICS** | АСУ ТП, промышленные системы | T0836 Modify Parameter |

Этот проект работает только с **Enterprise** — именно его техники встречаются в Sigma-правилах
для Windows/Linux-логов.

### Иерархия

```
Тактика (Tactic)              — ЗАЧЕМ атакующий это делает (цель этапа)
  └── Техника (Technique)     — КАК он этого добивается (общий метод)
        └── Сабтехника        — конкретная реализация метода
              (Sub-technique)
```

- **Тактика** = столбец матрицы = фаза атаки («Execution», «Persistence», «Exfiltration»).
- **Техника** = способ достичь цели тактики. Одна техника может относиться к нескольким тактикам
  (напр. T1055 Process Injection — это и Privilege Escalation, и Stealth).
- **Сабтехника** = уточнение. `T1059` — «запуск интерпретатора вообще», `T1059.001` — именно
  PowerShell, `T1059.003` — Windows Command Shell. Не у всех техник есть сабтехники.

Матрица — это просто визуализация: столбцы = тактики в порядке kill chain (слева направо, от
разведки к воздействию), в каждом столбце — техники этой тактики.

---

## 2. Система идентификаторов

Всё в ATT&CK адресуется коротким стабильным ID. Он **не меняется** при переименовании объекта.

| Префикс | Тип объекта | Пример | URL |
|---|---|---|---|
| `TA####` | Тактика (Tactic) | `TA0002` Execution | `/tactics/TA0002` |
| `T####` | Техника (Technique) | `T1059` | `/techniques/T1059` |
| `T####.###` | Сабтехника (Sub-technique) | `T1059.001` PowerShell | `/techniques/T1059/001` |
| `M####` | Митигация (Mitigation) | `M1038` Execution Prevention | `/mitigations/M1038` |
| `G####` | Группа / актор (Group) | `G0016` APT29 | `/groups/G0016` |
| `S####` | ПО (Software: malware / tool) | `S0002` Mimikatz | `/software/S0002` |
| `C####` | Кампания (Campaign) | `C0001` Frankenstein | `/campaigns/C0001` |
| `DS####` | Источник данных (Data Source) | `DS0009` Process | `/datasources/DS0009` |
| `DET####` | Стратегия обнаружения (Detection Strategy, v18+) | `DET0516` | `/detections/DET0516` |
| `AN####` | Аналитика (Analytic, v18+) | `AN1428` | — |

Правило разбора сабтехники: `T1059.001` → родитель `T1059` (всё до точки).

---

## 3. Тактики Enterprise

Порядок = kill chain. Ниже — состав на **ATT&CK v19.2** (столбцы матрицы):

| # | ID | Тактика | shortname | Цель этапа |
|---|---|---|---|---|
| 0 | TA0043 | Reconnaissance | `reconnaissance` | Сбор информации о цели до атаки |
| 1 | TA0042 | Resource Development | `resource-development` | Подготовка инфраструктуры (домены, аккаунты, вредонос) |
| 2 | TA0001 | Initial Access | `initial-access` | Первичное проникновение (фишинг, эксплойт периметра) |
| 3 | TA0002 | Execution | `execution` | Запуск своего кода на хосте |
| 4 | TA0003 | Persistence | `persistence` | Сохранить доступ после ребута / смены пароля |
| 5 | TA0004 | Privilege Escalation | `privilege-escalation` | Повысить права (до админа / SYSTEM / root) |
| 6 | TA0005 | Stealth | `stealth` | Обход и уклонение от защиты (**бывш. Defense Evasion**) |
| 7 | TA0112 | Defense Impairment | `defense-impairment` | Отключение/порча средств защиты (новое в v19) |
| 8 | TA0006 | Credential Access | `credential-access` | Кража учётных данных |
| 9 | TA0007 | Discovery | `discovery` | Изучение окружения изнутри |
| 10 | TA0008 | Lateral Movement | `lateral-movement` | Перемещение на другие хосты |
| 11 | TA0009 | Collection | `collection` | Сбор интересующих данных |
| 12 | TA0011 | Command and Control | `command-and-control` | Управление через канал связи с C2 |
| 13 | TA0010 | Exfiltration | `exfiltration` | Вывод данных наружу |
| 14 | TA0040 | Impact | `impact` | Воздействие: шифрование, wipe, отказ в обслуживании |

> **Важно:** ATT&CK переименовывает и реструктурирует тактики между версиями. В v19 «Defense
> Evasion» стала «Stealth» (ID `TA0005` сохранился), добавилась «Defense Impairment» (`TA0112`).
> Sigma-правила при этом продолжают тегировать `attack.defense-evasion` — старые теги остаются
> валидными как исторические, но `x_mitre_shortname` в свежем бандле уже `stealth`. Полагайтесь
> на **ID**, а не на название/shortname.

---

## 4. Техника: что внутри

Пример укороченного STIX-объекта техники:

```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
  "name": "Command and Scripting Interpreter",
  "description": "Adversaries may abuse command and script interpreters to execute ...",
  "kill_chain_phases": [
    { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
  ],
  "x_mitre_is_subtechnique": false,
  "x_mitre_platforms": ["Windows", "Linux", "macOS", "Network Devices", "..."],
  "x_mitre_version": "3.0",
  "revoked": false,
  "x_mitre_deprecated": false,
  "external_references": [
    { "source_name": "mitre-attack", "external_id": "T1059",
      "url": "https://attack.mitre.org/techniques/T1059" }
  ]
}
```

Ключевые поля:

| Поле | Значение |
|---|---|
| `name` / `description` | Название и подробный разбор техники (текст содержит `[ссылки](url)` и `(Citation: …)`) |
| `kill_chain_phases[].phase_name` | shortname тактик, к которым относится техника (может быть несколько) |
| `x_mitre_is_subtechnique` | флаг сабтехники |
| `x_mitre_platforms` | ОС/платформы, где техника применима |
| `x_mitre_version` | версия самого объекта (растёт при правках его содержимого) |
| `revoked` | техника отозвана (заменена другой — см. relationship `revoked-by`) |
| `x_mitre_deprecated` | признана устаревшей и убрана из матрицы |

`revoked` и `x_mitre_deprecated` объекты обычно **игнорируются** при построении матрицы.

### Поля, которых больше НЕТ (убраны в v18)

До ATT&CK v18 у техники были свободнотекстовые поля, которые многие инструменты используют
до сих пор:

- `x_mitre_detection` — абзац «как это детектить» человеческим языком;
- `x_mitre_data_sources` — плоский список типа `["Process: Process Creation", ...]`;
- `x_mitre_permissions_required` — `["Administrator", "SYSTEM"]`;
- `x_mitre_defense_bypassed` — `["Anti-virus", "Application Control"]`.

**В v18 эти поля из бандла удалены.** Детект переехал в структурные объекты (см. §5),
data sources — в отдельную таксономию (см. §8), а `permissions_required` / `defense_bypassed`
просто убрали. Если вам нужны эти поля — придётся пинить ATT&CK ≤ v16.1 (см. §10).

---

## 5. Обнаружение: Detection Strategies и Analytics (v18+)

Начиная с ATT&CK v18 «как детектить технику» описывается не абзацем текста, а деревом
объектов:

```
Техника (attack-pattern)
   ▲
   │ relationship: detects
   │
Detection Strategy (x-mitre-detection-strategy)   DET####
   │  "Behavioral Detection of Command and Scripting Interpreter Abuse"
   │
   └── x_mitre_analytic_refs → Analytic (x-mitre-analytic)   AN####
         ├── description          — что именно ищем
         ├── x_mitre_platforms    — ["Windows"] / ["Linux"] / ...
         ├── x_mitre_log_source_references   — КОНКРЕТНЫЙ лог-сорс + канал
         │     [{ "name": "WinEventLog:Sysmon", "channel": "EventCode=1" }]
         └── x_mitre_mutable_elements        — параметры под вашу среду
               [{ "field": "TimeWindow",
                  "description": "Restrict to work hours." }]
```

### Analytic — это шаблон, а не готовое правило

`description` аналитики описывает логику в общем виде:

> Detects the execution of scripting or command interpreters (e.g., powershell.exe, cmd.exe,
> wscript.exe) outside expected administrative time windows or from abnormal user contexts,
> often followed by encoded/obfuscated arguments or secondary execution events.

А `x_mitre_mutable_elements` — это «дырки», которые заполняет **каждый под свою
инфраструктуру** (без них аналитика либо не работает, либо тонет в ложных срабатываниях):

| `field` | `description` (что туда класть) |
|---|---|
| `TimeWindow` | Ваши рабочие часы / окна обслуживания — чтобы отсечь легитимную админскую активность |
| `ParentProcessName` | Что для ваших хостов нормальный родитель интерпретатора |
| `HighRiskAccounts` | Список привилегированных / чувствительных учёток (админы, сервисные, топ-менеджмент) |
| `FinanceAppList` | Baseline финансовых / ERP-приложений, за которыми следить особенно |

`x_mitre_log_source_references` — самое ценное для SIEM: указывает **конкретный источник и
канал** (`WinEventLog:Sysmon` / `EventCode=1`, `auditd:SYSCALL` / `execve`), что напрямую
бьётся с тем, какие события реально собираются.

### Data Sources (старая модель детекта, частично жива)

Раньше связь техника↔детект шла через `x-mitre-data-component` --`detects`--> `attack-pattern`.
В свежих версиях эту роль в основном взяли Analytics, но объекты data source / data component
в бандле остались (см. §8).

---

## 6. Митигации (Mitigations)

`course-of-action` с ID `M####` — **превентивные** меры: что настроить/захарденить заранее,
чтобы техника не сработала или стала менее эффективной. Это НЕ про обнаружение.

Связь: `course-of-action` --`relationship: mitigates`--> `attack-pattern`.

Пример для T1059:

| ID | Митигация | Суть |
|---|---|---|
| M1038 | Execution Prevention | AppLocker / WDAC — блокировать запуск неизвестного кода |
| M1026 | Privileged Account Management | Ограничить права, чтобы скрипты не бежали от админа |
| M1042 | Disable or Remove Feature or Program | Убрать неиспользуемые интерпретаторы (PowerShell v2) |
| M1049 | Antivirus/Antimalware | — |

Уровень применения — архитектура / hardening, обычно не задача SOC-аналитика. Для
расследования полезно как контекст: «если это true positive — вот чем это в принципе
закрывается / почему могло не закрыться».

---

## 7. Procedure examples — кто и как применял технику

Самый конкретный вид контекста. Это `description` у relationship `uses` между актором/ПО и
техникой:

```
intrusion-set (G####)  ──uses──▶  attack-pattern (T####)   + description
malware / tool (S####) ──uses──▶  attack-pattern (T####)   + description
campaign (C####)       ──uses──▶  attack-pattern (T####)   + description
```

Примеры для T1059 (текст — прямо из ATT&CK, после чистки markdown/citation):

> **G0035 · Dragonfly** — Dragonfly has used the command line for execution.
> **G0037 · FIN6** — FIN6 has used scripting to iterate through a list of compromised PoS systems...
> **S0002 · Mimikatz** — ...

Зачем аналитику / агенту расследования: это готовые **TP-паттерны для сравнения**. Если
сработал алерт на T1059.001 с `powershell -enc`, а в procedure examples у десятка APT-групп
ровно это описано — сигнал в пользу true positive. Плюс procedure-таблица бесплатно даёт
«какие группы / какое ПО вообще используют эту технику».

---

## 8. Data Sources и Data Components

Таксономия телеметрии, нужной для детекта:

```
Data Source (DS####, x-mitre-data-source)      "Process"  (DS0009)
   └── Data Component (x-mitre-data-component)  "Process Creation"
                                                "Process Termination"
                                                "OS API Execution"
```

- **Data Source** — крупная категория телеметрии (Process, Network Traffic, Windows Registry,
  File, Command, Logon Session, Cloud Service…).
- **Data Component** — конкретный наблюдаемый факт внутри неё («Process Creation»).

В свежих версиях у data-component есть поле `x_mitre_log_sources` — привязка к реальным
каналам логов, тот же формат, что у аналитик.

Практический смысл: карта «чтобы закрыть эти техники, нам нужны такие-то логи» — вход для
планирования сбора событий в SIEM.

---

## 9. Версии ATT&CK

ATT&CK выпускается пару раз в год: `v14`, `v15.1`, `v16`, … Каждая версия — это отдельный
STIX-файл в `attack-stix-data`. Внутри бандла версия лежит в объекте `x-mitre-collection`
(`x_mitre_version`).

### Что менялось (важно для инструментов)

| Версия | Изменение |
|---|---|
| ≤ v16.1 | Есть `x_mitre_detection` (текст), `x_mitre_data_sources` (плоский), `x_mitre_permissions_required`, `x_mitre_defense_bypassed` |
| v17.x | `permissions_required` / `defense_bypassed` убраны; текст детекта и плоские data_sources ещё есть |
| **v18** | **Крупная реструктуризация.** Свободный текст детекта и плоские data_sources удалены. Введены `x-mitre-detection-strategy` + `x-mitre-analytic` (структурный детект) |
| v19 | Тактики переименованы/добавлены: Defense Evasion → **Stealth**, новая **Defense Impairment** (`TA0112`) |

**Единой версии, где есть и старые богатые поля, и новые analytics, не существует** — это
осознанная развилка MITRE в v18.

### Как зафиксировать версию

Для воспроизводимых сборок бери файл по конкретной версии (не «latest»):

```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json
```

Ещё надёжнее — пинить и git-ref репозитория (тег релиза), и версию файла.

---

## 10. STIX-формат и `attack-stix-data`

ATT&CK распространяется как **STIX 2.1 bundle** — один большой JSON:

```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [ /* тысячи объектов разных типов */ ]
}
```

### Типы объектов (Enterprise, порядок по частоте, v19.2)

| STIX `type` | ATT&CK-сущность | ~кол-во |
|---|---|---|
| `relationship` | связи между объектами | ~21000 |
| `x-mitre-analytic` | аналитика детекта | ~1750 |
| `attack-pattern` | техника / сабтехника | ~860 |
| `malware` | вредоносное ПО (`S####`) | ~730 |
| `x-mitre-detection-strategy` | стратегия детекта | ~700 |
| `course-of-action` | митигация (`M####`) | ~270 |
| `intrusion-set` | группа / актор (`G####`) | ~190 |
| `x-mitre-data-component` | компонент данных | ~110 |
| `tool` | легитимный инструмент в руках атакующего (`S####`) | ~95 |
| `campaign` | кампания (`C####`) | ~55 |
| `x-mitre-data-source` | источник данных (`DS####`) | ~40 |
| `x-mitre-tactic` | тактика (`TA####`) | 15 |
| `x-mitre-matrix` | матрица (порядок тактик в `tactic_refs`) | 1 |
| `x-mitre-collection` | метаданные набора (версия ATT&CK) | 1 |

### Relationship'ы

Объект-связь: `{ type: "relationship", relationship_type: "...", source_ref, target_ref }`.

| `relationship_type` | Смысл | source → target |
|---|---|---|
| `uses` | «применяет» | group/software/campaign → technique (это и есть procedure example) |
| `mitigates` | «закрывает» | course-of-action → technique |
| `detects` | «детектит» | detection-strategy (или data-component) → technique |
| `subtechnique-of` | «сабтехника чего» | sub-technique → parent technique |
| `revoked-by` | «заменена на» | старый объект → новый |
| `attributed-to` | «приписывается» | campaign → group |

### `external_references`

У каждого «настоящего» ATT&CK-объекта есть ссылка с `source_name == "mitre-attack"`, откуда
берётся человекочитаемый ID и URL:

```json
"external_references": [
  { "source_name": "mitre-attack", "external_id": "T1059",
    "url": "https://attack.mitre.org/techniques/T1059" },
  { "source_name": "Cobalt Strike Manual", "url": "https://..." }   // прочие ссылки — из текста
]
```

STIX-id (`attack-pattern--7385dfaf-...`) — внутренний, для `source_ref`/`target_ref`.
`external_id` (`T1059`) — то, что показывают людям.

---

## 11. Теги ATT&CK в Sigma-правилах

Sigma-правило связывается с ATT&CK через `tags` (см. `sigma-rules-guide.md` §2.1):

```yaml
tags:
  - attack.execution          # тактика  (shortname с дефисами)
  - attack.t1059.001          # техника/сабтехника (в НИЖНЕМ регистре, с точкой)
  - attack.g0016              # опционально: связанная группа
  - attack.s0002              # опционально: связанное ПО
```

Правила нормализации, если сами извлекаете ATT&CK из тегов:

- регистр — любой, приводите к своему (`attack.t1059.001` ↔ `T1059.001`);
- тактика — это `attack.<shortname>` без `t` в начале id; техника — `attack.t####[.###]`;
- у части правил проставлена только тактика без конкретной техники;
- тег техники может «тянуть» тактику, которую автор правила не проставил (техника у ATT&CK
  числится под несколькими тактиками);
- теги-тактики устаревают вместе с ATT&CK (`attack.defense-evasion` в правилах ≠ `stealth` в
  v19-бандле) — матчьте по ID техники, тактику берите из `kill_chain_phases` самой техники.

---

## 12. ATT&CK в этом проекте

### Вкладка «База знаний» → MITRE ATT&CK

- **Матрица** — тактики-колонки в порядке kill chain, техники/сабтехники внутри, клиентский
  фильтр по ID/названию. Клик по технике → карточка справа.
- **Карточка техники**: описание, платформы, тактики, митигации, сабтехники + **Обнаружение**
  (detection strategies → analytics: описание, платформа, чипы лог-сорсов, тюнинг-параметры)
  + **Примеры применения** (procedure examples, первые 20).

### Хранилище — `kb.db` (отдельный read-only SQLite)

Путь: `SIEM_KB_DB_PATH` (по умолчанию `<проект>/kb/kb.db`). Один файл, **отдельно от `siem.db`**.
В Docker собирается на этапе `build` и вшивается в образ (volume'ом НЕ монтируется —
обновление базы знаний = пересборка образа). Открывается только на чтение (`app/kb.py`,
`mode=ro`); если файла нет — вкладка показывает заглушку, а обогащение алертов молча
откатывается на сырые теги.

Таблицы:

| Таблица | Содержимое |
|---|---|
| `mitre_meta` | версия ATT&CK, дата сборки, счётчики, URL источника |
| `mitre_tactic` | `tactic_id`, `shortname`, `name`, `sort_order` (порядок колонок), описание, url |
| `mitre_technique` | `technique_id`, `name`, `is_subtechnique`, `parent_id`, описание, платформы, url (+ пустые на v18+ `detection`/`data_sources`) |
| `mitre_technique_tactic` | техника ↔ тактика (из `kill_chain_phases`) |
| `mitre_mitigation` + `mitre_technique_mitigation` | митигации и их связь с техниками |
| `mitre_detection_strategy` | `strategy_id` (`DET####`), `name`, `technique_id` |
| `mitre_analytic` | `analytic_id` (`AN####`), `strategy_id`, описание, `platforms`, `log_sources` (JSON), `mutable_elements` (JSON) |
| `mitre_procedure` | `technique_id`, `source_id` (`G####`/`S####`), `source_name`, `source_type` (`group`/`malware`/`tool`), `description` |

### Сборка — `scripts/build_kb.py`

Автономный скрипт (stdlib + `requests`, без `import app.*`):

```bash
python scripts/build_kb.py --out kb/kb.db                       # latest (master)
python scripts/build_kb.py --out kb/kb.db --attack-version 15.1  # конкретная версия
python scripts/build_kb.py --out kb/kb.db --from-file enterprise-attack.json  # офлайн
```

Качает `enterprise-attack.json`, проходит по `bundle["objects"]` без библиотеки `stix2`,
пишет `kb.db` во временный файл и атомарно подменяет. В конце — sanity-check (адекватное
число тактик/техник), иначе `docker build` падает, а не вшивает битую базу.

В Docker вызывается в builder-стадии; версия управляется build-args `ATTACK_STIX_REF` /
`ATTACK_STIX_VERSION` (см. `docker-compose.yml`).

### Обогащение карточки алерта

`GET /alerts/{id}` добавляет в ответ ключ `mitre` — результат `kb.enrich_techniques(tags)`:

- берёт `attack.t*` теги правила, нормализует (`attack.t1059.001` → `T1059.001`);
- **найдено в KB** → `{tag, technique_id, name, url, is_subtechnique, parent_id, tactics, matched: true}`;
- **не найдено / KB недоступна** → `{tag, technique_id, matched: false}` — гибрид: UI покажет
  сырой тег как раньше, без «додумывания».

В UI (`renderMitreChips`) matched-техники рендерятся ссылкой с названием + собирается строка
чипов тактик (раньше тактик в карточке не было вовсе). O(1) запросов к `kb.db` независимо от
числа тегов. Обогащение — **только в карточке алерта**, не в списке `/alerts` и не в поиске
по событиям.

### Что дальше (Этап 4/5)

Те же query-функции `app/kb.py` (`get_technique`, `list_techniques`, …) станут инструментом
`lookup_mitre` для AI-агента расследования: по технике из алерта агент подтянет detection
strategy, procedure examples и митигации, чтобы обосновать вердикт TP / FP / needs-review.

---

## 13. Практика

### Как аналитику пользоваться

1. **От алерта к контексту.** В карточке алерта — техника со ссылкой. Открой её в «Базе
   знаний»: описание даёт понять, что вообще делает атакующий; procedure examples — как это
   выглядит у реальных групп (сверь с тем, что видишь в событиях); detection strategy —
   правильно ли вообще сработало и на том ли лог-сорсе.
2. **Тактика = приоритет.** `Impact` / `Credential Access` / `Exfiltration` в цепочке — почти
   всегда выше приоритет, чем одиночный `Discovery`.
3. **Цепочка тактик по хосту.** Несколько алертов на одном хосте, покрывающих разные тактики
   по порядку (Execution → Persistence → Credential Access → Lateral Movement) — сильный
   сигнал компрометации, даже если каждый по отдельности слабый.
4. **Митигации — для рекомендаций в тикете.** «Закрывается M1038 (Execution Prevention)».

### Карта покрытия детектов (ATT&CK Navigator)

<https://mitre-attack.github.io/attack-navigator/> — интерактивная матрица, где техники можно
подсвечивать слоями (layer, JSON). Типовое применение: выгрузить теги всех своих Sigma-правил,
построить слой «что мы детектим», увидеть белые пятна, приоритизировать написание новых
правил по техникам актуальных для вас групп (`G####` → его `uses` → список техник).

### Рекомендации при работе с данными ATT&CK

1. **Идентификатор — единственный надёжный ключ.** Названия, shortname тактик, состав матрицы
   меняются между версиями; `T####` / `TA####` — нет.
2. **Фиксируй версию ATT&CK** в сборке (не «latest») — иначе набор полей и тактик «уедет» под
   ногами, как случилось на переходе v17→v18→v19.
3. **Отбрасывай `revoked` и `x_mitre_deprecated`** объекты при построении матрицы/словаря.
4. **Одна техника — много тактик.** Не дедуплицируй технику «по id» при раскладке по столбцам,
   иначе потеряешь её в части тактик.
5. **Тексты ATT&CK — с разметкой.** `description` содержит markdown-ссылки `[text](url)` и
   `(Citation: …)` — чисти перед показом.
6. **Сабтехника несёт свой контекст.** У `T1059.001` свои platforms, свои procedure examples,
   своя detection strategy — не подменяй их родительскими.
7. **`enrich` должен быть гибридным.** Тег, которого нет в твоей версии KB (новая/устаревшая
   техника, опечатка в правиле), показывай как есть, не «додумывай».

---

## 14. Шпаргалка

```
TA0002        тактика Execution
T1059         техника Command and Scripting Interpreter
T1059.001     сабтехника PowerShell        (родитель = T1059)
M1038         митигация Execution Prevention
G0016         группа APT29
S0002         ПО Mimikatz
C0001         кампания
DS0009        источник данных Process
DET0516       стратегия обнаружения (v18+)
AN1428        аналитика (v18+)
```

Связи: `uses` (кто применяет технику), `mitigates` (чем закрыть), `detects` (чем поймать),
`subtechnique-of`, `revoked-by`, `attributed-to`.

Ссылки:

- Матрица Enterprise — <https://attack.mitre.org/matrices/enterprise/>
- STIX-данные — <https://github.com/mitre-attack/attack-stix-data>
- Navigator — <https://mitre-attack.github.io/attack-navigator/>
- Changelog версий — <https://attack.mitre.org/resources/versions/>
- Работа с ATT&CK в Python (офиц. либа) — <https://github.com/mitre-attack/mitreattack-python>
