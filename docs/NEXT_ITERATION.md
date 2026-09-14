# Следующая итерация: доводка детект-контента, форвардера и движка

Временный рабочий список (Этап 4.5, после первой волны контента от 2026-09-14). Когда пункт
закрыт — вычеркнуть отсюда и перенести факт в CLAUDE.md / docs/spec. Когда список пуст — удалить
файл и ссылку на него в CLAUDE.md (§1, §7 «Этап 4.5»).

Исходное состояние: 49 сценариев, 11 доменов в `artifacts/content/`, синтетика 165/165 на
изолированном экземпляре, реплей реального фона win10-lab чистый. Живого прогона не было, в
Docker-экземпляр новый контент не деплоился, коммитов нет.

---

## 1. Движок

- [ ] **Досоздание колонок таблицы флаша** (`app/detection/engine.py`). Сейчас правило, поле которого
      нет ни в одном событии флаша, падает с `no such column` и молча не срабатывает (Zircolite строит
      таблицу из полей событий, пустую строку при flatten выбрасывает вместе с полем). Перед прогоном
      добавлять в in-memory таблицу все поля, на которые ссылаются правила, значением NULL. Тест: флаш
      из одних событий 4104 + Sysmon-правило с редким полем — запрос не падает, остальные правила
      флаша срабатывают. После фикса убрать из `scripts/test_content.py` костыль с дополнением
      событий схемой полей (или оставить как проверку реалистичности — решить).
- [ ] **Логирование ошибок SQL правил.** Сейчас Zircolite глушит ошибку запроса; хотя бы WARNING с
      title правила и текстом ошибки (раз на правило за N минут), иначе мёртвые правила не видны.
- [ ] **Маппинг `ProviderName` → `Provider_Name`** в своём конфиге Zircolite (`SIEM_ZIRCOLITE_CONFIG_PATH`,
      копия `Zircolite/config/config.yaml` в проекте). Проверить, что явный маппинг обходит вырезание
      `_`. После — вернуть `Provider_Name` в адаптированные правила SigmaHQ (см. §3).
- [ ] **Member-алерты: один алерт — один инцидент.** `store.link_alerts_to_incident` ставит
      `alerts.incident_id` только если он пуст, поэтому при двух инцидентах на одни события (напр.
      `SCE_Recon_Scripted_Discovery` + `SCE_TH_Recon_Discovery_Burst`) второй получает 0 member-алертов
      (видно на реплее стенда). Решить: таблица связей many-to-many или приоритет по severity.
- [ ] **Резолв на флаш.** `main_ruleset.resolve_for` / `_active_correlation_rules` зовутся на каждый
      источник флаша (2 + N раз). Сейчас ~6 мс за счёт кэша скана с перепроверкой раз в 2 с — передать
      вычисленный набор внутрь `evaluate_batch` один раз на флаш и перепроверить
      `scripts/bench_correlation.py`.
- [ ] **Дедуп алертов на стриме почти не работает**: `_content_signature` исключает только
      `TIME_FIELDS`/`row_id`/`OriginalLogfile`, а у событий Fluent Bit уникальны `EventRecordID`,
      `ProcessID`/`ThreadID`, `ActivityID`. Решить, какие служебные поля исключать (осторожно:
      `ProcessGuid` — содержимое, не служебное).
- [ ] UI: пометка `via_dependency` у правил в просмотре «Основного рулсета» (API уже отдаёт
      `in_main: false` для подтянутых зависимостей), показ 409 с `detail.references` при удалении.

## 2. Агент и телеметрия стенда

Решено (2026-09-15): вместо Fluent Bit — **Vector** (`windows_event_log`, разбор XML события, правка
полей на VRL вместо Lua), подключение хоста одним скриптом. Сделано: `deploy/windows/vector.toml`,
`deploy/windows/install-agent.ps1` (аудит + Sysmon + Vector службой + самопроверка), сборщик
единого файла `scripts/build_agent_installer.py` → `dist/install-soc-agent.ps1`, гайд
`docs/guide/windows-agent.md`. **Проверено на win10-lab** (результаты — в гайде): поля
7045/104/4648/Sysmon 1/Sysmon 3, время с микросекундами, недоступность SIEM 5 мин без потерь и
дублей, перезапуск, повторная установка; простой закрыт условно. Fluent Bit удалён из репозитория и
документации, `telemetry/event_fields.json` перегенерирован (`scripts/export_event_fields.py`),
подтверждённые стендом ключи убраны из `event_fields_manual.json`; имена `SourceProcessGUID` (Sysmon 10)
и `NewValue`/`OldValue` (Defender 5007) совпали с правилами.

- [ ] **Время Sysmon.** `TimeCreated` у Sysmon 3 отстаёт от `UtcTime` самого события на секунды
      (сетевые события пишутся пачками); у Sysmon 1 — на миллисекунды. Для порядка в `temporal_ordered`
      у Sysmon точнее `UtcTime` (формат `YYYY-MM-DD HH:MM:SS.mmm`, UTC). Решить: подставлять `UtcTime`
      в `TimeCreated` в VRL агента (сервер не трогаем) или менять приоритет `TIME_FIELDS`.
- [ ] Перевыпустить токен источника `win10-lab-vector` (попал в переписку) и перезапустить установщик
      с новым `-Token -SkipAudit -SkipSysmon`.
- [ ] Адаптировать правила SigmaHQ на 7045 (PsExec service, getsystem, RMM
      services, CobaltStrike service installs); вернуть фильтр по очищенному каналу (`UserDataChannel`)
      в `evasion_system_log_cleared`.
- [ ] **`telemetry/sysmonconfig.xml`** (ставится установщиком): замерить объём по EventID за час простоя
      (`GET /events/group?group_by=EventID`). Проверить реальным событием, что пишутся: EID 10 к lsass,
      17/18, 19–21, запуск `7z.exe`, соединения на порты администрирования от произвольного процесса,
      создание архивов и файлов-записок. Проверка покрытия была грубым скриптом без логики AND/OR
      групп Sysmon. **Уже найдено на стенде (2026-09-15):** `hostname.exe` Sysmon 1 не пишет (только 4688),
      хотя он есть в value list `recon_discovery_tools` — сверить include ProcessCreate со всеми
      `*_image*`/`recon_*` списками, иначе process-правила Sysmon-only слепы к части утилит.
- [ ] **Поля, ещё не подтверждённые стендом**: в `event_fields_manual.json` остались Sysmon 8/18/19–21/23,
      Security 1102/4719, Defender 5001/1116; в `event_fields.json` 26 ключей `_legacy_keys` перенесены из
      выгрузки Fluent Bit с переименованием `ProcessID`/`ThreadID`. После живого прогона сценариев —
      повторить `scripts/export_event_fields.py`. Замечено: у Sysmon 16 на стенде нет
      `ConfigurationFileHash` (Zircolite раскладывает хэш в `SHA256`) — поправить фикстуру
      `SCE_Evasion_Telemetry_Tampering`, правила это поле не используют.
- [ ] Шум: EID 4 Sysmon (состояние службы) — отфильтровать, если заметен в объёме; 4672/4799 — оценить
      по замеру.

## 3. Контент

- [ ] **Покрытие базовых правил фикстурами.** Сейчас каждый сценарий проверен, но в группах «любое из»
      позитив есть лишь для 1–3 правил. Написать скрипт покрытия (какие базовые правила сработали хотя
      бы в одном позитивном кейсе) и дописать фикстуры. Известные дыры:
      RMM (LogMeIn, NetSupport, SimpleHelp, UltraViewer, GoToAssist), `cred_lsass_susp_access_flags`
      и `cred_lsass_access_dump_keyword` (позитивов нет), `evasion_sysmon_driver_unload`,
      `evasion_eventlog_disabled_registry`, `evasion_defender_config_tamper`, `privesc_*potato*_exec`,
      `privesc_uac_sdclt_*`, `privesc_uac_computerdefaults`, `exfil_rar_password`, `exfil_winzip_password`,
      `exfil_dns_mega`, `exfil_cli_data_exfiltration`, `impact_service_tampering`, агрегаторы
      `privesc_host_privilege_escalation` и `lateral_host_inbound` в `killchain`.
- [ ] **Живой прогон на win10-lab** по секциям `lab:` фикстур, волнами. Перед деструктивными (impact,
      очистка журналов, credaccess) — снимок ВМ. Для `lateral` нужен второй хост в Host-Only сети.
      `SCE_Exec_Office_Child_Network` — нужен Office/LibreOffice или остаётся только синтетика.
      Результат (сценарий → инцидент есть/нет, лишние инциденты) — в `docs/guide/windows-vm-lab.md`.
- [ ] **Доводка FP после расширения телеметрии**: `cred_lsass_susp_access_flags` (EID 10 от AV и
      системных компонентов), `persist_autorun_currentversion`, `persist_task_created_4698`,
      `exec_lolbin_outbound_connection` (PowerShell-обновления), `evasion_sysmon_config_change`
      (штатное обновление конфига даёт `SCE_Evasion_Telemetry_Tampering` — решить: фильтр или принять).
- [ ] **После фиксов движка/форвардера (§1, §2)**: вернуть `Provider_Name` в адаптированные правила
      там, где он сужал детект; добавить правила на 7045 и System 104 с фильтром по каналу.
- [ ] Описания value lists, созданных автоматически (`*_commandline2`, `*_image2`, английские
      описания-заглушки) — дать осмысленные имена и русские описания. Переименование списка = правка
      ссылок в правилах + пересборка.
- [ ] Сценарии, отложенные из-за ограничений: брутфорс/спрей по учётке без IP, корреляция учётки
      между 4720 (`TargetSid`) и 4732 (`MemberSid`) — нужен алиас полей или нормализация на входе.
- [ ] Инструменты адаптации SigmaHQ (`adapt2.py`, `corrgen.py`, индекс SigmaHQ) лежали во временном
      каталоге сессии — перенести в `scripts/content/` или переписать, если адаптацию SigmaHQ
      планируется повторять (обновление правил из апстрима).

## 4. Развёртывание

- [ ] Пересобрать Docker-образ (код движка запечён в образ): `docker compose build && docker compose up -d`.
- [ ] В Docker-экземпляре удалить старый рулсет `five-scenarios-v2` (`DELETE /rulesets?ruleset=...`)
      и убрать его из main; удалить старые файлы в корне `artifacts/content/`
      (`auth_after_brutforce.yml`, `windows_bruteforce.yml`, `recon_tools_detected.yml` и др.).
- [ ] `uv run python scripts/deploy_content.py http://localhost:8000 --prune`, затем
      `scripts/test_content.py` против изолированного экземпляра перед каждым деплоем.
- [ ] Коммит: движок (E1–E4, кэш скана, config-переменные), скрипты, контент, документация —
      отдельными коммитами; прогнать `uv run pytest` и `ruff` по изменённым файлам.

## 5. Документация

- [ ] `docs/spec/http-api.md` — `force` у `DELETE /rules/custom/{id}` и `DELETE /rulesets`, ответ 409.
- [ ] `docs/spec/config.md` — `SIEM_CUSTOM_RULESETS_DIR`, `SIEM_VALUE_LISTS_DIR`.
- [ ] `docs/spec/main-ruleset.md` — `resolve_for`, зависимости в `resolve_with_sources`.
- [ ] CLAUDE.md §4 (таблица модулей: `rules_catalog`, `main_ruleset`, `correlation`, `config`,
      `timeutil`) — дописать изменения этой итерации; §5 — раскладка `artifacts/content/`.
- [ ] Таблица телеметрии в CLAUDE.md §9 — обновить после замера на расширенной телеметрии.
