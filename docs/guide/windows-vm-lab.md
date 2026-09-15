# Лабораторный стенд: Windows-ВМ → мини-SIEM

Тестовая Windows 10 в VirtualBox как источник событий: сеть до SIEM, подключение хоста агентом,
проверка детекта. Ранбук проверен на живом стенде (Windows 10 22H2 в VirtualBox 7.1, агент
Vector 0.58.0) — команды и грабли ниже реальные, не гипотетические.

Сам хост подключается одним скриптом: аудит, Sysmon и агент ставит `install-soc-agent.ps1`, см.
**`docs/guide/windows-agent.md`**. Общий контракт приёма событий (формат тела, токен, коды ответов) —
`docs/guide/forwarder.md`. Здесь только то, что специфично для стенда.

---

## 0. Сеть между ВМ и хостом

SIEM поднят на хосте и слушает `0.0.0.0:8000`: либо `docker compose up` (порт `8000:8000`), либо
`uv run uvicorn app.main:app --host 0.0.0.0 --port 8000`. Из ВМ его надо чем-то достать.

**Не полагайся на NAT-шлюз `10.0.2.2`.** Формально это адрес хоста, но по пути стоит и
брандмауэр хоста, и (часто) VPN-клиент с TUN-интерфейсом, который уводит трафик в туннель.
На стенде именно это и не поехало. Надёжнее — **второй адаптер Host-Only**: NAT остаётся
на nic1 (интернет в ВМ: установщик качает Sysmon и Vector), Host-Only даёт прямой канал.

В GUI VirtualBox (7.1): выключить ВМ → **Настроить** → **Сеть** → вкладка **«Адаптер 2»** →
галка **«Включить сетевой адаптер»** → **Тип подключения: «Виртуальный адаптер хоста»**
(*Host-only Adapter*) → **Имя: `VirtualBox Host-Only Ethernet Adapter`** → в «Дополнительно»
проверить **«Кабель подключен»**.

> Не путать с пунктом **«Сеть хоста»** (*Host-only Network*) — это другой механизм 7.x со
> своей подсетью, хост на `192.168.56.1` там не окажется.

То же из командной строки хоста (ВМ должна быть выключена — привязку NIC на живой машине
VirtualBox менять не даёт):

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb modifyvm win10 --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter" --cableconnected2 on
& $vb list hostonlyifs | Select-String "^Name:|^IPAddress:"       # ждём 192.168.56.1
```

### Брандмауэр хоста — две отдельные проблемы

**Первая: нужно разрешающее правило.** Трафик из Host-Only сети — настоящее входящее
соединение (в отличие от loopback, который брандмауэр не фильтрует вовсе). На **хосте**,
PowerShell **от администратора**:

```powershell
New-NetFirewallRule -DisplayName "soc_agent SIEM 8000 (lab)" -Direction Inbound -Protocol TCP `
  -LocalPort 8000 -RemoteAddress 192.168.56.0/24 -Action Allow
```

**Вторая, для Docker: у Docker Desktop может стоять правило-ЗАПРЕТ.** Windows при первом
запуске Docker создаёт **пару** правил для `Docker Desktop Backend` (процесс, который держит
опубликованные порты): **Allow для профиля Private** и **Block для профиля Public**. Host-Only
сеть — «неопознанная», Windows относит её к **Public**, а запрещающее правило в Windows
Firewall всегда сильнее разрешающего. В итоге правило выше не даёт ничего, и симптом
обманчивый: с хоста `Test-NetConnection 192.168.56.1 -Port 8000` отвечает `True` (loopback,
фильтрации нет), из ВМ — `False`.

```powershell
# посмотреть, есть ли запрет
netsh advfirewall firewall show rule name="Docker Desktop Backend" | Select-String "Action|Profiles"
# снять (от администратора)
Get-NetFirewallRule -DisplayName "Docker Desktop Backend" | Where-Object { $_.Action -eq 'Block' } | Disable-NetFirewallRule
```

Это не открывает порт наружу: входящие на хосте по умолчанию запрещены, Allow-правил для Public
у Docker нет, так что единственная открытая дверь — правило `soc_agent SIEM 8000 (lab)`,
суженное до `192.168.56.0/24`. SIEM без Docker (uvicorn) эту проблему не имеет, но при первом
запуске Windows может спросить разрешение для `python.exe` — то же правило по порту его покрывает.

Проверка из ВМ — обязательно `Test-NetConnection`, он даёт внятную диагностику, в отличие от
`Invoke-RestMethod`:

```powershell
Test-NetConnection 192.168.56.1 -Port 8000     # ждём TcpTestSucceeded : True
Invoke-RestMethod http://192.168.56.1:8000/health
```

### Общий буфер обмена

Длинные команды и токен удобнее вставлять, чем печатать: при «допечатывании» в консоль ВМ
символы теряются (на стенде так ломался URL, и загрузка отдавала 404 на исправном адресе).
Включить нормальную вставку и перетаскивание файлов (Guest Additions должны быть установлены в ВМ):

```powershell
& $vb controlvm win10 clipboard mode bidirectional
& $vb controlvm win10 draganddrop bidirectional
& $vb showvminfo win10 --machinereadable | Select-String "^GuestAdditionsRunLevel"   # ждём 3
```

Работает на живой ВМ, перезагрузка не нужна.

---

## 1. Источник, токен и агент

1. UI SIEM → **«Источник данных»** → **«Создать источник»**. Имя обязательно, уникально и
   неизменяемо — оно становится меткой `source_batch` всех событий и алертов хоста. Токен
   показывается **один раз** (в БД лежит только sha256). `description` — до 64 символов.
2. На хосте с репозиторием: `uv run python scripts/build_agent_installer.py` → `dist/install-soc-agent.ps1`.
3. Файл — в ВМ (буфер обмена / drag-and-drop), там PowerShell от администратора:

```powershell
powershell -ExecutionPolicy Bypass -File C:\tools\install-soc-agent.ps1 -SiemUrl http://192.168.56.1:8000 -Token <токен>
```

Что делает скрипт, где лежат файлы агента, формат событий и чек-лист проверки —
`docs/guide/windows-agent.md`.

---

## 2. Проверка детекта

`/ingest/stream` гоняется **только по «основному рулсету»** (`app/rules/main_ruleset.py`) —
до первых алертов в main должен лежать контент: `uv run python scripts/deploy_content.py
http://localhost:8000 --prune` (домены `artifacts/content/`, CLAUDE.md §9).

Команды эмуляции каждого сценария — секция `lab:` его фикстуры в
`artifacts/content/<domain>/tests/`. Быстрый дымовой тест (проверено 2026-09-15), в ВМ от администратора:

```powershell
whoami; hostname                                                   # Discovery Utility Execution
wevtutil cl "Microsoft-Windows-Bits-Client/Operational"            # SCE_Evasion_Log_Cleared (инцидент)
net user soctest 'Lab-Pass-2026!' /add
runas /user:$env:COMPUTERNAME\soctest cmd                          # 4648: Logon Attempt With Explicit Credentials
net user soctest /delete                                           # SCE_TH_Auth_ShortLived_Account (инцидент)
```

С хоста — что доехало и что сработало:

```powershell
Invoke-RestMethod "http://localhost:8000/events/group?group_by=EventID&source_batch=<источник>"
(Invoke-RestMethod "http://localhost:8000/alerts?source_batch=<источник>&limit=500").alerts | Group-Object rule_title | Select-Object Count, Name
(Invoke-RestMethod "http://localhost:8000/incidents?source_batch=<источник>").incidents | Select-Object incident_type, severity, alert_count
```

> `Invoke-RestMethod` в Windows PowerShell 5.1 показывает кириллицу из ответа кракозябрами
> (`ÑÐ»ÑÐ¶Ð±Ð°`) — это ошибка декодирования на клиенте, в БД значение верное. Проверять через
> браузер/UI или `curl.exe`.

---

## 3. Известные ограничения стенда

**`Provider_Name`.** Агент шлёт поле `ProviderName`, а Zircolite у неотмапленных полей вырезает все
не-alnum символы (`_NON_ALNUM_RE` в `streaming.py`), так что переименованием в `Provider_Name`
делу не помочь — подчёркивание всё равно исчезнет. Своего маппинга не заводим (решено 2026-09-15):
при адаптации SigmaHQ `Provider_Name` заменяется на `ProviderName`, если реально сужает детект, иначе
убирается — роль играет guard `Channel`/`EventID` (CLAUDE.md §9).

**Время Sysmon.** У Sysmon агент берёт `TimeCreated` из `UtcTime` самого события (запись в журнал у
Sysmon 3 отстаёт на секунды) — проверено 2026-09-15, см. `docs/guide/windows-agent.md`.

**Покрытие конфига Sysmon (проверено 2026-09-15).** Все `.exe`, на которые смотрят process-правила
Sysmon 1 контента (включая value lists), запущены на стенде с `/?` через `cmd /c ... & rem <маркер>`
и сверены с событиями: 110 утилит, 39 системных процессов не запускались, 35 сторонних на ВМ нет,
75 запущено. У 28 был только 4688:
- **дыра**: `hostname`, `arp`, `getmac`, `driverquery`, `nltest` (include базы по `OriginalFileName`
  не срабатывает), `auditpol`, `vaultcmd`, `reagentc`, `sdclt`, `wmic` — сначала закрыта своей
  include-группой (после применения у всех десяти появился Sysmon 1), затем тем же днём решено
  перевести ProcessCreate в exclude-режим (см. ниже), и отдельная группа стала не нужна;
- **не дыра**: `bcdedit`/`wbadmin` конфиг пишет с `/set`/`delete` — ровно то, что нужно правилам;
  `cmstp`/`control`/`pcalua`/`workfolders`/`wsl`/`mmc` правила ловят как дочерние Office/WinRM/Event
  Viewer, такие запуски база включает по родителю; `atbroker`/`certreq`/`defrag`/`dfrgui`/`eventvwr`/
  `finger`/`fsquirt`/`taskmgr`/`winver` — только «системный бинарь не из своего каталога», а запуск из
  `\Temp\`/`\AppData\`/`C:\Users\Public\` база включает.

Ограничение метода: утилиты, которые база включала только при определённой командной строке, с `/?`
не писались — для них сверялись условия конфига, а не события. Конфиг применяется на ходу:
`sysmon64 -c C:\tools\sysmonconfig.xml` (взводит `SCE_Evasion_Telemetry_Tampering`).

**ProcessCreate в exclude-режиме (2026-09-15).** Include-группа ProcessCreate sysmon-modular удалена:
Sysmon 1 пишется для всех процессов, кроме шума из exclude-группы — как у SwiftOnSecurity/Neo23x0.
Причина — сама проверка выше: в include-режиме любое новое process-правило Sigma надо сверять с
конфигом. Проверено тем же прогоном утилит после переустановки: Sysmon 1 есть у всех 75 запущенных
(было 47 в include-режиме, 57 со своей include-группой). Объём сопоставим с 4688 (он и так пишет все процессы). Теги техник `RuleName` у Sysmon 1
пропали — контент на них не опирается. Любой `ProcessCreate onmatch="include"` возвращает режим
«только перечисленное» — при обновлении sysmon-modular его надо удалять.

**Аудит — по базовой линии Microsoft (2026-09-15).** Установщик включает подкатегории Windows Security
Baseline для рабочих станций, кроме осознанных отличий: Sensitive Privilege Use и Process Termination
выключены (шум без правил), Kerberos/SAM/Directory Service не включаются до появления контроллера
домена. Добавлены к прежнему набору: Other Logon/Logoff, File Share, Detailed File Share (отказы),
MPSSVC Rule-Level Policy Change, Security State Change, System Integrity, Other System Events,
Removable Storage, Plug and Play. PowerShell Module logging (4103) выключен — правил на 4103 в контенте
нет, объём был первым на стенде; ScriptBlock (4104) остаётся.

**Шум отфильтрован в агенте.** 4673/4674/5379 (`ignore_event_ids` в `deploy/windows/vector.toml`)
до SIEM не доезжают — пропуски `EventRecordID` в Security из-за них ожидаемы. Подкатегории
«Завершение процесса» (4689) и «Использование конфиденциальных прав» (4673/4674) выключены
установщиком.

**Инциденты не заводятся сами.** Таблица `incidents` заполняется только correlation-правилами
с блоком `correlation.incident`; catch-all прохода по алертам нет by design
(`docs/spec/incidents.md`).

**Объём informational-алертов.** Базовые правила сценариев пишут алерт на каждое срабатывание.
Для member-алертов инцидента это правильно, но вкладку «Алерты» забивает быстро — разбирать через
фильтр «Инцидент: в инцидентах / вне», поиск и «Группировать по правилу» (дедуп по служебным полям
намеренно не делается).

**Установка агента сама даёт инциденты.** Действия установщика взводят `SCE_Evasion_Telemetry_Tampering`
(`sysmon -c`), `SCE_Evasion_Log_Cleared` (`wevtutil sl`) и алерты «Audit Policy Tampering» (`auditpol /set`)
— известные ложные срабатывания, подробно в `docs/guide/windows-agent.md`; доводка — CLAUDE.md §7 «Этап 4.5».
