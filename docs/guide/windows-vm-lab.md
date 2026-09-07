# Лабораторный стенд: Windows-ВМ → мини-SIEM

Пошаговая настройка тестовой Windows 10 в VirtualBox как источника событий: аудит,
Sysmon, форвардер Fluent Bit, проверка детекта и корреляций. Ранбук проверен целиком на
живом стенде (Windows 10 22H2 в VirtualBox 7.1, Fluent Bit 5.1.1, SIEM в Docker на хосте) —
все команды и все грабли ниже реальные, не гипотетические.

Общий контракт приёма событий (формат тела, токен, коды ответов, другие форвардеры) —
`docs/guide/forwarder.md`. Здесь только конкретный стенд.

---

## 0. Сеть между ВМ и хостом

SIEM поднят на хосте (`docker compose up`, порт `8000:8000` — слушает `0.0.0.0`).
Из ВМ его надо чем-то достать.

**Не полагайся на NAT-шлюз `10.0.2.2`.** Формально это адрес хоста, но по пути стоит и
брандмауэр хоста, и (часто) VPN-клиент с TUN-интерфейсом, который уводит трафик в туннель.
На стенде именно это и не поехало. Надёжнее — **второй адаптер Host-Only**: NAT остаётся
на nic1 (интернет в ВМ для загрузки Sysmon/Fluent Bit), Host-Only даёт прямой канал.

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
```

Проверить, что хост слушает и адаптер поднят:

```powershell
docker ps --format "{{.Names}} | {{.Status}} | {{.Ports}}"       # ждём 0.0.0.0:8000->8000/tcp
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

**Вторая, и она важнее: у Docker Desktop может стоять правило-ЗАПРЕТ.** Windows при первом
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

Это не открывает порт наружу: входящие на хосте по умолчанию запрещены
(`DefaultInboundAction` не настроен = блок), Allow-правил для Public у Docker нет, так что
единственная открытая дверь — правило `soc_agent SIEM 8000 (lab)`, суженное до
`192.168.56.0/24`.

Проверка из ВМ — обязательно `Test-NetConnection`, он даёт внятную диагностику, в отличие от
`Invoke-RestMethod`:

```powershell
Test-NetConnection 192.168.56.1 -Port 8000     # ждём TcpTestSucceeded : True
Invoke-RestMethod http://192.168.56.1:8000/health
```

### Общий буфер обмена

Дальше идут длинные команды с URL. Если печатать их в консоль ВМ вручную или через
«допечатывание», символы теряются — на стенде `SwiftOnSecurity` превратился в `wiftnecurity`,
и `Invoke-WebRequest` отдал 404 на исправном адресе. Включить нормальную вставку (Guest
Additions должны быть установлены в ВМ):

```powershell
& $vb controlvm win10 clipboard mode bidirectional
& $vb controlvm win10 draganddrop bidirectional
& $vb showvminfo win10 --machinereadable | Select-String "^GuestAdditionsRunLevel"   # ждём 3
```

Работает на живой ВМ, перезагрузка не нужна.

---

## 1. Sysmon

Даёт основную часть покрытия Sigma-правил (process create с `Image`/`CommandLine`/`ParentImage`,
сетевые соединения, DNS, реестр). Всё дальнейшее — **внутри ВМ, PowerShell от администратора**,
по одной команде на строку:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
New-Item -ItemType Directory C:\tools -Force | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\tools\Sysmon.zip
Expand-Archive C:\tools\Sysmon.zip -DestinationPath C:\tools\Sysmon -Force
$u = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
Invoke-WebRequest $u -OutFile C:\tools\Sysmon\sysmonconfig.xml
C:\tools\Sysmon\Sysmon64.exe -accepteula -i C:\tools\Sysmon\sysmonconfig.xml
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 3
```

Длинный URL вынесен в `$u` намеренно: короткая строка меньше страдает от переносов при вставке.

---

## 2. Аудит Security-канала

`auditpol` принимает только **локализованные** имена подкатегорий, поэтому на русской Windows
английские названия не сработают. GUID-ы одинаковы в любой локали — используем их (проверить
соответствие на конкретной машине: `auditpol /list /subcategory:* /v`).

```powershell
$sub = @(
  '{0CCE922B-69AE-11D9-BED3-505054503030}',  # создание процесса (4688)
  '{0CCE922C-69AE-11D9-BED3-505054503030}',  # завершение процесса (4689)
  '{0CCE9215-69AE-11D9-BED3-505054503030}',  # вход в систему (4624/4625)
  '{0CCE9216-69AE-11D9-BED3-505054503030}',  # выход из системы
  '{0CCE9217-69AE-11D9-BED3-505054503030}',  # блокировка учётной записи (4740)
  '{0CCE921B-69AE-11D9-BED3-505054503030}',  # специальный вход (4672)
  '{0CCE923F-69AE-11D9-BED3-505054503030}',  # проверка учётных данных (4776)
  '{0CCE9235-69AE-11D9-BED3-505054503030}',  # управление учётными записями (4720/4726)
  '{0CCE9237-69AE-11D9-BED3-505054503030}',  # управление группами безопасности (4728/4732)
  '{0CCE9228-69AE-11D9-BED3-505054503030}',  # конфиденциальные права (4673/4674)
  '{0CCE922F-69AE-11D9-BED3-505054503030}',  # изменение политики аудита (4719)
  '{0CCE9211-69AE-11D9-BED3-505054503030}',  # расширение системы безопасности (4697)
  '{0CCE9227-69AE-11D9-BED3-505054503030}'   # другие события доступа к объектам (4698)
)
foreach ($g in $sub) { auditpol /set /subcategory:"$g" /success:enable /failure:enable | Out-Null; "$g -> $(if ($LASTEXITCODE -eq 0) {'ok'} else {'ОШИБКА'})" }
```

Командная строка в 4688 (**без неё почти все process-правила бесполезны**), логирование
PowerShell, размеры журналов:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
wevtutil sl Security /ms:209715200
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:209715200
```

Проверка, что 4688 пишется вместе с командной строкой:

```powershell
whoami /priv | Out-Null; Start-Sleep 2; (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1).Message
```

В выводе должна быть строка «Командная строка процесса:» с непустым значением. Если её нет —
нужен перезаход в систему.

> `4673` (использование конфиденциальных прав) — самая шумная из включённых подкатегорий:
> ~20 событий в минуту на полностью простаивающей машине. Если забивает поток, выключается
> отдельно: `auditpol /set /subcategory:"{0CCE9228-...}" /success:disable /failure:enable`.

---

## 3. Источник и токен в SIEM

UI → вкладка **«Источник данных»** → **«Создать источник»**. Имя обязательно, уникально и
неизменяемо — оно становится меткой `source_batch` всех событий и алертов этого хоста.
Токен показывается **один раз** (в БД лежит только sha256).

То же через API с хоста:

```powershell
$body = @{ name = "win10-lab"; description = "Win10 VM, Fluent Bit winevtlog" } | ConvertTo-Json
(Invoke-RestMethod http://localhost:8000/sources -Method Post -Body $body -ContentType "application/json").token
```

> `description` ограничено 64 символами (`models.SOURCE_DESCRIPTION_MAX`) — длиннее даёт `422`.

---

## 4. Fluent Bit

### Почему нужна версия ≥ 4.2.8 / 5.0.10

Плагин `winevtlog` **по умолчанию не разворачивает `EventData` в именованные поля** — отдаёт
позиционный массив `StringInserts` без имён. То есть `CommandLine`, `Image`, `NewProcessName`,
`TargetUserName` в событии просто не появляются, и Sigma-правила молча не срабатывают:
события идут, алертов ноль.

Лечится опцией **`Event_Data_As_Map true`** (PR fluent/fluent-bit#12082, влит 10.07.2026) — она
разворачивает `EventData` в именованную карту по метаданным провайдера. Опция есть с версий
**4.2.8 / 5.0.10 / 5.1.x**; последний опубликованный Windows-билд смотреть на
`https://packages.fluentbit.io/windows/`.

Вложенную карту `EventData.CommandLine` Zircolite при flatten схлопывает до `CommandLine`
(неотмапленное поле берётся по последнему сегменту пути, см. `Zircolite/zircolite/streaming.py`),
то есть ровно к тому имени, которое ждут правила. Аналогов у других форвардеров нет:
Winlogbeat отдаёт вложенный ECS (`winlog.event_data.*`) и не умеет слать по HTTP, NXLog CE
разворачивает поля нативно, но требует регистрации для скачивания.

### Установка и конфиг

```powershell
Invoke-WebRequest https://packages.fluentbit.io/windows/fluent-bit-5.1.1-win64.exe -OutFile C:\tools\fb.exe
C:\tools\fb.exe /S
New-Item -ItemType Directory C:\ProgramData\fluent-bit -Force | Out-Null
Test-Path 'C:\Program Files\fluent-bit\bin\fluent-bit.exe'
```

Конфиг проще всего создать блокнотом — консольные here-string (`@' ... '@`) требуют, чтобы
закрывающая `'@` стояла в самом начале строки, а при копировании блок обычно сдвигается на
пару пробелов, и PowerShell зависает в ожидании продолжения:

```powershell
notepad 'C:\Program Files\fluent-bit\conf\soc.conf'
```

```ini
[SERVICE]
    Flush        2
    Log_Level    info
    Log_File     C:\ProgramData\fluent-bit\fluent-bit.log

[INPUT]
    Name                    winevtlog
    Channels                Security,Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-PowerShell/Operational,System
    Interval_Sec            1
    DB                      C:\ProgramData\fluent-bit\winevtlog.sqlite
    Read_Existing_Events    false
    Event_Data_As_Map       true
    String_Inserts          false
    Ignore_Missing_Channels true

[OUTPUT]
    Name             http
    Match            *
    Host             192.168.56.1
    Port             8000
    URI              /ingest/stream
    Format           json_lines
    json_date_key    EventTime
    json_date_format iso8601
    Header           Authorization Bearer <ТОКЕН>
    Retry_Limit      False
    net.keepalive    off
```

Разбор нетривиальных параметров:

| Параметр | Зачем именно так |
|---|---|
| `Event_Data_As_Map true` | Единственное, что даёт именованные поля вместо `StringInserts` (см. выше). |
| `String_Inserts false` | Безопасно: при несовместимом шаблоне провайдера плагин всё равно упакует `StringInserts` как фолбэк (`pack_event_data` в `plugins/in_winevtlog/pack.c`), так что данные не теряются, а объём вдвое меньше. |
| `Format json_lines` | Ровно тот NDJSON, который ждёт `/ingest/stream`. Content-Type сервер не смотрит — тело разбирается по первому символу (`app/main.py:_parse_stream_body`), так что заголовок задавать не нужно. |
| `json_date_key EventTime` | `EventTime` есть в `TIME_FIELDS` (`app/fields.py`), а родной `TimeCreated` — нет; см. ограничение ниже. |
| `DB ...sqlite` | Позиция чтения по каналам, чтобы рестарт не дублировал и не терял события. |
| `net.keepalive off` | Обходит рассинхрон keep-alive; после правки `Dockerfile` (см. ниже) можно вернуть `on`. |
| `Read_Existing_Events false` | Не тащить историю журнала при первом старте. |

**`storage.type filesystem` / `storage.path` не включай.** На стенде дисковый буфер давал
бесконечный поток `write: No such file or directory` в консоль и терял поток событий; в памяти
всё работает, а при недоступности SIEM Fluent Bit и так буферизует и ретраит
(`Retry_Limit False` — без ограничения числа попыток). Если `storage.type filesystem` всё же
задан, `storage.path` в `[SERVICE]` **обязателен**, иначе движок вообще не стартует:
`requested filesystem storage but no filesystem path was defined`.

### Запуск

Сначала в консоли — чтобы видеть ошибки:

```powershell
& 'C:\Program Files\fluent-bit\bin\fluent-bit.exe' -c 'C:\Program Files\fluent-bit\conf\soc.conf'
```

Признак успеха — строки вида:

```
[output:http:http.0] 192.168.56.1:8000, HTTP status=202
{"queued":28,"skipped":0,"source":"win10-lab"}
```

Потом службой (LocalSystem, прав на Security-канал хватает). Консольный экземпляр перед этим
закрыть, иначе два процесса будут читать журнал параллельно:

```powershell
sc.exe create fluent-bit start= auto binPath= "\"C:\Program Files\fluent-bit\bin\fluent-bit.exe\" -c \"C:\Program Files\fluent-bit\conf\soc.conf\""
sc.exe start fluent-bit
sc.exe query fluent-bit
```

У службы нет консоли — `Log_File` в `[SERVICE]` обязателен, иначе диагностика пропадёт.

---

## 5. Проверка детекта

`/ingest/stream` гоняется **только по «основному рулсету»** (`app/rules/main_ruleset.py`),
per-request выбрать рулсет нельзя. Встроенные рулсеты в main добавить нельзя by design —
main собирается только из custom-рулсетов. То есть до первых алертов надо, чтобы в main
лежали свои правила (вкладка «Sigma-правила»).

Проверка на контенте из `artifacts/content/` (recon + брутфорс). В ВМ:

```powershell
# ≥5 различных recon-утилит на хост за час -> корреляция value_count
whoami /priv; hostname; ipconfig /all; net user; systeminfo; tasklist; arp -a; route print
```

```powershell
# ≥10 отказов с одного IP по одной учётке за 5 минут -> корреляция event_count
1..15 | ForEach-Object { cmd /c "net use \\127.0.0.1\IPC$ /delete /y >nul 2>&1 & net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\hacker WrongPass$_" 2>$null | Out-Null }
```

`/delete` между попытками обязателен: без него `net use` переиспользует уже установленную
сессию к `127.0.0.1`, часть попыток не доходит до 4625 и порог не набирается. Сколько реально
записалось:

```powershell
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-5)}).Count
```

С хоста — что доехало и что сработало:

```powershell
(Invoke-WebRequest http://localhost:8000/batches -UseBasicParsing).Content
(Invoke-WebRequest "http://localhost:8000/alerts?source_batch=win10-lab&limit=500" -UseBasicParsing).Content
```

Ожидаемая картина на проверенном стенде — 444 события, 121 сматчилось, 251 алерт, из них 10
корреляционных (`engine=correlation`): `Windows Brute Force - Ten/Twenty Failures ...` (high),
`More Than Ten Failed Authentications ... In One Day` (medium), `Recon Tools Detected - Windows
Image / NewProcessName` (medium). Сработали **обе** ветки — и `NewProcessName` из Security/4688,
и `Image` из Sysmon/1, что и подтверждает корректность разворота `EventData`.

---

## 6. Известные ограничения стенда

**`Provider_Name`.** Fluent Bit шлёт поле `ProviderName`, а Zircolite у неотмапленных полей
вырезает все не-alnum символы (`_NON_ALNUM_RE` в `streaming.py`), так что переименованием в
`Provider_Name` делу не помочь — подчёркивание всё равно исчезнет. Затронуто 104 правила из
4291 в `rules_windows_merged.json`, и у всех есть ещё и условие по `Channel`, так что канальная
фильтрация не ломается — просто эти правила не сработают. Лечится своим файлом маппингов через
`SIEM_ZIRCOLITE_CONFIG_PATH` (добавить `ProviderName: Provider_Name` в `mappings`).

**Точность метки времени.** Родной `TimeCreated` приходит в локальном времени со смещением
(`2026-09-07 08:00:39 +0300`), а `app/timeutil.normalize_event_time` такой формат (пробел перед
смещением) не разбирает и уходит в фолбэк с мусорной строкой. Поэтому `event_time` берётся из
`EventTime`, который подставляет `json_date_key` — это момент **чтения** журнала Fluent Bit,
отстающий от события примерно на секунду (`Interval_Sec 1`). Сырое значение `TimeCreated`
остаётся в `raw_json`. Точная метка — небольшая правка `timeutil.py` (разобрать
`ДАТА ВРЕМЯ ±ЧЧММ`), пока не сделана.

**Инциденты не заводятся сами.** Таблица `incidents` заполняется только correlation-правилами
с блоком `correlation.incident`; catch-all прохода по алертам нет by design
(`docs/spec/incidents.md`). Пока ни одно правило в main не помечено — инцидентов будет ноль,
сколько бы корреляций ни сработало.

**Объём informational-алертов.** Базовые правила сценариев пишут алерт на каждое срабатывание
(241 из 251 на прогоне выше). Для member-алертов инцидента это правильно, но вкладку «Алерты»
забивает быстро.
