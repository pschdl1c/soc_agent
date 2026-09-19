# Лабораторный стенд: Windows-ВМ → мини-SIEM

Тестовая Windows 10 в **Hyper-V** как источник событий: сеть до SIEM, подключение хоста агентом,
проверка детекта, живой прогон детект-контента. Ранбук проверен на живом стенде (Windows 10 22H2
в Hyper-V на Windows Server/Pro-хосте, агент Vector 0.58.0) — команды и грабли ниже реальные, не
гипотетические.

Стенд изначально стоял в VirtualBox; переезд на Hyper-V (2026-09-19) был вынужденным — на этом
хосте Hyper-V уже занят WSL2/Docker Desktop, и VirtualBox падал в режим NEM «Snail execution
mode» (AMD-V недоступен), из-за чего виртуальные часы гостя периодически прыгали на десятки
секунд вперёд и ломали `temporal`/`temporal_ordered`-корреляции ложными `MISSING`. Если на твоём
хосте Hyper-V ничем не занят и VirtualBox работает штатно (VT-x/AMD-V доступен нативно) — эта
причина не про тебя, но сам ранбук ниже написан под Hyper-V.

Сам хост подключается одним скриптом: аудит, Sysmon и агент ставит `install-soc-agent.ps1`, см.
**`docs/guide/windows-agent.md`**. Общий контракт приёма событий (формат тела, токен, коды ответов) —
`docs/guide/forwarder.md`. Здесь только то, что специфично для стенда.

---

## 0. Сеть и ВМ (Hyper-V)

### Коммутаторы

Два виртуальных коммутатора: **Default Switch** (интернет в гостя — нужен сценариям с
`certutil`/загрузками) и **Internal Switch `soc-lab`** (стабильный адрес SIEM — хосту
`192.168.56.1/24`, гостю `192.168.56.101/24` статикой). PowerShell от администратора:

```powershell
New-VMSwitch -Name soc-lab -SwitchType Internal
New-NetIPAddress -InterfaceAlias "vEthernet (soc-lab)" -IPAddress 192.168.56.1 -PrefixLength 24
Set-NetConnectionProfile -InterfaceAlias "vEthernet (soc-lab)" -NetworkCategory Private
New-NetFirewallRule -DisplayName "SOC SIEM 8000 (soc-lab)" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Any
```

Последние две строки не косметика: новый внутренний адаптер Windows по умолчанию относит к сети
**Public**, и брандмауэр хоста режет входящие на 8000, хотя докер слушает `0.0.0.0:8000`. Из
гостя это выглядит как таймаут `Test-NetConnection`, то есть как проблема сети ВМ, а не хоста.

Смысл именно подсети `192.168.56.0/24`: адрес SIEM из гостя остаётся `http://192.168.56.1:8000` —
ни `dist/vector.toml`, ни документацию не приходится подстраивать под конкретный хост.

### Создание ВМ

Gen 2 (UEFI; Secure Boot выключить — иначе не загрузится установщик с ISO), 4 ГБ памяти, 4 vCPU
(2 vCPU замерено ХУЖЕ на этом хосте), динамический VHDX 60 ГБ, два сетевых адаптера
(Default Switch + soc-lab):

```powershell
$vm = "win10-lab"; $dir = "D:\VMs\hyperv"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
New-VM -Name $vm -Generation 2 -MemoryStartupBytes 4GB -Path $dir `
  -NewVHDPath "$dir\$vm\Virtual Hard Disks\$vm.vhdx" -NewVHDSizeBytes 60GB -SwitchName "Default Switch"
Set-VMMemory    -VMName $vm -DynamicMemoryEnabled $false
Set-VMProcessor -VMName $vm -Count 4
Set-VMFirmware  -VMName $vm -EnableSecureBoot Off
Add-VMNetworkAdapter -VMName $vm -SwitchName soc-lab
Add-VMDvdDrive  -VMName $vm -Path "<путь к Windows10.iso>"
Set-VMFirmware  -VMName $vm -BootOrder (Get-VMDvdDrive -VMName $vm),(Get-VMHardDiskDrive -VMName $vm)
Set-VM -Name $vm -AutomaticCheckpointsEnabled $false -CheckpointType Standard
```

Два отступления от «стандартной» ВМ, оба намеренные:
- **автоматические checkpoint'ы выключены** — иначе Hyper-V снимает снимок при каждом старте и
  ест место, мешаясь с ручными контрольными точками перед деструктивными сценариями;
- **тип снимка `Standard`**, не `Production` — production снимается через VSS и не сохраняет
  память (после отката гость грузится как после выключения), а для возврата стенда перед
  `impact`-сценариями нужен точный слепок состояния.

Сеть намеренно убрана из `BootOrder` — иначе UEFI после пропущенного DVD уходит в
`Start PXE over IPv4` и висит там.

**Грабли загрузки с ISO.** `Start-VM`, а следом `vmconnect` — гарантированный промах: окно
консоли открывается уже после того, как истекли пять секунд «Press any key to boot from CD or
DVD», и Boot Summary рапортует `SCSI DVD — The boot loader failed` (это не про испорченный
образ). Правильно — сначала консоль на выключенной ВМ, старт уже из неё:

```powershell
vmconnect.exe localhost win10-lab   # окно откроется с кнопкой «Пуск»
```

Кликнуть в окно, нажать «Пуск», сразу давить пробел.

### Настройка гостя

- Статический `192.168.56.101/24` на адаптере soc-lab, без шлюза (шлюз — через Default Switch).
- Имя компьютера и учётка — держать неизменными между переустановками: инциденты ключуются по
  `Computer`, и фикстуры/доки на этом стенде их называют явно (`DESKTOP-A516CVK`/`workstation_x`).
- Проверить из гостя: `Test-NetConnection 192.168.56.1 -Port 8000` — ждём `True`.

**Интернет в гостя при включённом VPN на хосте.** У Hyper-V NAT ядерный (WinNAT) — пакеты гостя
транзитные, ничьим процессом не являются, и туннель VPN-клиента (TUN-интерфейс) их не пропускает,
даже когда хост в сети. Симптом обманчив: `ping 1.1.1.1` из гостя отвечает за 1 мс (отвечает сам
TUN локально), а TCP не устанавливается вообще.

Решение — пустить гостя через локальный прокси VPN-клиента (SOCKS5/HTTP-прокси на хосте).
На хосте:

```powershell
netsh interface portproxy add v4tov4 listenaddress=192.168.56.1 listenport=<порт> connectaddress=127.0.0.1 connectport=<порт>
New-NetFirewallRule -DisplayName "VPN proxy <порт> (soc-lab)" -Direction Inbound -Protocol TCP -LocalPort <порт> -Action Allow -Profile Any
```

Слушатель только на `192.168.56.1`, в домашнюю сеть прокси не торчит. В госте — оба уровня
системного прокси, WinHTTP (службы, `certutil`) и WinINET (`Invoke-WebRequest`, установщики):

```powershell
netsh winhttp set proxy proxy-server="192.168.56.1:<порт>" bypass-list="192.168.56.*;<local>"
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty $k ProxyEnable 1
Set-ItemProperty $k ProxyServer "192.168.56.1:<порт>"
Set-ItemProperty $k ProxyOverride "192.168.56.*;<local>"
```

`bypass-list`/`ProxyOverride` с `192.168.56.*` обязателен, иначе трафик к самому SIEM уйдёт в
прокси. Ограничение: непроксируемые соединения из гостя наружу так и не работают (`ping`,
`Test-NetConnection 1.1.1.1 -Port 443`, сырые сокеты) — при отладке сценариев это не путать с
поломкой сети. Через прокси тоже не всё гладко: TLS-хендшейк к внешнему сайту иногда падает
транзитно (`curl: (35) schannel: failed to receive handshake`) без видимой причины — раз-два
повторить, прежде чем считать сценарий сломанным.

### Буфер обмена и передача файлов

Нужен расширенный сеанс (`Set-VMHost -EnableEnhancedSessionMode $true`, в диалоге подключения
«Локальные ресурсы» — буфер оставить, **диски не отмечать**: проброс дисков даёт гостю запись в
файловую систему хоста, а на этой ВМ гоняются `impact`-сценарии).

Файлы — `Copy-VMFile` с хоста (drag-and-drop и общих папок в Hyper-V нет):

```powershell
Enable-VMIntegrationService -VMName win10-lab -Name "Guest Service Interface"
Copy-VMFile -Name win10-lab -SourcePath "<путь на хосте>" -DestinationPath "C:\tools\<имя>" -CreateFullPath -FileSource Host -Force
```

---

## 1. Источник, токен и агент

1. UI SIEM → **«Источник данных»** → **«Создать источник»**. Имя обязательно, уникально и
   неизменяемо — оно становится меткой `source_batch` всех событий и алертов хоста. Токен
   показывается **один раз** (в БД лежит только sha256). `description` — до 64 символов.
2. На хосте с репозиторием: `uv run python scripts/build_agent_installer.py` → `dist/install-soc-agent.ps1`.
3. Файл — в ВМ через `Copy-VMFile` (см. выше), там PowerShell от администратора:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
Unblock-File C:\tools\install-soc-agent.ps1
powershell -ExecutionPolicy Bypass -File C:\tools\install-soc-agent.ps1 -SiemUrl http://192.168.56.1:8000 -Token <токен>
```

Свежую Windows 10 стоит сначала прогнать через `dist/lab-disable-updates.ps1` — иначе фоновая
закачка обновлений может уйти в перезагрузку посреди установки агента (самому агенту Windows
Update не нужен, Sysmon и Vector он берёт напрямую с sysinternals и timber.io).

Что делает установщик, где лежат файлы агента, формат событий и чек-лист проверки —
`docs/guide/windows-agent.md`.

### Контрольная точка

Сразу после установки агента — снимок ВМ, пока стенд ещё чистый:

```powershell
Checkpoint-VM -VMName win10-lab -SnapshotName clean-after-agent
```

К нему откатываться перед деструктивными сценариями (домен `impact`, `SCE_KC_Evasion_Then_Impact`):

```powershell
Restore-VMSnapshot -VMName win10-lab -Name clean-after-agent -Confirm:$false
Start-VM -Name win10-lab
```

Тип снимка `Standard` (см. выше) сохраняет память — после отката ВМ возвращается в «работающее»
состояние на момент снимка, а не грузится с нуля. Часы гостя после отката будут отставать до
ресинхронизации со временем — не гнать сразу следующий сценарий, дать время устаканиться.

---

## 2. Проверка детекта

`/ingest/stream` гоняется **только по «основному рулсету»** (`app/rules/main_ruleset.py`) —
до первых алертов в main должен лежать контент: `uv run python scripts/deploy_content.py
http://localhost:8000 --prune` (домены `artifacts/content/`, CLAUDE.md §9).

Команды эмуляции каждого сценария — секция `lab:` его фикстуры в
`artifacts/content/<domain>/tests/`. Полный живой прогон всех сценариев волнами — раннер
`dist/run-lab-scenarios.ps1` (собирается из фикстур `scripts/build_lab_runner.py`), см. §5.

Быстрый дымовой тест вручную, в ВМ от администратора:

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

---

## 3. Быстрый старт (ВМ уже настроена)

Шпаргалка на каждый день, когда §0–§2 уже пройдены. Всё «с хоста» — PowerShell от администратора.

**ВМ: запуск, остановка, состояние.**

```powershell
Get-VM win10-lab | Select-Object Name, State, Uptime, MemoryAssigned
Start-VM -Name win10-lab
vmconnect.exe localhost win10-lab
Save-VM  -Name win10-lab              # заморозить состояние (быстрее выключения, часы потом отстают)
Stop-VM  -Name win10-lab              # корректное выключение гостя; -Force — если завис
```

**Контрольные точки** (перед деструктивными сценариями — обязательно):

```powershell
Get-VMSnapshot -VMName win10-lab | Select-Object Name, CreationTime
Checkpoint-VM  -VMName win10-lab -SnapshotName before-impact
Restore-VMSnapshot -VMName win10-lab -Name clean-after-agent -Confirm:$false; Start-VM -Name win10-lab
```

После отката часы гостя отстают до ресинхронизации — не гнать сразу следующий сценарий.

**Файлы в гостя** (только хост → гость; обратно — через буфер обмена):

```powershell
Copy-VMFile -Name win10-lab -FileSource Host -CreateFullPath -Force `
  -SourcePath D:\__projects\soc_agent\dist\run-lab-scenarios.ps1 -DestinationPath C:\tools\run-lab-scenarios.ps1
```

**SIEM и артефакты на хосте:**

```powershell
docker compose up -d                                       # или uvicorn app.main:app --port 8000
uv run python scripts/deploy_content.py http://localhost:8000 --prune   # контент в main
uv run python scripts/build_agent_installer.py             # пересобрать dist/install-soc-agent.ps1
uv run python scripts/build_lab_runner.py                  # пересобрать dist/run-lab-scenarios.ps1
```

**Агент в госте:**

```powershell
Get-Service soc-agent                                      # ждём Running
Restart-Service soc-agent
Get-ChildItem C:\ProgramData\soc-agent\logs\ | Select-Object -Last 1   # логи агента
Test-NetConnection 192.168.56.1 -Port 8000                 # связь до SIEM
```

Новый токен после перевыпуска в UI — просто повторный запуск `install-soc-agent.ps1` с новым
`-Token` (`docs/guide/windows-agent.md`).

**Прогон сценариев в госте** (`-Source` — имя источника в UI, читает `/incidents`, токен не нужен):

```powershell
powershell -ExecutionPolicy Bypass -File C:\tools\run-lab-scenarios.ps1 -Source win10-lab -ListOnly
.\run-lab-scenarios.ps1 -Source win10-lab -Domain recon,auth -Yes
.\run-lab-scenarios.ps1 -Source win10-lab -FromScenario SCE_Exec_Download_Then_Execute
.\run-lab-scenarios.ps1 -Source win10-lab -Domain impact -ConfirmDestructive   # только после Checkpoint-VM
```

**Что доехало — с хоста:** три `Invoke-RestMethod` из §2 (события по EventID, алерты по правилам,
инциденты).

---

## 4. Известные ограничения стенда

- **`Provider_Name` не доезжает.** Агент шлёт `ProviderName`, Zircolite вырезает не-alnum символы
  у неотмапленных полей — переименование не спасёт. Своего маппинга не заводим (решено
  2026-09-15): в правилах писать `ProviderName` либо убирать, роль играет guard (CLAUDE.md §9).
- **Время Sysmon.** Агент кладёт в `TimeCreated` значение `UtcTime` самого события — запись в
  журнал у Sysmon 3 отстаёт на секунды (`docs/guide/windows-agent.md`).
- **ProcessCreate у Sysmon — в exclude-режиме** (2026-09-15): Sysmon 1 пишется для всех процессов,
  кроме шума. Проверено прогоном 110 утилит из process-правил: Sysmon 1 есть у всех 75 запущенных
  (в include-режиме было 47). Любой `ProcessCreate onmatch="include"` возвращает режим «только
  перечисленное» — при обновлении sysmon-modular его надо удалять. Конфиг применяется на ходу:
  `sysmon64 -c C:\tools\sysmonconfig.xml` (взводит `SCE_Evasion_Telemetry_Tampering`).
- **Аудит — базовая линия Microsoft для рабочих станций**, кроме осознанных отличий: Sensitive
  Privilege Use и Process Termination выключены, Kerberos/SAM/Directory Service — до появления
  контроллера домена. PowerShell: ScriptBlock (4104) включён, Module logging (4103) выключен.
- **Шум отфильтрован в агенте** — 4673/4674/5379 (`ignore_event_ids` в `dist/vector.toml`) до SIEM
  не доезжают, пропуски `EventRecordID` в Security из-за них ожидаемы.
- **Инциденты не заводятся сами** — только correlation-правилами с `correlation.incident`,
  catch-all прохода по алертам нет by design (`docs/spec/incidents.md`).
- **Объём informational-алертов.** Базовые правила пишут алерт на каждое срабатывание — вкладка
  «Алерты» забивается быстро; разбирать фильтром «в инцидентах / вне», поиском и группировкой по
  правилу.
- **Установка агента сама даёт инциденты** — `SCE_Evasion_Telemetry_Tampering` (`sysmon -c`),
  `SCE_Evasion_Log_Cleared` (`wevtutil sl`), «Audit Policy Tampering» (`auditpol /set`). Известные
  ложные срабатывания, исключений под них не пишем (CLAUDE.md §9).
- **`Start-Process -Credential` пишет в 4625 адрес `::1`, а не `'-'`** (идёт через
  `CreateProcessWithLogonW`) — сценарий под «4625 без адреса» так не воспроизвести.
- **Windows 10 блокирует учётку после 10 неудачных входов** — перед сценариями брутфорса
  `net accounts /lockoutthreshold:0`, иначе успешный вход падает с «System error 1909».
- **Sysmon пишет EID 3 только по УСТАНОВЛЕННОМУ соединению** — при выходе в интернет через прокси
  (§0) сетевой сценарий должен целить в адрес, который реально примет соединение.
- **Волны сценариев подряд дают сквозные срабатывания — это не ошибка.** Активность одной волны
  попадает в окно корреляции соседней (и сама собой всплывают `kc_*`-инциденты); правило не может
  связать поля разных событий, чтобы отличить совпадение от цепочки. Хочешь чистые отчёты — держи
  паузу между волнами больше самого длинного задействованного окна.

### Что реально приезжает со стенда (телеметрия 2026-09-15)

Каналы: Security, System, Sysmon/Operational, PowerShell/Operational, Defender, WMI-Activity,
TaskScheduler, Bits-Client. **Замер простоя** (20 мин без действий после установившегося фона):
**~1500 событий/ч**, ни одного алерта. Доли: Sysmon 13 — 27% (`svchost`, `TiWorker`), 4702 — 13%
(задачи `UpdateOrchestrator`), Sysmon 11 — 12%, 4688 — 12%, Sysmon 7 — 11% (Defender `MpCmdRun`,
OneDrive), Sysmon 1 — 8%, 4957 — 5% (правила брандмауэра не применены), 4624 type 5 / 4672 SYSTEM /
4799 `VSSVC` — по 2–3%. После загрузки разовые всплески: 4907 от `TiWorker` (сотни), 4945/4957 при
старте брандмауэра — на установившемся фоне их нет или мало. Фильтрация шума при таком объёме не
нужна.

Колонка «правил» — сколько записей `rules_windows_merged.json` (4291 шт.) ссылается на этот
EventID, как ориентир ценности; контент пишется по этой таблице (CLAUDE.md §9).

| EventID | приезжает | правил | замечание |
|---|---|---:|---|
| 4688 / Sysmon 1 | да | 1349 / 1350 | ядро process-контента; Sysmon 1 — все процессы минус exclude-шум (~117/ч в простое) |
| Sysmon 13 / 11 | да, обильно | 261 / 211 | 13 — ~400/ч в простое (`svchost`, `TiWorker`); `CompatTelRunner` исключён в конфиге |
| 4104 / 4103 | 4104 да, 4103 выключен установщиком | 166 / 33 | PowerShell ScriptBlock; 4103 (Module logging) — объём без правил в контенте |
| 4624 / 4625 | да | 15 / 5 | только с фильтрами (белый список `LogonType`, отсечка машинных учёток) |
| Sysmon 22 / 12 / 3 | да, мало | 29 / 57 / 55 | DNS, реестр, сеть |
| 4697 / 7045 | да, мало | 22 / 48 | установка служб; 7045 с именованными полями |
| System 104 / Security 1102 | да (104 проверен) | — | очистка журналов, поля из `UserData` |
| Sysmon 7 / 10 / 16 / 17 / 26 / 29 | да (новый конфиг) | 114 / 25 / — / 19 / — / — | 10 — доступ к процессам (lsass), 17 — named pipe |
| Sysmon 8 / 18 / 19–21 / 23 | не встречались | — / 19 / — / 13 | конфиг включает, активности на стенде не было |
| Defender 5007, WMI-Activity 5857, Bits-Client | да | — | новые каналы |
| 4946 / 4948, 4663, 6416, 4608, 5038 | да (базовая линия) | — | правила брандмауэра, съёмные носители, устройства, старт/целостность; 5140/5145/4778 — будут при общих папках/RDP |
| 4702 / 4957 / 4799 | да, фон | — | обновление задач Windows, неприменённые правила брандмауэра, перечисление групп `VSSVC`; правил в контенте нет |
| 4657 | **НЕТ** | 268 | требует SACL на ветках реестра, на практике не настраивают; Sysmon 13 закрывает то же |
| 4673 / 4674 / 5379 | не доезжают | 1 / — / 3 | чистый шум (было ~19% объёма): отсекается в агенте (`ignore_event_ids`) |
| 4689 | нет | 0 | подкатегория выключена установщиком |

Практический вывод: process / PowerShell / auth / registry / services / log clearing — пиши контент;
Sysmon 10/17 доезжают, но FP-доводка правил на них — после живого прогона.

---

## 5. Живой прогон детект-контента (2026-09-19)

Полный прогон всех сценариев `artifacts/content/*/tests/*.yml` через `dist/run-lab-scenarios.ps1`
(гид по `lab:`-секциям фикстур, поллит `/incidents` до появления ожидаемых `incident_type`).
49 из 53 сценариев прогнаны живьём (`lateral`, 4 сценария, пропущен — нужен второй хост).

| волна | итог |
|---|---|
| `recon` | 3 PASS, 1 SKIP (manual only) |
| `execution` | все PASS (после 2 итераций фиксов, см. ниже) |
| `auth` + `persistence` | все 11 PASS (после 1 итерации фикса) |
| `privesc` + `credaccess` | 6 PASS, 2 SKIP (manual only — `GetSystem`/`Mimikatz`, нет бинаря/C2 на стенде) |
| `evasion` + `exfil` | 6 PASS, 1 не проверялся живьём (см. ниже) |
| `killchain` | 2 PASS, 3 SKIP (manual only — композиции уже пройденных по отдельности сценариев) |
| `impact` (после отката на checkpoint) | все 3 PASS |

Итог: **логика контента подтверждена живым прогоном** для 10 из 11 доменов. Остаётся: `lateral`
(нужен второй хост), телеметрия Sysmon 17/18 (именованные каналы) и 19–21 (WMI) — правил под них
в контенте пока нет, поэтому проверить было нечего; выгрузку `event_fields.json` со стенда
(`scripts/export_event_fields.py`) после этого прогона не переснимали.

### Фиксы фикстур по итогам прогона

- `SCE_Exec_Download_Then_Execute` — URL `live.sysinternals.com/whoami.exe` отдавал **404**
  (`whoami` — встроенная утилита Windows, у Sysinternals её нет): `certutil` сохранял страницу
  ошибки, запуск падал с «file is corrupted». Заменено на `PsInfo.exe` + `-accepteula` (без флага
  первый запуск утилиты Sysinternals показывает модальный диалог лицензии и вешает раннер) — тот же
  фикс применён и в `SCE_KC_Execution_Then_Persistence`.
- `SCE_TH_Exec_Beaconing_From_Suspicious_Location` — корреляция ключуется по `ProcessGuid` (модель
  импланта: один процесс, N соединений), а `lab:` запускал `curl` несколько раз НОВЫМИ процессами,
  давая счёт 1 на ключ. Теперь соединения делает ОДИН процесс (`Connection: close`, иначе curl
  переиспользует соединение).
- `SCE_Exec_Remote_Access_Tool` — если предыдущий прогон оставил файл AnyDesk, `Invoke-WebRequest`
  падал и обрывал строку до `Start-Process`. Строка теперь сначала гасит старый процесс.
- `SCE_Exfil_Archive_Then_Transfer` — без 7-Zip (в фикстуре — заметка, не команда) `curl
  --upload-file` проверяет существование локального файла ДО сети и падает мгновенно, не делая ни
  одного DNS-запроса; поэтому целевой (более узкий) инцидент `th_exfil_filesharing_dns` не
  поднимался. Добавлена строка-заглушка файла перед curl.
- `SCE_Exfil_Rclone` — `rclone.exe` на стенде не было; добавлена загрузка портативного бинаря с
  `downloads.rclone.org` перед запуском.

### Прочие находки раннера (не про контент, про сам скрипт)

- **`expected` — только позитивные кейсы фикстуры**, не объединение всех: `negative_*`-кейс одного
  сценария сплошь и рядом позитивен для соседнего и живым прогоном не воспроизводится. Где
  `lab:`-секция у́же любого позитивного кейса (нет второго хоста, нет 7-Zip), фикстура задаёт набор
  явно ключом `lab_expect` (формат — в шапке `scripts/test_content.py`; синтетика его не читает).
- **Раннер сверяет `updated_at`, а не `created_at`** у инцидентов — повтор сценария в том же бакете
  `dedup_key` (`UPDATE`, не новая строка) иначе давал ложный MISSING при работающем детекте.
- **`-Domain a,b` разбирается раннером сам** — PowerShell при вызове `-File` передаёт список через
  запятую одной строкой, `[string[]]` его не разбивает.
- Классификатор строк `_CODE_START_RE` — Windows-путь `C:\Users\...` не должен требовать двойного
  экранирования бэкслеша, иначе такие строки молча уезжают в `[NOTE]` и никогда не выполняются.

Хвосты воспроизводить не нужно — все уже в текущей версии `scripts/build_lab_runner.py` /
`dist/run-lab-scenarios.ps1`.
