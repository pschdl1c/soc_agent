# Агент на Windows-хосте: подключение одним скриптом

Хост подключается к SIEM одним файлом `install-soc-agent.ps1`: скрипт настраивает аудит, ставит
Sysmon с конфигом проекта и запускает агент **Vector**, который шлёт события в `/ingest/stream`.
Заменил ручную настройку Sysmon, аудита и Fluent Bit; стенд в VirtualBox (сеть, проверка
детекта) — `windows-vm-lab.md`.

## Почему Vector, а не Fluent Bit

Fluent Bit (`winevtlog`, `Event_Data_As_Map`) берёт имена полей из метаданных провайдера. У
классических провайдеров без манифеста (System 7045) и у событий с `UserData` (System 104) имён
там нет — приходил позиционный `StringInserts`, и чинить это пришлось бы Lua-фильтрами. Vector
(`windows_event_log`, MPL-2.0) разбирает XML события: имена берутся из `<Data Name=...>`, ровно
те, что ждут Sigma-правила. Проверено на реальных журналах: 7045 приходит с
`ServiceName`/`ImagePath`/`ServiceType`/`StartType`/`AccountName` без доработок.

Отброшены: Winlogbeat (нет вывода по HTTP), OpenTelemetry Collector (только OTLP, тяжёлый),
NXLog CE (закрытая лицензия, скачивание с регистрацией), свой агент на Go (запасной вариант,
не понадобился). Источник `windows_event_log` в Vector в статусе beta; баг с
зависанием после ~3 минут простоя (issue #25194) исправлен в 0.56, ставим 0.58.0.

## Сборка и запуск

На машине с репозиторием:

```powershell
uv run python scripts/build_agent_installer.py      # -> dist/install-soc-agent.ps1
```

Источник и токен создаются в SIEM заранее (UI → «Источник данных» → «Создать источник»). На хосте,
PowerShell от администратора:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install-soc-agent.ps1 -SiemUrl http://192.168.56.1:8000 -Token <токен>
# или одной командой, без смены политики окна:
powershell -ExecutionPolicy Bypass -File C:\tools\install-soc-agent.ps1 -SiemUrl http://192.168.56.1:8000 -Token <токен>
```

Без `Bypass` получишь «выполнение сценариев отключено в этой системе»: политика по умолчанию
запрещает скрипты. Файл, пришедший через браузер или общую папку, может ещё нести пометку
«из интернета» — её снимает `Unblock-File .\install-soc-agent.ps1`.

Параметры: `-SkipAudit`, `-SkipSysmon`, `-SkipSelfTest`, `-VectorVersion`/`-VectorSha256` (другая
версия агента), `-SysmonConfigPath` (только для запуска исходника из репозитория). Удаление агента
— `-Uninstall`, аудит и Sysmon при этом остаются.

| Что | Где |
|---|---|
| Vector | `C:\Program Files\soc-agent\vector\` |
| Конфиг (с токеном, ACL SYSTEM+Administrators) | `C:\ProgramData\soc-agent\vector.toml` |
| Позиции чтения журналов, дисковый буфер | `C:\ProgramData\soc-agent\data\` |
| Логи агента | `C:\ProgramData\soc-agent\logs\vector-ДАТА.log` |
| Служба | `soc-agent` (автозапуск, перезапуск при падении) |

Новый токен (после перевыпуска в UI) — просто повторный запуск скрипта с новым `-Token`.

## Формат событий

Контракт `/ingest/stream` не менялся: плоский JSON, преобразование — VRL в
`deploy/windows/vector.toml` (`transforms.sigma_fields`).

- Поля `EventData`/`UserData` — на верхний уровень под своими именами. `UserData` Vector разбирает
  только в виде `<Data Name=...>`, а у System 104 / Security 1102 данные вложены
  (`<UserData><LogFileCleared><SubjectUserName>`) и приходили пустыми. Поэтому источник отдаёт XML
  (`include_xml = true`), VRL разбирает `UserData` сам, берёт последний сегмент пути и отбрасывает
  поле `xml` перед отправкой. Проверено на стенде: 104 приходит с `SubjectUserName` и `UserDataChannel`.
- Системные поля — в именах Fluent Bit: `EventID`, `Channel`, `Computer`, `ProviderName`,
  `EventRecordID`, `Level` (число), `Task`, `Opcode`, `Keywords`, `Version`, `ActivityID`, `UserID`.
- **Отличия от Fluent Bit:**
  - `ExecutionProcessID`/`ExecutionThreadID` вместо `ProcessID`/`ThreadID`. Раньше системный PID
    конфликтовал с полем `ProcessId` Sysmon: колонки SQLite регистронезависимы.
  - `TimeCreated` — ISO UTC с микросекундами (`2026-09-15T08:00:39.123456Z`). У Fluent Bit была
    секундная точность. **У Sysmon** `TimeCreated` берётся из `UtcTime` самого события: момент записи
    в журнал у Sysmon 3 отстаёт на секунды (сетевые события пишутся пачками) и путал порядок шагов в
    `temporal_ordered`. Если `UtcTime` не разобрался — остаётся время записи.
  - Поле данных, совпавшее по имени с системным, получает префикс `EventData`/`UserData`. В System 104
    канал очищенного журнала приходит как `UserDataChannel`.
  - Строки `"true"`/`"false"` в данных превращаются в JSON boolean (Sysmon `Initiated`), как было
    у Fluent Bit.
  - `StringInserts` — только если у события нет именованных данных.
- Фильтр шума — `ignore_event_ids = [4673, 4674, 5379]` в самом источнике, без grep-фильтра.

VRL покрыт unit-тестами Vector (`vector test`), проверен на реальных журналах System/PowerShell и
на полном пути до SIEM (изолированный экземпляр, фильтр по `ServiceName` находит 7045).

## Проверка на стенде — пройдена 2026-09-15

win10-lab (Windows 10 22H2, VirtualBox), Vector 0.58.0, SIEM на хосте. Как повторить при
обновлении агента/конфига — те же шаги; снимок ВМ перед установкой.

| Проверка | Как | Результат |
|---|---|---|
| Установка и самопроверка | запуск скрипта | маркерный процесс доехал (Sysmon 1 + 4688) |
| Служба | `sc.exe qc soc-agent`; `Select-String ERROR,WARN` по `logs\vector-*.log` | `LocalSystem`, `AUTO_START`, ошибок нет, Security читается |
| 7045 | установка самого агента | `ServiceName`/`ImagePath`/`ServiceType`/`StartType`/`AccountName` |
| System 104 | `wevtutil cl "Microsoft-Windows-Bits-Client/Operational"` | `SubjectUserName`, `SubjectDomainName`, `UserDataChannel` (после правки разбора `UserData`) |
| 4648 | `runas` под учёткой **с паролем** (у учётки с пустым паролем `runas` падает с 1327 и даёт только 4625) | `ProcessName`, `TargetUserName`, `TargetServerName` |
| Sysmon 1 | `whoami` | `ProcessId` = PID процесса, `ExecutionProcessID` = PID службы Sysmon |
| Sysmon 3 | фон | `Initiated = 1`, `DestinationIsIpv6 = 0` |
| Время | 4688 и Sysmon 1 одного запуска | `…03.864571` против `…03.872923` — доли секунды |
| Каналы | фон | Defender, WMI-Activity, Bits-Client доезжают |
| Фильтр шума | `Get-WinEvent` по пропущенным `EventRecordID` Security | все пропуски — 5379 |
| Перезапуск и повторная установка | `Restart-Service soc-agent`; скрипт ещё раз | дублей нет, пропусков нет (кроме 5379) |
| Недоступность SIEM | SIEM выключен 5 мин, в ВМ `hostname`/`whoami` | 156 событий доехали за 5 с после старта, без потерь и дублей |
| Простой | ВМ без активности | условно закрыто; в логе агента видно срабатывание страховки из исправления #25194 (`Speculative timeout pull recovered events`) |

Попутно найдено: `hostname.exe` Sysmon 1 не пишет (конфиг Sysmon; закрыто 2026-09-15, см.
`docs/guide/windows-vm-lab.md` §3), у Sysmon 3 `TimeCreated` отстаёт от `UtcTime` события на секунды (исправлено в агенте:
у Sysmon время берётся из `UtcTime`; проверено на стенде 2026-09-15 — у Sysmon 1/3/7/8/10/11/12/13/17/
22/26/29 `TimeCreated` совпадает с `UtcTime` до миллисекунды, у Security/System время записи без изменений). Установка агента
даёт известные ложные срабатывания от собственных действий установщика: инциденты
`SCE_Evasion_Telemetry_Tampering` (`sysmon -c`) и `SCE_Evasion_Log_Cleared` (`wevtutil sl` — размеры
журналов), алерты «Audit Policy Tampering Via Auditpol» (`auditpol /set ... /success:disable`).

Остановка старой службы при переустановке: `sc stop` → ожидание 60 с → завершение процесса службы.
`Stop-Service` здесь не годится — на зависшей остановке Vector он падал с «Ошибка при остановке службы»
и обрывал установку, оставляя хост без агента (стенд, 2026-09-15). Дисковый буфер и позиция чтения
журнала переживают завершение процесса, возможны единичные повторы последних событий.

После любого изменения набора полей (конфиг агента, каналы, Sysmon) — перегенерировать схему для
синтетики контента:

```powershell
uv run python scripts/export_event_fields.py http://localhost:8000 --source <источник стенда> --rename-legacy
```