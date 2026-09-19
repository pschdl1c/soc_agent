#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Отключает Windows Update на ВМ стенда win10-lab (и возвращает обратно с -Revert).

.DESCRIPTION
    Только обновления: политика, три службы, задачи планировщика. Ничего больше не трогает -
    ни Defender, ни телеметрию, ни аудит, ни службы вообще. Это принципиально: аудит на стенде
    выставлен по базовой линии Microsoft установщиком агента, а фон простоя замерен
    (CLAUDE.md §9) - готовые "отключалки" с гитхаба правят всё подряд и незаметно ломают
    и то, и другое.

    Побочный полезный эффект: уходит заметная часть фонового шума - события 4702 (правка задач
    UpdateOrchestrator) давали 13% объёма в замере простоя.

    Запускать ПОСЛЕ install-soc-agent.ps1: тот тянет Sysmon с download.sysinternals.com и Vector
    с packages.timber.io, интернет ему нужен (сами обновления к этому отношения не имеют, но
    порядок "поставили агент -> checkpoint -> отключили обновления" оставляет рабочую точку отката).

.EXAMPLE
    .\lab-disable-updates.ps1

.EXAMPLE
    .\lab-disable-updates.ps1 -Revert
#>
param(
    [switch]$Revert
)

$ErrorActionPreference = 'Stop'

$policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$policyAu   = Join-Path $policyRoot 'AU'
$medicKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$taskPaths  = @('\Microsoft\Windows\UpdateOrchestrator\', '\Microsoft\Windows\WindowsUpdate\')
# wuauserv - сам Windows Update, UsoSvc - оркестратор сессий обновления,
# WaaSMedicSvc - "лекарь", который чинит отключённое обратно.
$services   = @('wuauserv', 'UsoSvc')

function Write-Step($text) { Write-Host "[*] $text" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "[+] $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "[!] $text" -ForegroundColor Yellow }

function Disable-Updates {
    Write-Step 'Политика: не проверять и не устанавливать обновления'
    New-Item -Path $policyAu -Force | Out-Null
    Set-ItemProperty -Path $policyAu   -Name NoAutoUpdate -Value 1 -Type DWord
    Set-ItemProperty -Path $policyAu   -Name AUOptions    -Value 1 -Type DWord   # 1 = никогда не проверять
    Set-ItemProperty -Path $policyRoot -Name DoNotConnectToWindowsUpdateInternetLocations -Value 1 -Type DWord
    Write-Ok 'политика записана'

    Write-Step 'Службы обновления'
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { Write-Warn "службы $svc нет, пропуск"; continue }
        if ($s.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
        Set-Service -Name $svc -StartupType Disabled
        Write-Ok "$svc остановлена и отключена"
    }
    # WaaSMedicSvc защищена: Set-Service/sc config отвечают "отказано в доступе", только реестр.
    if (Test-Path $medicKey) {
        Set-ItemProperty -Path $medicKey -Name Start -Value 4 -Type DWord
        Write-Ok 'WaaSMedicSvc отключена через реестр (применится после перезагрузки)'
    } else {
        Write-Warn 'ветки WaaSMedicSvc нет, пропуск'
    }

    Write-Step 'Задачи планировщика'
    $n = 0
    foreach ($path in $taskPaths) {
        Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue | ForEach-Object {
            try { Disable-ScheduledTask -InputObject $_ -ErrorAction Stop | Out-Null; $n++ } catch { }
        }
    }
    Write-Ok "отключено задач: $n"
}

function Enable-Updates {
    Write-Step 'Убираю политику'
    if (Test-Path $policyRoot) { Remove-Item -Path $policyRoot -Recurse -Force }
    Write-Ok 'ветка политики удалена'

    Write-Step 'Возвращаю службы'
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { Write-Warn "службы $svc нет, пропуск"; continue }
        Set-Service -Name $svc -StartupType Manual
        Write-Ok "$svc -> Manual"
    }
    if (Test-Path $medicKey) {
        Set-ItemProperty -Path $medicKey -Name Start -Value 3 -Type DWord
        Write-Ok 'WaaSMedicSvc -> Manual (после перезагрузки)'
    }

    Write-Step 'Включаю задачи'
    $n = 0
    foreach ($path in $taskPaths) {
        Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue | ForEach-Object {
            try { Enable-ScheduledTask -InputObject $_ -ErrorAction Stop | Out-Null; $n++ } catch { }
        }
    }
    Write-Ok "включено задач: $n"
}

if ($Revert) { Enable-Updates } else { Disable-Updates }

Write-Host ''
Write-Step 'Итоговое состояние'
Get-Service wuauserv, UsoSvc, WaaSMedicSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize
$disabled = @()
foreach ($path in $taskPaths) {
    $disabled += Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Disabled' }
}
Write-Host ("задач в состоянии Disabled: {0}" -f $disabled.Count)
Write-Warn 'StartType у WaaSMedicSvc покажет прежнее значение до перезагрузки - это нормально, правка в реестре'
