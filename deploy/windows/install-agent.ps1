#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Подключает Windows-хост к soc_agent SIEM: аудит, Sysmon, агент Vector службой.

.DESCRIPTION
    Идемпотентен - повторный запуск обновляет аудит, конфиг Sysmon, бинарник и конфиг агента.
    Шаги:
      1. Проверка SIEM и токена источника (пустой POST /ingest/stream: 202 - ок, 401 - токен).
      2. Аудит Security по GUID подкатегорий (локаль не важна), командная строка в 4688,
         логирование PowerShell, размеры журналов.
      3. Sysmon (download.sysinternals.com, проверка подписи Microsoft) + конфиг проекта.
      4. Vector (packages.timber.io, проверка sha256), конфиг, служба soc-agent.
      5. Самопроверка: маркерный процесс -> ждём его событие в GET /events.

    Самодостаточная версия одним файлом (конфиги внутри) собирается
    scripts/build_agent_installer.py -> dist/install-soc-agent.ps1. Этот исходник можно запускать и
    на месте: vector.toml берётся рядом со скриптом, sysmonconfig.xml - из -SysmonConfigPath,
    рядом со скриптом или из artifacts/content/telemetry/ репозитория.

.EXAMPLE
    .\install-soc-agent.ps1 -SiemUrl http://192.168.56.1:8000 -Token <токен источника>

.EXAMPLE
    .\install-soc-agent.ps1 -Uninstall
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$SiemUrl,
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$Token,
    [Parameter(ParameterSetName = 'Install')][string]$VectorVersion = '0.58.0',
    [Parameter(ParameterSetName = 'Install')][string]$VectorSha256 = '72bbedf4772302f7f67e7db2120fe5b42e39ae65873c895876fc2038050c10c5',
    [Parameter(ParameterSetName = 'Install')][string]$SysmonConfigPath,
    [Parameter(ParameterSetName = 'Install')][switch]$SkipAudit,
    [Parameter(ParameterSetName = 'Install')][switch]$SkipSysmon,
    [Parameter(ParameterSetName = 'Install')][switch]$SkipSelfTest,
    [Parameter(Mandatory, ParameterSetName = 'Uninstall')][switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # прогресс-бар Invoke-WebRequest в 5.1 замедляет загрузку в разы
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Встраиваются сборщиком (scripts/build_agent_installer.py); $null - режим запуска из репозитория.
$EmbeddedVectorToml = $null          # @@EMBED:vector.toml@@
$EmbeddedSysmonConfigGzB64 = $null   # @@EMBED:sysmonconfig.xml@@

$ServiceName = 'soc-agent'
$InstallDir  = Join-Path $env:ProgramFiles 'soc-agent'
$VectorDir   = Join-Path $InstallDir 'vector'
$SysmonDir   = Join-Path $InstallDir 'sysmon'
$StateDir    = Join-Path $env:ProgramData 'soc-agent'
$DataDir     = Join-Path $StateDir 'data'
$LogDir      = Join-Path $StateDir 'logs'
$ConfigPath  = Join-Path $StateDir 'vector.toml'
$TempDir     = Join-Path $env:TEMP 'soc-agent-install'

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "    ok: $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text) { Write-Host "    ВНИМАНИЕ: $Text" -ForegroundColor Yellow }

function Invoke-Native([string]$Exe, [string[]]$Arguments, [int[]]$OkCodes = @(0)) {
    # PowerShell 5.1 заворачивает stderr нативной программы в ErrorRecord, и при 'Stop' любая
    # строка в stderr (Vector пишет туда свои INFO-логи) обрывала бы установку. Успех - по коду.
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1 | Out-String
    if ($OkCodes -notcontains $LASTEXITCODE) {
        throw "$Exe $($Arguments -join ' ') -> код $LASTEXITCODE`n$out"
    }
    return $out
}

function Get-Download([string]$Url, [string]$OutFile) {
    New-Item -ItemType Directory -Force (Split-Path $OutFile) | Out-Null
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

# ACL: только SYSTEM и Administrators (в конфиге агента лежит токен источника).
function Set-PrivateAcl([string]$Path) {
    Invoke-Native icacls.exe @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') | Out-Null
}

function Remove-AgentService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $svc.WaitForStatus('Stopped', '00:00:30') }
    Invoke-Native sc.exe @('delete', $ServiceName) | Out-Null
}

# ---------------------------------------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Удаление агента"
    Remove-AgentService
    foreach ($d in @($VectorDir, $StateDir)) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
    Write-Ok "служба $ServiceName, $VectorDir и $StateDir удалены"
    Write-Host "Аудит и Sysmon оставлены как есть (Sysmon удаляется: Sysmon64.exe -u)."
    return
}

$SiemUrl = $SiemUrl.TrimEnd('/')

# --- 1. SIEM и токен --------------------------------------------------------------------------
Write-Step "Проверка SIEM $SiemUrl и токена"
try {
    $resp = Invoke-WebRequest -Uri "$SiemUrl/ingest/stream" -Method Post -Body '' -UseBasicParsing -TimeoutSec 15 `
        -Headers @{ Authorization = "Bearer $Token" }
} catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($code -eq 401) { throw "SIEM отклонил токен (401): источник не существует, выключен или токен перевыпущен." }
    throw "SIEM недоступен по $SiemUrl : $($_.Exception.Message)"
}
$SourceName = ($resp.Content | ConvertFrom-Json).source
Write-Ok "источник '$SourceName'"

# --- 2. Аудит ---------------------------------------------------------------------------------
if (-not $SkipAudit) {
    Write-Step "Политика аудита"
    # auditpol принимает только локализованные имена - GUID одинаковы в любой локали.
    $enable = [ordered]@{
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation (4688)'
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon (4624/4625/4648)'
        '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff'
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout (4740)'
        '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon (4672)'
        '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation (4776)'
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management (4720/4726)'
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management (4728/4732)'
        '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Audit Policy Change (4719)'
        '{0CCE9211-69AE-11D9-BED3-505054503030}' = 'Security System Extension (4697)'
        '{0CCE9227-69AE-11D9-BED3-505054503030}' = 'Other Object Access Events (4698)'
    }
    # Шум без правил (замер на стенде): завершение процесса и использование конфиденциальных прав.
    $disable = [ordered]@{
        '{0CCE922C-69AE-11D9-BED3-505054503030}' = 'Process Termination (4689)'
        '{0CCE9228-69AE-11D9-BED3-505054503030}' = 'Sensitive Privilege Use (4673/4674)'
    }
    foreach ($g in $enable.Keys) {
        Invoke-Native auditpol.exe @('/set', "/subcategory:$g", '/success:enable', '/failure:enable') | Out-Null
    }
    foreach ($g in $disable.Keys) {
        Invoke-Native auditpol.exe @('/set', "/subcategory:$g", '/success:disable', '/failure:disable') | Out-Null
    }
    Write-Ok "$($enable.Count) подкатегорий включено, $($disable.Count) выключено"

    $reg = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging', 'EnableModuleLogging', 1)
    )
    foreach ($r in $reg) {
        New-Item -Path $r[0] -Force | Out-Null
        New-ItemProperty -Path $r[0] -Name $r[1] -Value $r[2] -PropertyType DWord -Force | Out-Null
    }
    $mn = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    New-Item -Path $mn -Force | Out-Null
    New-ItemProperty -Path $mn -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    Write-Ok "командная строка в 4688, ScriptBlock/Module logging"

    $sizes = @{ 'Security' = 209715200; 'Microsoft-Windows-PowerShell/Operational' = 104857600; 'System' = 52428800 }
    foreach ($log in $sizes.Keys) { Invoke-Native wevtutil.exe @('sl', $log, "/ms:$($sizes[$log])") | Out-Null }
    Write-Ok "размеры журналов"
}

# --- 3. Sysmon --------------------------------------------------------------------------------
if (-not $SkipSysmon) {
    Write-Step "Sysmon"
    New-Item -ItemType Directory -Force $SysmonDir | Out-Null
    $sysmonCfg = Join-Path $SysmonDir 'sysmonconfig.xml'
    if ($EmbeddedSysmonConfigGzB64) {
        $gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String($EmbeddedSysmonConfigGzB64))), [IO.Compression.CompressionMode]::Decompress)
        $fs = [IO.File]::Create($sysmonCfg); try { $gz.CopyTo($fs) } finally { $fs.Dispose(); $gz.Dispose() }
    } else {
        $candidates = @($SysmonConfigPath, (Join-Path $PSScriptRoot 'sysmonconfig.xml'),
                        (Join-Path $PSScriptRoot '..\..\artifacts\content\telemetry\sysmonconfig.xml')) | Where-Object { $_ }
        $src = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $src) { throw "Не найден sysmonconfig.xml (укажи -SysmonConfigPath или -SkipSysmon)" }
        Copy-Item $src $sysmonCfg -Force
    }

    $zip = Join-Path $TempDir 'Sysmon.zip'
    Get-Download 'https://download.sysinternals.com/files/Sysmon.zip' $zip
    Expand-Archive $zip -DestinationPath $TempDir -Force
    $newExe = Join-Path $TempDir 'Sysmon64.exe'
    $sig = Get-AuthenticodeSignature $newExe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Подпись Sysmon64.exe не прошла проверку: $($sig.Status) $($sig.SignerCertificate.Subject)"
    }

    $installedExe = Join-Path $env:windir 'Sysmon64.exe'
    if ((Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) -and (Test-Path $installedExe)) {
        # Уже стоит (в т.ч. поставлен вручную по старому ранбуку) - только новый конфиг, и тем же
        # бинарником, что установлен: -c от другой версии Sysmon может отказаться работать с драйвером.
        Invoke-Native $installedExe @('-accepteula', '-c', $sysmonCfg) | Out-Null
        Write-Ok "конфиг обновлён (обновить сам Sysmon: Sysmon64.exe -u, затем повторный запуск скрипта)"
    } else {
        # -i копирует бинарник в %windir% и регистрирует службу и драйвер.
        Invoke-Native $newExe @('-accepteula', '-i', $sysmonCfg) | Out-Null
        Write-Ok "установлен"
    }
    Invoke-Native wevtutil.exe @('sl', 'Microsoft-Windows-Sysmon/Operational', '/ms:209715200') | Out-Null
}

# --- 4. Vector --------------------------------------------------------------------------------
Write-Step "Агент Vector $VectorVersion"
$zip = Join-Path $TempDir "vector-$VectorVersion.zip"
Get-Download "https://packages.timber.io/vector/$VectorVersion/vector-$VectorVersion-x86_64-pc-windows-msvc.zip" $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($hash -ne $VectorSha256.ToUpperInvariant()) {
    throw "sha256 архива Vector не совпал: $hash (ожидался $VectorSha256). Для другой версии передай -VectorSha256."
}
$unpacked = Join-Path $TempDir "vector-$VectorVersion"
if (Test-Path $unpacked) { Remove-Item $unpacked -Recurse -Force }
Expand-Archive $zip -DestinationPath $unpacked -Force
Write-Ok "загружен, sha256 совпал"

Remove-AgentService
if (Test-Path $VectorDir) { Remove-Item $VectorDir -Recurse -Force }
New-Item -ItemType Directory -Force $VectorDir | Out-Null
Copy-Item (Join-Path $unpacked '*') $VectorDir -Recurse -Force
$VectorExe = Join-Path $VectorDir 'bin\vector.exe'

foreach ($d in @($StateDir, $DataDir, $LogDir)) { New-Item -ItemType Directory -Force $d | Out-Null }
Set-PrivateAcl $StateDir

if ($EmbeddedVectorToml) { $template = $EmbeddedVectorToml }
else { $template = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'vector.toml')) }
# Прямые слэши - в TOML-строке обратный слэш был бы escape-последовательностью.
$config = $template.Replace('__DATA_DIR__', $DataDir.Replace('\', '/')).
                   Replace('__LOG_DIR__', $LogDir.Replace('\', '/')).
                   Replace('__SIEM_URL__', $SiemUrl).
                   Replace('__TOKEN__', $Token)
[IO.File]::WriteAllText($ConfigPath, $config, (New-Object Text.UTF8Encoding $false))
Invoke-Native $VectorExe @('validate', '--no-environment', $ConfigPath) | Out-Null
Write-Ok "конфиг $ConfigPath прошёл validate"

Invoke-Native $VectorExe @('service', 'install', '--name', $ServiceName, '--display-name', 'soc_agent log forwarder (Vector)', '--config-toml', $ConfigPath) | Out-Null
Invoke-Native sc.exe @('config', $ServiceName, 'start=', 'auto') | Out-Null
Invoke-Native sc.exe @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/60000') | Out-Null
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
Write-Ok "служба $ServiceName запущена (логи агента: $LogDir)"

Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# --- 5. Самопроверка --------------------------------------------------------------------------
if (-not $SkipSelfTest) {
    Write-Step "Самопроверка доставки"
    $marker = 'socagent-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    Start-Process -FilePath cmd.exe -ArgumentList "/c echo $marker" -WindowStyle Hidden -Wait
    $query = [uri]::EscapeDataString("CommandLine contains `"$marker`"")
    $url = "$SiemUrl/events?source_batch=$([uri]::EscapeDataString($SourceName))&query=$query&limit=5"
    $deadline = (Get-Date).AddSeconds(90)
    $found = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        try { $r = Invoke-RestMethod -Uri $url -TimeoutSec 10 } catch { continue }
        if ($r.total -gt 0) { $found = $true; break }
    }
    if ($found) { Write-Ok "событие маркерного процесса доехало до SIEM ($($r.total) шт.: Sysmon 1 и/или 4688)" }
    else { Write-Warn2 "за 90 с событие '$marker' в SIEM не появилось - смотри $LogDir и вкладку «Источник данных»" }
}

Write-Host ""
Write-Host "Готово. Хост подключён к $SiemUrl как источник '$SourceName'." -ForegroundColor Green
