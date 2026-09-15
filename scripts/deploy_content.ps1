<#
.SYNOPSIS
    Деплой детект-контента (artifacts/content) в SIEM без Python на хосте.

.DESCRIPTION
    Тонкая обёртка над scripts/deploy_content.py: запускает его в одноразовом контейнере из уже собранного
    образа soc_agent (там есть Python и PyYAML), репозиторий монтируется только на чтение. Логика деплоя одна -
    в deploy_content.py, здесь только запуск. Нужен Docker и собранный образ (docker compose build).

    localhost / 127.0.0.1 в адресе подменяются на host.docker.internal - из контейнера это адрес хоста.

.EXAMPLE
    .\scripts\deploy_content.ps1 --prune
    .\scripts\deploy_content.ps1 -Url http://localhost:8001 --domain auth
    powershell -ExecutionPolicy Bypass -File scripts\deploy_content.ps1 --prune   # если запуск .ps1 запрещён политикой
#>
param(
    [string]$Url = "http://localhost:8000",
    [string]$Image = "soc_agent:latest",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$DeployArgs
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker не найден в PATH"
    exit 1
}
docker image inspect $Image *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "образ $Image не найден - сначала docker compose build"
    exit 1
}

$root = Split-Path -Parent $PSScriptRoot
$containerUrl = $Url -replace '://(localhost|127\.0\.0\.1)(?=[:/]|$)', '://host.docker.internal'

$dockerArgs = @(
    "run", "--rm",
    "--add-host=host.docker.internal:host-gateway",
    "-e", "PYTHONIOENCODING=utf-8",
    "-v", "${root}:/work:ro",
    "-w", "/work",
    "--entrypoint", "python",
    $Image,
    "scripts/deploy_content.py", $containerUrl
) + @($DeployArgs | Where-Object { $_ })

& docker @dockerArgs
exit $LASTEXITCODE
