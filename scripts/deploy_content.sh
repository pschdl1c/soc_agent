#!/bin/sh
# Деплой детект-контента (artifacts/content) в SIEM без Python на хосте.
#
# Тонкая обёртка над scripts/deploy_content.py: запускает его в одноразовом контейнере из уже собранного
# образа soc_agent (там есть Python и PyYAML), репозиторий монтируется только на чтение. Логика деплоя одна -
# в deploy_content.py, здесь только запуск. Нужен Docker и собранный образ (docker compose build).
#
#   ./scripts/deploy_content.sh --prune
#   SIEM_URL=http://localhost:8001 ./scripts/deploy_content.sh --domain auth
#   SOC_AGENT_IMAGE=soc_agent:latest - другой образ
#
# localhost / 127.0.0.1 в адресе подменяются на host.docker.internal - из контейнера это адрес хоста.
set -eu

url="${SIEM_URL:-http://localhost:8000}"
image="${SOC_AGENT_IMAGE:-soc_agent:latest}"

command -v docker >/dev/null 2>&1 || { echo "docker не найден в PATH" >&2; exit 1; }
docker image inspect "$image" >/dev/null 2>&1 || { echo "образ $image не найден - сначала docker compose build" >&2; exit 1; }

# Git Bash / MSYS на Windows: иначе /work превращается в C:/Program Files/Git/work, а путь репозитория
# нужен в виде D:/... (pwd -W). На Linux/macOS pwd -W нет - берётся обычный pwd.
export MSYS_NO_PATHCONV=1
root="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"
container_url="$(printf '%s' "$url" | sed -E 's#://(localhost|127\.0\.0\.1)([:/]|$)#://host.docker.internal\2#')"

exec docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -e PYTHONIOENCODING=utf-8 \
    -v "$root:/work:ro" \
    -w /work \
    --entrypoint python \
    "$image" \
    scripts/deploy_content.py "$container_url" "$@"
