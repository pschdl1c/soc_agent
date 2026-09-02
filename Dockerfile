# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.12-slim

# =============================================================================
# builder — venv с зависимостями + клон Zircolite + собранная база знаний MITRE.
# Порядок слоёв = от самого стабильного к самому изменчивому, чтобы правка кода
# в app/ не инвалидировала ни установку зависимостей, ни клон Zircolite, ни kb.db.
# =============================================================================
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "${VIRTUAL_ENV}"

WORKDIR /app

# --- Зависимости: ключ кэша слоя — ТОЛЬКО pyproject.toml ----------------------
# pyproject.toml — единственный манифест проекта; список сторонних пакетов берём
# из [project].dependencies через stdlib tomllib и ставим ИХ (не сам пакет app —
# он не устанавливается, рантайм импортирует app из рабочей директории, как и в
# исходном образе). Правки в app/ этот слой не трогают. Кэш скачанных wheel'ов
# живёт на cache-mount (вне слоёв образа): при бампе одной зависимости заново
# качается только она, при неизменном pyproject слой берётся из кэша целиком.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip <<'SH'
set -eu
python - <<'PY' > /tmp/requirements.txt
import tomllib
with open("pyproject.toml", "rb") as fh:
    print("\n".join(tomllib.load(fh)["project"]["dependencies"]))
PY
pip install -r /tmp/requirements.txt
SH

# --- Zircolite — движок Sigma-детекта, подключается как БИБЛИОТЕКА из ./Zircolite
# (не pip-пакет, см. app/engine.py и CLAUDE.md §2). Тег закреплён — воспроизводимая
# сборка. Слой зависит только от ARG ZIRCOLITE_REF.
ARG ZIRCOLITE_REF=v3.7.6
RUN git clone --depth 1 --branch "${ZIRCOLITE_REF}" \
        https://github.com/wagga40/Zircolite.git /app/Zircolite \
    && rm -rf /app/Zircolite/.git

# --- База знаний MITRE ATT&CK -> компактный read-only kb.db (см. app/kb.py,
# scripts/build_kb.py). Собирается здесь и вшивается в образ; volume'ом НЕ
# монтируется — обновление базы = пересборка образа. Слой зависит от build_kb.py
# и ARG'ов версии, НЕ от кода app/ (скрипт автономен: stdlib + requests). Для
# полной воспроизводимости закрепи ATTACK_STIX_REF + ATTACK_STIX_VERSION.
ARG ATTACK_STIX_REF=master
ARG ATTACK_STIX_VERSION=
COPY scripts/build_kb.py ./scripts/build_kb.py
RUN python scripts/build_kb.py --out /app/kb/kb.db \
        --ref "${ATTACK_STIX_REF}" --attack-version "${ATTACK_STIX_VERSION}"

# =============================================================================
# runtime — только venv + артефакты сборки + код, без git/build-инструментов.
# =============================================================================
FROM python:${PYTHON_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

# Крупные, стабильные между пересборками артефакты — отдельными слоями с --link
# (content-addressable: слой переиспользуется, даже если предыдущие изменились;
# копии идут параллельно). Без --chown: с --link имя пользователя не резолвится
# (слой строится в изоляции, /etc/passwd не виден), а app-владелец этим путям и
# не нужен — рантайм только читает/импортирует/исполняет их, файлы и так
# world-readable. Пишет app лишь в /app, /app/db, /app/data/* — их chown ниже.
COPY --link --from=builder /opt/venv /opt/venv
COPY --link --from=builder /app/Zircolite /app/Zircolite
COPY --link --from=builder /app/kb /app/kb

# Код — последним: правки здесь не трогают слои выше.
COPY --link app/ ./app/

# Runtime-каталоги под volume/bind-mount (см. docker-compose.yml). Создаём заранее:
# sqlite3.connect (app/store.py) и UPLOADS_DIR.mkdir() (app/main.py) родительскую
# директорию сами не создают. /app/kb уже пришёл из builder — volume ему не нужен.
RUN mkdir -p /app/db /app/data/uploads /app/data/custom_rulesets /app/data/value_lists \
    && chown app:app /app /app/db /app/data /app/data/*

USER app

EXPOSE 8000

# /health — реальная проверка БД/Zircolite-ruleset/очереди ingest (app/main.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
