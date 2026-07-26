# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.12-slim

# ---- builder: ставит pip-зависимости в изолированный venv и клонирует Zircolite ----
# Zircolite - движок Sigma-детекта, импортируется как БИБЛИОТЕКА из ./Zircolite (не pip-пакет,
# см. app/engine.py и CLAUDE.md §2) - в образе его быть не может "само по себе", клонируем явно.
FROM python:${PYTHON_VERSION} AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Тег закреплён на версии, реально используемой в разработке (см. `git -C Zircolite describe
# --tags`) - воспроизводимая сборка, не ловим втихую breaking changes апстрима на каждый build.
ARG ZIRCOLITE_REF=v3.7.6
RUN git clone --depth 1 --branch "${ZIRCOLITE_REF}" https://github.com/wagga40/Zircolite.git /app/Zircolite \
    && rm -rf /app/Zircolite/.git

# ---- runtime: только venv + код, без git/build-инструментов ----
FROM python:${PYTHON_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/Zircolite /app/Zircolite
COPY app/ app/

# Runtime-каталоги - см. docker-compose.yml, монтируются как volume/bind-mount поверх этих же
# путей (/app/data/* - тот же относительный "data/..." путь, что использует локальный запуск
# без Docker, см. app/config.py:UPLOADS_DIR и app/rules_catalog.py:CUSTOM_ROOT; /app/db -
# отдельно, именованный volume для siem.db, см. README §Docker). Создаём заранее: sqlite3.connect
# (app/store.py) и UPLOADS_DIR.mkdir() (app/main.py) не создают родительскую директорию сами -
# без этого первый запуск без volume падал бы на несуществующем пути.
RUN mkdir -p /app/db /app/data/uploads /app/data/custom_rulesets && chown -R app:app /app

USER app

EXPOSE 8000

# /health - реальная проверка БД/Zircolite-ruleset/очереди ingest (app/main.py), не заглушка.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
