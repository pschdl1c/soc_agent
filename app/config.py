"""
Конфигурация приложения - читается из переменных окружения (опционально из файла `.env`
в корне проекта, см. `.env.example`). Явно выставленная переменная окружения имеет приоритет
над значением из `.env` (поведение `load_dotenv` по умолчанию).
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DB_PATH = os.getenv("SIEM_DB_PATH", str(BASE_DIR / "siem.db"))
ZIRCOLITE_CONFIG_PATH = os.getenv(
    "SIEM_ZIRCOLITE_CONFIG_PATH", str(BASE_DIR / "Zircolite" / "config" / "config.yaml")
)
DEFAULT_RULESET_PATH = os.getenv(
    "SIEM_DEFAULT_RULESET_PATH", str(BASE_DIR / "Zircolite" / "rules" / "rules_windows_merged.json")
)
UPLOADS_DIR = Path(os.getenv("SIEM_UPLOADS_DIR", str(BASE_DIR / "data" / "uploads")))

# База знаний MITRE ATT&CK (read-only SQLite, см. app/kb.py и scripts/build_kb.py). Собирается
# на этапе docker build и вшивается в образ - НЕ монтируется как volume. Локально файла может
# не быть вовсе (KB тогда деградирует до "недоступна", алерты матчатся по сырым тегам).
KB_DB_PATH = os.getenv("SIEM_KB_DB_PATH", str(BASE_DIR / "kb" / "kb.db"))

HOST = os.getenv("SIEM_HOST", "127.0.0.1")
PORT = int(os.getenv("SIEM_PORT", "8000"))

INGEST_BATCH_SIZE = int(os.getenv("SIEM_INGEST_BATCH_SIZE", "500"))
INGEST_FLUSH_INTERVAL = float(os.getenv("SIEM_INGEST_FLUSH_INTERVAL", "5.0"))

# Ретеншн events (app/store.py:delete_events_older_than, вызывается фоново из IngestWorker,
# см. app/main.py:_run_retention) - сколько дней хранить сырые события. 0 - выключено (события
# не удаляются автоматически). alerts ретеншн не подпадает - другой жизненный цикл, см. CLAUDE.md.
EVENTS_RETENTION_DAYS = int(os.getenv("SIEM_EVENTS_RETENTION_DAYS", "14"))
