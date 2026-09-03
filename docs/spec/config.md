# Конфигурация

**Модуль:** `app/config.py`
**Назначение:** единая точка чтения конфигурации из переменных окружения с необязательной
подгрузкой файла `.env` из корня проекта.

## Область ответственности

- Определение констант путей, хоста, порта и параметров micro-batch на уровне модуля.
- Загрузка `.env` при импорте (`python-dotenv`).
- Не выполняет валидацию значений, не создаёт директории, не хранит состояние.

## Загрузка `.env`

При импорте модуля выполняется `load_dotenv(BASE_DIR / ".env")`. Явно выставленная переменная
окружения имеет приоритет над значением из `.env` (поведение `load_dotenv` по умолчанию).
Отсутствие файла `.env` не является ошибкой.

`BASE_DIR = Path(__file__).resolve().parent.parent` — корень проекта (родитель каталога `app/`).

## Экспортируемые константы

| Константа | Переменная окружения | Тип | Значение по умолчанию |
|---|---|---|---|
| `BASE_DIR` | — | `Path` | родитель каталога `app/` |
| `DB_PATH` | `SIEM_DB_PATH` | `str` | `<BASE_DIR>/siem.db` |
| `ZIRCOLITE_CONFIG_PATH` | `SIEM_ZIRCOLITE_CONFIG_PATH` | `str` | `<BASE_DIR>/Zircolite/config/config.yaml` |
| `DEFAULT_RULESET_PATH` | `SIEM_DEFAULT_RULESET_PATH` | `str` | `<BASE_DIR>/Zircolite/rules/rules_windows_merged.json` |
| `UPLOADS_DIR` | `SIEM_UPLOADS_DIR` | `Path` | `<BASE_DIR>/data/uploads` |
| `KB_DB_PATH` | `SIEM_KB_DB_PATH` | `str` | `<BASE_DIR>/kb/kb.db` |
| `HOST` | `SIEM_HOST` | `str` | `127.0.0.1` |
| `PORT` | `SIEM_PORT` | `int` | `8000` |
| `INGEST_BATCH_SIZE` | `SIEM_INGEST_BATCH_SIZE` | `int` | `500` |
| `INGEST_FLUSH_INTERVAL` | `SIEM_INGEST_FLUSH_INTERVAL` | `float` | `5.0` |

## Приведение типов

- `PORT` → `int(os.getenv("SIEM_PORT", "8000"))`.
- `INGEST_BATCH_SIZE` → `int(...)`.
- `INGEST_FLUSH_INTERVAL` → `float(...)`.
- Нечисловое значение соответствующей переменной окружения вызывает `ValueError` при импорте модуля.

## Семантика путей

- `DB_PATH` — файл рабочей БД (`siem.db`); БД открывается в режиме WAL, рядом появляются
  `-wal` и `-shm`.
- `KB_DB_PATH` — read-only база знаний MITRE ATT&CK. Файл может отсутствовать; в этом случае
  зависимые компоненты деградируют без исключений.
- `UPLOADS_DIR` — каталог для файлов, загруженных через HTTP; создаётся вызывающим кодом
  (`app/main.py`), не этим модулем.
- `data/` — общий корень runtime-данных для локального запуска и Docker (в Docker — bind-mount
  или named volume на тот же путь).

## Зависимости

- Импортирует: `os`, `pathlib.Path`, `dotenv.load_dotenv`.
- Импортируется: `app/main.py`, `app/ingest_queue.py`, `app/kb.py` (`KB_DB_PATH`).
