# Технические спецификации

Строгие технические описания компонентов проекта `soc_agent`. Один файл — один компонент
(модуль или скрипт). Каждая спецификация самодостаточна: описывает интерфейс, формат данных,
поведение, инварианты и зависимости компонента без отсылок к другим документам.

## Карта компонентов

| Спецификация | Компонент | Ответственность |
|---|---|---|
| [`config.md`](config.md) | `app/config.py` | Конфигурация из окружения / `.env` |
| [`models.md`](models.md) | `app/models.py` | Pydantic-модели домена и запросов |
| [`fields.md`](fields.md) | `app/fields.py` | Кандидаты имён полей, маркер источника |
| [`storage.md`](storage.md) | `app/store.py` | SQLite-хранилище `siem.db`, схема, API `Store` |
| [`filter-language.md`](filter-language.md) | `app/filter_lang.py` | Мини-язык фильтра событий → SQL |
| [`detection-engine.md`](detection-engine.md) | `app/detection/engine.py` | Обёртка Zircolite, прогон батча |
| [`normalization.md`](normalization.md) | `app/detection/normalize.py` | Результат Zircolite → список `Alert` |
| [`correlation.md`](correlation.md) | `app/detection/correlation.py` | Стейтфул-корреляция `event_count` / `value_count` |
| [`rules-catalog.md`](rules-catalog.md) | `app/rules/rules_catalog.py` | Каталог Sigma-рулсетов и правил, компиляция |
| [`main-ruleset.md`](main-ruleset.md) | `app/rules/main_ruleset.py` | Состав «основного рулсета» |
| [`value-lists.md`](value-lists.md) | `app/rules/value_lists.py` | Именованные списки значений, `%name%` / `\|expand` |
| [`knowledge-base.md`](knowledge-base.md) | `app/kb.py` | Доступ на чтение к `kb.db` (MITRE ATT&CK) |
| [`kb-builder.md`](kb-builder.md) | `scripts/build_kb.py` | Сборка `kb.db` из STIX-бандла, схема `kb.db` |
| [`ingest-queue.md`](ingest-queue.md) | `app/ingest_queue.py` | Очередь потокового ingest, micro-batch flush |
| [`http-api.md`](http-api.md) | `app/main.py` | HTTP-эндпоинты, оркестрация батча, аутентификация ingest |

## Соглашения

- Сигнатуры функций приведены в форме Python 3.12.
- «Бросает» — исключения, выходящие за границу компонента; внутренние подавляемые не указываются.
- Пути к файлам БД и данных заданы относительно корня проекта; в Docker корень — `/app`.
- Формат HTTP-кодов: `2xx` — успех, `4xx` — ошибка запроса, `5xx` — не предусмотрено штатно.
