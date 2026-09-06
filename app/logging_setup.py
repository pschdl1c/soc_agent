"""
Единая настройка логирования приложения (лист-модуль, импортирует только stdlib).

Зачем отдельный модуль вместо голых print(): на Windows print() пишет в кодировке КОНСОЛИ
(cp1251/cp866), и при редиректе вывода в файл (`uvicorn ... > server.log`) русские сообщения
превращаются в мусор - а именно на сообщении "[ingest] ошибка обработки флаша..." держится
диагностика потери событий. Здесь поток вывода принудительно переводится в UTF-8, а к каждой
строке добавляются время и уровень, которых у print() нет.

Логгеры получаются штатным logging.getLogger(__name__) в каждом модуле - имена начинаются с
"app.", поэтому хендлер вешается ОДИН раз на логгер "app" с propagate=False: так наш вывод не
дублируется хендлерами uvicorn и не зависит от того, настроил ли кто-то root-логгер.
"""
from __future__ import annotations

import contextlib
import logging
import sys

LOGGER_NAME = "app"
_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _force_utf8(stream):
    """Переводит поток в UTF-8 (errors="replace") и возвращает его. Поток без reconfigure
    (подменённый в тестах, обёрнутый) отдаётся как есть.

    errors="replace" принципиально: НИ ОДИН вывод не должен уметь уронить процесс из-за
    символа, который кодировка потока не переваривает."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")
    return stream


def configure(level: str | int = "INFO") -> logging.Logger:
    """Идемпотентно настраивает логгер приложения. Зовётся один раз из app/main.py на импорте.

    Переводит в UTF-8 ОБА стандартных потока, а не только тот, куда пишет наш хендлер:

    * stderr - собственно логи приложения;
    * stdout - вывод сторонних библиотек. Zircolite рисует прогресс компиляции правил через
      `rich` (спиннер `⠋`, U+280B). Если stdout в cp1251 (Windows: перенаправление в файл,
      запуск службой, обычная консоль), запись этого символа бросает UnicodeEncodeError ВНУТРИ
      конвертации правил - Zircolite ловит его как «Cannot convert» и отдаёт ПУСТОЙ рулсет.
      Наружу это выглядит как «Правило не скомпилировалось в SQL - проверь detection/logsource»
      на заведомо корректном правиле и как потеря ЦЕЛОГО флаша ingest (исключение прилетает в
      `IngestWorker._flush`). Один символ прогресс-бара обрушивал детект целиком."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if _configured:
        return logger
    _force_utf8(sys.stdout)
    handler = logging.StreamHandler(_force_utf8(sys.stderr))
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT))
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(level if isinstance(level, int) else str(level).upper())
    _configured = True
    return logger


def _reset() -> None:
    """Тест-хук: снять отметку «уже настроено», чтобы configure() отработал заново."""
    global _configured
    _configured = False
