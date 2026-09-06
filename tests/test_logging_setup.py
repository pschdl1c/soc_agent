"""
Тесты app/logging_setup.py.

Главное здесь - не формат строки лога, а то, что configure() переводит в UTF-8 ОБА
стандартных потока. Стоимость ошибки несимметрично велика: Zircolite рисует прогресс
компиляции правил через `rich` (спиннер `⠋`, U+280B) в stdout, и на cp1251-потоке
(Windows: перенаправление в файл, запуск службой) запись этого символа роняет конвертацию
правил внутри Zircolite - наружу это выходит как «правило не скомпилировалось» на заведомо
корректном правиле и как потеря целого флаша ingest.

Потоки подменяются ВНУТРИ тела теста, а не в фикстуре: pytest переустанавливает свой захват
sys.stdout/sys.stderr на границе фаз setup -> call, и подмена из фикстуры до тела теста не
доживает (ловили).
"""
from __future__ import annotations

import logging

import pytest

from app import logging_setup


class _FakeStream:
    """Поток, считающий вызовы reconfigure и умеющий писать (как ждёт StreamHandler)."""

    def __init__(self) -> None:
        self.reconfigured: list[dict] = []
        self.written: list[str] = []

    def reconfigure(self, **kwargs):
        self.reconfigured.append(kwargs)

    def write(self, text: str) -> int:
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        pass


@pytest.fixture
def clean_logger():
    """Снимает отметку «уже настроено» и возвращает хендлеры логгера как были."""
    logging_setup._reset()
    saved = logging.getLogger(logging_setup.LOGGER_NAME).handlers[:]
    yield
    logging.getLogger(logging_setup.LOGGER_NAME).handlers = saved
    logging_setup._reset()


def _patch_streams(monkeypatch) -> tuple[_FakeStream, _FakeStream]:
    out, err = _FakeStream(), _FakeStream()
    monkeypatch.setattr(logging_setup.sys, "stdout", out)
    monkeypatch.setattr(logging_setup.sys, "stderr", err)
    return out, err


UTF8 = {"encoding": "utf-8", "errors": "replace"}


def test_configure_forces_utf8_on_both_streams(clean_logger, monkeypatch):
    out, err = _patch_streams(monkeypatch)
    logging_setup.configure("INFO")

    # stderr - наши логи; stdout - вывод сторонних библиотек (прогресс-бар Zircolite)
    assert out.reconfigured == [UTF8]
    assert err.reconfigured == [UTF8]


def test_configure_is_idempotent(clean_logger, monkeypatch):
    out, _err = _patch_streams(monkeypatch)
    logger = logging_setup.configure("INFO")
    again = logging_setup.configure("DEBUG")

    assert again is logger
    assert len(out.reconfigured) == 1  # второй вызов ничего не переоткрывает
    assert len(logger.handlers) == 1
    assert logger.level == logging.INFO  # уровень первого вызова, не второго


def test_module_loggers_write_through_single_handler(clean_logger, monkeypatch):
    _out, err = _patch_streams(monkeypatch)
    logging_setup.configure("INFO")

    logging.getLogger("app.ingest_queue").info("ошибка обработки батча: %s", 42)

    line = "".join(err.written)
    assert "ошибка обработки батча: 42" in line
    assert "[app.ingest_queue]" in line
    assert "INFO" in line


def test_stream_without_reconfigure_is_used_as_is(clean_logger, monkeypatch):
    """Обёрнутый/подменённый поток без reconfigure не должен ронять настройку логгера."""

    class _Bare:
        def write(self, text):
            return len(text)

        def flush(self):
            pass

    monkeypatch.setattr(logging_setup.sys, "stdout", _Bare())
    monkeypatch.setattr(logging_setup.sys, "stderr", _Bare())

    logger = logging_setup.configure("INFO")
    assert logger.handlers  # настроился, без исключений
