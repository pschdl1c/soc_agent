"""
Потоковый ingest для прода: события с форвардеров (Windows/Unix хосты) прилетают по HTTP
непрерывно, а прогонять их через Zircolite по одному нельзя - фиксированный оверхед движка
(создание ZircoliteCore + прогон КАЖДОГО скомпилированного правила отдельным SQL-запросом)
одинаков для 1 и для 1000 событий.

Поэтому здесь micro-batching: HTTP-обработчик только кладёт события в очередь и мгновенно
отвечает; фоновый поток копит их и флашит батчем по правилу «N событий ИЛИ T секунд - что
раньше». Так один прогон Zircolite амортизируется на сотни событий, а задержка ограничена
сверху flush_interval-ом.

Важно: флаш отдаёт весь накопленный буфер process_fn ОДНИМ вызовом, БЕЗ группировки по
источнику - до этого здесь была группировка по source_label с отдельным вызовом process_fn
на каждый источник, и это убивало ровно ту амортизацию, ради которой затевался батчинг: N
источников в одном окне флаша означало N последовательных прогонов движка (по ~0.25с
фиксированного оверхеда КАЖДЫЙ) на одном фоновом потоке, вместо одного прогона на всех.
Разбивка по источникам (для тегов source_batch в БД) теперь делается ПОСЛЕ прогона движка,
дёшево, на уровне main.py/app.normalize (см. INGEST_SOURCE_FIELD в app/fields.py).

Модуль намеренно не знает про engine/store - главный код передаёт колбэк process_fn,
который обрабатывает весь накопленный буфер (событие, source_label) сразу (см. app/main.py).
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable

from app import config

# Дефолты флаш-политики (переопределяются через SIEM_INGEST_BATCH_SIZE/SIEM_INGEST_FLUSH_INTERVAL
# в окружении или .env, см. app/config.py).
DEFAULT_BATCH_SIZE = config.INGEST_BATCH_SIZE
DEFAULT_FLUSH_INTERVAL = config.INGEST_FLUSH_INTERVAL

# Тип колбэка обработки целого флаша: список (событие, source_label) -> None. Группировка по
# источнику - забота process_fn/store, не этого модуля (см. докстринг выше).
ProcessFn = Callable[[list[tuple[dict[str, Any], str]]], None]

# Сигнал остановки воркера, кладётся в очередь при stop().
_SENTINEL = object()


class IngestQueueFull(RuntimeError):
    """Очередь ingest переполнена - принято `queued` из `total` событий запроса, остальные
    отклонены БЕЗ ожидания места (HTTP-обработчик /ingest/stream не должен висеть на сокете).
    app/main.py транслирует в HTTP 503 - форвардер повторяет запрос позже. Учитывать: `queued`
    событий этого запроса уже приняты, полный ретрай батча форвардером даст по ним дубли
    (event-level дедупа в store нет) - это осознанный компромисс для edge-случая перегрузки."""

    def __init__(self, queued: int, total: int) -> None:
        self.queued = queued
        self.total = total
        super().__init__(
            f"принято {queued} из {total} событий, остальные отклонены (очередь заполнена)"
        )


class IngestWorker:
    def __init__(
        self,
        process_fn: ProcessFn,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        max_queue: int = 100_000,
    ) -> None:
        self._process_fn = process_fn
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._queue: "queue.Queue[Any]" = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._running = False

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="ingest-worker", daemon=True)
        self._thread.start()
        print(f"[ingest] воркер запущен (batch_size={self._batch_size}, flush_interval={self._flush_interval}s)")

    def stop(self, timeout: float = 10.0) -> None:
        """Останавливает воркер и даёт ему дренировать остаток очереди."""
        if not self._running:
            return
        self._running = False
        self._queue.put(_SENTINEL)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        print("[ingest] воркер остановлен")

    def health(self) -> dict[str, Any]:
        """Проверка для /health: если фоновый поток умер (необработанное исключение внутри
        _run - сама _flush ошибки батчей глотает, но баг в самом цикле воркера всё-таки
        возможен), очередь продолжит расти, а форвардеры продолжат получать 202 Accepted,
        не подозревая, что события никто не обрабатывает - поэтому worker_alive это статус,
        а не просто информационное поле."""
        worker_alive = self._thread.is_alive() if self._thread else False
        return {
            "status": "ok" if (self._running and worker_alive) else "error",
            "worker_alive": worker_alive,
            "queue_size": self._queue.qsize(),
            "queue_max": self._queue.maxsize,
            "batch_size": self._batch_size,
            "flush_interval": self._flush_interval,
        }

    # ------------------------------------------------------------------ producer

    def enqueue(self, events: list[dict[str, Any]], source_label: str) -> int:
        """Ставит события в очередь БЕЗ блокировки (put_nowait) и возвращает число принятых.

        Раньше здесь был блокирующий put() без таймаута: при полной очереди (max_queue)
        HTTP-обработчик /ingest/stream зависал до освобождения места вместо быстрого ответа,
        а заявленная в main.py ветка "503 при переполнении" была недостижима (put никогда не
        бросал queue.Full). Теперь:
          - воркер не запущен (очередь никто не дренирует) -> RuntimeError;
          - очередь заполнилась по ходу -> IngestQueueFull с числом реально принятых событий.
        Обе транслируются в HTTP 503 в app/main.py.
        """
        if not self._running:
            raise RuntimeError("воркер ingest не запущен")
        queued = 0
        for event in events:
            try:
                self._queue.put_nowait((event, source_label))
            except queue.Full:
                raise IngestQueueFull(queued, len(events)) from None
            queued += 1
        return queued

    # ------------------------------------------------------------------ consumer

    def _run(self) -> None:
        # Буфер копится между флашами; группируем по источнику уже на флаше.
        buffer: list[tuple[dict[str, Any], str]] = []
        buffer_started = 0.0  # monotonic-время, когда в пустой буфер попало первое событие

        while True:
            # Пустой буфер - блокируемся на очереди без таймаута (никакого busy-spin, GIL свободен).
            # Есть накопленное - ждём только до дедлайна флаша, чтобы уложиться в flush_interval.
            if buffer:
                timeout: float | None = max(0.0, self._flush_interval - (time.monotonic() - buffer_started))
            else:
                timeout = None
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = None

            stop_now = False
            if item is _SENTINEL:
                stop_now = True
            elif item is not None:
                if not buffer:
                    buffer_started = time.monotonic()
                buffer.append(item)

            size_trigger = len(buffer) >= self._batch_size
            time_trigger = buffer and (time.monotonic() - buffer_started) >= self._flush_interval

            if buffer and (size_trigger or time_trigger or stop_now):
                self._flush(buffer)
                buffer = []

            if stop_now:
                # Дренируем всё, что осталось в очереди после сигнала остановки.
                remaining: list[tuple[dict[str, Any], str]] = []
                while True:
                    try:
                        leftover = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if leftover is not _SENTINEL:
                        remaining.append(leftover)
                if remaining:
                    self._flush(remaining)
                return

    def _flush(self, buffer: list[tuple[dict[str, Any], str]]) -> None:
        # ОДИН прогон движка на весь буфер, независимо от того, сколько разных source_label
        # в нём намешано - см. докстринг модуля про амортизацию оверхеда движка.
        try:
            self._process_fn(buffer)
        except Exception as exc:  # noqa: BLE001 - воркер не должен падать из-за одного битого батча
            sources = len({label for _, label in buffer})
            print(f"[ingest] ошибка обработки батча ({len(buffer)} событий, {sources} источников): {exc}")
