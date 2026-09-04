"""
Тесты IngestWorker.enqueue (app/ingest_queue.py): постановка событий в очередь БЕЗ
блокировки, поведение при переполнении и при незапущенном воркере. Реальный фоновый
поток не поднимаем - enqueue не должен от него зависеть; _running выставляем вручную
(как conftest трогает engine._rulesets_cache).
"""
from __future__ import annotations

import pytest

from app.ingest_queue import IngestQueueFull, IngestWorker


def _noop(_batch: list) -> None:
    pass


def test_enqueue_returns_count_when_running():
    worker = IngestWorker(process_fn=_noop, max_queue=10)
    worker._running = True
    assert worker.enqueue([{"a": 1}, {"a": 2}], source_label="s") == 2


def test_enqueue_raises_when_worker_not_started():
    worker = IngestWorker(process_fn=_noop, max_queue=10)
    with pytest.raises(RuntimeError):
        worker.enqueue([{"a": 1}], source_label="s")


def test_enqueue_does_not_block_on_full_queue_and_reports_partial():
    worker = IngestWorker(process_fn=_noop, max_queue=3)
    worker._running = True

    with pytest.raises(IngestQueueFull) as exc_info:
        worker.enqueue([{"i": i} for i in range(5)], source_label="s")

    assert exc_info.value.queued == 3   # влезло ровно max_queue
    assert exc_info.value.total == 5
    assert worker._queue.qsize() == 3   # частично принятые события остаются в очереди


# ------------------------------------------------------------------ retention_fn (Этап A)


def test_retention_fn_called_periodically_even_when_buffer_is_idle():
    """Регрессия: без ветки таймаута под пустой буфер воркер блокировался бы на очереди БЕЗ
    таймаута (timeout=None), и retention_fn НИКОГДА не звался бы в периоды простоя ingest'а -
    см. app/store.py:delete_events_older_than и app/ingest_queue.py:_run."""
    import threading
    import time

    calls = []
    lock = threading.Lock()

    def _record():
        with lock:
            calls.append(1)

    worker = IngestWorker(process_fn=_noop, flush_interval=10.0, retention_fn=_record, retention_interval=0.05)
    worker.start()
    try:
        time.sleep(0.3)  # при retention_interval=0.05с должно успеть сработать несколько раз
    finally:
        worker.stop()

    with lock:
        assert len(calls) >= 2


def test_retention_error_does_not_crash_worker():
    import time

    def _bad_retention():
        raise RuntimeError("boom")

    worker = IngestWorker(process_fn=_noop, flush_interval=10.0, retention_fn=_bad_retention, retention_interval=0.05)
    worker.start()
    try:
        time.sleep(0.15)
        assert worker._thread.is_alive()
    finally:
        worker.stop()


def test_no_retention_fn_means_no_periodic_wakeup_branch():
    """Без retention_fn (дефолт) воркер должен оставаться жив и штатно флашить по таймеру -
    просто убеждаемся, что None-ветка не ломает обычную работу."""
    import time

    flushed = []

    def _process(batch):
        flushed.append(len(batch))

    worker = IngestWorker(process_fn=_process, batch_size=100, flush_interval=0.05)
    worker.start()
    try:
        worker.enqueue([{"a": 1}], source_label="s")
        time.sleep(0.2)
    finally:
        worker.stop()

    assert sum(flushed) == 1
