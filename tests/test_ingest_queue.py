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
