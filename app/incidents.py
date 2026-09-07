"""
Фоновая обработка расследований инцидентов (таблица investigations).

Этап 4 - ЗАГЛУШКА: переводит расследование queued -> running -> done с placeholder-вердиктом
`needs-review`, без какого-либо анализа. Настоящий AI-агент (app/agent/, LangGraph +
OpenAI-совместимый провайдер) - Этап 5, он заменит ТЕЛО run_pending. Жизненный цикл статуса
(queued -> running -> done|error), формат строки investigations и точка вызова из фонового
потока IngestWorker (app/main.py: periodic_tasks) остаются теми же.

Запускается периодически тем же фоновым потоком, что и ретеншн events (см.
app/ingest_queue.py:IngestWorker), а не отдельным - LLM Этапа 5 будет медленным, синхронно на
создании инцидента его звать нельзя.
"""
from __future__ import annotations

from app import updates
from app.models import utcnow_naive
from app.store import Store

_STUB_RATIONALE = (
    "Автоматическое расследование не реализовано (Этап 4 - только каркас). "
    "Инцидент требует ручной проверки аналитиком."
)


def run_pending(store: Store, batch: int = 20) -> int:
    """Обрабатывает до batch расследований в статусе queued (FIFO). Возвращает число
    обработанных строк. Ошибка на одной строке не роняет проход - строка помечается error."""
    processed = 0
    for inv in store.list_pending_investigations(limit=batch):
        iid = inv["investigation_id"]
        try:
            store.update_investigation(iid, status="running", started_at=utcnow_naive().isoformat())
            store.update_investigation(
                iid,
                status="done",
                verdict="needs-review",
                rationale=_STUB_RATIONALE,
                confidence=None,
                steps=[{"step": "stub", "detail": "Заглушка Этапа 4, без анализа"}],
                finished_at=utcnow_naive().isoformat(),
            )
        except Exception as exc:  # noqa: BLE001 - джоба не должна падать из-за одной строки
            store.update_investigation(
                iid, status="error", error=str(exc), finished_at=utcnow_naive().isoformat()
            )
        processed += 1
    # Вердикт/статус расследования виден в списке инцидентов (колонка investigation_status) и в
    # карточке - для открытого UI это изменение списка, хотя новых инцидентов не появилось
    # (app/updates.py, created не трогаем).
    if processed:
        updates.bump("incidents")
    return processed
