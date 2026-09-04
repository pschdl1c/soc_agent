# Очередь потокового ingest

**Модуль:** `app/ingest_queue.py`
**Назначение:** приём событий с форвардеров без блокировки HTTP-обработчика; накопление в
очереди и flush батчами по политике «N событий ИЛИ T секунд».

## Область ответственности

- Потокобезопасная очередь событий и фоновый поток-потребитель.
- Micro-batch flush одним вызовом колбэка `process_fn` на весь накопленный буфер.
- Статус для `/health`.
- Не знает про `engine`/`store`; обработка делегирована `process_fn`.

## Типы и константы

| Имя | Значение / тип |
|---|---|
| `ProcessFn` | `Callable[[list[tuple[dict, str]]], None]` |
| `DEFAULT_BATCH_SIZE` | `config.INGEST_BATCH_SIZE` (по умолчанию 500) |
| `DEFAULT_FLUSH_INTERVAL` | `config.INGEST_FLUSH_INTERVAL` (по умолчанию 5.0 с) |

## `IngestQueueFull(RuntimeError)`

Поднимается из `enqueue`, когда очередь заполнилась в процессе постановки.

| Атрибут | Смысл |
|---|---|
| `queued` | сколько событий запроса реально принято |
| `total` | сколько было в запросе |

Приняты `queued` событий; остальные отклонены без ожидания. Полный ретрай батча форвардером
даст дубли по уже принятым событиям (event-level дедупа нет).

## Класс `IngestWorker`

### `__init__(process_fn, batch_size=DEFAULT_BATCH_SIZE, flush_interval=DEFAULT_FLUSH_INTERVAL, max_queue=100_000, retention_fn=None, retention_interval=3600.0)`

Создаёт `queue.Queue(maxsize=max_queue)`; поток не запускается. `retention_fn` (Этап A
дорожной карты) — опциональный колбэк ретеншна `events` (`app/store.py:
delete_events_older_than`, см. `app/main.py:_run_retention`), зовётся ЭТИМ ЖЕ фоновым потоком
раз в `retention_interval` секунд — второго потока не заводится. `None` (дефолт, либо когда
`SIEM_EVENTS_RETENTION_DAYS<=0`) полностью выключает ветку — ни одного лишнего пробуждения
потока сверх обычного цикла флаша.

### `start() -> None`

Запускает поток-демон `ingest-worker`. Повторный вызов при уже запущенном воркере — no-op.

### `stop(timeout: float = 10.0) -> None`

Кладёт в очередь сигнал остановки, ждёт завершения потока до `timeout`. Перед выходом поток
дренирует остаток очереди и флашит его.

### `enqueue(events: list[dict], source_label: str) -> int`

Ставит `(event, source_label)` в очередь через `put_nowait`. Возвращает число принятых.

- Воркер не запущен → `RuntimeError`.
- Очередь заполнилась → `IngestQueueFull(queued, len(events))`.

### `health() -> dict`

```
{
  "status": "ok" | "error",   # "ok" только если _running и поток жив
  "worker_alive": bool,
  "queue_size": int,
  "queue_max": int,
  "batch_size": int,
  "flush_interval": float
}
```

## Цикл потребителя (`_run`)

- Пустой буфер, `retention_fn` не задан — блокирующее ожидание `queue.get()` без таймаута.
- Пустой буфер, `retention_fn` задан — ожидание до дедлайна следующей проверки ретеншна
  (`last_retention + retention_interval`) — без этой ветки ретеншн не сработал бы вовсе в
  периоды простоя ingest'а (вечная блокировка на очереди без таймаута, до `retention_fn` дело
  никогда бы не дошло).
- Непустой буфер — ожидание до дедлайна `buffer_started + flush_interval` (приоритет над
  веткой ретеншна — таймаут очереди берётся по буферу, если он не пуст).
- Триггеры flush: `len(buffer) >= batch_size` (size), прошло `>= flush_interval` от первого
  события буфера (time), получен сигнал остановки.
- Flush — один вызов `process_fn(buffer)` на весь буфер, независимо от числа разных
  `source_label` в нём; затем `buffer = []`.
- После обработки flush-триггеров, на каждой итерации: если `retention_fn` задан и прошло
  `>= retention_interval` с прошлой проверки — `_run_retention()`, обновление `last_retention`.
- Сигнал остановки: после финального flush очередь дренируется до конца, остаток флашится,
  поток завершается.

## Обработка ошибок flush (`_flush`) и ретеншна (`_run_retention`)

`process_fn(buffer)` в `try/except Exception` — исключение логируется (`print`), поток
не падает. Форвардер получает `202` независимо от исхода обработки батча. Аналогично
`retention_fn()` обёрнут в `_run_retention` (`try/except Exception`, логирование) — ошибка
ретеншна не должна ронять ingest.

## Инварианты

- Группировка событий по источнику выполняется вызывающим кодом (`app/main.py`) **после**
  прогона движка, не в этом модуле.
- Один flush = один прогон движка (амортизация фиксированного оверхеда Zircolite на батч).

## Зависимости

- Импортирует: `queue`, `threading`, `time`; `app/config.py`.
- Импортируется: `app/main.py` (`IngestWorker`, `IngestQueueFull`).
