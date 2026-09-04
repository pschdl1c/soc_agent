r"""
Бенчмарк масштабируемости коррелятора (app/detection/correlation.py, app/store.py) - прямая
проверка требования "скорость коррелятора не зависит от размера БД" (см. CLAUDE.md/
docs/spec/correlation.md/план Этапа A). Только stdlib + app.store - без новых зависимостей,
как и остальные скрипты в scripts/ (не часть приложения, ручной запуск).

Что делает:
  1. Наполняет ВРЕМЕННУЮ БД (tempfile, удаляется после прогона) таблицу rule_hits до заданных
     размеров (по умолчанию 10^5 / 10^6 / 10^7 строк) синтетическими данными: почти все строки
     - "backlog" (старая история, размазанная ЗА ПРЕДЕЛАМИ окна корреляции, о котором пойдёт
     запрос), и ФИКСИРОВАННОЕ число строк (--window-hits, по умолчанию 50) - ВНУТРИ окна
     конкретного (rule_title, group-by-ключ), которое бенчмарк потом запрашивает. `events` НЕ
     наполняется - счётный путь коррелятора (store.evaluate_correlation_windows/
     evaluate_correlation_window) читает ИСКЛЮЧИТЕЛЬНО rule_hits.group_json, без JOIN к events
     (это и есть предмет проверки - см. docs/spec/correlation.md); наполнение events ничего бы
     не добавило к результату, но радикально замедлило бы сам бенчмарк.
  2. Замеряет store.evaluate_correlation_windows (фаза 1 двухфазного счёта, тот самый путь,
     что app/detection/correlation.py:_evaluate_correlation_rule зовёт на каждый flush) на
     ОДИНАКОВОЙ нагрузке (одно и то же окно, одна и та же плотность внутри него) для каждого
     размера БД.
  3. Печатает время на каждом размере и во сколько раз оно выросло между шагами - критерий
     приёмки: рост НЕ пропорционален росту размера БД (десятикратный рост БД -> единицы
     процентов роста времени, не десятикратный). Резкий линейный рост значит где-то остался
     скан всей таблицы на счётном пути - разбирайся, не полагайся на "и так сойдёт".
  4. Отдельно - замер зависимости времени от ПЛОТНОСТИ окна (--density-levels) при
     ФИКСИРОВАННОМ размере БД (последнем/самом крупном из --sizes) - здесь линейный рост
     ОЖИДАЕМ и НОРМАЛЕН (O(H), H - число попаданий в окне), это не баг.

Как пользоваться:
    python scripts/bench_correlation.py
    python scripts/bench_correlation.py --sizes 100000 1000000 10000000
    python scripts/bench_correlation.py --sizes 100000 1000000 --window-hits 200 --repeat 5

Наполнение идёт напрямую через store.insert_correlation_hits чанками (--chunk, по умолчанию
200000 строк) - генератор, не список, чтобы память не росла вместе с N.
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.store import Store  # noqa: E402

RULE_TITLE = "Bench Failed Auth"
GROUP_FIELD = "IpAddress"
WINDOW_KEY_VALUE = "10.0.0.1"
BACKLOG_KEY_VALUE = "10.0.0.99"  # намеренно другой IP - двойная защита от false positive в самом бенчмарке
TIMESPAN_SECONDS = 300  # 5m - как у windows_bruteforce.yml


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _group_json(value: str) -> str:
    return '{"' + GROUP_FIELD + '": "' + value + '"}'


def _generate_rows(
    total_rows: int, window_hits: int, source_batch: str, window_start: datetime,
) -> Iterator[tuple]:
    """Генератор (event_id, rule_title, source_batch, event_time, group_json) - window_hits
    строк ВНУТРИ окна [window_start, window_start+TIMESPAN_SECONDS], остальные - backlog
    СТРОГО ДО window_start (шаг 1с назад), с ДРУГИМ ключом group-by, чтобы никогда не попасть
    в счёт даже случайно. window_start вычисляется ОДИН раз в populate() и передаётся сюда -
    иначе повторный datetime.now() дал бы окно на несколько микросекунд уже другое."""
    for i in range(window_hits):
        ts = window_start + timedelta(seconds=(TIMESPAN_SECONDS * i / max(window_hits, 1)))
        yield (uuid4().hex, RULE_TITLE, source_batch, ts.isoformat(), _group_json(WINDOW_KEY_VALUE))

    backlog_rows = max(total_rows - window_hits, 0)
    for i in range(backlog_rows):
        ts = window_start - timedelta(seconds=i + 1)
        yield (uuid4().hex, RULE_TITLE, source_batch, ts.isoformat(), _group_json(BACKLOG_KEY_VALUE))


def populate(store: Store, total_rows: int, window_hits: int, source_batch: str, chunk: int) -> tuple[str, str]:
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(seconds=TIMESPAN_SECONDS)

    rows = _generate_rows(total_rows, window_hits, source_batch, window_start)
    buf: list[tuple] = []
    inserted = 0
    for row in rows:
        buf.append(row)
        if len(buf) >= chunk:
            store.insert_correlation_hits(buf)
            inserted += len(buf)
            buf = []
            print(f"\r  наполнение: {inserted}/{total_rows}", end="", flush=True)
    if buf:
        store.insert_correlation_hits(buf)
        inserted += len(buf)
    print(f"\r  наполнение: {inserted}/{total_rows} - готово" + " " * 10)

    return window_start.isoformat(), window_end.isoformat()


def bench_query(store: Store, time_from: str, time_to: str, repeat: int) -> float:
    """Среднее время одного вызова evaluate_correlation_windows (фаза 1) по repeat повторам."""
    durations = []
    result = {}
    for _ in range(repeat):
        t0 = time.perf_counter()
        result = store.evaluate_correlation_windows(
            rule_titles=[RULE_TITLE], source_batch="bench",
            time_from=time_from, time_to=time_to,
            group_by=[GROUP_FIELD], mode="events",
        )
        durations.append(time.perf_counter() - t0)
    assert result.get((WINDOW_KEY_VALUE,)) is not None, "бенчмарк сломан - окно не нашло свои же данные"
    assert (BACKLOG_KEY_VALUE,) not in result, "бенчмарк сломан - backlog просочился в окно"
    return sum(durations) / len(durations)


def run_size_sweep(sizes: list[int], window_hits: int, repeat: int, chunk: int) -> None:
    print(f"=== Масштабируемость по размеру rule_hits (окно фиксировано: {window_hits} попаданий) ===")
    print(f"{'rows':>12} | {'avg ms':>10} | {'x к предыдущему':>16}")
    prev_time = None
    for n in sizes:
        import tempfile

        db_path = Path(tempfile.mkdtemp()) / "bench.db"
        store = Store(db_path=str(db_path))
        try:
            print(f"[{n} строк]")
            time_from, time_to = populate(store, n, window_hits, "bench", chunk)
            avg = bench_query(store, time_from, time_to, repeat) * 1000
        finally:
            store.close()
        ratio = f"{avg / prev_time:.2f}x" if prev_time else "-"
        print(f"{n:>12} | {avg:>10.3f} | {ratio:>16}")
        prev_time = avg


def run_density_sweep(fixed_size: int, density_levels: list[int], repeat: int, chunk: int) -> None:
    print(f"\n=== Зависимость от плотности окна при фиксированном размере БД ({fixed_size} строк) ===")
    print("Линейный рост здесь ОЖИДАЕМ (O(H), H = попаданий в окне) - это не регрессия.")
    print(f"{'window_hits':>12} | {'avg ms':>10} | {'x к предыдущему':>16}")
    prev_time = None
    for h in density_levels:
        import tempfile

        db_path = Path(tempfile.mkdtemp()) / "bench.db"
        store = Store(db_path=str(db_path))
        try:
            print(f"[{h} попаданий в окне]")
            time_from, time_to = populate(store, fixed_size, h, "bench", chunk)
            avg = bench_query(store, time_from, time_to, repeat) * 1000
        finally:
            store.close()
        ratio = f"{avg / prev_time:.2f}x" if prev_time else "-"
        print(f"{h:>12} | {avg:>10.3f} | {ratio:>16}")
        prev_time = avg


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", type=int, nargs="+", default=[100_000, 1_000_000, 10_000_000])
    parser.add_argument("--window-hits", type=int, default=50)
    parser.add_argument("--density-levels", type=int, nargs="+", default=[10, 50, 200, 1000])
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--chunk", type=int, default=200_000)
    parser.add_argument("--skip-density", action="store_true", help="только замер по размеру БД")
    args = parser.parse_args()

    run_size_sweep(sorted(args.sizes), args.window_hits, args.repeat, args.chunk)
    if not args.skip_density:
        run_density_sweep(max(args.sizes), sorted(args.density_levels), args.repeat, args.chunk)


if __name__ == "__main__":
    main()
