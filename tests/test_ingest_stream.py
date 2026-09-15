"""
Тесты разбора тела /ingest/stream (app/main.py:_parse_stream_body) и защиты флаша от битой
записи в app/main.py:_process_events.

Регрессия, ради которой они написаны: одна не-объектная запись в NDJSON (голая строка, число,
вложенный массив) доезжала до _process_events, роняла там `{**event, ...}` с TypeError, а
ingest_queue._flush ловит исключение на ВЕСЬ буфер разом - вместе с битой записью молча
терялся весь флаш (до INGEST_BATCH_SIZE событий, в том числе от ДРУГИХ источников), при том
что форвардер уже получил 202 и повторять не станет.

app.main на импорте поднимает глобальные engine/store поверх РЕАЛЬНЫХ путей из app/config.py
(см. докстринг tests/conftest.py) - поэтому модуль импортируется здесь ЛЕНИВО, после подмены
SIEM_*-переменных на tmp_path и перезагрузки app.config.
"""
from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture(scope="module")
def main_module(tmp_path_factory):
    """app.main, поднятый поверх временных БД/uploads вместо реальных siem.db и data/uploads."""
    import os

    tmp = tmp_path_factory.mktemp("stream_main")
    saved = {k: os.environ.get(k) for k in ("SIEM_DB_PATH", "SIEM_UPLOADS_DIR")}
    os.environ["SIEM_DB_PATH"] = str(tmp / "test.db")
    os.environ["SIEM_UPLOADS_DIR"] = str(tmp / "uploads")

    from app import config

    importlib.reload(config)
    main = importlib.import_module("app.main")
    main = importlib.reload(main)
    try:
        yield main
    finally:
        main.store.close()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(config)


# ------------------------------------------------------------------ _parse_stream_body

def test_ndjson_objects_are_parsed(main_module):
    body = b'{"EventID": 1}\n{"EventID": 2}\n'
    events, skipped = main_module._parse_stream_body(body)
    assert events == [{"EventID": 1}, {"EventID": 2}]
    assert skipped == 0


def test_json_array_is_parsed(main_module):
    events, skipped = main_module._parse_stream_body(b'[{"EventID": 1}, {"EventID": 2}]')
    assert events == [{"EventID": 1}, {"EventID": 2}]
    assert skipped == 0


def test_empty_body_yields_nothing(main_module):
    assert main_module._parse_stream_body(b"   \n ") == ([], 0)


@pytest.mark.parametrize("body", [
    b'"oops"\n{"EventID": 1}\n',          # NDJSON: голая строка первой строкой
    b'{"EventID": 1}\n42\n',              # NDJSON: число
    b'[{"EventID": 1}, "oops"]',          # JSON-массив: строка внутри
    b'[{"EventID": 1}, [1, 2]]',          # JSON-массив: вложенный массив
    b'[{"EventID": 1}, null]',            # JSON-массив: null
])
def test_non_object_entries_are_dropped_and_counted(main_module, body):
    events, skipped = main_module._parse_stream_body(body)
    assert events == [{"EventID": 1}], "валидное событие должно уцелеть рядом с битой записью"
    assert skipped == 1


def test_all_entries_non_object_yields_empty_with_skipped(main_module):
    events, skipped = main_module._parse_stream_body(b'"a"\n"b"\n"c"\n')
    assert events == []
    assert skipped == 3


def test_body_that_is_not_a_list_still_raises(main_module):
    """Тело `[...]`, оказавшееся не списком, по-прежнему 400 (ValueError), а не тихий пропуск."""
    with pytest.raises(json.JSONDecodeError):
        main_module._parse_stream_body(b"[broken")


# ------------------------------------------------------------------ _process_events

def test_process_events_skips_non_dict_and_keeps_the_rest(main_module, monkeypatch):
    """Страховка второго уровня: даже если не-dict дойдёт до _process_events любым путём,
    теряется ОН, а не весь батч (иначе ingest_queue._flush потерял бы буфер целиком)."""
    written: list[dict] = []

    def fake_process_batch(events_path, input_type, ruleset_path, source_label):
        with open(events_path, encoding="utf-8") as fh:
            written.extend(json.loads(line) for line in fh if line.strip())
        return main_module.IngestResponse(
            source_batch=source_label, events_processed=len(written),
            rules_matched=0, alerts_created=0, duration_seconds=0.0,
        )

    monkeypatch.setattr(main_module, "_process_batch", fake_process_batch)

    tagged = [
        ({"EventID": 1}, "src-a"),
        ("oops", "src-a"),          # битая запись посреди буфера
        ({"EventID": 2}, "src-b"),  # событие ДРУГОГО источника - раньше терялось вместе с ней
    ]
    result = main_module._process_events(tagged)

    assert [e["EventID"] for e in written] == [1, 2]
    assert result.events_processed == 2


def test_process_events_resolves_rules_once_per_flush(main_module, monkeypatch):
    """Состав основного рулсета резолвится ОДИН раз на флаш, сколько бы источников в нём ни было:
    раньше отдельно для движка, для active_hit_spec и для evaluate_batch на КАЖДЫЙ источник
    (3 + N раз)."""
    from app.rules import main_ruleset

    rule = {
        "title": "Resolve Once Test", "id": "resolve-once-0001", "level": "informational",
        "tags": [], "rule": ["SELECT * FROM logs WHERE EventID=1"], "channel": [], "eventid": [],
    }
    calls = 0

    def fake_resolve_with_sources():
        nonlocal calls
        calls += 1
        return [("custom_rulesets/fake", rule)]

    monkeypatch.setattr(main_ruleset, "resolve_with_sources", fake_resolve_with_sources)

    tagged = [({"EventID": 1, "Computer": f"HOST-{s}"}, f"resolve-once-{s}") for s in "abc"]
    result = main_module._process_events(tagged)

    assert result.rules_matched == 1
    assert calls == 1
