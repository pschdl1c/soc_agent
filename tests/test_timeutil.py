"""
Тесты канонизации меток времени (app/timeutil.py) - фундамент фильтра по времени в Событиях
и окна корреляции. Регрессия, ради которой написаны: время сравнивалось наивной строкой, а
колонка нормализовалась в SQL - граница из параметра при этом не нормализовалась вовсе.
"""
from __future__ import annotations

from app.timeutil import normalize_event_time, normalize_time_bound


def test_space_separator_becomes_iso():
    assert normalize_event_time("2026-09-05 09:00:00") == "2026-09-05T09:00:00"


def test_z_suffix_dropped_value_unchanged():
    assert normalize_event_time("2026-09-05T18:00:00Z") == "2026-09-05T18:00:00"


def test_offset_converted_to_utc():
    """Ключевое: '+03:00' и 'Z' - один и тот же момент, значит и строка должна быть одна."""
    assert normalize_event_time("2026-09-05T21:00:00+03:00") == normalize_event_time("2026-09-05T18:00:00Z")


def test_fluent_bit_time_created_with_space_before_offset():
    """TimeCreated от Fluent Bit winevtlog: 'ДАТА ВРЕМЯ ±ЧЧММ' - раньше уходило в фолбэк мусором."""
    assert normalize_event_time("2026-09-14 02:08:49 +0300") == "2026-09-13T23:08:49"


def test_negative_offset_converted_to_utc():
    assert normalize_event_time("2026-09-05T13:00:00-05:00") == "2026-09-05T18:00:00"


def test_fraction_preserved_and_ordered_after_whole_second():
    whole = normalize_event_time("2026-09-05T21:01:30")
    fraction = normalize_event_time("2026-09-05T21:01:30.113")
    assert whole < fraction < normalize_event_time("2026-09-05T21:01:31")


def test_unparsable_value_falls_back_to_old_normalization():
    """Неизвестный формат не роняет ingest - метка просто чистится по старому правилу."""
    assert normalize_event_time("05.09.2026 21:01:30Z") == "05.09.2026T21:01:30"


def test_none_and_empty_pass_through():
    assert normalize_event_time(None) is None
    assert normalize_event_time("") == ""


def test_upper_bound_includes_same_second_with_fraction():
    bound = normalize_time_bound("2026-09-05 21:01:30", upper=True)
    assert bound > normalize_event_time("2026-09-05T21:01:30.999999")
    assert bound < normalize_event_time("2026-09-05T21:01:31")


def test_lower_bound_has_no_sentinel():
    """Нижней границе сентинель вреден - он отрезал бы события той же секунды с дробной частью."""
    bound = normalize_time_bound("2026-09-05 21:01:30")
    assert bound == "2026-09-05T21:01:30"
    assert bound < normalize_event_time("2026-09-05T21:01:30.001")


def test_blank_bound_is_none():
    assert normalize_time_bound(None) is None
    assert normalize_time_bound("   ") is None
