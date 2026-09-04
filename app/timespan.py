"""
Разбор Sigma-таймспана вида "5m"/"1h"/"1d" в секунды.

Отдельный лист-модуль без импортов, а не метод внутри app/detection/correlation.py: тот же
разбор нужен И в app/rules/rules_catalog.py (валидация формата timespan при СОХРАНЕНИИ
correlation-правила - см. _validate_correlation_doc), а заводить зависимость app/rules ->
app/detection (или наоборот) ради одной функции не хочется - rules_catalog уже используется
main_ruleset.py (не detection-модулем), а correlation.py и так импортирует rules_catalog
(чтение правил), но валидация при сохранении логически принадлежит rules_catalog. Симметрично
видимый обоим лист - самый дешёвый способ не дублировать регэксп.

Единицы: s/m/h/d/w (секунды/минуты/часы/дни/недели) - те, что реально встречаются в контенте
проекта. 'M' (месяц)/'y' (год) намеренно не поддержаны - неоднозначная длина в секундах.
"""
from __future__ import annotations

import re
from typing import Any

_TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_timespan(text: Any) -> int | None:
    """'5m' -> 300. None при пустом/нераспознанном формате (лишний оператор, 'M'/'y', мусор,
    отрицательное число - регэксп требует цифры без знака)."""
    if not text:
        return None
    m = _TIMESPAN_RE.match(str(text).strip())
    if not m:
        return None
    return int(m.group(1)) * _TIMESPAN_UNITS[m.group(2).lower()]
