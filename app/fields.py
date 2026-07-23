"""
Общие кандидаты имён полей для генерик-извлечения атрибутов из разнородных событий
(EVTX Security-канал, Sysmon, Auditd называют одно и то же по-разному).
"""
from __future__ import annotations

from typing import Any

HOST_FIELDS = ["Hostname", "Computer", "host", "ComputerName"]
USER_FIELDS = ["TargetUserName", "SubjectUserName", "User", "AccountName"]
SRC_IP_FIELDS = ["IpAddress", "SourceAddress", "SourceIp", "src_ip"]
DST_IP_FIELDS = ["DestAddress", "DestinationIp", "dst_ip"]
PROCESS_FIELDS = ["Image", "NewProcessName", "CommandLine", "exe"]
TIME_FIELDS = ["SystemTime", "EventTime", "@timestamp", "timestamp", "EventReceivedTime"]

# Служебный маркер источника, временно вписываемый в JSON события перед прогоном через движок
# (см. app/main.py:_process_events/_split_events_by_source, app/normalize.py) - нужен, чтобы
# можно было слить события НЕСКОЛЬКИХ источников в один прогон Zircolite (амортизация
# фиксированного оверхеда движка на батч, см. app/ingest_queue.py), но при этом не потерять,
# из какого именно источника пришло каждое событие/алерт.
#
# ВАЖНО (грабли, уже словили): имя ДОЛЖНО быть чисто алфанумерическим. Zircolite при
# flatten-е событий прогоняет имя каждого поля без явного маппинга через
# `_NON_ALNUM_RE.sub("", last_part)` (streaming.py) - ЛЮБые символы вне [A-Za-z0-9] (в т.ч.
# подчёркивания) молча вырезаются. "__ingest_source__" на выходе движка превращался в
# "ingestsource" - popstate по оригинальному имени в _split_events_by_source/normalize.py
# просто не находил ключ, и все события откатывались на default_label. Поэтому здесь - без
# подчёркиваний/спецсимволов, только буквы; читать это поле из событий после движка нужно
# ТОЧНО этим же именем (оно уже "как после чистки"). Длинный отличительный префикс -
# минимизировать шанс коллизии с реальным именем поля источника. Перед сохранением в БД/
# показом аналитику ВСЕГДА выпиливается (event.pop(...)) - наружу никогда не должен утекать.
INGEST_SOURCE_FIELD = "SocIngestSourceMarker"


def first_present(event: dict[str, Any], field_names: list[str]) -> str | None:
    for name in field_names:
        value = event.get(name)
        if value:
            return str(value)
    return None
