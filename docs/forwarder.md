# Приём событий с форвардеров (потоковый ingest)

Мини-SIEM принимает события с Windows/Unix хостов по HTTP через один endpoint
`POST /ingest/stream`. Endpoint **агностик к продукту** — подойдёт любой форвардер,
умеющий слать JSON по HTTP: Fluent Bit, NXLog, Winlogbeat→Logstash, Vector, самописный скрипт, `curl`.

## Как это работает (кратко)

События по одному прогонять через Zircolite нельзя: фиксированный оверхед движка (прогон
**каждого** Sigma-правила отдельным SQL-запросом) одинаков для 1 и 1000 событий. Поэтому:

1. Форвардер шлёт события в `POST /ingest/stream`.
2. Сервер кладёт их в очередь и **сразу** отвечает `202 Accepted` (не ждёт детект).
3. Фоновый воркер копит события и запускает Zircolite **батчем** по правилу
   «`SIEM_INGEST_BATCH_SIZE` событий ИЛИ `SIEM_INGEST_FLUSH_INTERVAL` секунд — что раньше»
   (дефолт 500 событий / 5 с). Задержка появления алерта ограничена сверху интервалом флаша.

Настройка флаша — через переменные окружения:

```bash
SIEM_INGEST_BATCH_SIZE=500        # размер микро-батча
SIEM_INGEST_FLUSH_INTERVAL=5.0    # макс. задержка флаша, секунды
```

## Контракт endpoint

```
POST /ingest/stream?source=<label>
Content-Type: application/x-ndjson   (или application/json)
```

- **Тело** — либо **NDJSON** (одно JSON-событие на строку), либо **JSON-массив** событий.
- **`source`** (query, необязательно; дефолт `live-stream`) — метка источника, обычно имя хоста.
  Под ней события группируются в хранилище (`source_batch`) и доступны в селекторе «Батч» в UI.
- **Ответ:** `202 Accepted`, тело `{"queued": <N>, "source": "<label>"}`.
- **Ошибки:** `400` — не удалось разобрать тело; `503` — очередь недоступна/переполнена.

### Формат события
Событие — плоский JSON, поля с теми же именами, что ждёт Zircolite (Windows Event Log,
рендер в JSON). Для срабатывания Sigma-правил важны, напр., `Channel`, `EventID`, `Hostname`,
`CommandLine`, `Image`/`NewProcessName` и т.п. Если форвардер вкладывает данные в
`Event.System` / `Event.EventData`, разложите их в плоский вид на стороне форвардера или
донастройте `Zircolite/config/fieldMappings.yaml`. Поле времени (`EventTime`, `SystemTime`,
`@timestamp` и др.) используется для фильтра по времени во вкладке «События».

## Быстрая проверка — `curl`

```bash
# NDJSON
curl -X POST 'http://SIEM_HOST:8000/ingest/stream?source=HOST01' \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary $'{"EventID":4688,"Channel":"Security","Hostname":"HOST01","CommandLine":"powershell -enc ...","EventTime":"2026-07-21 10:00:00"}\n{"EventID":4624,"Channel":"Security","Hostname":"HOST01","TargetUserName":"bob","EventTime":"2026-07-21 10:00:05"}'

# JSON-массив
curl -X POST 'http://SIEM_HOST:8000/ingest/stream?source=HOST01' \
  -H 'Content-Type: application/json' \
  -d '[{"EventID":4688,"Channel":"Security","Hostname":"HOST01"}]'
```

Через ≤ `SIEM_INGEST_FLUSH_INTERVAL` секунд события появятся в `/batches` под `HOST01`
и во вкладке «События».

## Fluent Bit (Windows и Linux)

Лёгкий, кроссплатформенный, нативный JSON, HTTP-output. Читает Windows Event Log и
Linux auditd/syslog.

**Windows — Security/Sysmon → SIEM:**
```ini
[INPUT]
    Name         winevtlog
    Channels     Security,Microsoft-Windows-Sysmon/Operational
    Read_Existing_Events  false

[FILTER]
    Name    modify
    Match   *
    Add     Hostname ${COMPUTERNAME}

[OUTPUT]
    Name          http
    Match         *
    Host          SIEM_HOST
    Port          8000
    URI           /ingest/stream?source=${COMPUTERNAME}
    Format        json_lines
    Header        Content-Type application/x-ndjson
    json_date_key EventTime
```

**Linux — auditd/syslog → SIEM:**
```ini
[INPUT]
    Name    tail
    Path    /var/log/audit/audit.log
    Tag     auditd

[OUTPUT]
    Name          http
    Match         *
    Host          SIEM_HOST
    Port          8000
    URI           /ingest/stream?source=linux-host01
    Format        json_lines
    Header        Content-Type application/x-ndjson
```
> `Format json_lines` даёт ровно NDJSON, который ждёт endpoint. `source` в URI —
> метка хоста; можно подставлять реальное имя из переменной окружения агента.

## NXLog (Windows, om_http)

```apache
<Input eventlog>
    Module  im_msvistalog
</Input>

<Output http>
    Module      om_http
    URL         http://SIEM_HOST:8000/ingest/stream?source=HOST01
    ContentType application/json
    # to_json() в Exec-строке даёт JSON-объект на событие
    Exec        to_json();
</Output>

<Route r>
    Path eventlog => http
</Route>
```
> NXLog по умолчанию шлёт по одному JSON-объекту в теле — endpoint это принимает
> (тело, начинающееся не с `[`, парсится как NDJSON, в т.ч. одна строка).

## Замечания по проду

- **HTTPS/аутентификация.** Endpoint пока без авторизации — за пределами localhost ставьте
  перед сервисом reverse-proxy (TLS + токен/mTLS). Это задача этапа «прод-готовность».
- **Надёжность доставки.** У форвардеров есть буфер/ретраи (Fluent Bit `storage`, NXLog buffer) —
  включите их, чтобы не терять события при недоступности SIEM.
- **Бэкпрешер.** При переполнении внутренней очереди endpoint вернёт `503` — форвардер должен
  ретраить. Тюньте `SIEM_INGEST_BATCH_SIZE` / `SIEM_INGEST_FLUSH_INTERVAL` под свой поток.
