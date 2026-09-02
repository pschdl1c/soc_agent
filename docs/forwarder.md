# Приём событий с форвардеров (потоковый ingest)

Мини-SIEM принимает события с Windows/Unix хостов по HTTP через один endpoint
`POST /ingest/stream`. Endpoint **агностик к продукту** — подойдёт любой форвардер,
умеющий слать JSON по HTTP с настраиваемым HTTP-заголовком (для токена): Fluent Bit, NXLog,
Winlogbeat→Logstash, Vector, самописный скрипт, `curl`.

## Как это работает (кратко)

События по одному прогонять через Zircolite нельзя: фиксированный оверхед движка (прогон
**каждого** Sigma-правила отдельным SQL-запросом) одинаков для 1 и 1000 событий. Поэтому:

1. Форвардер шлёт события в `POST /ingest/stream` с заголовком `Authorization: Bearer <token>`.
2. Сервер проверяет токен и кладёт события в очередь, **сразу** отвечая `202 Accepted`
   (не ждёт детект). Нет токена / неизвестен / источник выключен → `401`, событий не приняли.
3. Фоновый воркер копит события и запускает Zircolite **батчем** по правилу
   «`SIEM_INGEST_BATCH_SIZE` событий ИЛИ `SIEM_INGEST_FLUSH_INTERVAL` секунд — что раньше»
   (дефолт 500 событий / 5 с). Задержка появления алерта ограничена сверху интервалом флаша.

Настройка флаша — через переменные окружения:

```bash
SIEM_INGEST_BATCH_SIZE=500        # размер микро-батча
SIEM_INGEST_FLUSH_INTERVAL=5.0    # макс. задержка флаша, секунды
```

## Регистрация источника и токен

`/ingest/stream` (и `/ingest/events`) **требуют токен** зарегистрированного источника.

1. UI → вкладка **«Источник данных»** → **«Создать источник»**. Имя обязательно и уникально —
   оно становится меткой источника (`source_batch`) для всех его событий и алертов.
2. Скопируйте показанный токен **сразу** — он выводится один раз (в БД хранится только хэш).
   Потеряли — кнопка **«Перевыпустить»** выдаёт новый, старый перестаёт работать.
3. Форвардер шлёт токен в заголовке `Authorization: Bearer <token>` (или `X-Ingest-Token: <token>`).

Запрос без валидного токена активного источника отклоняется `401`, события в очередь не попадают.
Выключить приём по источнику, не удаляя его, — тумблер «Активен» в той же таблице.

## Контракт endpoint

```
POST /ingest/stream
Authorization: Bearer <token>
Content-Type: application/x-ndjson   (или application/json)
```

- **Тело** — либо **NDJSON** (одно JSON-событие на строку), либо **JSON-массив** событий.
- **Метка источника** (`source_batch`) берётся из имени зарегистрированного источника, к
  которому привязан токен. Query-параметр `?source=` больше не используется.
- **Ответ:** `202 Accepted`, тело `{"queued": <N>, "source": "<имя источника>"}`.
- **Ошибки:** `401` — нет/неизвестен/выключен токен; `400` — не удалось разобрать тело;
  `503` — очередь недоступна/переполнена.

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
curl -X POST 'http://SIEM_HOST:8000/ingest/stream' \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary $'{"EventID":4688,"Channel":"Security","Hostname":"HOST01","CommandLine":"powershell -enc ...","EventTime":"2026-07-21 10:00:00"}\n{"EventID":4624,"Channel":"Security","Hostname":"HOST01","TargetUserName":"bob","EventTime":"2026-07-21 10:00:05"}'

# JSON-массив
curl -X POST 'http://SIEM_HOST:8000/ingest/stream' \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '[{"EventID":4688,"Channel":"Security","Hostname":"HOST01"}]'
```

Через ≤ `SIEM_INGEST_FLUSH_INTERVAL` секунд события появятся в `/batches` под именем источника
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
    URI           /ingest/stream
    Format        json_lines
    Header        Content-Type application/x-ndjson
    Header        Authorization Bearer <TOKEN>
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
    URI           /ingest/stream
    Format        json_lines
    Header        Content-Type application/x-ndjson
    Header        Authorization Bearer <TOKEN>
```
> `Format json_lines` даёт ровно NDJSON, который ждёт endpoint. Метку источника задаёт токен
> (заголовок `Authorization`) — по одному источнику (и токену) на хост.

## NXLog (Windows, om_http)

```apache
<Input eventlog>
    Module  im_msvistalog
</Input>

<Output http>
    Module      om_http
    URL         http://SIEM_HOST:8000/ingest/stream
    ContentType application/json
    AddHeader   Authorization: Bearer <TOKEN>
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

- **Аутентификация.** Каждый источник аутентифицируется своим bearer-токеном (см. «Регистрация
  источника» выше); события без валидного токена отбрасываются с `401`. Токен хранится в БД
  только хэшем. **HTTPS** endpoint сам не терминирует — за пределами localhost ставьте перед
  сервисом reverse-proxy с TLS, иначе токен идёт по сети открытым.
- **Надёжность доставки.** У форвардеров есть буфер/ретраи (Fluent Bit `storage`, NXLog buffer) —
  включите их, чтобы не терять события при недоступности SIEM.
- **Бэкпрешер.** При переполнении внутренней очереди endpoint вернёт `503` — форвардер должен
  ретраить. Тюньте `SIEM_INGEST_BATCH_SIZE` / `SIEM_INGEST_FLUSH_INTERVAL` под свой поток.
