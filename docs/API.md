# BAZALT API

Base URL по умолчанию:

```text
http://127.0.0.1:65000
```

## Authentication

По умолчанию `BAZALT_AUTH_ENABLED=true`. При включённой авторизации все `/api/*`, `/metrics` и WebSocket `/api/live` требуют либо HttpOnly session cookie, полученную через login, либо HTTP Basic credentials. Неавторизованный запрос получает `403 Forbidden` до выполнения endpoint handler.

```text
POST /auth/login
POST /auth/logout
```

`POST /auth/login` принимает JSON:

```json
{"username":"admin","password":"..."}
```

Для CLI/Prometheus:

```bash
curl -u "$BAZALT_AUTH_USERNAME:$BAZALT_AUTH_PASSWORD" http://127.0.0.1:65000/metrics
```

В dev-режиме auth можно полностью отключить `BAZALT_AUTH_ENABLED=false`.

## Status / metrics

```text
GET /api/status
GET /api/resources
GET /metrics
```

`GET /api/resources` — лёгкий telemetry endpoint для UI. Он не обращается к ClickHouse/PostgreSQL и возвращает:

- `metrics` — snapshot внутренних atomic counters/gauges;
- `live_pressure_pct` — максимальная текущая загрузка bounded pipeline queue;
- `resources.process_cpu_seconds` — накопленное CPU time процесса, из которого frontend считает фактическую CPU load между samples;
- `resources.process_rss_bytes`, `process_virtual_bytes`, `process_threads`, `open_fds`, `process_uptime_seconds`;
- `resources.load_1m/load_5m/load_15m`;
- `resources.memory_scope_used_bytes`, `memory_scope_limit_bytes`, `memory_scope` — cgroup memory, если есть конечный container limit, иначе host memory.

Frontend опрашивает этот endpoint отдельно от `/api/status`, чтобы resource panel не увеличивал частоту per-service SPM запросов в ClickHouse.

## Services

```text
GET    /api/services
POST   /api/services
PUT    /api/services/{port}
DELETE /api/services/{port}
```

Service одновременно является capture allow-list entry.

Пример создания:

```json
{
  "port": 8080,
  "name": "http",
  "http": true,
  "urldecode_http_requests": false,
  "merge_adjacent_packets": false,
  "parse_websockets": false
}
```

## Flows

```text
GET /api/flows
GET /api/flows/{id}
GET /api/flows/{id}/content
POST /api/flows/{id}/favorite
```

Основные query parameters `/api/flows`:

```text
service
src_ip
dst_ip
src_port
dst_port
protocol
pattern_id
favorite
user_agent
user_agent_equals
user_agent_not_contains
user_agent_regex
limit
offset
```

`/content` возвращает presentation-deduplicated content: fully-covered `tcp_raw` не повторяется рядом с HTTP semantic representation. Pattern hits из скрытого raw canonical stream проецируются на visible HTTP items.

## Content

```text
GET /api/content/{content_id}?format=text
GET /api/content/{content_id}?format=hex
```

## Patterns

```text
GET    /api/patterns
POST   /api/patterns
PUT    /api/patterns/{id}
DELETE /api/patterns/{id}
PATCH  /api/patterns/{id}/enabled
POST   /api/patterns/{id}/lookback
```

Pattern fields:

```text
name
expression
kind             text | binary | regex
action           find | ignore
color
direction_type   input | output | both
service
view
```

Matching semantics:

- `both`: canonical TCP raw stream + decoded body representations;
- `input`: HTTP request views;
- `output`: HTTP response views.


## Management / retention

```text
GET  /api/management/storage
POST /api/management/cleanup
```

`GET /api/management/storage` возвращает:

- ClickHouse active-part bytes, physical row count и per-table breakdown;
- PostgreSQL database size;
- payload segment bytes/file count;
- суммарный managed storage footprint.

Retention request:

```json
{"older_than_seconds":86400,"confirm":"DELETE"}
```

Cleanup удаляет старые `flows`, `http_messages`, `content_index` и `matches` из ClickHouse. Перед mutation current payload segment запечатывается и metadata pipeline проходит barrier; historical replay на время операции держится за maintenance gate. Payload segment удаляется только если каждый record внутри старше cutoff. Mixed-age segment сохраняется до следующего retention cycle. PostgreSQL configuration (services/patterns/replay history) cleanup не затрагивает.

## Replay

```text
GET /api/replay/jobs
```

Новая pattern revision автоматически создаёт historical backfill job.

## Live WebSocket

```text
GET /api/live
```

События включают flow updates и new matches. Frontend использует их как trigger для throttled refresh, а не как транспорт полного payload.
