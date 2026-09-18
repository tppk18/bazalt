# BAZALT

Высокопроизводительный анализатор сетевого трафика для Attack/Defense CTF. Backend и data plane написаны на Rust. Интерфейс сохраняет удобную flow-модель оригинального Packmate: одна запись в левой ленте соответствует TCP/UDP flow, а содержимое request/response показывается справа.

BAZALT рассчитан на высокий PPS, HTTP-heavy трафик, live pattern matching и автоматический ретроспективный поиск новых паттернов по уже сохранённому трафику.

## v0.4: traffic fidelity

Версия 0.4 усиливает именно корректность захвата и реконструкции adversarial/неидеального трафика без переноса тяжёлой логики в обычный hot path:

- bounded sharded reassembly IPv4/IPv6 fragments; unfragmented packets не берут fragment lock;
- strict fragment-overlap policy: exact duplicate принимается, partial/conflicting overlap уничтожает datagram;
- VLAN/QinQ identity входит в `FlowKey`; bounded VXLAN/GRE/IP-in-IP decapsulation добавляет direction-independent outer-tunnel identity, чтобы одинаковые inner 4-tuples из разных tunnels не смешивались;
- snaplen/L3/L4 truncation никогда не продвигает TCP sequence state;
- TCP sequence space внутри reassembler расширен до `u64`, поэтому wraparound не ломает OOO ordering;
- overlapping TCP data использует deterministic first-seen semantics; in-order fast path остаётся zero-copy, interval normalization включается только после reorder;
- cumulative ACK используется как bounded inference-сигнал capture-gap и позволяет продолжить поток; дополнительно small gaps восстанавливаются по timeout/pressure/close, поэтому поток не зависит от ACK;
- превышение `BAZALT_MAX_OOO_BYTES` **или** `BAZALT_MAX_OOO_SEGMENTS`, а также `BAZALT_TCP_GAP_TIMEOUT_MS`, вызывает explicit gap/resync вместо permanent `truncated`/остановки flow;
- FIN закрывает half только при достижении его позиции в sequence space; out-of-order FIN остаётся tentative до peer ACK/contiguous retransmission и не может обрезать поздний payload; off-sequence RST не уничтожает state; повторный SYN с тем же ISN не создаёт новую generation;
- HTTP/1.x parser коррелирует request/response для HEAD/CONNECT, понимает 101 tunnel mode, строго разбирает duplicate `Content-Length` и `Transfer-Encoding`, сохраняет framing после oversized body и prefix-aware ресинхронизируется после TCP-gap даже на длинной request-line;
- header/chunk delimiter scans инкрементальные; body over-limit продолжает framing без materialization;
- `BAZALT_RAW_CAPTURE=true` архивирует каждый frame до parser/service filtering, поэтому incomplete fragments и malformed traffic остаются в forensic PCAP.

## Что реализовано

- AF_XDP capture с native → SKB → single-worker libpcap fallback;
- адаптивный CPU planner по реальному cgroup/cpuset; flow/L7/matcher/Tokio делят единый CPU budget;
- capture только по портам явно настроенных сервисов;
- динамический libpcap BPF при изменении списка сервисов;
- bounded data-plane queues;
- sharded TCP/UDP flow engine без глобального dispatcher-thread;
- TCP reassembly, retransmission/out-of-order handling и bounded per-flow state;
- live snapshots открытых flows — FIN/RST не требуется для появления потока в интерфейсе;
- streaming HTTP/1.x parser на `BytesMut`/`httparse` без `Vec::drain` и полного header-map allocation;
- User-Agent extraction и фильтрация;
- scoped text/binary Aho–Corasick + compiled regex matching по `service + content view`;
- request / response / anywhere pattern scopes;
- автоматический historical replay новых паттернов;
- append-only segment store без промежуточной полной копии payload при записи;
- batched segment reads: один open/canonicalize на файл вместо одного на каждый content record;
- throttled live UI refresh вместо ClickHouse query burst на каждое WebSocket-событие;
- ClickHouse metadata + PostgreSQL control plane;
- собственный SPA BAZALT;
- packet/payload logging выключен по умолчанию.

## HTTP и `tcp_raw`

Внутри storage BAZALT сохраняет reassembled `tcp_raw` как каноническое представление и HTTP semantic views как удобное L7-представление. В UI они не должны дублировать друг друга.

Для успешно распознанного HTTP `/api/flows/{id}/content` скрывает `tcp_raw`, если его byte range полностью покрыт HTTP headers/body. `tcp_raw` остаётся видимым только для непокрытого/fallback/non-HTTP содержимого.

Pattern matching разделён от presentation:

- `Anywhere` сканирует канонический reassembled TCP stream один раз;
- `Request` / `Response` сканируют соответствующие HTTP semantic views;
- decoded gzip/deflate body сканируется отдельно, потому что plaintext отсутствует в wire bytes;
- если hit найден в скрытом `tcp_raw`, API проецирует его offsets на видимый HTTP record, поэтому подсветка сохраняется без повторного сканирования тех же байтов.

Это устраняет визуальный дубль и не удваивает CPU matcher.

## Быстрый запуск

```bash
cp .env.example .env
$EDITOR .env
docker compose up --build -d
docker compose logs -f app
```

UI/API:

```text
http://127.0.0.1:65000
```

Проверка:

```bash
./scripts/smoke.sh
```

Docker build является compile/test gate:

```text
cargo test --release --all-features
cargo build --release --all-features
```

## Основная настройка

Канонические переменные окружения имеют префикс `BAZALT_`:

```env
BAZALT_CAPTURE_MODE=afxdp
BAZALT_INTERFACE=eth0
BAZALT_QUEUE_IDS=0,1,2,3

# Recommended default for unknown A/D hardware.
BAZALT_CPU_AUTO=true
# Optional override. Empty = adaptive budget: all CPUs on <=4-core hosts,
# ~75% on larger hosts to leave headroom for ClickHouse/PostgreSQL/kernel.
BAZALT_CPU_BUDGET=

# Manual topology is used only with BAZALT_CPU_AUTO=false:
# BAZALT_TOKIO_WORKERS=1
# BAZALT_CAPTURE_CPUS=0
# BAZALT_FLOW_CPUS=1,2
# BAZALT_L7_CPUS=3,4
# BAZALT_MATCHER_CPUS=5,6
# BAZALT_FLOW_SHARDS=2
# BAZALT_L7_WORKERS=2
# BAZALT_MATCHER_WORKERS=2

BAZALT_CAPTURE_QUEUE=32768
# Short bounded wait at capture -> flow absorbs microbursts instead of dropping
# immediately. 0 restores strict try-send semantics.
BAZALT_CAPTURE_ENQUEUE_TIMEOUT_US=250
BAZALT_FLOW_QUEUE=16384
BAZALT_MATCH_QUEUE=16384
BAZALT_STORAGE_QUEUE=16384

# ClickHouse is an asynchronous projection target. Accepted metadata is fsync'd
# to this bounded local spool first; replay yields as the spool approaches its cap.
BAZALT_METADATA_SPOOL_MAX_BYTES=2147483648
BAZALT_CLICKHOUSE_TIMEOUT_MS=5000

# HTTP decoded-body amplification bounds. Full streaming decode is still planned.
BAZALT_HTTP_MAX_DECODE_BYTES=16777216
BAZALT_HTTP_MAX_DECODE_RATIO=32

# Global flow-state admission is checked only for previously unseen tuples.
BAZALT_MAX_ACTIVE_FLOWS=262144
# Match output/work amplification bounds.
BAZALT_MATCH_MAX_HITS_PER_PATTERN=128
BAZALT_MATCH_MAX_HITS_PER_RECORD=1024
# Reject malformed segment lengths before allocation (must be <= segment size).
BAZALT_SEGMENT_MAX_RECORD_BYTES=268435456

BAZALT_LIVE_FLOW_UPDATE_MS=1000
BAZALT_PACKET_LOGGING=false
BAZALT_RAW_CAPTURE=false

# Compose no longer ships known database passwords. Generate URL-safe secrets
# (for example `openssl rand -hex 32`) before starting the stack.
BAZALT_POSTGRES_PASSWORD=change-this-too
BAZALT_CLICKHOUSE_PASSWORD=change-this-too

# Control plane auth is enabled by default. Both credentials are required.
BAZALT_AUTH_ENABLED=true
BAZALT_AUTH_USERNAME=admin
BAZALT_AUTH_PASSWORD=change-this
# Local dev only:
# BAZALT_AUTH_ENABLED=false
```

Для миграции с 0.1.x backend также принимает старые `PACKMATE_*` ключи, если соответствующий `BAZALT_*` не задан. Docker Compose 0.4.1.2 передаёт `BAZALT_*` как основные ключи и также пробрасывает legacy `PACKMATE_*`, поэтому существующий `.env` от 0.1.x продолжает работать.

PostgreSQL/ClickHouse database namespace пока сохранён как `packmate` для бесшовного обновления существующих volumes. Это внутренний storage namespace, не имя продукта.

В `0.4.1.2` PostgreSQL и ClickHouse публикуются на host только через `127.0.0.1`; native ClickHouse port наружу не публикуется. Это сохраняет доступ приложения с `network_mode: host`, но убирает обход HTTP-auth через прямое подключение к БД с game/hostile interface.

ClickHouse не входит в synchronous acceptance path: metadata сначала попадает в bounded `data/metadata-spool`, после чего projector асинхронно догоняет ClickHouse. `bazalt_metadata_spool_bytes`/`bazalt_metadata_spool_capacity` позволяют видеть outage backlog. При заполнении spool metadata writer считается critical failure и supervisor завершает процесс вместо тихой частичной работы.

## Диагностика входящего capture

`0.4.1.2` разделяет метрики source-level и accepted packet-level. По умолчанию `BAZALT_EARLY_PORT_FILTER=false`: libpcap не получает ранний BPF по портам, а обязательный userspace allow-list по настроенным сервисам остаётся активным. Это исключает ситуацию, когда несовместимость BPF/link-layer выглядит как полностью мёртвый capture.

Ключевые метрики:

```text
bazalt_capture_frames_total      # кадры, которые реально вернул capture backend
bazalt_capture_backend_drops_total # потери до userspace (pcap/AF_XDP backend)
bazalt_capture_backend_invalid_descs_total # invalid AF_XDP RX descriptors
bazalt_packets_received_total    # TCP/UDP пакеты на настроенных service ports
bazalt_packets_filtered_total    # разобранные пакеты с ненастроенных портов
bazalt_packets_ignored_total     # unsupported EtherType/L4/tunnel frames
bazalt_packet_parse_errors_total # ошибки Ethernet/IP/TCP/UDP parsing
```

Если ранняя фильтрация libpcap всё же нужна, включите `BAZALT_EARLY_PORT_FILTER=true`.

## CPU и post-capture pipeline

По умолчанию `BAZALT_CPU_AUTO=true`. При старте BAZALT учитывает `sched_getaffinity()` и effective `available_parallelism()` контейнера и строит один общий CPU budget вместо независимых пулов `N flow + N L7 + N matcher + N Tokio`. На машинах крупнее 4 logical CPU auto-budget использует примерно 75% доступного cpuset, оставляя headroom ClickHouse/PostgreSQL/kernel/OS; `BAZALT_CPU_BUDGET` позволяет задать верхнюю границу явно. На HTTP-heavy нагрузке post-capture бюджет распределяется примерно 30% / 40% / 30% между flow, L7 и matcher; control-plane Tokio получает 1–2 worker thread. На малых машинах гарантируется минимум один worker каждой stateful стадии.

Старые `BAZALT_FLOW_SHARDS`, `BAZALT_L7_WORKERS`, `BAZALT_MATCHER_WORKERS` и CPU lists при auto-режиме намеренно игнорируются, поэтому старый `.env` с `4/4/4` не вызывает oversubscription на 4-core машине. Для ручной схемы установите `BAZALT_CPU_AUTO=false`.

Matcher хранит overlap по фактическому ruleset: literals/binary используют только `max_pattern_len - 1`; `BAZALT_MATCH_OVERLAP_BYTES` применяется как bounded window только там, где для данного service/view есть regex. Literal data сканируется напрямую из `Bytes`, а отдельный маленький bridge создаётся только для cross-chunk boundary. Ruleset заранее partitioned по service и content view, поэтому request одного сервиса не сканируется правилами остальных сервисов. Перед matcher-очередью дополнительно стоит lock-free coarse view mask: если ни один активный pattern вообще не использует этот content view, record не будит matcher worker. Tail state сбрасывается при разрыве stream offsets, поэтому разные HTTP semantic records не склеиваются ложным cross-message match.
При закрытии flow matcher удаляет только его собственные state keys (число view на flow мало) и больше не делает `retain()` по всей таблице active tails на каждом коротком соединении.

Historical replay использует малое адаптивное число workers, queue-pressure throttling и пониженный Linux priority (`nice +10`), чтобы backfill нового паттерна уступал live traffic.

## Capture policy

Список сервисов является allow-list захвата. Если настроены порты:

```text
80
8080
31337
```

в data plane проходят только пакеты, у которых `src_port` или `dst_port` равен одному из этих портов.

При libpcap fallback дополнительно ставится kernel BPF:

```text
port 80 or port 8080 or port 31337
```

Если сервисов нет, полезный трафик не захватывается.

## UI

BAZALT использует очень тёмную basalt-палитру, прямую геометрию и моноширинную типографику. Request и response визуально различаются направлением рамки и функциональным цветом:

- request — тёплый янтарный левый контур;
- response — холодный стальной правый контур.

Левая лента остаётся flow-based, как в оригинальной модели Packmate. Агрегирующей вкладки `All` нет: пользователь выбирает конкретный сервис.

Справа в navbar постоянно доступна минимизированная resource-панель `CPU / RSS / PIPE / DROPS`. По клику она раскрывается и показывает process CPU относительно BAZALT CPU budget, RSS/cgroup memory, ingress pps/Mbit/s, load average, threads/FD, pipeline queue depth/peak и loss/error counters. Состояние раскрытия сохраняется в `localStorage`.

Вкладка `MANAGE` показывает фактический storage footprint: ClickHouse по таблицам, PostgreSQL control-plane DB и payload segment files. Оттуда можно выполнить retention cleanup старше заданного возраста. Cleanup сохраняет конфигурацию/паттерны, блокирует historical replay на время операции, запечатывает текущий segment, дожидается metadata barrier в ClickHouse и удаляет только segment files, целиком состоящие из просроченных records.

Control plane по умолчанию fail-closed. При `BAZALT_AUTH_ENABLED=true` все `/api/*`, `/metrics` и `/api/live` требуют session cookie или HTTP Basic credentials; отсутствие/невалидная авторизация получает `403 Forbidden` до тяжёлых handlers. UI login использует HttpOnly/SameSite=Strict cookie. Для dev можно явно поставить `BAZALT_AUTH_ENABLED=false`.

## Метрики

Prometheus-compatible endpoint:

```text
GET /metrics
```

При включённой авторизации Prometheus должен использовать HTTP Basic credentials из `BAZALT_AUTH_USERNAME` / `BAZALT_AUTH_PASSWORD`. Без них endpoint отвечает `403`.

Префикс метрик:

```text
bazalt_
```

Особенно полезны:

```text
bazalt_packets_received_total
bazalt_packets_filtered_total
bazalt_capture_drops_total
bazalt_capture_backend_drops_total
bazalt_packets_ignored_total
bazalt_active_flows
bazalt_flow_queue_high_watermark
bazalt_l7_queue_high_watermark
bazalt_match_queue_high_watermark
bazalt_storage_queue_high_watermark
bazalt_matcher_bytes_total
bazalt_replay_bytes_total
```

## Документация

- `docs/ARCHITECTURE.md` — data plane, storage, matcher и replay;
- `docs/API.md` — REST/WebSocket API;
- `docs/OPERATIONS.md` — production capture и диагностика;
- `docs/TESTING.md` — unit/smoke/soak tests;
- `VERIFYING.md` — какие проверки были выполнены для release artifact.
