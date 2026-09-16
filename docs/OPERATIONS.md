# Эксплуатация BAZALT

## Запуск

```bash
cp .env.example .env
$EDITOR .env
docker compose up --build -d
docker compose logs -f app
```

## Control-plane authentication

Production default is fail-closed:

```env
BAZALT_AUTH_ENABLED=true
BAZALT_AUTH_USERNAME=admin
BAZALT_AUTH_PASSWORD=<long-random-password>
BAZALT_AUTH_SESSION_SECS=43200
BAZALT_AUTH_COOKIE_SECURE=true   # only when UI is served over HTTPS
```

Если auth включён, но login/password пустые, BAZALT завершает startup с ошибкой конфигурации. Для локальной разработки:

```env
BAZALT_AUTH_ENABLED=false
```

Без валидной auth `/api/*`, `/metrics` и `/api/live` отвечают `403` до входа в ClickHouse/PostgreSQL/replay/management handlers. `POST /auth/login` остаётся публичной динамической точкой и имеет in-memory rate limit на неуспешные логины. Login cookie: `HttpOnly; SameSite=Strict`; `Secure` управляется `BAZALT_AUTH_COOKIE_SECURE`.

403 не является заменой сетевому DDoS-фильтру: на недоверенной сети всё равно нужен firewall/reverse proxy/rate limiting перед BAZALT.

## Adaptive CPU mode

Для неизвестных A/D машин рекомендуемый режим:

```env
BAZALT_CPU_AUTO=true
BAZALT_CPU_BUDGET=
```

BAZALT читает фактический cpuset через `sched_getaffinity()` и effective CPU quota через `available_parallelism()`.

При пустом `BAZALT_CPU_BUDGET`:

- на 1–4 доступных CPU используется весь небольшой cpuset;
- на более крупных машинах BAZALT по умолчанию использует примерно 75% доступных logical CPU, оставляя headroom ClickHouse/PostgreSQL/kernel/OS;
- flow/L7/matcher workers распределяются автоматически с уклоном в HTTP processing;
- Tokio получает 1–2 worker thread;
- replay получает 1–3 background workers и работает с `nice +10`.

Проверить выбранный план:

```bash
docker compose logs app | grep 'adaptive CPU plan'
curl -s http://127.0.0.1:65000/metrics | grep -E 'bazalt_(cpu_|tokio_workers|flow_workers|l7_workers|matcher_workers|replay_workers)'
```

Пример метрик:

```text
bazalt_cpu_available 16
bazalt_cpu_budget 12
bazalt_tokio_workers 2
bazalt_flow_workers 2
bazalt_l7_workers 3
bazalt_matcher_workers 2
bazalt_replay_workers 2
```

Точные числа зависят также от capture reservation.

### Ограничить BAZALT вручную

Если ClickHouse/другие сервисы требуют больше CPU:

```env
BAZALT_CPU_AUTO=true
BAZALT_CPU_BUDGET=8
```

BAZALT сам распределит эти 8 CPU внутри pipeline.

### Полностью ручной режим

```env
BAZALT_CPU_AUTO=false
BAZALT_TOKIO_WORKERS=1
BAZALT_CAPTURE_CPUS=0
BAZALT_FLOW_CPUS=1,2
BAZALT_L7_CPUS=3,4
BAZALT_MATCHER_CPUS=5,6
BAZALT_FLOW_SHARDS=2
BAZALT_L7_WORKERS=2
BAZALT_MATCHER_WORKERS=2
BAZALT_REPLAY_WORKERS=1
```

Использовать manual mode стоит только после измерения queue high-watermarks/profile.

## Capture

Для AF_XDP пустой `BAZALT_QUEUE_IDS` означает auto-discovery всех
`/sys/class/net/$BAZALT_INTERFACE/queues/rx-*`. Это безопаснее, чем молча
привязываться только к queue 0: XSK принимает трафик только своей RX queue.

```env
BAZALT_CAPTURE_MODE=afxdp
BAZALT_INTERFACE=eth0
BAZALT_QUEUE_IDS=
BAZALT_CAPTURE_ENQUEUE_TIMEOUT_US=250
```

Если хотя бы одна выбранная AF_XDP queue не инициализируется, BAZALT не
оставляет частичную XSK-топологию: при разрешённом fallback весь capture
переключается на один libpcap worker. Это исключает потерю отдельных RSS buckets.

`BAZALT_CAPTURE_ENQUEUE_TIMEOUT_US` задаёт короткое bounded ожидание на ребре
capture -> flow. Ноль включает историческое поведение «drop immediately»;
ненулевое значение поглощает короткие scheduler/flow-worker stalls, но при
устойчивой перегрузке drop всё равно фиксируется метрикой.

Для AF_XDP также учитываются kernel/XSK drop counters, выполняется RX wakeup при
`XDP_USE_NEED_WAKEUP`, а multi-buffer descriptors собираются обратно в один
Ethernet frame. Если интерфейс использует MTU, не помещающийся в 2048-byte UMEM
frame, и scatter/gather недоступен, AF_XDP считается lossy и запускается общий
libpcap fallback вместо молчаливой потери jumbo frames.

Список сервисов остаётся allow-list портов.

### Диагностика пропавших пакетов

```bash
curl -s http://127.0.0.1:65000/metrics | \
  grep -E 'bazalt_(capture_frames|capture_backend|capture_drops|packets_(received|filtered|ignored)|packet_parse_errors)'
```

Интерпретация:

- растёт `bazalt_capture_backend_drops_total` — кадры теряются до нормального userspace parsing (AF_XDP/libpcap/kernel path);
- растёт `bazalt_capture_drops_total` — заполнено ребро `capture -> flow` даже после bounded wait;
- растёт `bazalt_packets_filtered_total` — пакет корректный, но его порт отсутствует в service allow-list;
- растёт `bazalt_packets_ignored_total` — unsupported EtherType/L4/tunnel traffic; IP fragments учитываются отдельными fragment metrics;
- растёт `bazalt_packet_parse_errors_total` — malformed/truncated frame;
- `capture_frames_total` не растёт при известном входящем трафике — проверять interface/RSS/XDP redirect и выбранные RX queues.

## Как искать post-capture bottleneck

```bash
curl -s http://127.0.0.1:65000/metrics | grep bazalt_
```

Смотреть прежде всего:

```text
bazalt_flow_queue_depth
bazalt_flow_queue_high_watermark
bazalt_l7_queue_depth
bazalt_l7_queue_high_watermark
bazalt_match_queue_depth
bazalt_match_queue_high_watermark
bazalt_storage_queue_depth
bazalt_storage_queue_high_watermark
bazalt_live_pressure_pct
```

Интерпретация:

- растёт `flow_queue` → reassembly/flow workers не успевают;
- растёт `l7_queue` → HTTP parsing/decompression является bottleneck;
- растёт `match_queue` → ruleset/regex является bottleneck;
- растёт `storage_queue` → segment/ClickHouse path ограничивает pipeline;
- queue depths низкие, но CPU высокий → смотреть `perf`, regex mix, ClickHouse/UI workload.

High-watermark важнее единичного текущего значения при burst traffic.

### Resource panel в UI

Минимизированная панель справа в navbar показывает:

- `CPU` — CPU процесса, нормализованный относительно `bazalt_cpu_budget`;
- `RSS` — resident memory процесса BAZALT;
- `PIPE` — максимальный текущий процент заполнения bounded pipeline queue;
- `DROPS` — новые backend + capture-to-flow drops в секунду.

По клику открывается подробный режим. Memory denominator берётся из конечного Linux cgroup limit (Docker/systemd), если он существует; иначе используется host `MemTotal`. Панель получает данные через `GET /api/resources` каждые 2 секунды. Endpoint читает только atomic metrics и Linux `/proc`/cgroup pseudo-files и не делает запросов в ClickHouse/PostgreSQL.

Красный индикатор означает свежие pipeline/backend drops, parse errors либо критическое давление CPU/memory/queue; жёлтый — приближение к configured thresholds. Для точной диагностики потерь всё равно использовать `/metrics`, потому что UI показывает operational summary, а не заменяет Prometheus history.


## Management / retention

Вкладка `MANAGE` показывает три независимых слоя storage:

- ClickHouse: active-part disk size, physical row count, parts и average bytes/row по таблицам;
- PostgreSQL: размер control-plane database;
- immutable payload segments: число файлов и суммарный размер.

Retention принимает возраст, а не абсолютную дату. Перед удалением UI требует ввести `DELETE`. Backend затем:

1. берёт maintenance write-lock, блокируя historical replay;
2. seal/rotate текущего payload segment;
3. ждёт metadata barrier, чтобы старые queued rows уже были записаны в ClickHouse;
4. синхронно выполняет ClickHouse mutations для expired traffic metadata;
5. удаляет только immutable segment files, в которых newest record старше cutoff.

ClickHouse может освободить физические obsolete parts не мгновенно после завершения mutation, поэтому `bytes_on_disk` после cleanup иногда уменьшается с задержкой. Raw-PCAP archive (`BAZALT_RAW_CAPTURE=true`) retention этой операцией не удаляется.

## Matcher tuning

`BAZALT_MATCH_OVERLAP_BYTES` теперь относится главным образом к regex groups. Literal/binary rules автоматически удерживают только длину самого длинного literal минус один байт.

Если regex rules не требуют большого cross-chunk контекста, можно уменьшить:

```env
BAZALT_MATCH_OVERLAP_BYTES=4096
```

Не уменьшайте без проверки паттернов, которые должны совпадать через границы chunk.

## Replay

Replay автоматически уступает live pipeline:

```env
BAZALT_REPLAY_PAUSE_PCT=70
```

При достижении этого процента в любой live queue backfill ждёт. Replay threads дополнительно имеют `nice +10` на Linux.

## Packet logging

Остаётся выключенным по умолчанию:

```env
BAZALT_PACKET_LOGGING=false
```

`RUST_LOG` не включает payload logging автоматически.

## Legacy environment

Backend принимает `PACKMATE_*` только как migration aliases, если соответствующий `BAZALT_*` отсутствует. В auto CPU mode старые фиксированные worker counts намеренно игнорируются.

Внутренний PostgreSQL/ClickHouse namespace `packmate` сохранён для совместимости с уже созданными volumes.

## UI query load

BAZALT 0.3 throttles WebSocket-triggered list refreshes to 500 ms and performs full periodic reconciliation every 30 s instead of every 3 s. This significantly lowers ClickHouse CPU when the browser remains open during heavy traffic.


## v0.4 traffic-fidelity diagnostics

Основные переменные:

```env
BAZALT_MAX_OOO_BYTES=4194304
BAZALT_MAX_OOO_SEGMENTS=8192
BAZALT_TCP_GAP_TIMEOUT_MS=1000
BAZALT_IP_FRAGMENT_CACHE_BYTES=16777216
BAZALT_IP_FRAGMENT_MAX_DATAGRAMS=4096
BAZALT_IP_FRAGMENT_TIMEOUT_SECS=30
BAZALT_TUNNEL_DECAPSULATION=true
```

`BAZALT_MAX_FLOW_BYTES` сохранён только для совместимости и в v0.4 не обрывает sequence tracking. Если OOO cache достигает byte/interval limit, gap остаётся дольше `BAZALT_TCP_GAP_TIMEOUT_MS` или flow закрывается с buffered OOO data, BAZALT фиксирует explicit gap и продолжает/дренирует наблюдавшиеся байты.

Диагностика fidelity:

- `bazalt_capture_truncated_packets_total` — frame/L3/L4 был короче declared length и не попал в TCP state;
- `bazalt_ip_fragments_received_total` / `bazalt_ip_fragments_reassembled_total` — fragment slow path;
- `bazalt_ip_fragment_overlap_drops_total` — конфликтующий overlap; datagram отброшен целиком;
- `bazalt_ip_fragment_expired_total` — incomplete datagram не завершился до timeout;
- `bazalt_ip_fragment_evicted_total` — fragment cache исчерпал byte/datagram budget;
- `bazalt_tcp_gap_events_total` / `bazalt_tcp_gap_bytes_total` — BAZALT ACK-inferred/timeout/pressure/close recovery зафиксировал stream discontinuity и продолжил после gap;
- `bazalt_tcp_rejected_resets_total` — RST не совпал с ожидаемым receive-next и не разрушил flow state.

При `BAZALT_EARLY_PORT_FILTER=true` BPF специально пропускает fragments, поддерживаемые tunnel encapsulations и tagged Ethernet frames; окончательный service-port allow-list применяется после reassembly/decapsulation. Если service list пуст, BPF дропает всё ещё в kernel.
