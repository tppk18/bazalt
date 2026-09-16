# BAZALT 0.4.0 — traffic-fidelity release

## Fidelity fixes

- IPv4 and IPv6 fragmentation use a bounded 64-shard slow-path cache; normal unfragmented packets remain lock-free.
- Conflicting/partial IP fragment overlap invalidates the datagram; exact duplicate fragments are ignored.
- VLAN/QinQ identity participates in flow identity; optional VXLAN, GRE and IP-in-IP decapsulation is bounded to three levels and includes direction-independent outer tunnel endpoints in overlay identity.
- Raw PCAP retention now receives every backend frame before parser/service filtering, preserving malformed/incomplete-fragment evidence.
- Declared L3/L4 lengths larger than captured data are rejected and counted instead of silently advancing TCP sequence state.
- TCP uses extended 64-bit sequence ordering, first-seen overlap normalization on the OOO slow path, original OOO timestamps, tentative out-of-order FIN validation, sequence-aware closure and conservative exact-RCV.NXT RST handling.
- The peer cumulative ACK watermark provides bounded gap inference even when the ACK arrived before later OOO data; timeout/OOO pressure/flow-close recovery resynchronizes or drains observed later bytes instead of killing the flow.
- Same-ISN SYN retransmissions stay in the same generation; a bounded recent-close tombstone suppresses only empty/control tail retransmissions.
- `BAZALT_MAX_FLOW_BYTES` is retained as a compatibility setting but no longer terminates analysis of long streams. Memory bounds are enforced by OOO/fragment/body limits.
- HTTP is connection-aware for HEAD/CONNECT/1xx/101, validates repeated Content-Length and transfer-coding order, preserves framing when fixed/chunked bodies exceed analysis limits, and uses bounded prefix-aware line resynchronization after an explicit TCP offset gap or malformed message.
- HTTP delimiter scans are incremental; chunked over-limit payload is consumed without retaining the discarded tail.
- Optional early libpcap BPF explicitly admits IP fragments, supported tunnel encapsulations and tagged Ethernet frames so port filtering can happen after reconstruction; an empty service set drops everything in-kernel.

## Performance contract

- ordinary in-order TCP with no OOO state stays zero-copy and does not touch the interval tree;
- unfragmented IP never takes a fragment-cache mutex;
- raw-frame `Bytes` cloning exists only when raw capture is enabled and is reference-counted;
- ACK tracking adds only sequence extension/comparison until OOO or pending-FIN recovery is needed;
- HTTP body limits switch to skip/framing mode rather than buffering the rest of the body.

---

## Previous 0.3.3 implementation baseline

# BAZALT 0.3.3 — packet-loss/capture correctness hotfix

## Hotfix 0.3.3

- AF_XDP now auto-discovers all interface RX queues when no explicit queue list is supplied; startup is all-or-nothing across that queue set so one failed XSK cannot silently remove an RSS bucket.
- AF_XDP `XDP_USE_NEED_WAKEUP` refill handling now wakes RX immediately when the FILL ring requests it instead of waiting for the RX ring to drain.
- AF_XDP preserves descriptor `options`, supports scatter/gather when available and reconstructs `XDP_PKT_CONTD` packets across receive batches. A jumbo MTU is rejected to libpcap fallback when only lossy single-buffer AF_XDP is available.
- Capture-backend counters expose kernel/XSK/libpcap drops separately from the bounded `capture -> flow` drops.
- The capture-to-flow edge uses a configurable short `send_timeout` (`BAZALT_CAPTURE_ENQUEUE_TIMEOUT_US`, default 250 us) instead of unconditional drop-on-first-full.
- Live libpcap uses a 64 MiB capture buffer and `pcap_dispatch()` batching.
- TCP reassembly learns sequence space from SYN/ACK-only packets, keeps a longer retransmission for an already-buffered out-of-order sequence, and no longer exhausts the flow byte limit with duplicate retransmitted payload.
- Frames deliberately ignored by the parser (unsupported EtherType/L4 and IP fragments) are counted as `bazalt_packets_ignored_total` instead of disappearing from the accounting model.
- Early libpcap service-port BPF remains opt-in (`BAZALT_EARLY_PORT_FILTER=false` by default).
- UI resource telemetry adds a sticky compact `CPU/RSS/PIPE/DROPS` navbar panel and a detailed process/pipeline view. A separate lightweight `/api/resources` endpoint samples Linux `/proc` and finite cgroup memory limits without querying ClickHouse/PostgreSQL.
- Control-plane authentication is fail-closed by default: UI sessions and HTTP Basic protect `/api/*`, `/metrics` and WebSocket access; unauthorized requests return 403 before expensive handlers. Auth can be disabled explicitly with `BAZALT_AUTH_ENABLED=false` for development.
- UI now includes a `MANAGE` view with ClickHouse/PostgreSQL/payload storage size breakdown and confirmed age-based retention cleanup coordinated with replay and metadata barriers.
- Resource telemetry labels were expanded to remove ambiguous abbreviations (`PKT/STREAM`, `Packet -> Flow`, explicit backend/queue drops).

## Scope

The service-port capture policy remains unchanged, but capture correctness and
loss observability are now part of this hotfix in addition to the existing
adaptive post-capture work.

## Adaptive CPU topology

`BAZALT_CPU_AUTO=true` is now the default topology mode.

At startup BAZALT combines the Linux cgroup/container affinity mask from `sched_getaffinity()` with `available_parallelism()` so both cpuset and common CPU-quota limits are respected and creates one machine-wide CPU budget instead of independently spawning `N` flow + `N` L7 + `N` matcher + default Tokio workers.

Default policy:

- 1–4 logical CPUs: use the available CPU set because the three stateful post-capture stages must remain alive;
- >4 logical CPUs: reserve approximately 25% as headroom for ClickHouse, PostgreSQL, kernel/network work and the OS;
- an explicit `BAZALT_CPU_BUDGET=N` overrides the automatic headroom;
- flow/L7/matcher receive approximately 30%/40%/30% of the processing budget because the expected workload is HTTP-heavy;
- Tokio control plane receives 1 worker on small hosts and 2 on larger hosts;
- historical replay receives only 1–3 workers and runs at Linux `nice +10` in addition to queue-pressure throttling;
- flow, L7 and matcher native workers are pinned to the planned cpuset.

Manual worker counts and CPU lists remain available with `BAZALT_CPU_AUTO=false`.

## Matcher CPU/memory reductions

The matcher no longer uses one fixed 8 KiB overlap for every stream/view.

- text/binary rules retain exactly `max_literal_length - 1` bytes;
- the configured `BAZALT_MATCH_OVERLAP_BYTES` window is retained only for a service/view group containing regex rules;
- rules are compiled into service + content-view groups, so traffic for one service/request side does not traverse unrelated automata;
- a lock-free active-view bitmask drops content views with no possible active rule before they enter matcher shard queues, avoiding worker wakeups/copies when only a subset of views is searched;
- literal/binary scanning no longer copies `tail + full current chunk`; the current chunk is scanned directly and only a small boundary bridge is allocated for cross-chunk matches;
- matcher tails are dropped on stream-offset gaps, preventing false cross-message matches and useless retained state;
- live matcher flow-close cleanup tracks the small set of view keys per flow and removes them directly instead of `retain()`-scanning every active matcher tail;
- live workers cache the current compiled `Arc` and load a new snapshot only when the pattern generation changes;
- live and replay matcher state uses `AHashMap`.

`Anywhere` / Request / Response semantics from 0.2.0 are preserved.

## Flow engine

- active flow tables use randomized `AHashMap` instead of the standard SipHash-based map on the per-packet lookup path;
- lazy timeout heaps are periodically rebuilt when stale closed-flow timers materially exceed active-flow state;
- aggregate queue depth/high-watermark counters now represent all shards, so replay throttling sees the actual hottest pipeline pressure rather than whichever shard happened to update a gauge last.

## HTTP/L7 processing

The streaming HTTP parser was moved away from front-draining `Vec<u8>` buffers:

- `BytesMut::split_to()` removes parsed prefixes without memmoving the remaining HTTP stream;
- `httparse` parses request/status lines and headers from bytes;
- only fields BAZALT actually indexes are allocated as strings (`Host`, `User-Agent`, `Content-Type`, method/path);
- fixed/chunked body records transfer `Bytes` instead of cloning body vectors;
- service/parser maps use `AHashMap`.

Compressed bodies still require bounded accumulation/decompression because decoded bytes do not exist in the wire representation.

## Segment/storage processing

- segment writer no longer constructs `metadata + complete payload` in a temporary `Vec` for every record;
- CRC is computed incrementally over metadata prefix and `Bytes` payload and the two slices are written directly;
- metadata batches coalesce for up to 2 ms / 2048 events before ClickHouse insertion, reducing tiny HTTP insert requests;
- content API groups segment reads by file, canonicalizes/opens each segment once, then seeks all requested records from the same open reader instead of open/canonicalize per content record;
- frontend live updates are throttled to one refresh burst per 500 ms and periodic reconciliation is reduced from 3 s to 30 s; `new_match` badges are applied locally immediately when possible.

## Replay

- replay worker count follows the adaptive CPU budget;
- replay threads are lowered to `nice +10` on Linux;
- existing live queue-pressure throttling remains and now uses exact aggregate queue gauges;
- replay dispatch no longer uses `DefaultHasher` for every content record.

## Observability

The UI now polls `GET /api/resources` every 2 seconds for process CPU time, RSS/virtual memory, cgroup-or-host memory pressure, load average, threads/open FDs, ingress rate, queue pressure and loss/error deltas. CPU percentage is computed client-side from process CPU-time deltas and normalized to the configured BAZALT CPU budget.

`/metrics` additionally exposes:

- `bazalt_cpu_available`;
- `bazalt_cpu_budget`;
- `bazalt_tokio_workers`;
- `bazalt_flow_workers`;
- `bazalt_l7_workers`;
- `bazalt_matcher_workers`;
- `bazalt_replay_workers`;
- exact aggregate queue depth/high-watermarks and `bazalt_live_pressure_pct`.

The startup log prints the selected adaptive plan.

## Retained behavior

- BAZALT terminal UI and Packmate-style flow feed;
- HTTP/tcp_raw presentation deduplication with hidden-raw match projection;
- service-port allow-list;
- live open-flow snapshots;
- automatic pattern backfill;
- bounded queues;
- packet/payload logging disabled by default;
- legacy `PACKMATE_*` environment aliases and existing `packmate` database namespace for volume compatibility.
