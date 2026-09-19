# Архитектура BAZALT

## Общая схема

```text
capture backend
      │
      ▼
bounded flow queues
      │
      ▼
flow shards             TCP reassembly / UDP state
      │
      ▼
bounded L7 queues
      │
      ▼
HTTP/L7 shards           streaming HTTP parser
      │
      ├────────► segment writer
      │
      ▼
bounded matcher queues
      │
      ▼
matcher shards           service/view scoped rules
      │
      ▼
metadata writer          ClickHouse batches
```

Capture is queue-complete by default: AF_XDP discovers all interface RX queues
unless an explicit queue list is provided. Queue-set initialization is
all-or-nothing; a failed queue causes a global libpcap fallback instead of a
partially active RSS topology. The capture->flow edge uses a short configurable
bounded wait and exposes userspace drops separately from backend/kernel drops.

AF_XDP replenishment honors `XDP_USE_NEED_WAKEUP`; descriptor options are kept
so multi-buffer packets can be reconstructed across receive batches. TCP
sequence state is seeded by control-only SYN/ACK packets before payload arrives,
which prevents a later out-of-order payload from becoming an incorrect stream
origin.

Every inter-stage queue remains bounded. One flow hashes deterministically to one worker in every stateful stage, preserving in-flow ordering without global flow locks.

## Adaptive CPU plan

BAZALT must run on unknown A/D hardware, including Docker/cgroup-limited hosts. `BAZALT_CPU_AUTO=true` therefore uses `sched_getaffinity()` rather than assuming host CPU numbers.

The planner creates a single CPU budget for the process. This prevents the old topology where every subsystem independently created `available_parallelism()` workers.

For more than four available logical CPUs, the default budget uses roughly 75% of the allowed cpuset and leaves the rest available to ClickHouse, PostgreSQL, kernel networking and the OS. `BAZALT_CPU_BUDGET` overrides this policy.

Within the budget:

```text
capture reservation     small hint only; capture algorithm unchanged
Tokio control plane     1–2 workers
flow                    ~30% of post-capture budget
HTTP/L7                 ~40%
matcher                 ~30%
replay                  1–3 low-priority background workers
```

On very small machines BAZALT keeps at least one worker for each flow/L7/matcher state machine. This can create slight thread oversubscription, but prevents collapsing pipeline stages into shared mutable state.

Flow, L7 and matcher native workers are pinned to planned CPUs. Historical replay is not allowed to take priority over live processing.

## Flow engine

Active flows are owned by one shard and stored in randomized `AHashMap` tables. This removes general-purpose SipHash cost from the per-packet lookup path while retaining per-process random hashing.

Timeout handling uses lazy deadlines. Because a closed short flow can leave a stale deadline until its original timeout, the heap is periodically rebuilt when stale entries materially exceed the active flow count. Steady-state timeout memory therefore tracks active/recent flows rather than `connection_rate × timeout` without bound.

Open flows become visible after the first payload and receive throttled snapshots; FIN/RST is not required for live presentation.

## HTTP/L7

HTTP parsing is streaming and flow-affine.

The parser uses `BytesMut`:

```text
incoming Bytes
    ↓ extend
BytesMut buffer
    ↓ split_to()
headers/body Bytes
```

Parsed prefixes are detached without shifting the remainder of the stream. `httparse` reads the header bytes; only indexed fields are materialized into owned strings. Body `Bytes` are transferred directly into content records.

For compressed HTTP bodies, BAZALT keeps a bounded compressed accumulator and creates a separate decoded record because decoded bytes have no zero-copy representation in the wire stream.

## HTTP representations and raw dedupe

Internal storage still distinguishes:

```text
tcp_raw                         canonical reassembled TCP stream
http_request/response_*         semantic presentation
*_decoded_body                  derived plaintext
```

The content API suppresses a `tcp_raw` record only when its complete stream range is represented by semantic HTTP wire records. Raw data remains available internally for fallback, replay and `Anywhere` matching.

## Matcher architecture

Pattern databases are compiled by two dimensions:

```text
service scope
    ×
content view
```

One content record therefore scans only:

1. a global group for its exact view, if present;
2. a service-specific group for its exact view, if present.

Unrelated service/request/response rules do not enter the hot path.

### Literal/binary matching

Aho–Corasick scans the current `Bytes` directly. Cross-chunk matching allocates only a small bridge containing the retained suffix plus at most `max_literal_length - 1` bytes from the new chunk.

Retained state is exactly:

```text
max_literal_length - 1
```

for literal-only groups.

### Regex matching

Regex groups retain the bounded `BAZALT_MATCH_OVERLAP_BYTES` window. Only groups containing regex pay that cost. `RegexSet` is used as a prefilter before exact regex offset recovery.

### Continuity

Matcher state stores the end stream offset of its tail. A tail is reused only when:

```text
previous_end_offset == current.stream_offset
```

This prevents a pattern from crossing gaps between separate HTTP semantic records/messages merely because they share `(flow, direction, view)`.

### Pattern updates

Each matcher worker keeps a local `Arc<CompiledPatternSet>` and compares an atomic generation number. `ArcSwap::load_full()` is executed only after a real ruleset update, not per content record.

## Segment store

Segment records remain append-only and CRC protected.

The writer no longer serializes `metadata + payload` into one temporary full-size vector. It now:

1. serializes the small metadata prefix;
2. updates CRC with prefix;
3. updates CRC with the immutable payload `Bytes`;
4. writes record header, prefix and payload separately.

This removes one full payload copy per stored content record.

When UI/API requests many records from one flow, locations are grouped by segment path. One file is canonicalized/opened once and all requested offsets are read from the same `BufReader`.

## Metadata storage

PostgreSQL remains the control plane; ClickHouse remains flow/HTTP/match/content-index metadata storage.

Metadata writer batches up to 2048 events with a short 2 ms coalescing window. This reduces CPU and HTTP overhead from many tiny ClickHouse inserts while keeping live latency low.

## Replay

Replay uses the same compiled matching logic as live processing. Worker count follows the adaptive CPU budget, threads run at `nice +10`, and replay pauses when aggregate bounded-queue pressure reaches the configured threshold.

Queue pressure is calculated from exact aggregate enqueue/dequeue accounting across all shards, not from a sample of one shard.

## UI / query pressure

WebSocket events remain control-plane triggers, but the frontend no longer converts every event into an immediate full ClickHouse refresh. Continuous event streams are throttled to at most one refresh burst per 500 ms; the 30 s timer is only periodic reconciliation. A `new_match` event can update an already-present flow badge locally before persistence-driven refresh.

This does not change the flow-based UI model; it only removes avoidable query CPU amplification.

### Matcher flow-close cleanup

Live matcher maintains a compact per-flow list of active stream/view tail keys. Closing a short-lived flow removes only those keys instead of scanning the entire tail table, keeping close cost proportional to views per flow rather than total active matcher state.

### Matcher ingress prefilter

An atomic active-view bitmask is published with the compiled pattern generation. Content views that cannot match any active global/service rule are discarded before the matcher shard queue. Service-specific filtering still happens inside the compiled service/view partition; the bitmask is intentionally only a cheap coarse prefilter.

## Authentication and management plane

Static login assets remain public, but API/metrics/WebSocket routes are guarded by the outer auth middleware. With `BAZALT_AUTH_ENABLED=true`, the middleware validates either an in-memory session cookie or HTTP Basic credentials and returns `403` before handler execution on failure. This keeps unauthenticated requests away from ClickHouse/PostgreSQL and replay/storage control paths.

Retention shares an `RwLock` maintenance gate with historical replay. Replay owns a read guard from immutable segment snapshot through job completion; cleanup requires the write guard. Retention seals the active segment, executes a metadata barrier against the single ordered metadata channel, mutates ClickHouse, then deletes only segment files proven to contain no record at or after the cutoff. This avoids deleting payload files underneath replay and avoids an index row being inserted after its old segment was removed.



## v0.4 traffic-fidelity pipeline

Unfragmented Ethernet/IP remains the dominant lock-free path. Only packets carrying IPv4/IPv6 fragmentation enter a 64-shard bounded fragment cache. Completed datagrams return to the normal L4 parser; conflicting overlaps invalidate the entire datagram. `l2_domain` carries VLAN/tunnel identity into `FlowKey`; tunnel identity includes a direction-independent outer endpoint pair plus VNI/GRE key/type, preventing identical inner 4-tuples from different L2/overlay domains from sharing TCP state.

TCP halves use an extended `u64` sequence coordinate. In-order traffic emits the existing `Bytes` slice directly. `BTreeMap` interval normalization and compact copies are used only while OOO state exists. Existing intervals win conflicts. The highest peer cumulative ACK is retained as a capture-loss inference signal and can advance over a missing range once an OOO segment or pending FIN supplies a sequence landmark. Small unresolved holes also recover after a bounded OOO-only timeout, and buffered bytes are drained with explicit gaps when a flow closes. Stream offsets include skipped gaps, so L7 observes a discontinuity instead of falsely concatenated bytes. FIN is consumed in sequence space; an out-of-order FIN remains tentative until peer ACK or a contiguous FIN retransmission validates it, and conflicting later payload invalidates an unacknowledged tentative FIN. An RST closes a synchronized half only at the expected sequence.

HTTP state is per connection rather than per direction only. A small request-method queue supplies HEAD/CONNECT response semantics. TCP offset discontinuity clears request correlation and enters bounded prefix-aware line-oriented resynchronization, preserving long request-line candidates split across chunks. Fixed/chunked bodies above the analysis limit remain framed but are no longer materialized, so resource limits do not desynchronize subsequent messages.

## IPv4 topology and enforcement

Traffic topology is deliberately outside the flow/L7 hot path, but it is service-scoped. Ordinary IPv4 TCP/UDP whose transport endpoints cannot match any configured service is rejected by a tiny pre-decode classifier. Fragments, supported tunnels and other ambiguous frames are decoded conservatively; only after decoding does a remote IPv4 packet whose actual destination port is configured contribute to topology counters. Accepted source counters remain worker-local and are merged into shared topology state approximately every 250 ms, avoiding a shared lock/atomic update on every packet.

The default automatic grouping is source `/24`, matching the common A/D convention where each team owns a subnet. Individual source IPs remain visible inside the group. A source becomes visible only after service-directed ingress. Idle source nodes are removed from the live view after `BAZALT_TOPOLOGY_SOURCE_TTL_SECS`. The UI renders the busiest groups radially around the configured service ports and keeps a detailed table below the star map.

Real traffic punishment is deliberately broader than topology visibility. Once an operator selects a visible source or automatic group, enforcement is an ingress source policy independent of destination port. When `BAZALT_THROTTLE_ENABLED=true`, BAZALT embeds and loads a small XDP program directly on `BAZALT_INTERFACE`; a second enforcement-interface setting does not exist. `/32` rules override broader `/24` rules by longest-prefix match. Each active rule stores a drop percentage, monotonic expiry and kernel-side seen/dropped counters. The XDP program probabilistically returns `XDP_DROP` before the normal network stack; it never fakes enforcement by merely suppressing analysis in userspace. If AF_XDP capture was requested, BAZALT intentionally uses libpcap as the effective capture backend so the throttle program remains the sole XDP ingress owner and `XDP_PASS` traffic continues through the host network stack. The loader first attempts a native BPF-link attachment, whose FD owns the XDP lifecycle. If BPF-link attachment is unavailable it falls back to libbpf netlink attach, which may remain native or select generic/SKB as needed; `XDP_FLAGS_UPDATE_IF_NOEXIST` prevents replacement of a foreign XDP program. All drop rules carry a 1–3600 second monotonic expiry checked in-kernel.

The topology source table is explicitly bounded (`BAZALT_TOPOLOGY_MAX_SOURCES`, default 65536). Once saturated, unseen source addresses are aggregated into overflow counters instead of allocating unbounded state; existing tracked sources continue to receive updates. API/UI snapshots are independently bounded to the 256 busiest groups and 2048 busiest source rows. Aggregate accounting remains complete for all tracked sources, while `view_truncated` and `returned_*` disclose presentation truncation.
