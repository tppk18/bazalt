# BAZALT 0.4.1.6 — P0 correctness and crash-safety hotfix

Cargo reports `0.4.1+hotfix.6`; the external/API release label is `0.4.1.6`.

## Fixed in 0.4.1.6

- **Live matcher overload no longer silently loses accepted content.** Content first attempts non-blocking matcher admission; a full matcher shard then applies backpressure through the existing bounded pipeline instead of discarding work. `matcher_queue_backpressure_total` exposes this condition; `matcher_queue_drops_total` is reserved for a disconnected matcher. Best-effort `FlowClosed` tail cleanup remains non-blocking and has its own `matcher_housekeeping_drops_total` metric.
- **Remote source-port collision no longer bypasses service scoping.** Before full decode, remote ingress is admitted only when its destination port is configured. Local egress is admitted by source service port so response reconstruction remains intact. New-flow admission remains destination-only.
- **Dynamic live BPF updates are fail-safe.** The live filter uses directional service semantics and avoids `protochain` in the kernel program. If the optimized filter cannot be installed, BAZALT installs a broad fail-open filter and keeps the exact userspace gate authoritative. If even fail-open installation fails, the supervised capture worker stops instead of running with a stale restrictive filter.
- **Segment rotation is now a crash-consistent commit boundary.** Before opening the next segment BAZALT fsyncs payload bytes, publishes every pending `content_index` row without draining unsent suffixes, waits for the local metadata spool durable barrier, and only then rotates.
- **Historical orphaned payload indexes are healed once on upgrade.** A durable recovery marker triggers one full retained-segment index rebuild on the first 0.4.1.6 startup; later startups only recover the segment that was active at the previous crash.
- **Netlink XDP fallback can recover its own stale attachment after an abnormal exit.** Recovery checks the attached XDP program name and exact BPF tag before detach, keeps `UPDATE_IF_NOEXIST`, and uses a per-interface ownership lock. Foreign XDP programs are not replaced.

## Verification gates

`./scripts/verify_source.sh` now includes two distinct P0 source gates: `verify_p0_fixes.py` for local implementation contracts and `review_p0_integration.py` for cross-file pipeline/failure-ordering contracts, in addition to fixture, repository invariant, hot-path, JS, shell, YAML, Rust fmt/clippy/test and release-build gates.

---

# BAZALT 0.4.1.5 — service-scoped topology and radial map

This hotfix aligns Traffic Topology with the A/D service model. Cargo reports `0.4.1+hotfix.5`; the external/API release label is `0.4.1.5`.

## Fixed in 0.4.1.5

- Topology and participant traffic statistics now count only remote IPv4 packets whose actual destination port is one of the configured services. Off-service traffic is intentionally absent from team/source statistics.
- Throttle semantics remain source-wide. After a `/32` or automatic group rule is installed, XDP still matches only source IPv4/prefix and applies the selected drop percentage across every destination port.
- Added a lightweight pre-decode IPv4 service classifier so ordinary unrelated TCP/UDP is rejected before the full packet decoder. Fragments and supported tunnels stay conservative and are decided after bounded reassembly/decapsulation.
- New flow allocation is directional: a packet can create flow/L7 state only when it is actually addressed to a configured service destination port. A hostile sender using a configured value as its source port can no longer create a false service flow. Existing admitted flows continue to process reverse traffic normally.
- `packets_received`/`packet_bytes` are now incremented only after flow admission, so source-port collisions/off-service new flows cannot leak into accepted-service metrics.
- Post-decode service classification uses one immutable `ArcSwap` snapshot for both topology visibility and bidirectional service-flow membership; the rare new-flow path performs its own directional admission check.
- With an empty service registry, capture rejects frames before the full decoder even on AF_XDP backends.
- `BAZALT_EARLY_PORT_FILTER=true` is compatible again and is now the default; backend BPF is an optimization while the userspace service gate remains authoritative.
- `GET /api/topology` now returns the current `service_ports` list so the UI can make the analysis scope explicit.
- Replaced the topology-only list presentation with a radial/star map centered on BAZALT/service ports. Automatic source groups form the rays, while the detailed per-source table remains available below for precise throttle actions.
- Updated release/static verification to prevent regressions back to pre-service topology accounting.

## Semantics

If `192.168.0.2` sends to a configured port, it becomes visible in topology/statistics. If the operator then applies a throttle to `192.168.0.2`, the kernel rule penalizes all IPv4 traffic from `192.168.0.2`, including traffic to ports that are not configured services.

---

# BAZALT 0.4.1.4 — throttle configuration and XDP ownership correction

This hotfix corrects the remaining design mistakes in the first Traffic Topology/XDP enforcement implementation. Cargo reports `0.4.1+hotfix.4`; the external/API release label is `0.4.1.4`.

## Fixed in 0.4.1.4

- Removed `BAZALT_THROTTLE_INTERFACE` from the user-facing configuration. Enforcement is always attached to `BAZALT_INTERFACE`; a different interface no longer exists as a supported topology.
- Added the explicit safety switch `BAZALT_THROTTLE_ENABLED` (default `false`). Enabling it means the operator intentionally arms real packet drops on the capture ingress.
- When throttle is enabled and AF_XDP was requested, effective capture is passive libpcap. RX queue discovery/CPU planning now use the effective mode, so unused AF_XDP queues are not probed or reserved.
- Reworked XDP ownership: BAZALT first attempts a native BPF link for fail-safe process lifecycle; if BPF-link attach is unavailable it falls back through libbpf netlink attach, which may select native or generic/SKB mode. The fallback uses `XDP_FLAGS_UPDATE_IF_NOEXIST` and never replaces a foreign XDP program.
- The loader exposes whether enforcement is `native-link`, `native-netlink`, or `generic-skb-netlink`. Netlink cleanup checks the exact BPF program id before detach so Bazalt does not remove a program that another component replaced.
- Throttle targets are now restricted to exactly one automatic group prefix (for example `/24`) or one host (`/32`); hidden intermediate CIDRs such as `/25` are rejected.
- Permanent drop rules were removed. Every rule has a finite `1..3600s` TTL; the kernel checks expiry itself, so even a generic/netlink enforcement rule stops dropping after its deadline if userspace crashes.
- Active throttle rules are rendered independently of the live source list, so a `100%` drop cannot make its own Disable control disappear after the source TTL.
- Passive libpcap topology ignores frames sourced from the capture interface MAC, preventing the host's own outgoing traffic from being misclassified as a participant sender while keeping bidirectional packets available to flow/L7 analysis.
- Complete topology accounting now rejects `BAZALT_EARLY_PORT_FILTER=true`; otherwise off-service/spam IPv4 could be hidden in kernel before Topology observes it.
- Active rule UI derives live matched/drop rates from consecutive kernel counters, so operators can still see pre-drop pressure after a throttle is applied instead of only the survivor rate from libpcap.
- API/UI/docs/static verification were updated to the same-interface-only model.

## Operational note

`BAZALT_THROTTLE_ENABLED=true` is destructive by design: matching ingress packets can be returned as `XDP_DROP`. Rules always expire within one hour. When enabled, live topology rates from libpcap represent traffic that survived XDP; per-rule kernel counters are authoritative for matched/dropped traffic. On a netlink fallback, a hard process kill may leave a pass-only XDP program attached after all rule TTLs expire; this no longer causes indefinite packet loss, but a native-link-capable NIC has the cleaner crash lifecycle.

---

# BAZALT 0.4.1.2 — second stabilization tranche

This hotfix implements a coherent second half-step of the pre-feature P0/P1 work while deliberately leaving the ordering/disk-retention redesign for the next tranche. Cargo reports `0.4.1+hotfix.2`; the external/API release label comes from `VERSION` and is `0.4.1.2`.

## Fixed in 0.4.1.2

- Restored the lost new-flow discriminator in `flow/mod.rs` using the behavior confirmed by the older 0.4.1 source, while preserving the newer bounded admission path.
- ClickHouse is no longer a synchronous metadata acceptance dependency. Metadata batches are fsync'd to a bounded local spool and projected asynchronously with an explicit HTTP timeout; replay checkpoints wait for local durability rather than ClickHouse availability.
- Clean shutdown also waits only for local spool durability, so a ClickHouse outage cannot hang SIGTERM. Retention still uses the stronger projected barrier before destructive deletion.
- Critical capture/raw, flow, L7, matcher, segment, metadata-spool and metadata-projector workers are supervised. Unexpected exit marks health false, triggers ordered shutdown and returns a non-zero process result.
- Added a cheap protected `/api/health` endpoint and made the Docker HEALTHCHECK auth-aware. `/api/status` still exposes richer status but is no longer used as the container liveness probe.
- PostgreSQL/ClickHouse compose credentials no longer ship as known production passwords; ClickHouse now uses a dedicated authenticated user. The smoke harness supplies isolated test-only credentials.
- Invalid boolean environment values now fail startup instead of silently falling back to defaults.
- HTTP gzip/deflate decoding now has both a reduced absolute output cap (16 MiB default) and a configurable expansion-ratio cap (`BAZALT_HTTP_MAX_DECODE_RATIO`, default 32). This bounds the previous 128 MiB decoded allocation; full streaming/off-thread decoding remains deferred.
- Startup reconciles the newest recovered segment into the durable metadata spool, closing the segment-bytes/content-index crash window for the active crash tail.
- Metadata spool occupancy/capacity are exported as Prometheus gauges and participate in live-pressure throttling, so historical replay yields before consuming the entire outage buffer.
- Source verification no longer silently skips Rust checks when `cargo` is missing; missing Rust tooling is a hard verification failure.

## Intentionally still open after 0.4.1.2

- Exact live/replay/deferred activation watermark (`ingest_seq` / `activation_seq`).
- A true durable deferred live-matcher queue. Live matching remains blocking after storage acceptance rather than silently dropping matches when saturated.
- Full streaming/off-thread HTTP decompression. The current change bounds amplification but decoding still executes in the L7 worker.
- Global normalized-segment/raw-PCAP disk quota and automatic pressure retention policy.
- Two-tier embryonic/established flow admission for tuple-flood resistance.
- Wall-clock TCP gap timers, DLT validation, BPF update failure policy, pattern soft-delete and the remaining P1/P2 items.
- `Cargo.lock` / `--locked` reproducible dependency resolution.

---

# BAZALT 0.4.1.1 — traffic-fidelity release

## 0.4.1.1 P0 stabilization tranche

This patch intentionally fixes the first, relatively independent half of the v0.4.1 P0 backlog without restructuring the capture/L7 pipeline. The external release label is `0.4.1.1`; because Cargo requires three-component SemVer, `Cargo.toml` uses `0.4.1+hotfix.1` while the API reports the release label from `VERSION`.

- PostgreSQL is bound to `127.0.0.1:65001`; ClickHouse HTTP is bound to `127.0.0.1:65002`; the unused native ClickHouse port is no longer published.
- Historical replay checkpoints are commit points: each segment waits for matcher workers, the hit collector, and `MetadataSink::barrier()` before `segments_done` advances.
- Match timestamps inherit `ContentRecord.ts_ns`, keeping replayed matches aligned with traffic time and retention semantics.
- Immutable segment scans are strict. CRC/encoding/interior-truncation errors propagate to replay/retention instead of being interpreted as EOF. Startup may truncate only a physically incomplete tail of the newest segment; a complete record with a bad CRC remains a hard error.
- Segment record length is checked against `BAZALT_SEGMENT_MAX_RECORD_BYTES` before payload allocation, and the writer enforces the same bound.
- Active flow state has a global `BAZALT_MAX_ACTIVE_FLOWS` admission limit. The global atomic CAS is executed only for a new tuple, leaving existing-flow packet processing unchanged.
- Match amplification is bounded by `BAZALT_MATCH_MAX_HITS_PER_PATTERN` and `BAZALT_MATCH_MAX_HITS_PER_RECORD`; the total budget counts candidate occurrences so suppressed repetitive matches cannot force unbounded enumeration.

New observability counters:

- `bazalt_flow_state_rejections_total`;
- `bazalt_matcher_match_limit_events_total`.

### Deliberately deferred to the second P0 tranche

The following known issues are not represented as fixed in 0.4.1.1: matcher backpressure isolation/storage-first fanout, bounded streaming HTTP decompression, critical-worker supervision, an exact live/replay activation watermark, and a global normalized-segment disk budget. They require coordinated pipeline changes and are intentionally separated from this low-risk tranche.

## 0.4.1.1 build hygiene

- fixes the stale `MetadataSink` unit-test call site from 0.4.0-r1;
- removes the two rustc warnings in `capture/parser.rs`;
- local crates use `#![deny(warnings)]`;
- local rustc warnings are build-breaking via `#![deny(warnings)]`; `scripts/verify_source.sh` keeps the separate rustfmt/clippy gate when a toolchain is available.


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

## Unreleased feature work: IPv4 traffic topology

- Added automatic source-based IPv4 topology grouping (default `/24`) with per-source/per-group PPS, bit-rate and cumulative wire counters.
- Topology source cardinality is bounded (`BAZALT_TOPOLOGY_MAX_SOURCES`, default 65536); spoofed-source overflow remains visible in aggregate counters instead of allocating unbounded state.
- Topology API/UI output is independently bounded to the busiest 256 groups / 2048 source rows so a spoofed high-cardinality view cannot freeze the browser; aggregate accounting remains complete and truncation is explicit.
- Topology observes Ethernet/VLAN IPv4 frames before service filtering and aggregates per capture worker before periodic merge to avoid a global packet-path lock.
- Added protected `/api/topology` and XDP throttle control endpoints.
- Added an optional XDP LPM-trie enforcement plane with `/24`/`/32` longest-prefix rules, probabilistic percentage drops, TTL, kernel-side seen/drop statistics and bounded in-memory audit history.
- Added a `TOPOLOGY` operator view with group/member traffic share and throttle controls.
- Historical note: the first unreleased topology prototype incorrectly forced AF_XDP capture and throttle onto separate interfaces; 0.4.1.4 replaces that model with same-interface enforcement plus passive capture when armed.
