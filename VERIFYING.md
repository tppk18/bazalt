# BAZALT 0.4.1.2 verification

The artifact-generation environment does not provide a local Rust toolchain or Docker daemon. Therefore this release does **not** claim a native Rust compile in that environment.

The local library and binary roots use `#![deny(warnings)]`, so rustc warnings in BAZALT itself fail the native build instead of scrolling past. `scripts/verify_source.sh` now requires a Rust toolchain and fails instead of silently skipping rustfmt/clippy/tests/build.

The Dockerfile remains a native release gate and executes:

```bash
cargo test --release --all-features
cargo build --release --all-features
```

Release-side checks available in the artifact environment:

```bash
python3 scripts/verify_fixture.py
python3 scripts/static_verify.py
python3 -m py_compile scripts/*.py
node --check frontend/app.js
bash -n scripts/smoke.sh
bash -n scripts/verify_source.sh
```

Compose YAML is parsed separately before packaging.

The static verifier checks, among other invariants:

- release label `0.4.1.2`, Cargo-compatible SemVer `0.4.1+hotfix.2`, and Docker compile gate;
- packet logging disabled by default;
- bounded queues and direct sharded data-plane topology;
- AF_XDP RX-queue auto-discovery plus all-or-nothing queue-set fallback;
- bounded capture->flow enqueue wait instead of unconditional immediate drop;
- AF_XDP backend drop statistics, need-wakeup refill handling and multi-buffer descriptor support;
- TCP SYN-only sequence observation, extended-sequence wraparound, first-seen overlap, ACK-before-OOO gap recovery, FIN ordering and off-sequence RST regression invariants;
- bounded IPv4/IPv6 fragment cache, strict overlap policy, VLAN identity and tunnel/early-BPF preservation;
- strict snaplen/L3/L4 truncation rejection before TCP state;
- HTTP HEAD/CONNECT/101 framing, duplicate CL/TE validation, fixed/chunked body skip states and TCP-gap resynchronization;
- adaptive `sched_getaffinity()` CPU plan and auto mode;
- CPU headroom policy plus explicit `BAZALT_CPU_BUDGET` override;
- explicit Tokio worker budget;
- flow/L7/matcher worker pinning;
- replay low-priority scheduling and live-pressure throttling;
- exact aggregate queue accounting;
- AHash flow/state maps;
- matcher partitioning by service/content view;
- literal-sized overlap and regex-only configured overlap;
- no full-current-chunk copy for literal boundary matching;
- matcher tail discontinuity protection;
- generation-cached live ruleset snapshot;
- `BytesMut`/`httparse` HTTP parsing without front `Vec::drain`;
- body ownership transfer without body `Vec` clone;
- timer-heap compaction;
- incremental CRC/direct segment payload write;
- batched per-segment content reads;
- metadata coalescing window;
- historical replay behavior and prior HTTP/raw presentation invariants;
- host-loopback-only PostgreSQL/ClickHouse publication and no native ClickHouse host port;
- replay worker/hit/metadata barriers before per-segment checkpoint advancement;
- traffic-time timestamps for live and historical match rows;
- strict segment corruption propagation plus newest-tail-only crash recovery;
- pre-allocation segment record-length limits;
- new-flow-only global active-flow admission;
- bounded per-pattern/per-record match amplification;
- restored new-flow creation state from the 0.4.1 reference path;
- durable metadata spool decoupling ClickHouse outages from replay checkpoints;
- explicit ClickHouse request timeout and authenticated ClickHouse client;
- critical-worker supervision plus protected cheap `/api/health`;
- auth-aware Docker HEALTHCHECK;
- fail-fast invalid boolean configuration;
- bounded gzip/deflate expansion ratio and reduced decoded-body absolute cap;
- newest-segment content-index startup reconciliation;
- metadata-spool occupancy in metrics/live-pressure throttling.

Full acceptance on a Linux Docker host:

```bash
./scripts/smoke.sh
```

`smoke.sh` retains the functional regression path: service CRUD, configured-port filtering, open flow without FIN/RST, User-Agent filters, historical replay, HTTP/raw deduplication, raw-hit projection and payload retrieval.

## 0.4.1.2 compile/capture regression gates

The HTTP test configuration includes both `early_port_filter` and
`capture_enqueue_timeout`; this prevents new `Config` fields from breaking the
Docker test gate.

Capture diagnostics are intentionally split into two levels:

- `bazalt_capture_frames_total` counts frames returned by the capture backend before parsing/filtering;
- `bazalt_capture_backend_drops_total` counts backend/kernel drops reported by libpcap or AF_XDP;
- `bazalt_capture_drops_total` counts packets that reached userspace but could not enter a flow shard within the configured bounded wait;
- `bazalt_packets_received_total` counts parsed TCP/UDP packets accepted by the service-port allow-list.
- `bazalt_packets_ignored_total` counts intentionally unsupported EtherType/L4/tunnel traffic; IP fragments have dedicated received/reassembled/overlap/timeout/eviction metrics.

`BAZALT_EARLY_PORT_FILTER=false` is the default so a backend/link-layer BPF quirk cannot make capture silently look dead; the userspace service allow-list remains authoritative.

### Independent v0.4 hot-path contract

```bash
python3 scripts/verify_v04_hotpath.py
```

This separately checks that normal in-order/unfragmented traffic does not enter fragment/OOO slow paths, that global flow admission does not add synchronization to existing-flow packets, and that match-amplification bounds remain on the positive-match slow path.
