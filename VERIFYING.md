# BAZALT 0.4.1.6 verification

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
python3 scripts/verify_p0_fixes.py
python3 scripts/review_p0_integration.py
python3 -m py_compile scripts/*.py
node --check frontend/app.js
bash -n scripts/smoke.sh
bash -n scripts/verify_source.sh
```

Compose YAML is parsed separately before packaging.

The static verifier checks, among other invariants:

- release label `0.4.1.6`, Cargo-compatible SemVer `0.4.1+hotfix.6`, and Docker compile gate;
- packet logging disabled by default;
- bounded queues and direct sharded data-plane topology;
- AF_XDP RX-queue auto-discovery plus all-or-nothing queue-set fallback;
- same-interface XDP throttle compatibility: `afxdp` request resolves to passive `pcap-live` capture when enforcement owns the same ingress;
- requested/effective capture mode logging so backend fallback/override is observable;
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
- lossless content-matcher overload with separate non-blocking flow-tail housekeeping;
- directional live service admission plus bidirectional offline-PCAP preservation;
- fail-open dynamic live BPF updates with supervised failure on double-install failure;
- crash-consistent segment/index rotation and one-time historical index healing;
- stale netlink-XDP self-recovery without replacing foreign owners;

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
- `bazalt_packets_received_total` counts TCP/UDP packets only after the flow engine admits them into a configured service flow; source-port collisions/off-service new flows are excluded, while reverse traffic of an already admitted service flow remains included.
- `bazalt_packets_ignored_total` counts intentionally unsupported EtherType/L4/tunnel traffic; IP fragments have dedicated received/reassembled/overlap/timeout/eviction metrics.

`BAZALT_EARLY_PORT_FILTER=true` is now the default when the backend supports dynamic BPF. Traffic Topology and participant statistics are intentionally service-scoped, so unrelated ports should be filtered early; the userspace service allow-list remains authoritative after bounded fragment/tunnel decoding.

### Independent v0.4 hot-path contract

```bash
python3 scripts/verify_v04_hotpath.py
```

This separately checks that normal in-order/unfragmented traffic does not enter fragment/OOO slow paths, that global flow admission does not add synchronization to existing-flow packets, and that match-amplification bounds remain on the positive-match slow path.

## IPv4 topology / XDP throttle verification

The traffic-topology feature adds an always-on IPv4 source observer and an optional XDP enforcement plane. Topology itself never drops traffic. Real enforcement is enabled only by `BAZALT_THROTTLE_ENABLED=true` and is always attached to `BAZALT_INTERFACE`; there is no independent enforcement-interface setting.

Checks completed in the artifact environment after the feature implementation:

```text
python3 scripts/static_verify.py                    PASS
python3 scripts/verify_fixture.py                   PASS
python3 scripts/verify_v04_hotpath.py               PASS
python3 -m py_compile scripts/*.py                  PASS
node --check frontend/app.js                        PASS
bash -n scripts/smoke.sh                            PASS
bash -n scripts/verify_source.sh                    PASS
docker-compose.yml YAML parse                       PASS
clang -Wall -Wextra -Werror -fsyntax-only
  native/throttle.bpf.c                             PASS (host C syntax)
```

Topology-specific invariants covered by source/unit checks:

- Topology accounting happens only after decoded packet direction is known and the actual destination port matches a configured service; off-service IPv4 is absent from participant statistics.
- A lightweight IPv4 TCP/UDP classifier rejects obvious off-service traffic before the full decoder, while fragments and supported tunnels remain conservative until bounded reassembly/decapsulation can reveal the real service port.
- New flow allocation requires a packet addressed to a configured service destination port. Reverse packets remain valid for an existing flow, but a hostile source-port collision cannot create service flow/L7 state.
- Passive live capture excludes frames sourced from the local interface MAC so host egress is not counted as a participant source.
- Capture workers aggregate accepted source counters locally and merge periodically rather than taking a global lock per packet.
- Automatic grouping defaults to source `/24`, while individual `/32` members remain visible and independently throttleable.
- The per-source table is bounded by `BAZALT_TOPOLOGY_MAX_SOURCES`; cardinality overflow of service-directed traffic remains included in aggregate counters instead of allocating unbounded source state.
- API/UI snapshots are independently capped to the busiest 256 groups / 2048 source rows while keeping full tracked aggregate counters and explicit truncation metadata.
- `GET /api/topology` exposes configured `service_ports`; the UI renders the busiest groups as a radial/star map centered on those ports and keeps a detailed table for exact source actions.
- Throttle targets are canonicalized and XDP uses an LPM trie, so overlapping group/source rules resolve by longest prefix.
- Topology visibility and enforcement scope are intentionally different: after a rule is installed, XDP matches only source IPv4/prefix and applies the configured percentage to all destination ports.
- Control-plane `set`/`clear`/TTL-expiry operations are serialized across the kernel map and in-memory rulebook to prevent stale-expiry races from deleting replacement rules.
- Percentage drops are probabilistic per packet; every rule has a mandatory 1–3600 second TTL, with explicit early disable still available.
- Same-interface throttle is supported: when AF_XDP was requested, effective capture becomes passive libpcap so the throttle XDP program owns ingress without a competing XSK redirect.
- Throttle changes and expiry are retained in a bounded in-memory audit ring.

Native Rust compile/clippy/test execution is still not possible in this artifact environment because no Rust toolchain is installed. `./scripts/verify_source.sh` therefore correctly stops at the mandatory cargo gate instead of claiming a native build. The available clang is a Swift clang build without the BPF backend (`-target bpf` is unavailable), so the actual eBPF target compile/load must be validated by the Docker release gate or a Linux host with Debian/LLVM clang and libbpf/libxdp development headers. The Docker builder installs those dependencies and `cargo test/build --all-features` invokes the BPF compile through `build.rs`.

A destructive enforcement acceptance test should be run only on a disposable veth/test ingress: apply 25/50/100% `/32` and `/24` rules, verify kernel seen/drop counters, TTL expiry, overlapping `/24` + `/32` precedence, and confirm the management/capture interface is unaffected.

## 0.4.1.6 P0 verification result

Two independent P0 verification passes were run on the final source tree:

1. Regression/source gates: fixture verification, repository/static invariants, v0.4 hot-path contract, dedicated P0 regression assertions, frontend JavaScript syntax, Python/shell syntax, Compose YAML parsing, and BPF program C syntax.
2. Independent integration/failure-ordering audit: matcher runtime wiring and shutdown order, live/offline capture direction semantics, post-decode service gating, dynamic BPF fail-safe state transitions, metadata spool durability ordering, segment rotation commit ordering, and XDP ownership/detach safety.

Both passes completed successfully on the final source tree. `scripts/verify_source.sh` also completes all non-Rust source gates here and then exits with code 2 at the mandatory Rust gate because this verification environment does not provide Cargo; the Rust build/test gate is intentionally not skipped. `native/throttle.bpf.c` passes the available C syntax check; host compilation of `native/throttle.c` is not available here because the environment does not provide the libbpf development headers.
