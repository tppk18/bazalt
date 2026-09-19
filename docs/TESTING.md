# Тестирование BAZALT

## Native gate

Docker build выполняет:

```bash
cargo test --release --all-features
cargo build --release --all-features
```

## Release-side checks

```bash
python3 scripts/verify_fixture.py
python3 scripts/static_verify.py
python3 -m py_compile scripts/*.py
node --check frontend/app.js
bash -n scripts/smoke.sh
bash -n scripts/verify_source.sh
```

## CPU planner unit properties

Проверяются:

- минимум один flow/L7/matcher worker;
- HTTP-weighted distribution;
- automatic CPU headroom на 8/16/32-core layouts;
- cgroup/cpuset affinity list не пуст;
- manual override не требуется для корректного auto mode.

На реальном Docker host дополнительно проверить startup log и `/metrics` на 2/4/8/16+ CPU limits, например:

```bash
docker run --cpuset-cpus=0-3 ...
docker run --cpuset-cpus=0-7 ...
```

## Matcher regressions

Обязательные свойства:

```text
literal cross-chunk                  => match
literal overlap                      => max_literal_len - 1
regex overlap                        => configured bounded window
service A rule + service B record    => record not scanned by that group
request rule + tcp_raw               => no request-scope match
Anywhere + tcp_raw                   => match
semantic stream-offset gap           => previous tail is not reused
pattern generation change            => worker refreshes compiled snapshot
```

## HTTP regressions

- split request headers;
- fixed body;
- chunked body;
- gzip/deflate bounded decode;
- keep-alive / pipelining;
- User-Agent extraction;
- no front `Vec::drain` data shifting;
- body chunks use `Bytes` ownership transfer.

## Segment/storage regressions

- record CRC and decode format remains compatible;
- writer CRC covers metadata prefix + payload without changing on-disk record format;
- multi-record reads from one segment use one open reader;
- crash-tail handling remains bounded to valid records;
- metadata writer coalesces without losing shutdown drain semantics.

## Functional smoke

```bash
./scripts/smoke.sh
```

Smoke checks service CRUD, configured-port filtering, open HTTP flow without FIN/RST, User-Agent filters, content retrieval, HTTP/raw presentation dedupe, automatic historical backfill, hidden-raw hit projection and payload retrieval.

## Performance test plan

For production validation collect at minimum:

```text
CPU utilization per worker thread
context switches/sec
flow/L7/matcher/storage queue high-watermarks
matcher_bytes/sec
HTTP requests/sec
segment_bytes/sec
ClickHouse insert rows/sec
replay MB/sec
RSS
```

Recommended matrix:

- 2, 4, 8, 16, 32 available logical CPUs;
- literals only / mixed regex / regex-heavy rulesets;
- 10 / 100 / 1k / 10k patterns;
- many short HTTP flows and fewer long keep-alive flows;
- gzip-heavy responses;
- live-only and live + historical replay.

A 24h soak test should show bounded RSS and bounded queue depth; replay must reduce/pause when live pressure grows.


## v0.4 fidelity regression matrix

Native Rust tests cover: IPv4/IPv6 out-of-order fragments, fragment overlap rejection, snaplen truncation, VLAN/tunnel flow identity, TCP 32-bit wraparound, conflicting OOO and bridging overlaps, ACK-before-OOO recovery, OOO-timeout/final-drain recovery, OOO-pressure recovery, tentative OOO FIN validation/payload conflict, off-sequence RST, same-ISN SYN retransmission, HEAD pipelining, CONNECT tunnel mode, conflicting/equal Content-Length, transfer-coding order, oversized fixed/chunked bodies and prefix-aware HTTP resynchronization after a TCP offset gap.

Performance invariants checked statically before release: no fragment lock on the unfragmented branch, zero-copy in-order TCP when OOO state is empty, bounded compact copies only on OOO/fragment paths, incremental HTTP header/chunk scans, and no semantic body retention after configured body limits.

## Topology / throttle regressions

Unit coverage verifies automatic `/24` grouping, local-egress suppression, directional service-destination admission, early rejection of obvious off-service IPv4, conservative fragment handling and canonicalization of `/32`/CIDR throttle targets. Repository verification checks that topology accounting happens only after the service-destination decision, while same-interface throttle still forces passive capture instead of starting a competing AF_XDP/XSK attachment.

For an integration test on a Linux host, set `BAZALT_INTERFACE` to a disposable veth ingress and `BAZALT_THROTTLE_ENABLED=true`, generate a fixed-rate IPv4 stream, apply a 50% `/32` rule through `PUT /api/topology/throttle`, and compare transmitted/received packet counts with the rule's `seen_packets`/`dropped_packets`. Repeat with a `/24` rule and an overlapping `/32` rule to verify longest-prefix precedence. Verify `ttl_seconds=0` and values above 3600 are rejected, and verify a 100% rule remains visible in the Active Rules table after its source disappears from pass-traffic topology. Verify `native-link`, `native-netlink`, and `generic-skb-netlink` attach reporting where the host/kernel combinations make those paths available. Never run the destructive drop test on a management interface.

Topology QA also covers passive-capture direction semantics: a synthetic frame carrying the local interface source MAC is excluded from Topology while service-directed remote ingress remains visible. Add an integration case where one source sends to both a configured port and an unrelated port: only configured-port traffic may affect Topology, then a `/32` throttle must reduce packets from that source on both ports.

Topology QA also covers bounded source cardinality: set a small source cap in the unit fixture and verify additional source addresses are accounted in overflow rather than allocated in the source map. Separate unit cases verify that large topology snapshots cap returned groups/source rows while retaining full aggregate counters and original group/source cardinality.

## 0.4.1.6 P0 regression gate

`python3 scripts/verify_p0_fixes.py` checks the local P0 implementation contracts introduced in 0.4.1.6: lossless content-matcher overload behavior, non-blocking `FlowClosed` housekeeping, directional service-port admission, dynamic BPF fail-safe behavior, crash-consistent segment/index rotation, one-time historical index healing, and stale netlink-XDP ownership recovery.

A second, independent source audit, `python3 scripts/review_p0_integration.py`, checks cross-file wiring rather than the same local assertions: matcher runtime preservation and shutdown ordering, live-vs-offline capture direction semantics, service-generation acknowledgement only after a safe filter state, metadata-spool fsync/rename durability before rotation, clean-shutdown durability, and XDP ownership boundaries. Both gates are invoked by `scripts/verify_source.sh`.
