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
