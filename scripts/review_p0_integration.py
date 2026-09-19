#!/usr/bin/env python3
"""Cross-file P0 integration audit for BAZALT 0.4.1.6.

This is deliberately separate from verify_p0_fixes.py: it checks pipeline
wiring and failure semantics rather than the local implementation patterns.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

runtime = text("src/runtime.rs")
matching = text("src/matching/mod.rs")
http = text("src/http/mod.rs")
model = text("src/model.rs")
capture = text("src/capture/mod.rs")
pcap = text("src/capture/pcap_source.rs")
flow = text("src/flow/mod.rs")
segment = text("src/storage/segment.rs")
storage = text("src/storage/mod.rs")
spool = text("src/storage/spool.rs")
throttle = text("native/throttle.c")

# Matcher: preserve the full worker runtime and route only durable content
# through lossless backpressure. FlowClosed is deliberately best-effort.
assert "pub struct MatcherRuntime" in matching
assert "fn matcher_worker_loop(" in matching
assert "matcher_tx.send_content(record)" in http
assert "matcher_tx.try_flow_closed(flow_id)" in http
assert "MatchInput" not in model and "MatchInput" not in http and "MatchInput" not in matching
content = matching.split("pub fn send_content", 1)[1].split("pub fn try_flow_closed", 1)[0]
assert ".try_send(work)" in content and ".send(work)" in content
housekeeping = matching.split("pub fn try_flow_closed", 1)[1].split("\n}\n\npub struct MatcherRuntime", 1)[0]
assert ".try_send(MatcherWork::FlowClosed" in housekeeping
assert ".send(MatcherWork::FlowClosed" not in housekeeping
# Ordered shutdown drains L7 before dropping matcher senders/workers.
assert runtime.index("l7.join()") < runtime.index("matcher.join()")

# Capture: live remote ingress is destination-port scoped, live local egress
# keeps responses, and offline PCAP remains bidirectional independent of host MAC.
assert "CaptureMode::PcapLive => Some(topology_ignore_l2)" in capture
assert "CaptureMode::AfXdp => Some(false)" in capture
assert "CaptureMode::PcapFile => None" in capture
assert "offline_pcap_preserves_both_service_directions" in capture
assert "post_decode_live_direction_rejects_remote_source_port_collision" in capture
assert "fn service_flow_visible(" in capture
assert "CaptureMode::PcapLive | CaptureMode::AfXdp" in capture
assert "if !services.accepts_destination(&packet)" in flow
# The optimized kernel filter is directional when the interface MAC is known.
expr = pcap.split("fn live_port_filter_expression", 1)[1].split("fn live_fail_open_expression", 1)[0]
assert "dst port {p}" in expr and "ether src" in expr and "src port {p}" in expr

# Dynamic BPF: only successful optimized/fail-open installs acknowledge the
# service generation; a double failure terminates the supervised live worker.
update = capture.split("if generation != service_generation", 1)[1].split("// Offline fixtures", 1)[0]
assert update.count("service_generation = generation") == 3  # optimized, fail-open, early-filter disabled
err_match = re.search(r"Err\(error\) => \{(?P<body>.*?)\n\s*\}", update, re.S)
assert err_match is not None
err_arm = err_match.group("body")
assert "service_generation = generation" not in err_arm
assert "return;" in err_arm
assert "PortFilterMode::FailOpen" in update
assert "live_fail_open_expression" in pcap

# Storage: spool durability is fsync+rename+directory-fsync; segment rotation
# waits for that durable barrier before creating the next file.
assert "file.sync_all()?" in spool
assert "fs::rename(&tmp_path, &final_path)" in spool
assert "File::open(self.root.as_path())?.sync_all()?" in spool
commit = segment.split("fn commit_and_rotate", 1)[1].split("struct PreparedRecord", 1)[0]
assert re.search(r"flush_and_publish\([^;]+true\)\?;\s*metadata_tx\.durable_barrier\(\)\?;\s*writer\.rotate_after_commit\(\)", commit, re.S)
assert "pending.drain(..published)" in segment
assert "rebuild_index(&recovery_metadata)" in storage
assert "write_recovery_marker" in storage
# Clean shutdown also obtains a local-durability barrier after the segment writer exits.
shutdown = storage.split("pub async fn shutdown", 1)[1]
assert shutdown.index("shutdown_and_join") < shutdown.index("durable_barrier")

# XDP fallback: no blind replacement of foreign programs; stale cleanup is
# exact-image/name based and the current loader holds a per-interface lock.
assert "XDP_FLAGS_UPDATE_IF_NOEXIST" in throttle
assert "program_is_stale_own_copy" in throttle
assert "memcmp(info.tag, handle->program_tag" in throttle
assert 'strncmp((const char *)info.name, "bazalt_throttle"' in throttle
assert "flock(fd, LOCK_EX | LOCK_NB)" in throttle
assert "bpf_xdp_detach" in throttle

print("P0 INTEGRATION REVIEW PASS: cross-file matcher, capture/filter, storage durability, shutdown ordering and XDP ownership contracts verified")
