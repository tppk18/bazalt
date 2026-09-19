#!/usr/bin/env python3
"""Independent P0 regression gate for BAZALT 0.4.1.6."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

matching = text("src/matching/mod.rs")
metrics = text("src/metrics.rs")
capture = text("src/capture/mod.rs")
pcap = text("src/capture/pcap_source.rs")
http = text("src/http/mod.rs")
segment = text("src/storage/segment.rs")
storage = text("src/storage/mod.rs")
throttle = text("native/throttle.c")

# P0: accepted live content must not be silently lost when the matcher queue is full.
assert "pub fn send_content" in matching
assert "Err(TrySendError::Full(work))" in matching
assert "self.shard_txs[idx].send(work)" in matching
assert "matcher_queue_backpressure" in matching and "matcher_queue_backpressure_total" in metrics
assert "full_live_content_queue_applies_backpressure_instead_of_dropping_work" in matching
assert "pub fn try_flow_closed" in matching
assert "matcher_housekeeping_drops" in matching and "matcher_housekeeping_drops_total" in metrics
assert "flow_closed_housekeeping_never_blocks_on_full_queue" in matching
full_branch = matching.split("pub fn send_content", 1)[1].split("pub fn try_flow_closed", 1)[0]
assert full_branch.index("matcher_queue_backpressure") < full_branch.index("self.shard_txs[idx].send(work)")
assert "return false" not in full_branch.split("self.shard_txs[idx].send(work)", 1)[0]
housekeeping = matching.split("pub fn try_flow_closed", 1)[1].split("\n}\n\npub struct MatcherRuntime", 1)[0]
assert ".send(" not in housekeeping

# P0: remote ingress is destination-service scoped; local egress keeps response fidelity.
assert "match local_egress" in capture
assert "Some(true) => services.accepts_port(src_port)" in capture
assert "Some(false) => services.accepts_port(dst_port)" in capture
assert "None => services.accepts_port(src_port) || services.accepts_port(dst_port)" in capture
assert "hostile_source_port_collision_is_rejected_on_remote_ingress" in capture
assert "offline_pcap_preserves_both_service_directions" in capture
assert "post_decode_live_direction_rejects_remote_source_port_collision" in capture
assert "fn service_flow_visible(" in capture
assert "CaptureMode::PcapLive | CaptureMode::AfXdp" in capture
assert "pub fn accepts_port(&self, port: u16) -> bool" in http

# P0: dynamic live BPF must never acknowledge a generation while a stale restrictive filter can remain.
assert "PortFilterMode::FailOpen" in capture and "live_fail_open_expression" in pcap
assert "installed broad fail-open capture filter" in pcap
assert "stopping capture worker to avoid a silent service blind spot" in capture
assert "dst port {p}" in pcap and "ether src" in pcap
assert "protochain" not in pcap.split("fn live_port_filter_expression", 1)[1].split("fn live_fail_open_expression", 1)[0]

# P0: segment rotation is a commit boundary: payload fsync -> index enqueue -> durable spool barrier -> rotate.
assert "fn commit_and_rotate" in segment
commit = segment.split("fn commit_and_rotate", 1)[1].split("struct PreparedRecord", 1)[0]
a = commit.index("flush_and_publish(writer, pending, metadata_tx, true)?")
b = commit.index("metadata_tx.durable_barrier()?")
c = commit.index("writer.rotate_after_commit()")
assert a < b < c
assert "while published < pending.len()" in segment and "pending[published].clone()" in segment and "pending.drain(..published)" in segment
assert "metadata_send_failure_preserves_unsent_index_suffix" in segment
assert "rotation_waits_for_durable_metadata_barrier" in segment
assert "CONTENT_INDEX_RECOVERY_MARKER" in storage
assert "recovery_segments.rebuild_index(&recovery_metadata)" in storage
assert "completed one-time full content-index recovery" in storage

# Conditional P0: netlink XDP stale owner recovery must identify only the same program image.
assert "program_tag" in throttle
assert "bpf_prog_get_fd_by_id" in throttle
assert "program_is_stale_own_copy" in throttle
assert "memcmp(info.tag, handle->program_tag" in throttle
assert "bazalt-throttle-%u.lock" in throttle and "flock(fd, LOCK_EX | LOCK_NB)" in throttle
assert "XDP_FLAGS_UPDATE_IF_NOEXIST" in throttle
assert "detach_stale_own_netlink" in throttle

print("P0 PASS: matcher overload, directional service gating, dynamic BPF fail-safe, segment/index crash consistency, and stale XDP recovery invariants verified")
