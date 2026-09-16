#!/usr/bin/env python3
"""Repository-level invariant checks that do not require Rust or Docker."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(rel: str) -> str:
    return (ROOT / rel).read_text()

cargo = tomllib.loads(text("Cargo.toml"))
assert cargo["package"]["name"] == "bazalt"
assert cargo["package"]["version"] == "0.4.1"
assert "afxdp" in cargo["features"]["default"]
assert "serde" in cargo["dependencies"]["bytes"].get("features", []), "bytes::Bytes models require the bytes serde feature"

src = "\n".join(p.read_text() for p in (ROOT / "src").rglob("*.rs"))
assert "unbounded_channel" not in src
assert not re.search(r"\bunbounded\s*\(", src), "unbounded data-plane channel found"
assert 'parse_bool_env("PACKMATE_PACKET_LOGGING", false)' in text("src/config.rs"), "legacy key should remain accepted through BAZALT compatibility resolver"
assert 'format!("BAZALT_{suffix}")' in text("src/config.rs")
assert "BAZALT_PACKET_LOGGING=false" in text(".env.example")
assert "BAZALT_PACKET_LOGGING: ${BAZALT_PACKET_LOGGING:-}" in text("docker-compose.yml")
assert "PACKMATE_PACKET_LOGGING: ${PACKMATE_PACKET_LOGGING:-}" in text("docker-compose.yml")
assert "BAZALT_L7_WORKERS" in text("docker-compose.yml")
assert "BAZALT_MATCHER_WORKERS" in text("docker-compose.yml")
assert "pub struct FlowIngress" in text("src/flow/mod.rs")
assert "flow-dispatcher" not in text("src/flow/mod.rs")
assert "DefaultHasher" not in text("src/flow/mod.rs")
assert "shard_hash64" in text("src/model.rs") and "shard_seed" in text("src/flow/mod.rs")
assert "last_activity" in text("src/flow/mod.rs")
assert text("src/flow/mod.rs").count("timers.push(TimerItem") == 2, "timeout should schedule only on flow creation/reschedule, not per packet"
assert "snapshot_for_replay" in text("src/storage/segment.rs")
assert "segment_paths" in text("src/model.rs") and "segment_paths" in text("src/storage/postgres.rs")
assert "user_agent_regex" in text("src/model.rs") and "user_agent_regex" in text("src/storage/clickhouse.rs")
assert "user_agent_equals" in text("src/model.rs") and "user_agent_not_contains" in text("src/model.rs")
assert '.route("/metrics", get(prometheus_metrics))' in text("src/api/mod.rs")
assert '.route("/api/resources", get(resource_status))' in text("src/api/mod.rs")
assert "process_cpu_seconds" in text("src/resources.rs") and "memory_scope_limit_bytes" in text("src/resources.rs")
assert 'concat!("bazalt_", $name' in text("src/metrics.rs")
for q in ("flow", "l7", "match", "storage"):
    assert f"{q}_queue_high_watermark" in text("src/metrics.rs")
for m in ("capture_truncated_packets_total", "ip_fragments_reassembled_total",
          "ip_fragment_overlap_drops_total", "ip_fragment_evicted_total",
          "tcp_gap_events_total", "tcp_gap_bytes_total", "tcp_rejected_resets_total"):
    assert m in text("src/metrics.rs")

# Native build/release gate and runtime binary rebrand.
dockerfile = text("Dockerfile")
assert "#![deny(warnings)]" in text("src/lib.rs")
assert "#![deny(warnings)]" in text("src/main.rs")
assert "cargo test --release --all-features" in dockerfile
assert "cargo build --release --all-features" in dockerfile
assert "/target/release/bazalt" in dockerfile
assert 'ENTRYPOINT ["/usr/local/bin/bazalt"]' in dockerfile
assert "libxdp-dev" in dockerfile
assert "XDP_ZEROCOPY" in text("native/afxdp.c") and "XDP_COPY" in text("native/afxdp.c")
assert "postgres:" in text("docker-compose.yml") and "clickhouse:" in text("docker-compose.yml")

# Live visibility and configured-port-only capture invariants.
assert "FlowOutput::Snapshot" in text("src/flow/mod.rs")
assert "live_flow_update_interval" in text("src/config.rs")
assert "flow_update" in text("src/storage/mod.rs")
assert "accepts_flow" in text("src/http/mod.rs") and "packets_filtered" in text("src/capture/mod.rs")
assert "configure_port_filter" in text("src/capture/mod.rs") and "port_filter_expression" in text("src/capture/pcap_source.rs")
assert "generation" in text("src/http/mod.rs") and "capture service-port filter updated" in text("src/capture/mod.rs")
assert 'parse_bool_env("PACKMATE_EARLY_PORT_FILTER", false)' in text("src/config.rs")
assert "early capture BPF disabled; userspace service allow-list active" in text("src/capture/mod.rs")
assert "capture_frames_total" in text("src/metrics.rs")
assert "packets_ignored_total" in text("src/metrics.rs")
assert "ArcSwap<AHashMap<u16, ServiceConfig>>" in text("src/http/mod.rs")
assert "if flow.visible" in text("src/flow/mod.rs"), "empty/no-payload flows must not be persisted"
assert "All</button>" not in text("frontend/app.js"), "All service tab must not be rendered"
assert "scheduleLiveRefresh" in text("frontend/app.js") and "openFlow(state.selectedFlow)" in text("frontend/app.js")
assert "Port allow-list regression" in text("scripts/smoke.sh")
assert "open live flow was not visible before close/timeout" in text("scripts/smoke.sh")

# Docker-host robustness: AF_XDP native -> generic/SKB -> all-or-nothing
# queue-set initialization -> one libpcap fallback, and CPU affinity must
# respect the container's actual cpuset.
assert "XDP_FLAGS_SKB_MODE" in text("native/afxdp.c")
assert "capture_fallback_pcap" in text("src/config.rs")
assert "falling back globally to one libpcap worker" in text("src/capture/mod.rs")
assert "auto-detected AF_XDP RX queues" in text("src/config.rs")
assert "capture_enqueue_timeout" in text("src/config.rs") and "send_timeout" in text("src/capture/mod.rs")
assert "capture_backend_drops_total" in text("src/metrics.rs") and "XDP_STATISTICS" in text("native/afxdp.c")
assert "XDP_PKT_CONTD" in text("src/capture/afxdp.rs") and "desc->options" in text("native/afxdp.c")
assert "XDP_USE_SG" in text("native/afxdp.c") and "refusing lossy single-buffer capture" in text("src/capture/afxdp.rs")
assert "xsk_ring_prod__needs_wakeup(&h->fill)" in text("native/afxdp.c")
# v0.4 traffic-fidelity invariants. Expensive state is strictly on slow paths:
# unfragmented packets never enter SharedFragmentCache, in-order TCP bypasses the
# interval tree, and bounded resource limits recover framing/state instead of
# permanently killing a flow.
parser = text("src/capture/parser.rs")
fragment = text("src/capture/fragment.rs")
flow_reassembly = text("src/flow/reassembly.rs")
assert "SharedFragmentCache" in fragment and "FRAGMENT_SHARDS" in fragment
assert "FragmentInsert::Complete" in parser and "DroppedOverlap" in fragment
assert "capture_truncated_packets" in parser and "declared {total_len}, captured" in parser
assert "canonical_with_domain" in parser and "l2_domain" in text("src/model.rs")
assert "VXLAN" in parser or "vxlan" in parser
assert "mix_tunnel_domain" in parser
assert "decode_gre" in parser and "protocol { 47" not in parser  # GRE is decoded, not ignored
pcap_source = text("src/capture/pcap_source.rs")
assert "ip6 protochain 44" in pcap_source and "udp port 4789" in pcap_source
assert "tagged_expr" in pcap_source
assert "INITIAL_SEQ_EPOCH" in flow_reassembly and "fn extend_seq" in flow_reassembly
assert "insert_ooo_first_seen" in flow_reassembly and "if self.out_of_order.is_empty()" in flow_reassembly
assert "peer_ack_abs" in flow_reassembly and "ack_arriving_before_ooo_is_remembered" in flow_reassembly
assert "recover_ooo_pressure" in flow_reassembly and "out.truncated" not in flow_reassembly
assert "max_ooo_segments" in flow_reassembly and "PACKMATE_MAX_OOO_SEGMENTS" in text("src/config.rs")
assert "recover_ooo_timeout" in flow_reassembly and "PACKMATE_TCP_GAP_TIMEOUT_MS" in text("src/config.rs")
assert "pub fn finalize" in flow_reassembly and "finalize_tcp_halves" in text("src/flow/mod.rs")
assert "FRAGMENT_DATAGRAM_OVERHEAD" in fragment and "FRAGMENT_PIECE_OVERHEAD" in fragment
assert "pending_fin_requires_ack" in flow_reassembly
assert "ooo_fin_waits_for_peer_ack_after_missing_data_arrives" in flow_reassembly
assert "payload_beyond_unacked_ooo_fin_invalidates_tentative_fin" in flow_reassembly
assert "rst_matches_next" in flow_reassembly and "tcp_rejected_resets" in text("src/flow/mod.rs")
assert "retransmitted_syn_with_same_isn_keeps_generation" in text("src/flow/mod.rs")
assert "ts_ns: u64" in flow_reassembly and "segment.ts_ns" in flow_reassembly
assert "max_flow_bytes" in text("src/config.rs") and "tracked_payload" not in text("src/flow/mod.rs")
assert "sched_getaffinity" in text("src/affinity.rs") and "requested % allowed.len()" in text("src/affinity.rs")

# Service CRUD and pattern revisions remain persisted.
api = text("src/api/mod.rs")
pg = text("src/storage/postgres.rs")
assert '.route("/api/services/{port}", put(update_service).delete(delete_service))' in api
assert "StatusCode::CREATED" in api and "upsert_service" in api
assert "http BOOLEAN NOT NULL DEFAULT TRUE" in pg
assert "urldecode_http_requests" in pg and "merge_adjacent_packets" in pg and "parse_websockets" in pg
assert 'VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)' in pg
assert "WHERE enabled = TRUE" in pg and ") latest" in pg

# ClickHouse 25.8 alias regression.
ch = text("src/storage/clickhouse.rs")
assert "AS latest_user_agent" in ch and "AS user_agent FROM" not in ch
assert "HAVING notEmpty(latest_user_agent)" in ch
assert "cannot enrich flow list with user agents" in api
assert "cannot enrich flow list with pattern ids" in api

# BAZALT presentation: very dark basalt palette, square terminal geometry and
# deliberately different request/response treatment.
html = text("frontend/index.html")
js = text("frontend/app.js")
css = text("frontend/styles.css")
assert "<title>BAZALT</title>" in html and 'navbar-brand">BAZALT<' in html
assert "--bg:#050607" in css
assert "border-radius:0" in css and "box-shadow:5px 5px 0 var(--shadow)" in css
assert ".packet.request" in css and "border-left:4px solid var(--request)" in css
assert ".packet.response" in css and "border-right:4px solid var(--response)" in css
assert "item.request?'REQ':'RES'" in js
assert "viewLabel(view)" in js
assert "localStorage.getItem('bazalt.pageSize')" in js
assert 'id="resource-toggle"' in html and 'id="resource-panel"' in html
assert "loadResources" in js and "setInterval(()=>{if($('#login-screen').classList.contains('hidden'))loadResources();},2000)" in js
assert "bazalt.resourcesExpanded" in js and ".resource-panel" in css
assert "BAZALT_AUTH_ENABLED=true" in text(".env.example")
assert 'parse_bool_env("PACKMATE_AUTH_ENABLED", true)' in text("src/config.rs")
assert '.route("/api/management/storage", get(management_storage))' in api
assert '.route("/api/management/cleanup", post(management_cleanup))' in api
assert 'StatusCode::FORBIDDEN' in api and 'access_control' in api
assert 'path == "/metrics"' in api and 'path.starts_with("/api/")' in api
assert 'id="management-view"' in html and 'id="login-screen"' in html
assert "retention_candidates" in text("src/storage/segment.rs") and "metadata.barrier()" in api
assert "maintenance.write().await" in api and "maintenance.read().await" in text("src/replay/mod.rs")

# HTTP/raw presentation dedupe and matcher projection. ANYWHERE scans the
# canonical TCP stream once; request/response-scoped patterns scan semantic
# HTTP views. Hidden raw hits are projected to the visible HTTP record so
# highlighting survives without duplicate pattern CPU.
assert "suppress_redundant_tcp_raw" in api
assert "project_matches_to_visible_content" in api
assert "ANYWHERE patterns intentionally scan the canonical reassembled TCP" in api
matching = text("src/matching/mod.rs")
assert "anywhere_uses_canonical_raw_stream_not_duplicate_http_wire_view" in matching
assert "request_scope_uses_http_semantic_view" in matching

# 0.3 CPU/post-capture optimization invariants.
config = text("src/config.rs")
affinity = text("src/affinity.rs")
http = text("src/http/mod.rs")
segment = text("src/storage/segment.rs")
assert 'parse_bool_env("PACKMATE_CPU_AUTO", true)' in config
assert "adaptive_plan" in config and "BAZALT_CPU_AUTO=true" in text(".env.example")
assert "distribute_stage_workers" in affinity and "lower_current_priority" in affinity
assert "default_cpu_budget" in affinity and "roughly 25%" in affinity
assert "cpu_available" in config and "cpu_available" in text("src/metrics.rs")
assert "worker_threads(cfg.tokio_workers.max(1))" in text("src/main.rs")
assert "cfg.l7_cpus" in http and "worker CPU remapped" in http
assert "worker_cpus: Vec<usize>" in matching and "matcher worker CPU remapped" in matching
assert "global_groups" in matching and "service_groups" in matching
assert "required_overlap(&self, record" in matching and "service_scoped_patterns_do_not_enter_other_service_hot_paths" in matching
assert "bridge_current" in matching and "Scan the current chunk directly" in matching
assert "TailState" in matching and "end_offset == record.stream_offset" in matching
assert "flow_tail_keys" in matching and "tails.retain" not in matching
assert "interest_mask" in matching and "content_view_bit" in matching
assert "is_interested_view" in matching and "matcher_tx.is_interested_view(record.view)" in http
assert '"live matcher stopped"' in http and '"content segment writer stopped"' in http
assert "semantic_tail_is_not_reused_across_stream_offset_gap" in matching
assert "BytesMut" in http and "httparse::Request" in http and "HashMap::<String,String>" not in http
assert "buffer.drain" not in http and "body_record(&info, self.stream_offset, data.clone())" not in http
assert "RequestKind::Head" in http and "RequestKind::Connect" in http and "HttpMode::Tunnel" in http
assert "SkipFixed" in http and "transfer_encoding_framing" in http and "parse_content_length" in http
assert "find_double_crlf_from" in http and "header_scan_from" in http
assert "oversized_chunked_body_is_consumed_without_materializing_tail" in http
assert "tcp_offset_gap_forces_http_resync" in http and "find_plausible_http_start" in http
assert "resync_keeps_long_request_target_split_across_chunks" in http
assert "encode_record_prefix" in segment and "crc.update(&record.data)" in segment
assert "read_many_at" in segment and "Group reads by path" in api
assert "},500);" in js and "}},30000);" in js
assert "timers.len() > 4096" in text("src/flow/mod.rs")
assert "queue_enqueued" in text("src/metrics.rs") and "queue_dequeued" in text("src/metrics.rs")
assert "DefaultHasher" not in text("src/replay/mod.rs")

print("STATIC PASS: BAZALT 0.4.1 traffic-fidelity, bounded slow paths, auth/management, adaptive CPU and prior safety/UI invariants verified")
