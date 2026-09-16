#!/usr/bin/env python3
"""Static performance-contract checks for BAZALT v0.4 fidelity paths.

This is intentionally independent from static_verify.py: it checks that fixes
for adversarial/reordered traffic remain off the dominant in-order path and
that all slow-path state is bounded by both bytes and object counts.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

reasm = text("src/flow/reassembly.rs")
flow = text("src/flow/mod.rs")
parser = text("src/capture/parser.rs")
frag = text("src/capture/fragment.rs")
capture = text("src/capture/mod.rs")
http = text("src/http/mod.rs")
config = text("src/config.rs")
model = text("src/model.rs")
pcap_source = text("src/capture/pcap_source.rs")

# TCP common path: no interval-tree lookup/copy when the stream is ordered.
assert "if self.out_of_order.is_empty()" in reasm
fast = reasm.split("if self.out_of_order.is_empty()", 1)[1].split("} else {", 1)[0]
assert "self.emit(tail" in fast
assert "insert_ooo_first_seen" not in fast
assert "Bytes::copy_from_slice" not in fast

# Pure ACKs only update the peer watermark; they skip accept()/OOO work unless
# there is actually a gap/FIN to recover.
assert "if self.out_of_order.is_empty() && self.pending_fin.is_none()" in reasm
assert "let needs_sequence_work = !packet.payload.is_empty()" in flow

# OOO state is bounded by payload bytes and interval count. Pressure recovers
# by a gap instead of setting a permanent per-flow truncation flag.
assert "self.out_of_order_bytes > max_ooo || self.out_of_order.len() > max_segments" in reasm
assert "out.truncated" not in reasm
assert "gap_started_ts_ns" in reasm and "recover_ooo_timeout" in reasm
assert "pub fn finalize" in reasm
assert 'parse_env("PACKMATE_MAX_OOO_SEGMENTS", 8192usize)' in config
assert "pending_fin_requires_ack" in reasm

# IP fragments are the only packets that enter the shared sharded cache.
frag_branch = parser.split("if offset != 0 || more {", 1)[1].split("self.decode_ip_payload", 1)[0]
assert "self.fragments.insert" in frag_branch
assert parser.count("depth < MAX_TUNNEL_DEPTH") >= 3
assert "FRAGMENT_SHARDS: usize = 64" in frag
assert "FRAGMENT_DATAGRAM_OVERHEAD" in frag and "FRAGMENT_PIECE_OVERHEAD" in frag
assert "self.bytes > self.max_bytes || self.states.len() > self.max_datagrams" in frag
assert "mix_tunnel_domain" in parser
assert "tagged_expr" in pcap_source

# Raw capture adds a cheap Bytes clone only when explicitly enabled.
assert "if let Some(raw_tx) = &raw_tx" in capture
raw = capture.split("if let Some(raw_tx) = &raw_tx", 1)[1].split("}", 1)[0]
assert "frame.clone()" in raw

# Untagged FlowKey hashing preserves the old common-path shape: the new domain
# word is mixed/hashed only when VLAN/tunnel identity is non-zero.
assert model.count("if self.l2_domain != 0") >= 2

# HTTP delimiter searches are incremental, not full-buffer rescans per feed.
assert "header_scan_from" in http and "find_double_crlf_from" in http
assert "scan_from" in http and "find_crlf_from" in http
assert "SkipFixed" in http
assert "max_collect" in http
assert "Waiting for the complete request-target/version" in http

print("HOTPATH PASS: v0.4 common paths stay zero-copy/unlocked; fragment/OOO/HTTP slow paths are bounded")
