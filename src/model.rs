use std::{cmp::Ordering, hash::{Hash, Hasher}, net::IpAddr};

use bytes::Bytes;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type FlowId = Uuid;
pub type ContentId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    pub port: u16,
    pub name: String,
    #[serde(default = "default_true")]
    pub http: bool,
    #[serde(default)]
    pub urldecode_http_requests: bool,
    #[serde(default)]
    pub merge_adjacent_packets: bool,
    #[serde(default)]
    pub parse_websockets: bool,
}

fn default_true() -> bool { true }


#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    AToB,
    BToA,
}

impl Direction {
    pub fn opposite(self) -> Self {
        match self {
            Self::AToB => Self::BToA,
            Self::BToA => Self::AToB,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        endpoint_sort_key(self).cmp(&endpoint_sort_key(other))
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn endpoint_sort_key(e: &Endpoint) -> (u8, [u8; 16], u16) {
    match e.ip {
        IpAddr::V4(ip) => {
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&ip.octets());
            (4, bytes, e.port)
        }
        IpAddr::V6(ip) => (6, ip.octets(), e.port),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
    pub protocol: TransportProtocol,
    /// L2/tunnel identity. Zero means plain untagged Ethernet. Keeping this in
    /// the key prevents identical IP/port tuples from different VLAN/VXLAN
    /// domains from sharing TCP sequence state.
    #[serde(default)]
    pub l2_domain: u64,
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Preserve the pre-v0.4 hot hash shape for ordinary untagged traffic.
        // Unequal keys are allowed to collide, so the domain discriminator only
        // needs to be added when a VLAN/tunnel identity is actually present.
        self.a.hash(state);
        self.b.hash(state);
        self.protocol.hash(state);
        if self.l2_domain != 0 {
            0x4c32_444fu32.hash(state);
            self.l2_domain.hash(state);
        }
    }
}

impl FlowKey {
    /// Fast per-process keyed hash for data-plane sharding. This intentionally
    /// avoids the general-purpose `DefaultHasher` cost on every packet while
    /// still changing the mapping between process starts through `seed`.
    pub fn shard_hash64(&self, seed: u64) -> u64 {
        #[inline(always)]
        fn mix(state: u64, word: u64) -> u64 {
            // SplitMix64 finalizer folded into the running state. The function
            // is not a cryptographic MAC; the unpredictable process seed is
            // used to avoid a stable externally targetable shard mapping.
            let mut z = word.wrapping_add(state).wrapping_add(0x9e37_79b9_7f4a_7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        #[inline(always)]
        fn mix_endpoint(mut state: u64, ep: &Endpoint) -> u64 {
            state = match ep.ip {
                IpAddr::V4(ip) => mix(state, u32::from_be_bytes(ip.octets()) as u64),
                IpAddr::V6(ip) => {
                    let o = ip.octets();
                    let hi = u64::from_be_bytes(o[0..8].try_into().expect("8 byte IPv6 half"));
                    let lo = u64::from_be_bytes(o[8..16].try_into().expect("8 byte IPv6 half"));
                    mix(mix(state, hi), lo)
                }
            };
            mix(state, ep.port as u64)
        }

        let protocol_word = match self.protocol {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
        };
        let mut state = mix(seed, protocol_word);
        if self.l2_domain != 0 {
            state = mix(state, self.l2_domain);
        }
        let state = mix_endpoint(state, &self.a);
        mix_endpoint(state, &self.b)
    }

    pub fn canonical(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: TransportProtocol,
    ) -> (Self, Direction) {
        Self::canonical_with_domain(src_ip, src_port, dst_ip, dst_port, protocol, 0)
    }

    pub fn canonical_with_domain(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: TransportProtocol,
        l2_domain: u64,
    ) -> (Self, Direction) {
        let src = Endpoint { ip: src_ip, port: src_port };
        let dst = Endpoint { ip: dst_ip, port: dst_port };
        if src <= dst {
            (Self { a: src, b: dst, protocol, l2_domain }, Direction::AToB)
        } else {
            (Self { a: dst, b: src, protocol, l2_domain }, Direction::BToA)
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub ts_ns: u64,
    pub key: FlowKey,
    pub direction: Direction,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub flags: TcpFlags,
    pub payload: Bytes,
    pub wire_len: usize,
}

impl ParsedPacket {
    #[inline]
    pub fn source_endpoint(&self) -> &Endpoint {
        match self.direction {
            Direction::AToB => &self.key.a,
            Direction::BToA => &self.key.b,
        }
    }

    #[inline]
    pub fn destination_endpoint(&self) -> &Endpoint {
        match self.direction {
            Direction::AToB => &self.key.b,
            Direction::BToA => &self.key.a,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContentView {
    TcpRaw,
    HttpRequestHeaders,
    HttpRequestBody,
    HttpRequestDecodedBody,
    HttpResponseHeaders,
    HttpResponseBody,
    HttpResponseDecodedBody,
}

impl ContentView {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpRaw => "tcp_raw",
            Self::HttpRequestHeaders => "http_request_headers",
            Self::HttpRequestBody => "http_request_body",
            Self::HttpRequestDecodedBody => "http_request_decoded_body",
            Self::HttpResponseHeaders => "http_response_headers",
            Self::HttpResponseBody => "http_response_body",
            Self::HttpResponseDecodedBody => "http_response_decoded_body",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub flow_id: FlowId,
    pub ts_ns: u64,
    pub direction: Direction,
    pub key: FlowKey,
    pub offset: u64,
    pub data: Bytes,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct ContentRecord {
    pub id: ContentId,
    pub flow_id: FlowId,
    pub ts_ns: u64,
    pub service: Option<String>,
    pub direction: Direction,
    pub view: ContentView,
    pub stream_offset: u64,
    pub data: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentIndexRecord {
    pub content_id: ContentId,
    pub flow_id: FlowId,
    pub ts_ns: u64,
    pub service: Option<String>,
    pub direction: Direction,
    pub view: ContentView,
    pub stream_offset: u64,
    pub payload_len: u32,
    pub segment_path: String,
    pub segment_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub flow_id: FlowId,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub service: Option<String>,
    pub packets_c2s: u64,
    pub packets_s2c: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRecord {
    pub id: Uuid,
    pub flow_id: FlowId,
    pub timestamp: DateTime<Utc>,
    pub request: bool,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub body_content_id: Option<ContentId>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    Text,
    Binary,
    Regex,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternAction {
    Find,
    Ignore,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternDirection {
    Both,
    Input,
    Output,
}

impl Default for PatternDirection {
    fn default() -> Self { Self::Both }
}

fn default_pattern_color() -> String { "#FF7474".to_owned() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRevision {
    pub id: Uuid,
    pub revision: i64,
    pub name: String,
    pub expression: String,
    pub kind: PatternKind,
    pub action: PatternAction,
    #[serde(default = "default_pattern_color")]
    pub color: String,
    #[serde(default)]
    pub direction_type: PatternDirection,
    pub service: Option<String>,
    pub view: Option<ContentView>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPattern {
    pub name: String,
    pub expression: String,
    pub kind: PatternKind,
    #[serde(default = "default_pattern_action")]
    pub action: PatternAction,
    #[serde(default = "default_pattern_color")]
    pub color: String,
    #[serde(default)]
    pub direction_type: PatternDirection,
    pub service: Option<String>,
    pub view: Option<ContentView>,
}

fn default_pattern_action() -> PatternAction {
    PatternAction::Find
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRecord {
    pub timestamp: DateTime<Utc>,
    pub pattern_id: Uuid,
    pub pattern_revision: i64,
    pub flow_id: FlowId,
    pub content_id: ContentId,
    pub view: ContentView,
    pub action: PatternAction,
    pub offset_start: u64,
    pub offset_end: u64,
    pub historical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRef {
    pub id: Uuid,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayJob {
    pub id: Uuid,
    pub pattern_ids: Vec<Uuid>,
    #[serde(default)]
    pub pattern_revisions: Vec<PatternRef>,
    pub segment_cutoff: Option<String>,
    #[serde(default)]
    pub segment_paths: Vec<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub segments_total: i64,
    pub segments_done: i64,
    pub bytes_processed: i64,
    pub matches_found: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TrafficFilter {
    pub service: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub pattern_id: Option<Uuid>,
    pub favorite: Option<bool>,
    pub user_agent: Option<String>,
    pub user_agent_equals: Option<String>,
    pub user_agent_not_contains: Option<String>,
    pub user_agent_regex: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveEvent {
    pub event: String,
    pub flow_id: FlowId,
    pub pattern_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub service: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn flow_key_canonicalizes_complete_endpoint() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (k1, d1) = FlowKey::canonical(a, 2000, b, 1000, TransportProtocol::Tcp);
        let (k2, d2) = FlowKey::canonical(b, 1000, a, 2000, TransportProtocol::Tcp);
        assert_eq!(k1, k2);
        assert_ne!(d1, d2);
    }
}

#[derive(Debug, Clone)]
pub enum FlowOutput {
    Chunk(StreamChunk),
    /// A live snapshot for a flow that has emitted payload but is still open.
    Snapshot(FlowSummary),
    Closed(FlowSummary),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetadataEvent {
    Flow(FlowSummary),
    Http(HttpRecord),
    Match(MatchRecord),
    ContentIndex(ContentIndexRecord),
}

