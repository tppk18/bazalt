use std::{
    collections::VecDeque,
    io::Read,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use ahash::AHashMap;
use anyhow::{bail, Result};
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use crossbeam_channel::{Receiver, Sender};
use flate2::read::{GzDecoder, ZlibDecoder};
use uuid::Uuid;

use crate::{
    config::Config,
    matching::MatcherIngress,
    metrics::Metrics,
    model::{
        ContentRecord, ContentView, Direction, FlowId, FlowKey, FlowOutput, HttpRecord,
        MetadataEvent, ParsedPacket, ServiceConfig, StreamChunk,
    },
    storage::segment::SegmentStore,
};

#[derive(Debug, Clone, Copy)]
pub struct ServicePacketScope {
    pub destination: bool,
    pub flow: bool,
}

pub struct ServiceRegistry {
    // Readers are on the packet hot path. Service edits are rare, so publish a
    // completely new immutable map with ArcSwap instead of taking an RwLock on
    // every captured packet.
    by_port: ArcSwap<AHashMap<u16, ServiceConfig>>,
    generation: AtomicU64,
}

impl ServiceRegistry {
    pub fn new(initial: impl IntoIterator<Item = ServiceConfig>) -> Arc<Self> {
        let mut map = AHashMap::new();
        for service in initial {
            map.insert(service.port, service);
        }
        Arc::new(Self {
            by_port: ArcSwap::from_pointee(map),
            generation: AtomicU64::new(1),
        })
    }

    pub fn upsert(&self, service: ServiceConfig) {
        let current = self.by_port.load_full();
        let mut next = (*current).clone();
        next.insert(service.port, service);
        self.by_port.store(Arc::new(next));
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn delete(&self, port: u16) -> bool {
        let current = self.by_port.load_full();
        if !current.contains_key(&port) {
            return false;
        }
        let mut next = (*current).clone();
        next.remove(&port);
        self.by_port.store(Arc::new(next));
        self.generation.fetch_add(1, Ordering::Release);
        true
    }

    pub fn list(&self) -> Vec<ServiceConfig> {
        let current = self.by_port.load();
        let mut v = current.values().cloned().collect::<Vec<_>>();
        v.sort_by_key(|service| service.port);
        v
    }

    pub fn by_port(&self, port: u16) -> Option<ServiceConfig> {
        self.by_port.load().get(&port).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.by_port.load().is_empty()
    }

    pub fn ports(&self) -> Vec<u16> {
        let current = self.by_port.load();
        let mut ports = current.keys().copied().collect::<Vec<_>>();
        ports.sort_unstable();
        ports
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[inline]
    pub fn accepts_port(&self, port: u16) -> bool {
        self.by_port.load().contains_key(&port)
    }

    /// A source becomes topology-visible, and a new flow may be admitted, only
    /// when the packet is actually addressed to one of the configured service
    /// ports. This is deliberately directional: a hostile sender using source
    /// port 80 must not look like traffic to our port 80.
    #[inline]
    pub fn packet_scope(&self, packet: &ParsedPacket) -> ServicePacketScope {
        let current = self.by_port.load();
        let destination = current.contains_key(&packet.destination_endpoint().port);
        let source = current.contains_key(&packet.source_endpoint().port);
        ServicePacketScope {
            destination,
            flow: destination || source,
        }
    }

    #[inline]
    pub fn accepts_destination(&self, packet: &ParsedPacket) -> bool {
        self.by_port
            .load()
            .contains_key(&packet.destination_endpoint().port)
    }

    /// Capture semantics: traffic is accepted only if one side of the flow is a
    /// configured service port. With an empty service registry, no traffic is
    /// admitted into the flow engine.
    pub fn accepts_flow(&self, key: &FlowKey) -> bool {
        let current = self.by_port.load();
        current.contains_key(&key.a.port) || current.contains_key(&key.b.port)
    }

    pub fn service_for_http(&self, key: &FlowKey, request_direction: Direction) -> String {
        let port = match request_direction {
            Direction::AToB => key.b.port,
            Direction::BToA => key.a.port,
        };
        let current = self.by_port.load();
        current
            .get(&port)
            .map(|service| service.name.clone())
            .unwrap_or_else(|| format!("http:{port}"))
    }

    pub fn service_for_flow(&self, key: &FlowKey) -> Option<String> {
        let current = self.by_port.load();
        current
            .get(&key.a.port)
            .or_else(|| current.get(&key.b.port))
            .map(|service| service.name.clone())
    }

    pub fn should_parse_http(&self, key: &FlowKey) -> bool {
        let current = self.by_port.load();
        current
            .get(&key.a.port)
            .or_else(|| current.get(&key.b.port))
            .map(|service| service.http)
            .unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct L7Ingress {
    shard_txs: Arc<Vec<Sender<FlowOutput>>>,
    metrics: Arc<Metrics>,
}

impl L7Ingress {
    pub fn send(
        &self,
        event: FlowOutput,
    ) -> std::result::Result<usize, crossbeam_channel::SendError<FlowOutput>> {
        let flow_id = match &event {
            FlowOutput::Chunk(chunk) => chunk.flow_id,
            FlowOutput::Snapshot(summary) | FlowOutput::Closed(summary) => summary.flow_id,
        };
        let idx = (flow_id.as_u128() as usize) % self.shard_txs.len();
        let tx = &self.shard_txs[idx];
        tx.send(event)?;
        Ok(Metrics::queue_enqueued(
            &self.metrics.l7_queue_depth,
            &self.metrics.l7_queue_high_watermark,
        ) as usize)
    }
}

pub struct L7Runtime {
    pub input: L7Ingress,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl L7Runtime {
    pub fn worker_count(&self) -> usize {
        self.handles.len()
    }

    pub fn critical_worker_finished(&self) -> bool {
        self.handles
            .iter()
            .any(std::thread::JoinHandle::is_finished)
    }

    pub fn join(self) -> anyhow::Result<()> {
        let L7Runtime { input, handles } = self;
        drop(input);
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("L7 worker panicked"))?;
        }
        Ok(())
    }
}

pub fn spawn_l7(
    cfg: Arc<Config>,
    matcher_tx: MatcherIngress,
    segments: Arc<SegmentStore>,
    metadata_tx: crate::storage::MetadataSink,
    services: Arc<ServiceRegistry>,
    metrics: Arc<Metrics>,
) -> anyhow::Result<L7Runtime> {
    let worker_count = cfg.l7_workers.max(1);
    let per_worker_capacity = (cfg.flow_to_l7_capacity / worker_count).max(1);
    metrics.l7_queue_capacity.store(
        (per_worker_capacity * worker_count) as u64,
        Ordering::Relaxed,
    );
    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut handles = Vec::with_capacity(worker_count);

    for worker_id in 0..worker_count {
        let (tx, rx) = crossbeam_channel::bounded::<FlowOutput>(per_worker_capacity);
        worker_txs.push(tx);
        let cfg2 = cfg.clone();
        let matcher2 = matcher_tx.clone();
        let segments2 = segments.clone();
        let metadata2 = metadata_tx.clone();
        let services2 = services.clone();
        let metrics2 = metrics.clone();
        let l7_cpu = if cfg.l7_cpus.is_empty() {
            None
        } else {
            Some(cfg.l7_cpus[worker_id % cfg.l7_cpus.len()])
        };
        handles.push(
            std::thread::Builder::new()
                .name(format!("l7-http-{worker_id}"))
                .spawn(move || {
                    if let Some(cpu) = l7_cpu {
                        match crate::affinity::pin_current(cpu) {
                            Ok(actual) if actual != cpu => tracing::info!(
                                worker_id,
                                requested_cpu = cpu,
                                actual_cpu = actual,
                                "L7 worker CPU remapped to container cpuset"
                            ),
                            Ok(_) => {}
                            Err(e) => {
                                tracing::warn!(worker_id, cpu, error=%e, "cannot pin L7 worker")
                            }
                        }
                    }
                    l7_worker_loop(
                        cfg2, rx, matcher2, segments2, metadata2, services2, metrics2,
                    )
                })?,
        );
    }

    Ok(L7Runtime {
        input: L7Ingress {
            shard_txs: Arc::new(worker_txs),
            metrics,
        },
        handles,
    })
}

fn l7_worker_loop(
    cfg: Arc<Config>,
    flow_rx: Receiver<FlowOutput>,
    matcher_tx: MatcherIngress,
    segments: Arc<SegmentStore>,
    metadata_tx: crate::storage::MetadataSink,
    services: Arc<ServiceRegistry>,
    metrics: Arc<Metrics>,
) {
    let mut parsers: AHashMap<FlowId, HttpConnection> = AHashMap::new();
    let mut detected_services: AHashMap<FlowId, String> = AHashMap::new();
    while let Ok(event) = flow_rx.recv() {
        metrics.touch_progress();
        Metrics::queue_dequeued(&metrics.l7_queue_depth);
        match event {
            FlowOutput::Chunk(chunk) => {
                // Parse while the chunk is borrowed, then transfer ownership of
                // its buffer into the immutable raw-content record. This avoids
                // one full payload clone per reassembled TCP chunk in the hot path.
                let parsed_events = if chunk.key.protocol == crate::model::TransportProtocol::Tcp
                    && services.should_parse_http(&chunk.key)
                {
                    let parser = parsers
                        .entry(chunk.flow_id)
                        .or_insert_with(|| HttpConnection::new(cfg.clone()));
                    let report = parser.feed(&chunk);
                    if report.parse_errors != 0 {
                        metrics
                            .http_parse_errors
                            .fetch_add(report.parse_errors, Ordering::Relaxed);
                    }
                    Some(report.events)
                } else {
                    None
                };

                let raw = ContentRecord {
                    id: Uuid::new_v4(),
                    flow_id: chunk.flow_id,
                    ts_ns: chunk.ts_ns,
                    service: services.service_for_flow(&chunk.key),
                    direction: chunk.direction,
                    view: ContentView::TcpRaw,
                    stream_offset: chunk.offset,
                    data: chunk.data,
                };
                fanout_content(raw, &matcher_tx, &segments, &metrics);

                if let Some(events) = parsed_events {
                    for evt in events {
                        if let Some(req_dir) = evt.request_direction {
                            let service = services.service_for_http(&chunk.key, req_dir);
                            detected_services.insert(chunk.flow_id, service.clone());
                            emit_http_event(
                                evt,
                                Some(service),
                                &matcher_tx,
                                &segments,
                                &metadata_tx,
                                &metrics,
                            );
                        } else {
                            emit_http_event(
                                evt,
                                detected_services.get(&chunk.flow_id).cloned(),
                                &matcher_tx,
                                &segments,
                                &metadata_tx,
                                &metrics,
                            );
                        }
                    }
                }
            }
            FlowOutput::Snapshot(mut summary) => {
                summary.service = summary.service.or_else(|| {
                    let a = summary.src_port;
                    let b = summary.dst_port;
                    services
                        .by_port(a)
                        .or_else(|| services.by_port(b))
                        .map(|service| service.name)
                });
                if metadata_tx.send(MetadataEvent::Flow(summary)).is_err() {
                    break;
                }
            }
            FlowOutput::Closed(mut summary) => {
                if let Some(mut parser) = parsers.remove(&summary.flow_id) {
                    for evt in parser.finish() {
                        emit_http_event(
                            evt,
                            detected_services.get(&summary.flow_id).cloned(),
                            &matcher_tx,
                            &segments,
                            &metadata_tx,
                            &metrics,
                        );
                    }
                }
                summary.service = detected_services.remove(&summary.flow_id).or_else(|| {
                    let a = summary.src_port;
                    let b = summary.dst_port;
                    services
                        .by_port(a)
                        .or_else(|| services.by_port(b))
                        .map(|service| service.name)
                });
                let flow_id = summary.flow_id;
                if metadata_tx.send(MetadataEvent::Flow(summary)).is_err() {
                    break;
                }
                // FlowClosed is recoverable housekeeping.  If the matcher is
                // overloaded its bounded tail cache has an independent expiry;
                // never let this analytical notification stop L7.
                let _ = matcher_tx.try_flow_closed(flow_id);
            }
        }
    }
}

fn fanout_content(
    record: ContentRecord,
    matcher_tx: &MatcherIngress,
    segments: &SegmentStore,
    _metrics: &Metrics,
) {
    // Storage acceptance has higher priority than analytical latency. The
    // payload is accepted into the bounded durable segment pipeline first; if
    // the matcher is saturated, lossless matcher admission then backpressures
    // L7 rather than silently discarding already-accepted content.
    let match_copy = matcher_tx
        .is_interested_view(record.view)
        .then(|| record.clone());
    if let Err(e) = segments.append(record) {
        tracing::error!(error=%e, "content segment writer stopped");
        return;
    }
    let Some(record) = match_copy else {
        return;
    };
    let _ = matcher_tx.send_content(record);
}

fn emit_http_event(
    mut evt: HttpEmission,
    service: Option<String>,
    matcher_tx: &MatcherIngress,
    segments: &SegmentStore,
    metadata_tx: &crate::storage::MetadataSink,
    metrics: &Metrics,
) {
    for mut record in evt.content.drain(..) {
        record.service = service.clone();
        fanout_content(record, matcher_tx, segments, metrics);
    }
    if let Some(meta) = evt.meta.take() {
        if meta.request {
            metrics.http_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            metrics.http_responses.fetch_add(1, Ordering::Relaxed);
        }
        if metadata_tx.send(MetadataEvent::Http(meta)).is_err() {
            tracing::warn!("metadata writer stopped while emitting HTTP metadata");
        }
    }
}

const HTTP_PENDING_REQUEST_LIMIT: usize = 4096;
const HTTP_RESYNC_SUFFIX: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpMode {
    Http,
    Tunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Other,
    Head,
    Connect,
}

impl RequestKind {
    #[inline]
    fn from_method(method: Option<&str>) -> Self {
        match method {
            Some(m) if m.eq_ignore_ascii_case("HEAD") => Self::Head,
            Some(m) if m.eq_ignore_ascii_case("CONNECT") => Self::Connect,
            _ => Self::Other,
        }
    }
}

struct HttpConnection {
    a_to_b: HttpStreamParser,
    b_to_a: HttpStreamParser,
    pending_requests: VecDeque<RequestKind>,
    request_direction: Option<Direction>,
    mode: HttpMode,
}

#[derive(Default)]
struct HttpFeedReport {
    events: Vec<HttpEmission>,
    parse_errors: u64,
}

impl HttpConnection {
    fn new(cfg: Arc<Config>) -> Self {
        Self {
            a_to_b: HttpStreamParser::new(cfg.clone()),
            b_to_a: HttpStreamParser::new(cfg),
            pending_requests: VecDeque::new(),
            request_direction: None,
            mode: HttpMode::Http,
        }
    }

    fn feed(&mut self, chunk: &StreamChunk) -> HttpFeedReport {
        if self.mode == HttpMode::Tunnel {
            return HttpFeedReport::default();
        }
        let Self {
            a_to_b,
            b_to_a,
            pending_requests,
            request_direction,
            mode,
        } = self;
        let parser = match chunk.direction {
            Direction::AToB => a_to_b,
            Direction::BToA => b_to_a,
        };
        parser.feed(chunk, pending_requests, request_direction, mode)
    }

    fn finish(&mut self) -> Vec<HttpEmission> {
        if self.mode == HttpMode::Tunnel {
            return Vec::new();
        }
        let mut out = self.a_to_b.finish();
        out.extend(self.b_to_a.finish());
        out
    }
}

struct HttpStreamParser {
    cfg: Arc<Config>,
    buffer: BytesMut,
    state: BodyState,
    /// Canonical TCP application-stream offset corresponding to the next byte
    /// consumed from `buffer`/body framing.
    stream_offset: u64,
    next_input_offset: Option<u64>,
    synced: bool,
    header_scan_from: usize,
}

#[derive(Debug)]
enum BodyState {
    Headers,
    Fixed {
        remaining: u64,
        info: MessageInfo,
        compressed: Vec<u8>,
    },
    SkipFixed {
        remaining: u64,
        capture_remaining: usize,
        info: MessageInfo,
    },
    Chunked {
        info: MessageInfo,
        decoder: ChunkedDecoder,
        compressed: Vec<u8>,
        body_seen: usize,
        capture_body: bool,
    },
    UntilClose {
        info: MessageInfo,
        compressed: Vec<u8>,
        body_seen: usize,
        capture_body: bool,
    },
}

#[derive(Debug, Clone)]
struct MessageInfo {
    flow_id: FlowId,
    ts_ns: u64,
    direction: Direction,
    request_direction: Direction,
    encoding: Encoding,
    body_view: ContentView,
    decoded_view: ContentView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Identity,
    Gzip,
    Deflate,
}

struct HttpEmission {
    content: Vec<ContentRecord>,
    meta: Option<HttpRecord>,
    request_direction: Option<Direction>,
}

impl HttpStreamParser {
    fn new(cfg: Arc<Config>) -> Self {
        Self {
            cfg,
            buffer: BytesMut::new(),
            state: BodyState::Headers,
            stream_offset: 0,
            next_input_offset: None,
            synced: true,
            header_scan_from: 0,
        }
    }

    fn feed(
        &mut self,
        chunk: &StreamChunk,
        pending_requests: &mut VecDeque<RequestKind>,
        request_direction: &mut Option<Direction>,
        mode: &mut HttpMode,
    ) -> HttpFeedReport {
        let mut report = HttpFeedReport::default();

        match self.next_input_offset {
            Some(expected) if expected != chunk.offset => {
                // TCP reassembly explicitly leaves a stream-offset hole when an
                // ACK/pressure recovery proves bytes were missed. Never glue
                // HTTP framing across that discontinuity.
                self.buffer.clear();
                self.state = BodyState::Headers;
                self.stream_offset = chunk.offset;
                self.synced = false;
                self.header_scan_from = 0;
                // Request/response pairing is no longer trustworthy across a
                // TCP discontinuity. Rebuild correlation from subsequently
                // parsed requests instead of applying stale HEAD/CONNECT rules.
                pending_requests.clear();
            }
            None => {
                self.stream_offset = chunk.offset;
                // A non-zero first semantic offset means TCP reassembly already
                // emitted a leading gap before any application bytes. Do not
                // assume that the first observed byte is an HTTP message boundary.
                // Offset zero can still be a mid-flow capture; a parse failure
                // there enters the same bounded resynchronization path.
                self.synced = chunk.offset == 0;
            }
            _ => {}
        }
        self.next_input_offset = Some(chunk.offset.saturating_add(chunk.data.len() as u64));
        self.buffer.extend_from_slice(&chunk.data);

        loop {
            let state = std::mem::replace(&mut self.state, BodyState::Headers);
            match state {
                BodyState::Headers => {
                    if !self.synced && !self.resync_to_http_start() {
                        self.state = BodyState::Headers;
                        break;
                    }

                    let Some(end) = find_double_crlf_from(&self.buffer, self.header_scan_from)
                    else {
                        if self.buffer.len() > self.cfg.http_max_header_bytes {
                            report.parse_errors = report.parse_errors.saturating_add(1);
                            self.synced = false;
                            self.header_scan_from = 0;
                            pending_requests.clear();
                            self.trim_desynced_suffix();
                        } else {
                            self.header_scan_from = self.buffer.len().saturating_sub(3);
                        }
                        self.state = BodyState::Headers;
                        break;
                    };
                    self.header_scan_from = 0;
                    let header = self.buffer.split_to(end + 4).freeze();
                    let header_offset = self.stream_offset;
                    self.stream_offset = self.stream_offset.saturating_add(header.len() as u64);

                    let parsed = match parse_header(&header) {
                        Ok(parsed) => parsed,
                        Err(_) => {
                            report.parse_errors = report.parse_errors.saturating_add(1);
                            self.synced = false;
                            pending_requests.clear();
                            self.state = BodyState::Headers;
                            continue;
                        }
                    };

                    if parsed.ambiguous_framing {
                        // TE wins framing per RFC 9112, but the combination is
                        // still smuggling-prone and should be visible as an error.
                        report.parse_errors = report.parse_errors.saturating_add(1);
                    }

                    let req_dir = if parsed.request {
                        *request_direction = Some(chunk.direction);
                        chunk.direction
                    } else {
                        (*request_direction).unwrap_or(chunk.direction.opposite())
                    };
                    let response_kind = if parsed.request {
                        None
                    } else {
                        pending_requests.front().copied()
                    };
                    let status = parsed.status;
                    let informational =
                        !parsed.request && matches!(status, Some(100..=199)) && status != Some(101);
                    if parsed.request {
                        if pending_requests.len() >= HTTP_PENDING_REQUEST_LIMIT {
                            pending_requests.pop_front();
                            report.parse_errors = report.parse_errors.saturating_add(1);
                        }
                        // Response framing only needs HEAD/CONNECT semantics;
                        // avoid a second String allocation for every request.
                        pending_requests
                            .push_back(RequestKind::from_method(parsed.method.as_deref()));
                    } else if !informational {
                        pending_requests.pop_front();
                    }

                    let response_to_head =
                        !parsed.request && response_kind == Some(RequestKind::Head);
                    let connect_tunnel = !parsed.request
                        && response_kind == Some(RequestKind::Connect)
                        && matches!(status, Some(200..=299));
                    let upgrade_tunnel = !parsed.request && status == Some(101);
                    let no_body_status = !parsed.request
                        && matches!(status, Some(100..=199) | Some(204) | Some(205) | Some(304));

                    let header_view = if parsed.request {
                        ContentView::HttpRequestHeaders
                    } else {
                        ContentView::HttpResponseHeaders
                    };
                    let body_view = if parsed.request {
                        ContentView::HttpRequestBody
                    } else {
                        ContentView::HttpResponseBody
                    };
                    let decoded_view = if parsed.request {
                        ContentView::HttpRequestDecodedBody
                    } else {
                        ContentView::HttpResponseDecodedBody
                    };
                    let info = MessageInfo {
                        flow_id: chunk.flow_id,
                        ts_ns: chunk.ts_ns,
                        direction: chunk.direction,
                        request_direction: req_dir,
                        encoding: parsed.encoding,
                        body_view,
                        decoded_view,
                    };
                    let header_record = ContentRecord {
                        id: Uuid::new_v4(),
                        flow_id: chunk.flow_id,
                        ts_ns: chunk.ts_ns,
                        service: None,
                        direction: chunk.direction,
                        view: header_view,
                        stream_offset: header_offset,
                        data: header,
                    };
                    let meta = HttpRecord {
                        id: Uuid::new_v4(),
                        flow_id: chunk.flow_id,
                        timestamp: ns_to_datetime(chunk.ts_ns),
                        request: parsed.request,
                        method: parsed.method,
                        host: parsed.host,
                        path: parsed.path,
                        status: parsed.status,
                        user_agent: parsed.user_agent,
                        content_type: parsed.content_type,
                        body_content_id: None,
                    };
                    report.events.push(HttpEmission {
                        content: vec![header_record],
                        meta: Some(meta),
                        request_direction: Some(req_dir),
                    });

                    if connect_tunnel || upgrade_tunnel {
                        // Everything after the successful CONNECT/101 header is
                        // a different protocol. Keep canonical TCP raw records,
                        // but never guess HTTP framing inside the tunnel.
                        *mode = HttpMode::Tunnel;
                        self.buffer.clear();
                        self.state = BodyState::Headers;
                        break;
                    }

                    let no_body = no_body_status || response_to_head;
                    self.state = if no_body
                        || (parsed.request
                            && !parsed.has_transfer_encoding
                            && parsed.content_length.is_none())
                    {
                        BodyState::Headers
                    } else if parsed.has_transfer_encoding {
                        if parsed.transfer_final_chunked {
                            BodyState::Chunked {
                                info,
                                decoder: ChunkedDecoder::default(),
                                compressed: Vec::new(),
                                body_seen: 0,
                                capture_body: true,
                            }
                        } else if parsed.request {
                            // A request whose final transfer coding is not
                            // chunked has no self-delimiting HTTP/1.1 framing.
                            report.parse_errors = report.parse_errors.saturating_add(1);
                            self.synced = false;
                            pending_requests.clear();
                            BodyState::Headers
                        } else {
                            BodyState::UntilClose {
                                info,
                                compressed: Vec::new(),
                                body_seen: 0,
                                capture_body: true,
                            }
                        }
                    } else if let Some(len) = parsed.content_length {
                        if len == 0 {
                            BodyState::Headers
                        } else if len > self.cfg.http_max_body_bytes as u64 {
                            // Preserve framing at O(1) memory: skip semantic body
                            // materialization, not the stream state.
                            BodyState::SkipFixed {
                                remaining: len,
                                capture_remaining: self.cfg.http_max_body_bytes,
                                info,
                            }
                        } else {
                            BodyState::Fixed {
                                remaining: len,
                                info,
                                compressed: Vec::new(),
                            }
                        }
                    } else {
                        BodyState::UntilClose {
                            info,
                            compressed: Vec::new(),
                            body_seen: 0,
                            capture_body: true,
                        }
                    };
                }
                BodyState::Fixed {
                    mut remaining,
                    info,
                    mut compressed,
                } => {
                    if self.buffer.is_empty() {
                        self.state = BodyState::Fixed {
                            remaining,
                            info,
                            compressed,
                        };
                        break;
                    }
                    let take = (remaining.min(self.buffer.len() as u64)) as usize;
                    let data = self.buffer.split_to(take).freeze();
                    if info.encoding != Encoding::Identity
                        && compressed.len().saturating_add(data.len())
                            <= self.cfg.http_max_decode_bytes
                    {
                        compressed.extend_from_slice(&data);
                    }
                    let rec = body_record(&info, self.stream_offset, data);
                    self.stream_offset = self.stream_offset.saturating_add(take as u64);
                    remaining -= take as u64;
                    report.events.push(HttpEmission {
                        content: vec![rec],
                        meta: None,
                        request_direction: Some(info.request_direction),
                    });
                    if remaining == 0 {
                        if let Some(record) = decoded_record(
                            &info,
                            self.stream_offset,
                            &mut compressed,
                            self.cfg.http_max_decode_bytes,
                            self.cfg.http_max_decode_ratio,
                        ) {
                            report.events.push(HttpEmission {
                                content: vec![record],
                                meta: None,
                                request_direction: Some(info.request_direction),
                            });
                        }
                        self.state = BodyState::Headers;
                    } else {
                        self.state = BodyState::Fixed {
                            remaining,
                            info,
                            compressed,
                        };
                        break;
                    }
                }
                BodyState::SkipFixed {
                    mut remaining,
                    mut capture_remaining,
                    info,
                } => {
                    if self.buffer.is_empty() {
                        self.state = BodyState::SkipFixed {
                            remaining,
                            capture_remaining,
                            info,
                        };
                        break;
                    }
                    let take = (remaining.min(self.buffer.len() as u64)) as usize;
                    let wire = self.buffer.split_to(take).freeze();
                    let collect = take.min(capture_remaining);
                    if collect != 0 {
                        let captured = wire.slice(..collect);
                        report.events.push(HttpEmission {
                            content: vec![body_record(&info, self.stream_offset, captured)],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                        capture_remaining -= collect;
                    }
                    self.stream_offset = self.stream_offset.saturating_add(take as u64);
                    remaining -= take as u64;
                    if remaining == 0 {
                        self.state = BodyState::Headers;
                    } else {
                        self.state = BodyState::SkipFixed {
                            remaining,
                            capture_remaining,
                            info,
                        };
                        break;
                    }
                }
                BodyState::Chunked {
                    info,
                    mut decoder,
                    mut compressed,
                    mut body_seen,
                    mut capture_body,
                } => {
                    if self.buffer.is_empty() {
                        self.state = BodyState::Chunked {
                            info,
                            decoder,
                            compressed,
                            body_seen,
                            capture_body,
                        };
                        break;
                    }
                    let before = self.buffer.len();
                    let base_offset = self.stream_offset;
                    let collect_remaining = if capture_body {
                        self.cfg.http_max_body_bytes.saturating_sub(body_seen)
                    } else {
                        0
                    };
                    match decoder.consume(
                        &mut self.buffer,
                        self.cfg.http_max_header_bytes,
                        collect_remaining,
                    ) {
                        Ok(result) => {
                            for chunk_data in result.data_chunks {
                                let data_len = chunk_data.data.len();
                                let record_offset =
                                    base_offset.saturating_add(chunk_data.relative_offset as u64);
                                if info.encoding != Encoding::Identity
                                    && compressed.len().saturating_add(data_len)
                                        <= self.cfg.http_max_decode_bytes
                                {
                                    compressed.extend_from_slice(&chunk_data.data);
                                }
                                report.events.push(HttpEmission {
                                    content: vec![body_record(
                                        &info,
                                        record_offset,
                                        chunk_data.data,
                                    )],
                                    meta: None,
                                    request_direction: Some(info.request_direction),
                                });
                            }
                            body_seen = body_seen.saturating_add(result.body_bytes);
                            if body_seen > self.cfg.http_max_body_bytes {
                                capture_body = false;
                            }
                            self.stream_offset = self
                                .stream_offset
                                .saturating_add(result.wire_consumed as u64);
                            if result.done {
                                if capture_body {
                                    if let Some(record) = decoded_record(
                                        &info,
                                        self.stream_offset,
                                        &mut compressed,
                                        self.cfg.http_max_decode_bytes,
                                        self.cfg.http_max_decode_ratio,
                                    ) {
                                        report.events.push(HttpEmission {
                                            content: vec![record],
                                            meta: None,
                                            request_direction: Some(info.request_direction),
                                        });
                                    }
                                }
                                self.state = BodyState::Headers;
                            } else {
                                let made_progress = self.buffer.len() != before;
                                self.state = BodyState::Chunked {
                                    info,
                                    decoder,
                                    compressed,
                                    body_seen,
                                    capture_body,
                                };
                                if !made_progress {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            let consumed = before.saturating_sub(self.buffer.len());
                            self.stream_offset = self.stream_offset.saturating_add(consumed as u64);
                            report.parse_errors = report.parse_errors.saturating_add(1);
                            self.synced = false;
                            pending_requests.clear();
                            self.state = BodyState::Headers;
                        }
                    }
                }
                BodyState::UntilClose {
                    info,
                    mut compressed,
                    mut body_seen,
                    mut capture_body,
                } => {
                    if self.buffer.is_empty() {
                        self.state = BodyState::UntilClose {
                            info,
                            compressed,
                            body_seen,
                            capture_body,
                        };
                        break;
                    }
                    let data = self.buffer.split().freeze();
                    let data_len = data.len();
                    let collect = if capture_body {
                        data_len.min(self.cfg.http_max_body_bytes.saturating_sub(body_seen))
                    } else {
                        0
                    };
                    if collect != 0 {
                        let captured = data.slice(..collect);
                        if info.encoding != Encoding::Identity
                            && compressed.len().saturating_add(captured.len())
                                <= self.cfg.http_max_decode_bytes
                        {
                            compressed.extend_from_slice(&captured);
                        }
                        report.events.push(HttpEmission {
                            content: vec![body_record(&info, self.stream_offset, captured)],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                    body_seen = body_seen.saturating_add(data_len);
                    if body_seen > self.cfg.http_max_body_bytes {
                        capture_body = false;
                    }
                    self.stream_offset = self.stream_offset.saturating_add(data_len as u64);
                    self.state = BodyState::UntilClose {
                        info,
                        compressed,
                        body_seen,
                        capture_body,
                    };
                    break;
                }
            }
        }
        report
    }

    fn finish(&mut self) -> Vec<HttpEmission> {
        let mut out = Vec::new();
        let state = std::mem::replace(&mut self.state, BodyState::Headers);
        match state {
            BodyState::UntilClose {
                info,
                mut compressed,
                body_seen,
                capture_body,
            } => {
                let mut final_capture = capture_body;
                if !self.buffer.is_empty() {
                    let data = self.buffer.split().freeze();
                    let data_len = data.len();
                    let collect = if capture_body {
                        data_len.min(self.cfg.http_max_body_bytes.saturating_sub(body_seen))
                    } else {
                        0
                    };
                    if collect != 0 {
                        let captured = data.slice(..collect);
                        if info.encoding != Encoding::Identity
                            && compressed.len().saturating_add(captured.len())
                                <= self.cfg.http_max_decode_bytes
                        {
                            compressed.extend_from_slice(&captured);
                        }
                        out.push(HttpEmission {
                            content: vec![body_record(&info, self.stream_offset, captured)],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                    final_capture &=
                        body_seen.saturating_add(data_len) <= self.cfg.http_max_body_bytes;
                    self.stream_offset = self.stream_offset.saturating_add(data_len as u64);
                }
                if final_capture {
                    if let Some(record) = decoded_record(
                        &info,
                        self.stream_offset,
                        &mut compressed,
                        self.cfg.http_max_decode_bytes,
                        self.cfg.http_max_decode_ratio,
                    ) {
                        out.push(HttpEmission {
                            content: vec![record],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                }
            }
            BodyState::Fixed {
                remaining,
                info,
                mut compressed,
            } => {
                let take = (remaining.min(self.buffer.len() as u64)) as usize;
                if take > 0 {
                    let data = self.buffer.split_to(take).freeze();
                    if info.encoding != Encoding::Identity
                        && compressed.len().saturating_add(data.len())
                            <= self.cfg.http_max_decode_bytes
                    {
                        compressed.extend_from_slice(&data);
                    }
                    out.push(HttpEmission {
                        content: vec![body_record(&info, self.stream_offset, data)],
                        meta: None,
                        request_direction: Some(info.request_direction),
                    });
                    self.stream_offset = self.stream_offset.saturating_add(take as u64);
                }
                if take as u64 == remaining {
                    if let Some(record) = decoded_record(
                        &info,
                        self.stream_offset,
                        &mut compressed,
                        self.cfg.http_max_decode_bytes,
                        self.cfg.http_max_decode_ratio,
                    ) {
                        out.push(HttpEmission {
                            content: vec![record],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                }
                self.buffer.clear();
            }
            BodyState::SkipFixed {
                remaining,
                capture_remaining,
                info,
            } => {
                let take = (remaining.min(self.buffer.len() as u64)) as usize;
                if take != 0 {
                    let wire = self.buffer.split_to(take).freeze();
                    let collect = take.min(capture_remaining);
                    if collect != 0 {
                        let captured = wire.slice(..collect);
                        out.push(HttpEmission {
                            content: vec![body_record(&info, self.stream_offset, captured)],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                    self.stream_offset = self.stream_offset.saturating_add(take as u64);
                }
                self.buffer.clear();
            }
            BodyState::Chunked {
                info,
                mut decoder,
                mut compressed,
                mut body_seen,
                mut capture_body,
            } => {
                let collect_remaining = if capture_body {
                    self.cfg.http_max_body_bytes.saturating_sub(body_seen)
                } else {
                    0
                };
                if let Ok(result) = decoder.consume(
                    &mut self.buffer,
                    self.cfg.http_max_header_bytes,
                    collect_remaining,
                ) {
                    let base_offset = self.stream_offset;
                    for chunk_data in result.data_chunks {
                        let len = chunk_data.data.len();
                        if info.encoding != Encoding::Identity
                            && compressed.len().saturating_add(len)
                                <= self.cfg.http_max_decode_bytes
                        {
                            compressed.extend_from_slice(&chunk_data.data);
                        }
                        out.push(HttpEmission {
                            content: vec![body_record(
                                &info,
                                base_offset + chunk_data.relative_offset as u64,
                                chunk_data.data,
                            )],
                            meta: None,
                            request_direction: Some(info.request_direction),
                        });
                    }
                    body_seen = body_seen.saturating_add(result.body_bytes);
                    if body_seen > self.cfg.http_max_body_bytes {
                        capture_body = false;
                    }
                    self.stream_offset = self
                        .stream_offset
                        .saturating_add(result.wire_consumed as u64);
                    if result.done && capture_body {
                        if let Some(record) = decoded_record(
                            &info,
                            self.stream_offset,
                            &mut compressed,
                            self.cfg.http_max_decode_bytes,
                            self.cfg.http_max_decode_ratio,
                        ) {
                            out.push(HttpEmission {
                                content: vec![record],
                                meta: None,
                                request_direction: Some(info.request_direction),
                            });
                        }
                    }
                }
                self.buffer.clear();
            }
            BodyState::Headers => self.buffer.clear(),
        }
        out
    }

    fn resync_to_http_start(&mut self) -> bool {
        if let Some(pos) = find_plausible_http_start(&self.buffer) {
            if pos != 0 {
                let _ = self.buffer.split_to(pos);
                self.stream_offset = self.stream_offset.saturating_add(pos as u64);
            }
            self.synced = true;
            self.header_scan_from = 0;
            true
        } else {
            self.trim_desynced_suffix();
            false
        }
    }

    fn trim_desynced_suffix(&mut self) {
        let drop = self.buffer.len().saturating_sub(HTTP_RESYNC_SUFFIX);
        if drop != 0 {
            let _ = self.buffer.split_to(drop);
            self.stream_offset = self.stream_offset.saturating_add(drop as u64);
        }
    }
}

fn body_record(info: &MessageInfo, offset: u64, data: Bytes) -> ContentRecord {
    ContentRecord {
        id: Uuid::new_v4(),
        flow_id: info.flow_id,
        ts_ns: info.ts_ns,
        service: None,
        direction: info.direction,
        view: info.body_view,
        stream_offset: offset,
        data,
    }
}

fn decoded_record(
    info: &MessageInfo,
    offset: u64,
    compressed: &mut Vec<u8>,
    absolute_limit: usize,
    max_ratio: usize,
) -> Option<ContentRecord> {
    if info.encoding == Encoding::Identity || compressed.is_empty() {
        return None;
    }
    let data = std::mem::take(compressed);
    let ratio_limit = data.len().saturating_mul(max_ratio);
    let limit = absolute_limit.min(ratio_limit);
    if limit == 0 {
        return None;
    }
    let decoded = match info.encoding {
        Encoding::Gzip => read_bounded(GzDecoder::new(data.as_slice()), limit),
        Encoding::Deflate => read_bounded(ZlibDecoder::new(data.as_slice()), limit),
        Encoding::Identity => return None,
    }
    .ok()?;
    Some(ContentRecord {
        id: Uuid::new_v4(),
        flow_id: info.flow_id,
        ts_ns: info.ts_ns,
        service: None,
        direction: info.direction,
        view: info.decoded_view,
        stream_offset: offset,
        data: bytes::Bytes::from(decoded),
    })
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if out.len().saturating_add(read) > limit {
            bail!("decompressed body limit exceeded");
        }
        out.extend_from_slice(&buffer[..read]);
    }
    Ok(out)
}

struct ParsedHeader {
    request: bool,
    method: Option<String>,
    host: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    user_agent: Option<String>,
    content_type: Option<String>,
    content_length: Option<u64>,
    has_transfer_encoding: bool,
    transfer_final_chunked: bool,
    ambiguous_framing: bool,
    encoding: Encoding,
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    // Parse directly from the byte buffer. Only metadata fields used by BAZALT
    // are materialized into Strings; the complete wire header remains in the
    // ContentRecord and is not reconstructed here.
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let (request, method, path, status, parsed_headers) = if bytes.starts_with(b"HTTP/") {
        let mut response = httparse::Response::new(&mut headers);
        if response.parse(bytes)?.is_partial() {
            bail!("partial HTTP response header");
        }
        (false, None, None, response.code, response.headers)
    } else {
        let mut request = httparse::Request::new(&mut headers);
        if request.parse(bytes)?.is_partial() {
            bail!("partial HTTP request header");
        }
        let method = request.method.map(str::to_owned);
        let path = request.path.map(str::to_owned);
        if method.is_none() || path.is_none() {
            bail!("invalid HTTP request line");
        }
        (true, method, path, None, request.headers)
    };

    let host = header_text(parsed_headers, "host");
    let user_agent = header_text(parsed_headers, "user-agent");
    let content_type = header_text(parsed_headers, "content-type");
    let content_length = parse_content_length(parsed_headers)?;
    let (has_transfer_encoding, transfer_final_chunked) =
        transfer_encoding_framing(parsed_headers)?;
    let ambiguous_framing = has_transfer_encoding && content_length.is_some();

    let encoding = match header_bytes(parsed_headers, "content-encoding") {
        Some(v) if ascii_contains_ignore_case(v, b"gzip") => Encoding::Gzip,
        Some(v) if ascii_contains_ignore_case(v, b"deflate") => Encoding::Deflate,
        _ => Encoding::Identity,
    };

    Ok(ParsedHeader {
        request,
        method,
        host,
        path,
        status,
        user_agent,
        content_type,
        // RFC 9112: Transfer-Encoding overrides Content-Length for framing.
        // Keeping the CL out of the decision also prevents CL/TE smuggling
        // differentials inside the analyzer.
        content_length: if has_transfer_encoding {
            None
        } else {
            content_length
        },
        has_transfer_encoding,
        transfer_final_chunked,
        ambiguous_framing,
        encoding,
    })
}

fn parse_content_length(headers: &[httparse::Header<'_>]) -> Result<Option<u64>> {
    let mut value = None::<u64>;
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        let text = std::str::from_utf8(h.value)
            .map_err(|_| anyhow::anyhow!("invalid Content-Length encoding"))?;
        // RFC permits a repeated/comma-joined field only when all decimal
        // values are identical. Anything else is ambiguous framing.
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() || !token.as_bytes().iter().all(|b| b.is_ascii_digit()) {
                bail!("invalid Content-Length value");
            }
            let parsed = token
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Content-Length overflow"))?;
            match value {
                Some(existing) if existing != parsed => bail!("conflicting Content-Length values"),
                Some(_) => {}
                None => value = Some(parsed),
            }
        }
    }
    Ok(value)
}

fn transfer_encoding_framing(headers: &[httparse::Header<'_>]) -> Result<(bool, bool)> {
    let mut seen_any = false;
    let mut final_chunked = false;
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        let text = std::str::from_utf8(h.value)
            .map_err(|_| anyhow::anyhow!("invalid Transfer-Encoding"))?;
        for raw in text.split(',') {
            let coding = raw.split(';').next().unwrap_or("").trim();
            if coding.is_empty() {
                bail!("empty Transfer-Encoding coding");
            }
            // If a prior coding was chunked, seeing anything after it makes
            // chunked non-final and therefore invalid for HTTP/1.1 framing.
            if final_chunked {
                bail!("chunked transfer coding is not final");
            }
            seen_any = true;
            final_chunked = coding.eq_ignore_ascii_case("chunked");
        }
    }
    Ok((seen_any, final_chunked))
}

fn header_bytes<'h, 'b>(headers: &'h [httparse::Header<'b>], name: &str) -> Option<&'b [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value)
}

fn header_text(headers: &[httparse::Header<'_>], name: &str) -> Option<String> {
    header_bytes(headers, name).map(|v| String::from_utf8_lossy(v).trim().to_owned())
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[derive(Default, Debug)]
struct ChunkedDecoder {
    state: ChunkState,
    scan_from: usize,
}

#[derive(Default, Debug)]
enum ChunkState {
    #[default]
    Size,
    Data(usize),
    DataCrlf,
    Trailers,
}

struct ChunkData {
    relative_offset: usize,
    data: Bytes,
}

struct ChunkConsume {
    data_chunks: Vec<ChunkData>,
    done: bool,
    wire_consumed: usize,
    body_bytes: usize,
}

impl ChunkedDecoder {
    fn consume(
        &mut self,
        buf: &mut BytesMut,
        max_line: usize,
        max_collect: usize,
    ) -> Result<ChunkConsume> {
        let initial_len = buf.len();
        let mut chunks = Vec::new();
        let mut collected = 0usize;
        let mut body_bytes = 0usize;
        let mut done = false;
        loop {
            match self.state {
                ChunkState::Size => {
                    let Some(pos) = find_crlf_from(buf, self.scan_from) else {
                        if buf.len() > max_line {
                            bail!("chunk-size line limit exceeded");
                        }
                        self.scan_from = buf.len().saturating_sub(1);
                        break;
                    };
                    self.scan_from = 0;
                    let line = buf.split_to(pos + 2);
                    let s = std::str::from_utf8(&line[..pos])?
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if s.is_empty() || s.len() > 16 {
                        bail!("bad chunk size");
                    }
                    let n = usize::from_str_radix(s, 16)
                        .map_err(|_| anyhow::anyhow!("bad chunk size"))?;
                    if n == 0 {
                        self.state = ChunkState::Trailers;
                    } else {
                        self.state = ChunkState::Data(n);
                    }
                }
                ChunkState::Data(mut remaining) => {
                    if buf.is_empty() {
                        break;
                    }
                    let take = remaining.min(buf.len());
                    let relative_offset = initial_len.saturating_sub(buf.len());
                    let collect = take.min(max_collect.saturating_sub(collected));
                    if collect != 0 {
                        let data = buf.split_to(take).freeze();
                        chunks.push(ChunkData {
                            relative_offset,
                            data: data.slice(..collect),
                        });
                        collected = collected.saturating_add(collect);
                    } else {
                        let _ = buf.split_to(take);
                    }
                    body_bytes = body_bytes.saturating_add(take);
                    remaining -= take;
                    self.state = if remaining == 0 {
                        ChunkState::DataCrlf
                    } else {
                        ChunkState::Data(remaining)
                    };
                    if remaining != 0 {
                        break;
                    }
                }
                ChunkState::DataCrlf => {
                    if buf.len() < 2 {
                        break;
                    }
                    if &buf[..2] != b"\r\n" {
                        bail!("missing chunk CRLF");
                    }
                    let _ = buf.split_to(2);
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    if buf.starts_with(b"\r\n") {
                        let _ = buf.split_to(2);
                        done = true;
                        self.state = ChunkState::Size;
                        self.scan_from = 0;
                        break;
                    }
                    let Some(pos) = find_double_crlf_from(buf, self.scan_from) else {
                        if buf.len() > max_line {
                            bail!("chunk trailer limit exceeded");
                        }
                        self.scan_from = buf.len().saturating_sub(3);
                        break;
                    };
                    let _ = buf.split_to(pos + 4);
                    done = true;
                    self.state = ChunkState::Size;
                    self.scan_from = 0;
                    break;
                }
            }
        }
        Ok(ChunkConsume {
            data_chunks: chunks,
            done,
            wire_consumed: initial_len.saturating_sub(buf.len()),
            body_bytes,
        })
    }
}

fn find_crlf_from(v: &[u8], from: usize) -> Option<usize> {
    if v.len() < 2 {
        return None;
    }
    let start = from.min(v.len().saturating_sub(1));
    v[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

fn find_double_crlf_from(v: &[u8], from: usize) -> Option<usize> {
    if v.len() < 4 {
        return None;
    }
    let start = from.min(v.len().saturating_sub(3));
    v[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| start + p)
}

fn find_plausible_http_start(v: &[u8]) -> Option<usize> {
    // Resynchronize only at a line boundary. Besides reducing false positives
    // inside binary/body data, this makes the scan linear in the input size
    // instead of trying a multi-kilobyte request-line probe at every byte.
    if looks_like_http_start(v) {
        return Some(0);
    }
    for (idx, byte) in v.iter().enumerate() {
        if *byte == b'\n' {
            let start = idx.saturating_add(1);
            if start < v.len() && looks_like_http_start(&v[start..]) {
                return Some(start);
            }
        }
    }
    None
}

fn looks_like_http_start(v: &[u8]) -> bool {
    // During gap recovery recognize a plausible start as soon as its prefix is
    // unambiguous. Waiting for the complete request-target/version would make a
    // long request line vulnerable to suffix trimming across TCP chunks. The
    // complete header is still validated by httparse before any event is emitted.
    if v.starts_with(b"HTTP/") {
        return true;
    }
    let Some(method_end) = v.iter().take(17).position(|b| *b == b' ') else {
        return false;
    };
    if !(1..=16).contains(&method_end) {
        return false;
    }
    let method = &v[..method_end];
    if !method.iter().all(|b| b.is_ascii_uppercase() || *b == b'-') {
        return false;
    }

    let rest = &v[method_end + 1..];
    if rest.is_empty() {
        return false;
    }
    if method == b"CONNECT" {
        return !rest[0].is_ascii_whitespace(); // authority-form candidate
    }
    rest.starts_with(b"/")
        || rest.starts_with(b"*")
        || rest.starts_with(b"http://")
        || rest.starts_with(b"https://")
}

fn ns_to_datetime(ns: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Endpoint, FlowKey, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow_key() -> FlowKey {
        FlowKey {
            a: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 1234,
            },
            b: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 80,
            },
            protocol: TransportProtocol::Tcp,
            l2_domain: 0,
        }
    }

    fn chunk(direction: Direction, offset: u64, data: &[u8]) -> StreamChunk {
        StreamChunk {
            flow_id: Uuid::nil(),
            ts_ns: 1,
            direction,
            key: flow_key(),
            offset,
            data: Bytes::copy_from_slice(data),
            truncated: false,
        }
    }

    fn request_metas(report: &HttpFeedReport) -> Vec<&HttpRecord> {
        report
            .events
            .iter()
            .filter_map(|e| e.meta.as_ref())
            .filter(|m| m.request)
            .collect()
    }

    fn response_metas(report: &HttpFeedReport) -> Vec<&HttpRecord> {
        report
            .events
            .iter()
            .filter_map(|e| e.meta.as_ref())
            .filter(|m| !m.request)
            .collect()
    }

    #[test]
    fn extracts_user_agent_and_streams_body() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let report = c.feed(&chunk(
            Direction::AToB,
            0,
            b"POST /x HTTP/1.1\r\nHost: a\r\nUser-Agent: python-requests/2\r\nContent-Length: 5\r\n\r\nhello",
        ));
        assert_eq!(report.parse_errors, 0);
        let meta = request_metas(&report)[0];
        assert_eq!(meta.user_agent.as_deref(), Some("python-requests/2"));
        assert!(report
            .events
            .iter()
            .flat_map(|e| e.content.iter())
            .any(|c| { c.view == ContentView::HttpRequestBody && c.data.as_ref() == b"hello" }));
    }

    #[test]
    fn head_response_does_not_consume_next_response_as_body() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let req = b"HEAD /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let rr = c.feed(&chunk(Direction::AToB, 0, req));
        assert_eq!(request_metas(&rr).len(), 2);

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        let sr = c.feed(&chunk(Direction::BToA, 0, resp));
        assert_eq!(sr.parse_errors, 0);
        assert_eq!(response_metas(&sr).len(), 2);
        assert_eq!(response_metas(&sr)[0].status, Some(200));
        assert_eq!(response_metas(&sr)[1].status, Some(204));
    }

    #[test]
    fn connect_switches_connection_to_tunnel() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let rq = c.feed(&chunk(
            Direction::AToB,
            0,
            b"CONNECT host:443 HTTP/1.1\r\nHost: host\r\n\r\n",
        ));
        assert_eq!(request_metas(&rq).len(), 1);
        let rs = c.feed(&chunk(
            Direction::BToA,
            0,
            b"HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x01garbage",
        ));
        assert_eq!(response_metas(&rs).len(), 1);
        assert_eq!(c.mode, HttpMode::Tunnel);
        let later = c.feed(&chunk(
            Direction::BToA,
            48,
            b"GET /not-http-inside-tunnel HTTP/1.1\r\n\r\n",
        ));
        assert!(later.events.is_empty());
        assert_eq!(later.parse_errors, 0);
    }

    #[test]
    fn oversized_fixed_body_is_skipped_without_losing_framing() {
        let mut cfg = test_cfg();
        cfg.http_max_body_bytes = 4;
        let mut c = HttpConnection::new(Arc::new(cfg));
        let wire = b"POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789GET /ok HTTP/1.1\r\nHost: x\r\n\r\n";
        let r = c.feed(&chunk(Direction::AToB, 0, wire));
        assert_eq!(r.parse_errors, 0);
        let metas = request_metas(&r);
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].path.as_deref(), Some("/big"));
        assert_eq!(metas[1].path.as_deref(), Some("/ok"));
        let captured = r
            .events
            .iter()
            .flat_map(|e| e.content.iter())
            .filter(|c| c.view == ContentView::HttpRequestBody)
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&captured, b"0123");
    }

    #[test]
    fn conflicting_content_length_resyncs_to_next_message() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let wire = b"POST /bad HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nGET /ok HTTP/1.1\r\nHost: x\r\n\r\n";
        let r = c.feed(&chunk(Direction::AToB, 0, wire));
        assert_eq!(r.parse_errors, 1);
        let metas = request_metas(&r);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].path.as_deref(), Some("/ok"));
    }

    #[test]
    fn leading_tcp_gap_starts_http_parser_unsynchronized() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let r = c.feed(&chunk(
            Direction::AToB,
            100,
            b"garbage\r\nGET /recovered HTTP/1.1\r\nHost: x\r\n\r\n",
        ));
        assert_eq!(r.parse_errors, 0);
        let metas = request_metas(&r);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].path.as_deref(), Some("/recovered"));
    }

    #[test]
    fn resync_keeps_long_request_target_split_across_chunks() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let mut first = b"junk\nGET /".to_vec();
        first.extend_from_slice(&[b'a'; 200]);
        let r1 = c.feed(&chunk(Direction::AToB, 100, &first));
        assert!(request_metas(&r1).is_empty());

        let second = b" HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let r2 = c.feed(&chunk(Direction::AToB, 100 + first.len() as u64, &second));
        let metas = request_metas(&r2);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].method.as_deref(), Some("GET"));
        assert_eq!(metas[0].path.as_ref().map(String::len), Some(201));
    }

    #[test]
    fn tcp_offset_gap_forces_http_resync() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let first = c.feed(&chunk(
            Direction::AToB,
            0,
            b"POST /lost HTTP/1.1\r\nContent-Length: 20\r\n\r\nabc",
        ));
        assert_eq!(request_metas(&first).len(), 1);
        // Offset jumps over an inferred/forced capture gap. The new plausible start
        // must be treated as a fresh message rather than body continuation.
        let second = c.feed(&chunk(
            Direction::AToB,
            200,
            b"GET /recovered HTTP/1.1\r\nHost: x\r\n\r\n",
        ));
        assert_eq!(second.parse_errors, 0);
        let metas = request_metas(&second);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].path.as_deref(), Some("/recovered"));
    }

    #[test]
    fn duplicate_equal_content_length_is_allowed_but_conflict_is_not() {
        let ok = parse_header(b"POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n").unwrap();
        assert_eq!(ok.content_length, Some(5));
        assert!(
            parse_header(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn transfer_encoding_requires_chunked_to_be_final() {
        let p = parse_header(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 999\r\n\r\n",
        )
        .unwrap();
        assert!(p.has_transfer_encoding);
        assert!(p.transfer_final_chunked);
        assert!(p.ambiguous_framing);
        assert_eq!(p.content_length, None);
        assert!(
            parse_header(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n").is_err()
        );
    }

    #[test]
    fn oversized_chunked_body_is_consumed_without_materializing_tail_or_losing_next_message() {
        let mut cfg = test_cfg();
        cfg.http_max_body_bytes = 4;
        let mut c = HttpConnection::new(Arc::new(cfg));
        let wire = b"POST /big HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\nGET /ok HTTP/1.1\r\nHost: x\r\n\r\n";
        let r = c.feed(&chunk(Direction::AToB, 0, wire));
        assert_eq!(r.parse_errors, 0);
        let metas = request_metas(&r);
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].path.as_deref(), Some("/big"));
        assert_eq!(metas[1].path.as_deref(), Some("/ok"));
        let captured = r
            .events
            .iter()
            .flat_map(|e| e.content.iter())
            .filter(|c| c.view == ContentView::HttpRequestBody)
            .map(|c| c.data.len())
            .sum::<usize>();
        assert_eq!(captured, 4);
    }

    #[test]
    fn resync_accepts_connect_authority_form_at_line_boundary() {
        let mut c = HttpConnection::new(Arc::new(test_cfg()));
        let first = c.feed(&chunk(Direction::AToB, 0, b"bad framing\r\n"));
        assert!(first.parse_errors >= 1 || first.events.is_empty());
        let second = c.feed(&chunk(
            Direction::AToB,
            100,
            b"junk\nCONNECT host:443 HTTP/1.1\r\nHost: host\r\n\r\n",
        ));
        let metas = request_metas(&second);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].method.as_deref(), Some("CONNECT"));
    }

    #[test]
    fn decodes_chunked_incrementally() {
        let mut d = ChunkedDecoder::default();
        let mut b = BytesMut::from(&b"4\r\ntest\r\n0\r\n\r\n"[..]);
        let r = d.consume(&mut b, 1024, usize::MAX).unwrap();
        assert!(r.done);
        assert_eq!(r.data_chunks.len(), 1);
        assert_eq!(r.data_chunks[0].data.as_ref(), b"test");
        assert_eq!(r.data_chunks[0].relative_offset, 3);
    }

    #[test]
    fn service_registry_is_capture_allow_list() {
        let registry = ServiceRegistry::new([ServiceConfig {
            port: 8080,
            name: "http".into(),
            http: true,
            urldecode_http_requests: false,
            merge_adjacent_packets: false,
            parse_websockets: false,
        }]);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (allowed, allowed_dir) =
            FlowKey::canonical(a, 45000, b, 8080, TransportProtocol::Tcp);
        let (denied, _) = FlowKey::canonical(a, 45000, b, 9999, TransportProtocol::Tcp);
        let inbound = ParsedPacket {
            ts_ns: 1,
            key: allowed.clone(),
            direction: allowed_dir,
            seq: Some(1),
            ack: Some(0),
            flags: crate::model::TcpFlags::default(),
            payload: Bytes::new(),
            wire_len: 64,
        };
        let (spoof_key, spoof_dir) =
            FlowKey::canonical(a, 8080, b, 9999, TransportProtocol::Tcp);
        let spoofed_source_port = ParsedPacket {
            ts_ns: 2,
            key: spoof_key.clone(),
            direction: spoof_dir,
            seq: Some(1),
            ack: Some(0),
            flags: crate::model::TcpFlags::default(),
            payload: Bytes::new(),
            wire_len: 64,
        };
        assert!(registry.accepts_flow(&allowed));
        assert!(!registry.accepts_flow(&denied));
        assert!(registry.accepts_destination(&inbound));
        assert!(registry.accepts_flow(&spoof_key));
        assert!(!registry.accepts_destination(&spoofed_source_port));
        registry.delete(8080);
        assert!(registry.is_empty());
        assert!(!registry.accepts_flow(&allowed));
    }

    fn test_cfg() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            capture_mode: crate::config::CaptureMode::Disabled,
            interface: "lo".into(),
            queue_id: 0,
            queue_ids: vec![0],
            cpu_auto: false,
            cpu_available: 1,
            cpu_budget: 1,
            tokio_workers: 1,
            capture_cpus: vec![],
            flow_cpus: vec![],
            l7_cpus: vec![],
            matcher_cpus: vec![],
            pcap_file: None,
            bpf_filter: None,
            snaplen: 65535,
            capture_batch: 64,
            capture_enqueue_timeout: std::time::Duration::from_micros(250),
            capture_fallback_pcap: true,
            early_port_filter: false,
            capture_to_flow_capacity: 128,
            flow_to_l7_capacity: 128,
            l7_to_match_capacity: 128,
            storage_capacity: 128,
            segment_queue_capacity: 128,
            metadata_spool_dir: "/tmp/bazalt-test-spool".into(),
            metadata_spool_max_bytes: 1024 * 1024,
            clickhouse_request_timeout: std::time::Duration::from_secs(1),
            flow_shards: 1,
            l7_workers: 1,
            matcher_workers: 1,
            tcp_idle_timeout: std::time::Duration::from_secs(1),
            tcp_gap_timeout: std::time::Duration::from_secs(1),
            udp_idle_timeout: std::time::Duration::from_secs(1),
            live_flow_update_interval: std::time::Duration::from_millis(100),
            max_flow_bytes: 0,
            max_active_flows: 1024,
            max_flows_per_source_prefix: 128,
            max_ooo_bytes: 1024,
            max_ooo_segments: 128,
            ip_fragment_cache_bytes: 1024 * 1024,
            ip_fragment_max_datagrams: 128,
            ip_fragment_timeout: std::time::Duration::from_secs(30),
            tunnel_decapsulation: true,
            http_max_header_bytes: 128 * 1024,
            http_max_body_bytes: 1024 * 1024,
            http_max_decode_bytes: 1024 * 1024,
            http_max_decode_ratio: 32,
            matcher_overlap_bytes: 1024,
            matcher_max_hits_per_pattern: 128,
            matcher_max_hits_per_record: 1024,
            segment_dir: "/tmp".into(),
            segment_max_bytes: 1024 * 1024,
            segment_store_max_bytes: 16 * 1024 * 1024,
            segment_max_record_bytes: 512 * 1024,
            raw_capture_enabled: false,
            raw_segment_dir: "/tmp".into(),
            topology_group_prefix_v4: 24,
            topology_source_ttl: std::time::Duration::from_secs(300),
            topology_max_sources: 65_536,
            throttle_enabled: false,
            postgres_url: String::new(),
            clickhouse_url: String::new(),
            clickhouse_database: "x".into(),
            clickhouse_username: None,
            clickhouse_password: None,
            replay_workers: 1,
            replay_live_queue_pause_pct: 70,
            replay_poll_ms: 10,
            worker_stall_timeout: std::time::Duration::from_secs(30),
            packet_logging: false,
            auth: crate::config::AuthConfig {
                enabled: false,
                username: String::new(),
                password: String::new(),
                session_ttl: std::time::Duration::from_secs(3600),
                cookie_secure: false,
            },
        }
    }
}
