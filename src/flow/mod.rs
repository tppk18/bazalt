mod reassembly;

use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BinaryHeap, VecDeque},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use chrono::{DateTime, Utc};
use crossbeam_channel::{bounded, Receiver, SendTimeoutError, Sender};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    http::L7Ingress,
    metrics::Metrics,
    model::{Direction, FlowKey, FlowOutput, FlowSummary, ParsedPacket, StreamChunk, TransportProtocol},
};

use reassembly::TcpHalf;


const TCP_TOMBSTONE_TTL: Duration = Duration::from_secs(2);
const TCP_TOMBSTONE_MAX: usize = 65_536;

/// Bounded recent-close set. It prevents FIN/RST retransmissions that arrive a
/// few milliseconds after flow removal from being misclassified as a brand-new
/// midstream connection. A real tuple reuse starts with SYN and bypasses/removes
/// the tombstone immediately.
struct TcpTombstones {
    by_key: AHashMap<FlowKey, Instant>,
    order: VecDeque<(Instant, FlowKey)>,
}

impl TcpTombstones {
    fn new() -> Self {
        Self { by_key: AHashMap::new(), order: VecDeque::new() }
    }

    fn contains_live(&mut self, key: &FlowKey, now: Instant) -> bool {
        self.expire(now);
        self.by_key.get(key).is_some_and(|deadline| *deadline > now)
    }

    fn remove(&mut self, key: &FlowKey) {
        self.by_key.remove(key);
    }

    fn insert(&mut self, key: FlowKey, now: Instant) {
        let deadline = now + TCP_TOMBSTONE_TTL;
        self.by_key.insert(key.clone(), deadline);
        self.order.push_back((deadline, key));
        self.expire(now);
        while self.by_key.len() > TCP_TOMBSTONE_MAX {
            let Some((deadline, key)) = self.order.pop_front() else { break; };
            if self.by_key.get(&key).is_some_and(|current| *current == deadline) {
                self.by_key.remove(&key);
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        while self.order.front().is_some_and(|(deadline, _)| *deadline <= now) {
            let (deadline, key) = self.order.pop_front().expect("front exists");
            if self.by_key.get(&key).is_some_and(|current| *current == deadline) {
                self.by_key.remove(&key);
            }
        }
    }
}

#[derive(Clone)]
pub struct FlowIngress {
    shard_txs: Arc<Vec<Sender<ParsedPacket>>>,
    shard_seed: u64,
    metrics: Arc<Metrics>,
}

impl FlowIngress {
    pub fn send_timeout(&self, packet: ParsedPacket, timeout: Duration) -> Result<usize, SendTimeoutError<ParsedPacket>> {
        let idx = (packet.key.shard_hash64(self.shard_seed) as usize) % self.shard_txs.len();
        let tx = &self.shard_txs[idx];
        tx.send_timeout(packet, timeout)?;
        Ok(Metrics::queue_enqueued(&self.metrics.flow_queue_depth, &self.metrics.flow_queue_high_watermark) as usize)
    }
}

pub struct FlowRuntime {
    pub input: FlowIngress,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl FlowRuntime {
    pub fn spawn(cfg: Arc<Config>, metrics: Arc<Metrics>, l7: L7Ingress) -> anyhow::Result<Self> {
        let per_shard_capacity = (cfg.capture_to_flow_capacity / cfg.flow_shards.max(1)).max(1);
        metrics.flow_queue_capacity.store((per_shard_capacity * cfg.flow_shards.max(1)) as u64, Ordering::Relaxed);

        let mut shard_txs = Vec::with_capacity(cfg.flow_shards);
        let mut handles = Vec::with_capacity(cfg.flow_shards);
        for shard_id in 0..cfg.flow_shards {
            let (tx, rx) = bounded::<ParsedPacket>(per_shard_capacity);
            shard_txs.push(tx);
            let cfg2 = cfg.clone();
            let metrics2 = metrics.clone();
            let out2 = l7.clone();
            let flow_cpu = if cfg.flow_cpus.is_empty() { None } else { Some(cfg.flow_cpus[shard_id % cfg.flow_cpus.len()]) };
            handles.push(std::thread::Builder::new()
                .name(format!("flow-shard-{shard_id}"))
                .spawn(move || {
                    if let Some(cpu) = flow_cpu {
                        match crate::affinity::pin_current(cpu) {
                            Ok(actual) if actual != cpu => tracing::info!(shard_id, requested_cpu=cpu, actual_cpu=actual, "flow worker CPU remapped to container cpuset"),
                            Ok(_) => {}
                            Err(e) => tracing::warn!(shard_id, cpu, error=%e, "cannot pin flow worker"),
                        }
                    }
                    shard_loop(shard_id, cfg2, metrics2, rx, out2)
                })?);
        }

        let seed_uuid = Uuid::new_v4();
        let seed_bytes = seed_uuid.as_bytes();
        let shard_seed = u64::from_le_bytes(seed_bytes[0..8].try_into().expect("8 byte UUID half"))
            ^ u64::from_le_bytes(seed_bytes[8..16].try_into().expect("8 byte UUID half"));
        Ok(Self {
            input: FlowIngress { shard_txs: Arc::new(shard_txs), shard_seed, metrics },
            handles,
        })
    }

    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Stop accepting packets and drain all shard queues. Capture workers must
    /// be joined first so they no longer hold FlowIngress clones.
    pub fn shutdown_and_join(self) -> anyhow::Result<()> {
        let FlowRuntime { input, handles } = self;
        drop(input);
        for handle in handles {
            handle.join().map_err(|_| anyhow::anyhow!("flow worker panicked"))?;
        }
        Ok(())
    }
}

struct FlowState {
    id: Uuid,
    key: FlowKey,
    initiator: Direction,
    started_ns: u64,
    last_seen_ns: u64,
    last_activity: Instant,
    a_to_b: TcpHalf,
    b_to_a: TcpHalf,
    packets_a_to_b: u64,
    packets_b_to_a: u64,
    bytes_a_to_b: u64,
    bytes_b_to_a: u64,
    truncated: bool,
    visible: bool,
    last_snapshot: Instant,
}

impl FlowState {
    fn new(packet: &ParsedPacket) -> Self {
        Self {
            id: Uuid::new_v4(),
            key: packet.key.clone(),
            // FlowKey is canonical/sorted for stable hashing only. Preserve the
            // observed initiator separately so query-facing src/dst and c2s/s2c
            // do not inherit canonical endpoint ordering. A later fresh SYN
            // starts a new FlowState, making this the TCP initiator in the
            // normal capture case.
            initiator: packet.direction,
            started_ns: packet.ts_ns,
            last_seen_ns: packet.ts_ns,
            last_activity: Instant::now(),
            a_to_b: TcpHalf::default(),
            b_to_a: TcpHalf::default(),
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            truncated: false,
            visible: false,
            last_snapshot: Instant::now(),
        }
    }

    fn half(&self, d: Direction) -> &TcpHalf {
        match d {
            Direction::AToB => &self.a_to_b,
            Direction::BToA => &self.b_to_a,
        }
    }

    fn half_mut(&mut self, d: Direction) -> &mut TcpHalf {
        match d {
            Direction::AToB => &mut self.a_to_b,
            Direction::BToA => &mut self.b_to_a,
        }
    }

    fn is_syn_retransmit(&self, p: &ParsedPacket) -> bool {
        p.flags.syn
            && !p.flags.ack
            && p.seq.is_some()
            && self.half(p.direction).initial_syn_seq() == p.seq
    }

    fn count_packet(&mut self, p: &ParsedPacket) {
        match p.direction {
            Direction::AToB => {
                self.packets_a_to_b += 1;
                self.bytes_a_to_b += p.payload.len() as u64;
            }
            Direction::BToA => {
                self.packets_b_to_a += 1;
                self.bytes_b_to_a += p.payload.len() as u64;
            }
        }
        self.last_seen_ns = p.ts_ns;
        self.last_activity = Instant::now();
    }

    fn should_close(&self, rst_accepted: bool) -> bool {
        rst_accepted || (self.a_to_b.fin_consumed() && self.b_to_a.fin_consumed())
    }

    fn summary(&self) -> FlowSummary {
        let (src, dst, packets_c2s, packets_s2c, bytes_c2s, bytes_s2c) = match self.initiator {
            Direction::AToB => (
                &self.key.a, &self.key.b,
                self.packets_a_to_b, self.packets_b_to_a,
                self.bytes_a_to_b, self.bytes_b_to_a,
            ),
            Direction::BToA => (
                &self.key.b, &self.key.a,
                self.packets_b_to_a, self.packets_a_to_b,
                self.bytes_b_to_a, self.bytes_a_to_b,
            ),
        };
        FlowSummary {
            flow_id: self.id,
            started_at: ns_to_datetime(self.started_ns),
            ended_at: ns_to_datetime(self.last_seen_ns),
            src_ip: src.ip.to_string(),
            dst_ip: dst.ip.to_string(),
            src_port: src.port,
            dst_port: dst.port,
            protocol: self.key.protocol,
            service: None,
            packets_c2s,
            packets_s2c,
            bytes_c2s,
            bytes_s2c,
            truncated: self.truncated,
        }
    }
}

#[derive(Clone)]
struct TimerItem {
    deadline: Instant,
    serial: u64,
    key: FlowKey,
    flow_id: Uuid,
}

impl PartialEq for TimerItem {
    fn eq(&self, other: &Self) -> bool { self.deadline == other.deadline && self.serial == other.serial }
}
impl Eq for TimerItem {}
impl PartialOrd for TimerItem {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> { Some(self.cmp(other)) }
}
impl Ord for TimerItem {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering so BinaryHeap acts as a min-heap.
        other.deadline.cmp(&self.deadline).then_with(|| other.serial.cmp(&self.serial))
    }
}

fn shard_loop(
    shard_id: usize,
    cfg: Arc<Config>,
    metrics: Arc<Metrics>,
    rx: Receiver<ParsedPacket>,
    output: L7Ingress,
) {
    let mut flows: AHashMap<FlowKey, FlowState> = AHashMap::new();
    let mut tombstones = TcpTombstones::new();
    let mut timers = BinaryHeap::<TimerItem>::new();
    let mut serial = 0u64;
    let tcp_gap_timeout_ns = cfg.tcp_gap_timeout.as_nanos().min(u64::MAX as u128) as u64;

    loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(mut packet) => {
                Metrics::queue_dequeued(&metrics.flow_queue_depth);
                let key = packet.key.clone();

                if packet.key.protocol == TransportProtocol::Tcp {
                    if packet.flags.syn && !packet.flags.ack {
                        // A fresh initiating SYN is an explicit new-generation signal.
                        tombstones.remove(&key);
                    } else if !flows.contains_key(&key)
                        && !packet.flags.syn
                        && tombstones.contains_live(&key, Instant::now())
                        && (packet.flags.fin || packet.flags.rst || packet.payload.is_empty())
                    {
                        // Suppress only control/empty tail retransmissions from a
                        // just-closed generation. Never blanket-drop payload under
                        // a tombstone: if a legitimate tuple reuse SYN was missed,
                        // keeping midstream application bytes is preferable to a
                        // silent two-second fidelity hole.
                        continue;
                    }
                }

                // A genuinely new SYN starts a new 4-tuple generation, but an
                // ordinary retransmission of the same initial sequence number
                // must not split one connection into two BAZALT flows.
                if packet.key.protocol == TransportProtocol::Tcp
                    && packet.flags.syn
                    && !packet.flags.ack
                {
                    let new_generation = flows.get(&key)
                        .map(|existing| !existing.is_syn_retransmit(&packet))
                        .unwrap_or(false);
                    if new_generation {
                        close_flow(&mut flows, &key, &output, &metrics, shard_id);
                    }
                }
                let is_new_flow = !flows.contains_key(&key);
                let state = flows.entry(key.clone()).or_insert_with(|| {
                    metrics.active_flows.fetch_add(1, Ordering::Relaxed);
                    FlowState::new(&packet)
                });
                state.count_packet(&packet);

                let mut emitted_content = false;
                let mut rst_accepted = false;
                match packet.key.protocol {
                    TransportProtocol::Tcp => {
                        let flow_id = state.id;
                        let key_copy = packet.key.clone();
                        let dir = packet.direction;
                        let max_ooo = cfg.max_ooo_bytes;
                        let max_ooo_segments = cfg.max_ooo_segments;

                        if packet.flags.rst {
                            let seq = packet.seq.unwrap_or(0);
                            rst_accepted = state.half(dir).rst_matches_next(seq);
                            if !rst_accepted {
                                metrics.tcp_rejected_resets.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // Cumulative ACKs are a zero-allocation recovery signal:
                        // if the peer acknowledged bytes that BAZALT missed but
                        // later OOO bytes are buffered, infer a capture gap from
                        // the ACK watermark and continue the stream.
                        if packet.flags.ack && (!packet.flags.rst || rst_accepted) {
                            if let Some(ack) = packet.ack {
                                // Remember the peer's cumulative ACK even when no
                                // OOO segment is buffered yet. That is one cheap
                                // sequence-extension/compare on the ACK path and
                                // lets a later OOO arrival recover an already
                                // ACK-inferred capture gap immediately.
                                let ack_outcome = state.half_mut(dir.opposite()).acknowledge(ack, packet.ts_ns, tcp_gap_timeout_ns);
                                emitted_content |= emit_tcp_outcome(
                                    state,
                                    ack_outcome,
                                    dir.opposite(),
                                    &key_copy,
                                    flow_id,
                                    &output,
                                    &metrics,
                                    shard_id,
                                );
                            }
                        }

                        // RST terminates the TCP generation. Do not reinterpret a
                        // payload carried on a reset segment as application data.
                        if !packet.flags.rst {
                            // Once sequence state exists, a pure ACK with no SYN/FIN
                            // carries no sequence-space information for this half.
                            // Skip reassembly entirely on that dominant hot path.
                            let needs_sequence_work = !packet.payload.is_empty()
                                || packet.flags.syn
                                || packet.flags.fin
                                || !state.half(dir).is_initialized();
                            if needs_sequence_work {
                                let seq = packet.seq.unwrap_or(0);
                                let payload = std::mem::take(&mut packet.payload);
                                let outcome = state.half_mut(dir).accept(
                                    seq,
                                    packet.flags.syn,
                                    packet.flags.fin,
                                    packet.ts_ns,
                                    payload,
                                    max_ooo,
                                    max_ooo_segments,
                                    tcp_gap_timeout_ns,
                                );
                                if outcome.retransmit {
                                    metrics.tcp_retransmits.fetch_add(1, Ordering::Relaxed);
                                }
                                if outcome.out_of_order {
                                    metrics.tcp_out_of_order.fetch_add(1, Ordering::Relaxed);
                                }
                                emitted_content |= emit_tcp_outcome(
                                    state,
                                    outcome,
                                    dir,
                                    &key_copy,
                                    flow_id,
                                    &output,
                                    &metrics,
                                    shard_id,
                                );
                            }
                        }
                    }
                    TransportProtocol::Udp => {
                        if !packet.payload.is_empty() {
                            let half = state.half_mut(packet.direction);
                            let offset = half.reserve_udp_offset(packet.payload.len());
                            emitted_content = true;
                            let msg = FlowOutput::Chunk(StreamChunk {
                                flow_id: state.id,
                                ts_ns: packet.ts_ns,
                                direction: packet.direction,
                                key: packet.key.clone(),
                                offset,
                                data: std::mem::take(&mut packet.payload),
                                truncated: state.truncated,
                            });
                            if output.send(msg).is_err() {
                                state.truncated = true;
                            }
                        }
                    }
                }

                if emitted_content {
                    let now = Instant::now();
                    if !state.visible || now.duration_since(state.last_snapshot) >= cfg.live_flow_update_interval {
                        state.visible = true;
                        state.last_snapshot = now;
                        if output.send(FlowOutput::Snapshot(state.summary())).is_err() {
                            state.truncated = true;
                        }
                    }
                }

                let close = state.should_close(rst_accepted);
                let new_flow_id = is_new_flow.then_some(state.id);

                // Schedule only once per flow lifetime. Packet activity updates
                // `last_activity`; when this timer fires it either expires the
                // flow or is lazily rescheduled to last_activity + timeout.
                // This keeps timer memory O(active/recent flows), not O(PPS * timeout).
                if let Some(flow_id) = new_flow_id.filter(|_| !close) {
                    serial = serial.wrapping_add(1);
                    let timeout = match packet.key.protocol {
                        TransportProtocol::Tcp => cfg.tcp_idle_timeout,
                        TransportProtocol::Udp => cfg.udp_idle_timeout,
                    };
                    timers.push(TimerItem {
                        deadline: Instant::now() + timeout,
                        serial,
                        key: key.clone(),
                        flow_id,
                    });
                }

                if close {
                    if packet.key.protocol == TransportProtocol::Tcp {
                        tombstones.insert(key.clone(), Instant::now());
                    }
                    close_flow(&mut flows, &key, &output, &metrics, shard_id);
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();
        while timers.peek().map(|t| t.deadline <= now).unwrap_or(false) {
            let item = timers.pop().unwrap();
            let Some(flow) = flows.get(&item.key) else {
                // Flow already closed; this is the single stale lifetime timer.
                continue;
            };
            if flow.id != item.flow_id {
                // Same canonical 4-tuple was reused by a newer connection.
                continue;
            }

            let timeout = match flow.key.protocol {
                TransportProtocol::Tcp => cfg.tcp_idle_timeout,
                TransportProtocol::Udp => cfg.udp_idle_timeout,
            };
            let next_deadline = flow.last_activity + timeout;
            let flow_id = flow.id;
            if next_deadline <= now {
                debug!(shard_id, flow_id = %flow_id, "flow idle timeout");
                close_flow(&mut flows, &item.key, &output, &metrics, shard_id);
            } else {
                serial = serial.wrapping_add(1);
                timers.push(TimerItem {
                    deadline: next_deadline,
                    serial,
                    key: item.key,
                    flow_id,
                });
            }
        }

        // Closed short-lived flows leave one lazy timer behind until its original
        // deadline. Compact occasionally so a connection storm cannot grow the
        // heap toward `flow_rate * timeout`; the steady-state bound stays close
        // to the number of active flows.
        if timers.len() > 4096 && timers.len() > flows.len().saturating_mul(2).saturating_add(1024) {
            let mut rebuilt = BinaryHeap::with_capacity(flows.len());
            for (key, flow) in &flows {
                serial = serial.wrapping_add(1);
                let timeout = match flow.key.protocol {
                    TransportProtocol::Tcp => cfg.tcp_idle_timeout,
                    TransportProtocol::Udp => cfg.udp_idle_timeout,
                };
                rebuilt.push(TimerItem {
                    deadline: flow.last_activity + timeout,
                    serial,
                    key: key.clone(),
                    flow_id: flow.id,
                });
            }
            timers = rebuilt;
        }
    }

    for (key, mut flow) in flows.drain() {
        finalize_tcp_halves(&mut flow, &key, &output, &metrics, shard_id);
        if flow.visible {
            let _ = output.send(FlowOutput::Closed(flow.summary()));
            metrics.flows_completed.fetch_add(1, Ordering::Relaxed);
        }
        metrics.active_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

fn emit_tcp_outcome(
    state: &mut FlowState,
    outcome: reassembly::ReassemblyOutcome,
    direction: Direction,
    key: &FlowKey,
    flow_id: Uuid,
    output: &L7Ingress,
    metrics: &Metrics,
    shard_id: usize,
) -> bool {
    if !outcome.gaps.is_empty() {
        metrics.tcp_gap_events.fetch_add(outcome.gaps.len() as u64, Ordering::Relaxed);
        let gap_bytes = outcome.gaps.iter().map(|g| g.len).sum::<u64>();
        metrics.tcp_gap_bytes.fetch_add(gap_bytes, Ordering::Relaxed);
    }

    let mut emitted = false;
    for chunk in outcome.emitted {
        emitted = true;
        let msg = FlowOutput::Chunk(StreamChunk {
            flow_id,
            ts_ns: chunk.ts_ns,
            direction,
            key: key.clone(),
            offset: chunk.offset,
            data: chunk.data,
            truncated: state.truncated,
        });
        if output.send(msg).is_err() {
            state.truncated = true;
            warn!(shard_id, flow_id = %flow_id, "L7 worker stopped; flow marked truncated");
            break;
        }
    }
    emitted
}

fn finalize_tcp_halves(
    flow: &mut FlowState,
    key: &FlowKey,
    output: &L7Ingress,
    metrics: &Metrics,
    shard_id: usize,
) {
    if key.protocol != TransportProtocol::Tcp {
        return;
    }
    let flow_id = flow.id;
    let ts_ns = flow.last_seen_ns;
    let a = flow.a_to_b.finalize(ts_ns);
    let b = flow.b_to_a.finalize(ts_ns);
    let emitted_a = emit_tcp_outcome(flow, a, Direction::AToB, key, flow_id, output, metrics, shard_id);
    let emitted_b = emit_tcp_outcome(flow, b, Direction::BToA, key, flow_id, output, metrics, shard_id);
    if emitted_a || emitted_b {
        flow.visible = true;
    }
}

fn close_flow(
    flows: &mut AHashMap<FlowKey, FlowState>,
    key: &FlowKey,
    output: &L7Ingress,
    metrics: &Metrics,
    shard_id: usize,
) {
    if let Some(mut flow) = flows.remove(key) {
        finalize_tcp_halves(&mut flow, key, output, metrics, shard_id);
        if flow.visible {
            let _ = output.send(FlowOutput::Closed(flow.summary()));
            metrics.flows_completed.fetch_add(1, Ordering::Relaxed);
        }
        metrics.active_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

fn ns_to_datetime(ns: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
        .unwrap_or_else(Utc::now)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn tcp_packet(seq: u32, syn: bool) -> ParsedPacket {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (key, direction) = FlowKey::canonical(a, 50000, b, 80, TransportProtocol::Tcp);
        ParsedPacket {
            ts_ns: 1,
            key,
            direction,
            seq: Some(seq),
            ack: Some(0),
            flags: crate::model::TcpFlags { syn, ..Default::default() },
            payload: bytes::Bytes::new(),
            wire_len: 60,
        }
    }

    #[test]
    fn retransmitted_syn_with_same_isn_keeps_generation() {
        let first = tcp_packet(1000, true);
        let mut state = FlowState::new(&first);
        let _ = state.half_mut(first.direction).accept(1000, true, false, 1, bytes::Bytes::new(), 1024, 128, 1_000_000_000);
        let retry = tcp_packet(1000, true);
        let new_isn = tcp_packet(2000, true);
        assert!(state.is_syn_retransmit(&retry));
        assert!(!state.is_syn_retransmit(&new_isn));
    }

    #[test]
    fn tcp_tombstone_is_bounded_recent_close_state() {
        let packet = tcp_packet(1000, true);
        let key = packet.key.clone();
        let now = Instant::now();
        let mut tombstones = TcpTombstones::new();
        tombstones.insert(key.clone(), now);
        assert!(tombstones.contains_live(&key, now));
        tombstones.remove(&key);
        assert!(!tombstones.contains_live(&key, now));
    }

    #[test]
    fn query_summary_preserves_observed_initiator_not_canonical_order() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (key, direction) = FlowKey::canonical(client, 50000, server, 80, TransportProtocol::Tcp);
        assert_eq!(direction, Direction::BToA);
        let packet = ParsedPacket {
            ts_ns: 1_700_000_000_000_000_000,
            key,
            direction,
            seq: Some(10),
            ack: Some(0),
            flags: crate::model::TcpFlags { syn: true, ..Default::default() },
            payload: bytes::Bytes::new(),
            wire_len: 60,
        };
        let mut state = FlowState::new(&packet);
        state.count_packet(&packet);
        let summary = state.summary();
        assert_eq!(summary.src_ip, client.to_string());
        assert_eq!(summary.dst_ip, server.to_string());
        assert_eq!(summary.src_port, 50000);
        assert_eq!(summary.dst_port, 80);
        assert_eq!(summary.packets_c2s, 1);
        assert_eq!(summary.packets_s2c, 0);
    }
}
