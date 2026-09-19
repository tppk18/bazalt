mod fragment;
mod parser;
mod pcap_source;
mod raw;

#[cfg(feature = "afxdp")]
mod afxdp;

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use bytes::Bytes;
use tracing::{debug, warn};

use crate::{
    config::{effective_capture_mode, CaptureMode, Config},
    flow::FlowIngress,
    http::{ServicePacketScope, ServiceRegistry},
    metrics::Metrics,
    topology::TopologyTracker,
};

use fragment::SharedFragmentCache;
pub use parser::parse_ethernet_frame;
use parser::{DecodeOutcome, PacketDecoder};

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub ts_ns: u64,
    pub wire_len: usize,
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Frames dropped by the capture backend/kernel before userspace received
    /// them (for example libpcap ps_drop/ps_ifdrop or AF_XDP rx_dropped).
    pub dropped: u64,
    /// Invalid AF_XDP descriptors rejected before they could become packets.
    /// Backends without an equivalent counter leave this at zero.
    pub invalid_descs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFilterMode {
    /// Backend is applying the requested service-port optimization.
    Optimized,
    /// Backend intentionally widened capture after a filter-install failure.
    /// Userspace service gating remains authoritative, so this is safe but can
    /// cost more CPU until the next successful update.
    FailOpen,
}

pub trait FrameSource: Send {
    fn receive_batch(&mut self, max: usize, out: &mut Vec<CapturedFrame>) -> Result<usize>;

    fn stats(&mut self) -> Result<Option<SourceStats>> {
        Ok(None)
    }

    /// Install/update an early capture filter for configured service ports when
    /// the backend supports it. AF_XDP currently keeps the userspace allow-list
    /// as the authoritative guard; libpcap compiles this to kernel BPF.
    fn configure_port_filter(
        &mut self,
        _ports: &[u16],
        _extra: Option<&str>,
    ) -> Result<PortFilterMode> {
        Ok(PortFilterMode::Optimized)
    }
}

pub struct CaptureRuntime {
    capture_handles: Vec<std::thread::JoinHandle<()>>,
    raw_handles: Vec<std::thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    requested_mode: CaptureMode,
    effective_mode: CaptureMode,
    mode_adjusted: bool,
}

impl CaptureRuntime {
    pub fn shutdown_and_join(self) -> Result<()> {
        self.shutdown.store(true, Ordering::Release);
        for handle in self.capture_handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("capture worker panicked"))?;
        }
        // Raw writers only terminate after capture workers drop their senders.
        for handle in self.raw_handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("raw capture writer panicked"))?;
        }
        Ok(())
    }

    pub fn worker_count(&self) -> usize {
        self.capture_handles.len()
    }

    pub fn requested_mode(&self) -> CaptureMode {
        self.requested_mode
    }

    pub fn effective_mode(&self) -> CaptureMode {
        self.effective_mode
    }

    pub fn mode_adjusted(&self) -> bool {
        self.mode_adjusted
    }

    pub fn critical_worker_finished(&self) -> bool {
        self.capture_handles
            .iter()
            .chain(self.raw_handles.iter())
            .any(std::thread::JoinHandle::is_finished)
    }
}

#[cfg(target_os = "linux")]
fn interface_mac(interface: &str) -> Option<[u8; 6]> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{interface}/address")).ok()?;
    let mut out = [0u8; 6];
    let mut parts = raw.trim().split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(not(target_os = "linux"))]
fn interface_mac(_interface: &str) -> Option<[u8; 6]> {
    None
}

#[inline]
fn service_flow_visible(
    scope: ServicePacketScope,
    mode: CaptureMode,
    local_egress: bool,
) -> bool {
    match mode {
        CaptureMode::PcapLive if local_egress => scope.flow,
        CaptureMode::PcapLive | CaptureMode::AfXdp => scope.destination,
        CaptureMode::PcapFile => scope.flow,
        CaptureMode::Disabled => false,
    }
}

/// Cheap pre-decode rejection for ordinary IPv4 TCP/UDP frames. Returning
/// `false` is definitive: remote ingress is not addressed to a configured
/// service port (or local egress did not originate from one), and the frame is
/// not a supported tunnel/fragment that could reveal an inner service packet
/// after bounded decoding. Unknown/complex traffic returns `true` so the
/// authoritative decoder can decide without sacrificing fidelity.
#[inline]
fn frame_may_belong_to_service(
    frame: &[u8],
    services: &ServiceRegistry,
    tunnel_decapsulation: bool,
    local_egress: Option<bool>,
) -> bool {
    // With no configured services there is nothing to analyze. This fast path
    // is especially important for AF_XDP, whose backend does not install the
    // dynamic libpcap port filter.
    if services.is_empty() {
        return false;
    }
    if frame.len() < 14 {
        return true;
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    for _ in 0..4 {
        if matches!(ether_type, 0x8100 | 0x88a8 | 0x9100 | 0x9200) {
            if frame.len() < offset + 4 {
                return true;
            }
            ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        } else {
            break;
        }
    }
    // IPv6 extension chains are intentionally left to the full decoder. The
    // A/D topology itself is IPv4, but service analysis remains IPv6-capable.
    if ether_type != 0x0800 {
        return true;
    }
    if frame.len() < offset + 20 || frame[offset] >> 4 != 4 {
        return true;
    }
    let ihl = ((frame[offset] & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < offset + ihl {
        return true;
    }
    let frag = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    if (frag & 0x3fff) != 0 {
        return true;
    }
    let protocol = frame[offset + 9];
    let l4 = offset + ihl;
    match protocol {
        6 | 17 => {
            if frame.len() < l4 + 4 {
                return true;
            }
            let src_port = u16::from_be_bytes([frame[l4], frame[l4 + 1]]);
            let dst_port = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
            // Remote ingress is service-scoped strictly by destination port.
            // A hostile sender cannot force full decoding merely by choosing a
            // source port equal to a configured service.  Local egress needs
            // the inverse rule so responses from an admitted service remain
            // available to flow/L7 reconstruction.
            let service_match = match local_egress {
                Some(true) => services.accepts_port(src_port),
                Some(false) => services.accepts_port(dst_port),
                // Offline PCAP has no relationship to the current host's MAC,
                // so preserve both request and response directions. This path
                // cannot be abused as a live remote CPU source.
                None => services.accepts_port(src_port) || services.accepts_port(dst_port),
            };
            if service_match {
                return true;
            }
            // VXLAN may carry the real service port only in the inner packet.
            tunnel_decapsulation && protocol == 17 && matches!(dst_port, 4789 | 8472)
        }
        // GRE / IP-in-IP can likewise contain the actual service flow.
        47 | 4 | 41 => tunnel_decapsulation,
        _ => false,
    }
}

pub fn spawn_capture_workers(
    cfg: Arc<Config>,
    flow_tx: FlowIngress,
    metrics: Arc<Metrics>,
    services: Arc<ServiceRegistry>,
    topology: Arc<TopologyTracker>,
    shutdown: Arc<AtomicBool>,
) -> Result<CaptureRuntime> {
    if cfg.capture_mode == CaptureMode::Disabled {
        return Ok(CaptureRuntime {
            capture_handles: Vec::new(),
            raw_handles: Vec::new(),
            shutdown,
            requested_mode: CaptureMode::Disabled,
            effective_mode: CaptureMode::Disabled,
            mode_adjusted: false,
        });
    }

    // Prepare capture backends before any worker starts consuming traffic. AF_XDP
    // is deliberately all-or-nothing across the configured RX queues: silently
    // disabling one failed queue loses exactly the RSS bucket mapped to it.
    //
    // Same-interface throttle is intentionally different: the throttle XDP program
    // must own ingress so it can return XDP_DROP/XDP_PASS. An AF_XDP XSK program on
    // the same interface would compete for that XDP hook and redirect passed packets
    // away from the normal stack. In that case BAZALT uses passive libpcap capture
    // for the packets that survive enforcement.
    let mut prepared = Vec::<(u32, Box<dyn FrameSource>)>::new();
    let planned_mode = effective_capture_mode(cfg.capture_mode, cfg.throttle_enabled);
    let same_interface_throttle = cfg.capture_mode == CaptureMode::AfXdp
        && cfg.throttle_enabled
        && planned_mode == CaptureMode::PcapLive;
    let mut effective_mode = cfg.capture_mode;
    let mut mode_adjusted = false;
    match cfg.capture_mode {
        CaptureMode::AfXdp if same_interface_throttle => {
            tracing::info!(
                interface = %cfg.interface,
                "same-interface XDP throttle enabled; using passive libpcap capture instead of AF_XDP redirect"
            );
            let source = pcap_source::PcapLiveSource::open(&cfg).map_err(|error| {
                anyhow::anyhow!(
                    "same-interface throttle requires passive libpcap capture on {}: {error}",
                    cfg.interface
                )
            })?;
            prepared.push((cfg.queue_id, Box::new(source)));
            effective_mode = CaptureMode::PcapLive;
            mode_adjusted = true;
        }
        CaptureMode::AfXdp => {
            let mut failure = None;
            for &queue_id in &cfg.queue_ids {
                match create_source(&cfg, queue_id) {
                    Ok(source) => prepared.push((queue_id, source)),
                    Err(error) => {
                        failure = Some((queue_id, error));
                        break;
                    }
                }
            }

            if let Some((failed_queue, af_xdp_error)) = failure {
                // Dropping already-open XSKs first tears down the partial AF_XDP
                // topology before libpcap is opened, avoiding a mixed backend
                // where some RSS queues are redirected to XSK and others pass.
                prepared.clear();
                if !cfg.capture_fallback_pcap {
                    return Err(anyhow::anyhow!(
                        "AF_XDP queue {failed_queue} failed to initialize: {af_xdp_error}"
                    ));
                }
                tracing::warn!(
                    queue_id = failed_queue,
                    error = %af_xdp_error,
                    interface = %cfg.interface,
                    "AF_XDP queue set incomplete; falling back globally to one libpcap worker"
                );
                let source = pcap_source::PcapLiveSource::open(&cfg).map_err(|pcap_error| {
                    anyhow::anyhow!(
                        "AF_XDP initialization failed on queue {failed_queue}: {af_xdp_error}; libpcap fallback failed: {pcap_error}"
                    )
                })?;
                prepared.push((cfg.queue_id, Box::new(source)));
                effective_mode = CaptureMode::PcapLive;
                mode_adjusted = true;
            }
        }
        CaptureMode::PcapLive | CaptureMode::PcapFile => {
            prepared.push((cfg.queue_id, create_source(&cfg, cfg.queue_id)?));
        }
        CaptureMode::Disabled => unreachable!(),
    }

    if prepared.is_empty() {
        anyhow::bail!("capture backend initialized no workers");
    }

    // Live libpcap captures can include locally transmitted Ethernet frames.
    // Topology represents ingress senders, so exclude frames whose L2 source is
    // this interface's own MAC without changing the bidirectional capture used
    // by flow/L7 analysis. AF_XDP receives ingress only, and offline fixtures
    // must remain independent of the host MAC.
    let topology_ignored_source_mac = if effective_mode == CaptureMode::PcapLive {
        let mac = interface_mac(&cfg.interface);
        if mac.is_none() {
            tracing::warn!(
                interface = %cfg.interface,
                "cannot resolve local interface MAC; live topology may include locally transmitted frames"
            );
        }
        mac
    } else {
        None
    };

    let fragment_cache = SharedFragmentCache::new(
        cfg.ip_fragment_cache_bytes,
        cfg.ip_fragment_max_datagrams,
        cfg.ip_fragment_timeout,
    );
    let mut capture_handles = Vec::with_capacity(prepared.len());
    let mut raw_handles = Vec::with_capacity(prepared.len());
    for (worker_idx, (queue_id, mut source)) in prepared.into_iter().enumerate() {
        let capture_cpu = if cfg.capture_cpus.is_empty() {
            None
        } else {
            Some(cfg.capture_cpus[worker_idx % cfg.capture_cpus.len()])
        };
        let raw_tx = if cfg.raw_capture_enabled {
            let (raw_tx, raw_handle) = raw::spawn_raw_writer(
                cfg.raw_segment_dir.clone(),
                queue_id,
                cfg.segment_max_bytes,
            )?;
            raw_handles.push(raw_handle);
            Some(raw_tx)
        } else {
            None
        };
        let cfg = cfg.clone();
        let fragments = fragment_cache.clone();
        let tx = flow_tx.clone();
        let metrics = metrics.clone();
        let services = services.clone();
        let topology = topology.clone();
        let topology_ignored_source_mac = topology_ignored_source_mac;
        let shutdown2 = shutdown.clone();
        capture_handles.push(std::thread::Builder::new()
            .name(format!("capture-{queue_id}"))
            .spawn(move || {
                if let Some(cpu) = capture_cpu {
                    match crate::affinity::pin_current(cpu) {
                        Ok(actual) if actual != cpu => tracing::info!(queue_id, requested_cpu=cpu, actual_cpu=actual, "capture worker CPU remapped to container cpuset"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(queue_id, cpu, error=%e, "cannot pin capture worker"),
                    }
                }
                let mut batch = Vec::with_capacity(cfg.capture_batch);
                // Decoder state is worker-local; only actual IP fragments touch
                // the shared sharded fragment cache. Normal packets stay lock-free.
                let mut decoder = PacketDecoder::new(&cfg, metrics.clone(), fragments.clone());
                let mut topology_observer =
                    topology.local_observer_ignoring_source_mac(topology_ignored_source_mac);
                let mut service_generation = 0u64;
                let mut last_source_stats = SourceStats::default();
                let mut last_stats_poll = Instant::now();
                loop {
                    metrics.touch_progress();
                    if shutdown2.load(Ordering::Acquire) { break; }
                    let generation = services.generation();
                    if generation != service_generation {
                        let ports = services.ports();
                        if cfg.early_port_filter {
                            match source.configure_port_filter(&ports, cfg.bpf_filter.as_deref()) {
                                Ok(PortFilterMode::Optimized) => {
                                    tracing::info!(queue_id, ?ports, "capture service-port filter updated");
                                    service_generation = generation;
                                }
                                Ok(PortFilterMode::FailOpen) => {
                                    tracing::warn!(
                                        queue_id,
                                        ?ports,
                                        "capture filter update failed open; userspace service gating remains authoritative"
                                    );
                                    // The broad fallback cannot hide a newly-added
                                    // service, so it is safe to accept this generation.
                                    // A later service change gets another optimization
                                    // attempt without spinning/logging on every packet.
                                    service_generation = generation;
                                }
                                Err(error) => {
                                    // The source could still have an older
                                    // restrictive filter. Continuing would create
                                    // a silent observability hole, so fail the
                                    // supervised capture worker instead.
                                    tracing::error!(queue_id, %error, "cannot install service filter or fail-open capture filter; stopping capture worker to avoid a silent service blind spot");
                                    return;
                                }
                            }
                        } else {
                            tracing::info!(queue_id, ?ports, "early capture BPF disabled; userspace service allow-list active");
                            service_generation = generation;
                        }
                    }
                    // Offline fixtures are deterministic and finite. Do not
                    // consume them before at least one service port exists;
                    // live capture continues draining/discarding unrelated
                    // traffic while its allow-list is empty.
                    if cfg.capture_mode == CaptureMode::PcapFile && services.is_empty() {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        continue;
                    }

                    // Kernel/XSK loss is a different failure domain from the
                    // bounded capture->flow queue. Sample it out of the hot
                    // path so operators can tell exactly where frames vanish.
                    // Do this before receive_batch(): an overloaded backend can
                    // legitimately return no frames while its drop counter rises.
                    if last_stats_poll.elapsed() >= std::time::Duration::from_secs(1) {
                        match source.stats() {
                            Ok(Some(now)) => {
                                metrics.capture_backend_drops.fetch_add(
                                    now.dropped.saturating_sub(last_source_stats.dropped),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                metrics.capture_backend_invalid_descs.fetch_add(
                                    now.invalid_descs.saturating_sub(last_source_stats.invalid_descs),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                last_source_stats = now;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                debug!(queue_id, %error, "capture backend statistics query failed");
                            }
                        }
                        last_stats_poll = Instant::now();
                    }
                    batch.clear();
                    match source.receive_batch(cfg.capture_batch, &mut batch) {
                        Ok(0) if cfg.capture_mode == CaptureMode::PcapFile => {
                            tracing::info!(queue_id, "pcap file exhausted");
                            break;
                        }
                        Ok(0) => continue,
                        Ok(_) => {
                            for frame in batch.drain(..) {
                                // Source-level capture-health metrics are updated for every
                                // frame delivered by the backend. They are intentionally separate
                                // from participant/service statistics below: this answers the
                                // diagnostic question whether the interface delivered frames at all.
                                metrics.capture_frames.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                metrics.capture_frame_bytes.fetch_add(frame.wire_len as u64, std::sync::atomic::Ordering::Relaxed);
                                // Determine local egress before the frame is moved into the
                                // decoder. Topology represents remote senders only; reverse
                                // service responses still continue through flow/L7 analysis.
                                let topology_ignore_l2 =
                                    topology_observer.ignores_ethernet_frame(&frame.data);

                                // Raw capture is a true forensic copy of every frame
                                // delivered by the selected backend. Publish before
                                // parsing/filtering so malformed, incomplete-fragment
                                // and off-service traffic remains inspectable. Bytes is
                                // ref-counted, so this clone does not copy frame data.
                                if let Some(raw_tx) = &raw_tx {
                                    if raw_tx.try_send(frame.clone()).is_err() {
                                        metrics.raw_capture_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }

                                // Avoid full IP/L4/L7 work for ordinary IPv4 packets that
                                // provably have no relation to any configured service. Complex
                                // fragments/tunnels remain conservative and are decided after
                                // bounded decoding.
                                if !frame_may_belong_to_service(
                                    &frame.data,
                                    &services,
                                    cfg.tunnel_decapsulation,
                                    match effective_mode {
                                        CaptureMode::PcapLive => Some(topology_ignore_l2),
                                        CaptureMode::AfXdp => Some(false),
                                        CaptureMode::PcapFile => None,
                                        CaptureMode::Disabled => None,
                                    },
                                ) {
                                    metrics
                                        .packets_filtered
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    continue;
                                }

                                match decoder.decode(frame) {
                                    Ok(DecodeOutcome::Packet(packet)) => {
                                        // One ArcSwap snapshot supplies both decisions on the
                                        // common post-decode path: directional participant
                                        // visibility and bidirectional service-flow membership.
                                        let service_scope = services.packet_scope(&packet);

                                        // Topology/statistics are intentionally narrower than
                                        // flow membership: count only remote IPv4 packets whose
                                        // *destination* is an added service port. Once the source
                                        // is throttled, the XDP rule remains source-only and drops
                                        // its traffic to every port.
                                        if !topology_ignore_l2 && service_scope.destination {
                                            if let std::net::IpAddr::V4(source_ip) =
                                                packet.source_endpoint().ip
                                            {
                                                topology_observer.observe_ipv4_source(
                                                    packet.ts_ns,
                                                    packet.wire_len,
                                                    source_ip,
                                                );
                                            }
                                        }

                                        // Services are the capture allow-list. Re-apply live
                                        // direction semantics after bounded IP/tunnel decoding so
                                        // IPv6 extension chains, fragments and encapsulation cannot
                                        // reintroduce the hostile source-port collision that the
                                        // cheap IPv4 prefilter rejects. Offline PCAP remains
                                        // bidirectional because it has no relation to this host's
                                        // interface direction.
                                        if !service_flow_visible(
                                            service_scope,
                                            effective_mode,
                                            topology_ignore_l2,
                                        ) {
                                            metrics
                                                .packets_filtered
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            continue;
                                        }
                                        // Service analysis counters are incremented only after
                                        // the flow engine confirms that this packet belongs to an
                                        // admitted service flow. This avoids counting a hostile
                                        // ingress packet merely because its *source* port equals a
                                        // configured service port.
                                        if cfg.packet_logging {
                                            debug!(?packet.key, payload_len = packet.payload.len(), "captured packet");
                                        }
                                        match tx.send_timeout(packet, cfg.capture_enqueue_timeout) {
                                            Ok(_) => {},
                                            Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                                                metrics.capture_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            }
                                            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                                warn!(queue_id, "flow runtime stopped; capture worker exiting");
                                                return;
                                            }
                                        }
                                    }
                                    Ok(DecodeOutcome::PendingFragment) => {
                                        // Not ignored and not lost: bytes are retained in the
                                        // bounded sharded fragment cache until completion,
                                        // timeout or pressure eviction.
                                    }
                                    Ok(DecodeOutcome::Ignored) => {
                                        metrics.packets_ignored.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        metrics.packet_parse_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        debug!(error = %e, "packet parse failed");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(queue_id, error = %e, "capture receive failed");
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                    topology_observer.flush_if_due();

                }
            })?);
    }
    Ok(CaptureRuntime {
        capture_handles,
        raw_handles,
        shutdown,
        requested_mode: cfg.capture_mode,
        effective_mode,
        mode_adjusted,
    })
}

fn create_source(cfg: &Config, queue_id: u32) -> Result<Box<dyn FrameSource>> {
    match cfg.capture_mode {
        CaptureMode::PcapLive => Ok(Box::new(pcap_source::PcapLiveSource::open(cfg)?)),
        CaptureMode::PcapFile => Ok(Box::new(pcap_source::PcapFileSource::open(cfg)?)),
        CaptureMode::AfXdp => {
            #[cfg(feature = "afxdp")]
            {
                Ok(Box::new(afxdp::AfXdpSource::open(
                    &cfg.interface,
                    queue_id,
                )?))
            }
            #[cfg(not(feature = "afxdp"))]
            {
                let _ = queue_id;
                anyhow::bail!("binary was built without the afxdp feature")
            }
        }
        CaptureMode::Disabled => anyhow::bail!("capture disabled"),
    }
}

pub fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod service_scope_tests {
    use super::*;
    use crate::model::ServiceConfig;

    fn registry(port: u16) -> Arc<ServiceRegistry> {
        ServiceRegistry::new([ServiceConfig {
            port,
            name: format!("svc-{port}"),
            http: true,
            urldecode_http_requests: false,
            merge_adjacent_packets: false,
            parse_websockets: false,
        }])
    }

    fn ipv4_tcp(src_port: u16, dst_port: u16, frag_field: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
        frame[ip + 6..ip + 8].copy_from_slice(&frag_field.to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 168, 0, 2]);
        frame[ip + 16..ip + 20].copy_from_slice(&[192, 168, 0, 10]);
        let tcp = ip + 20;
        frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[tcp + 12] = 5 << 4;
        frame
    }

    #[test]
    fn empty_service_registry_rejects_every_frame_before_decode() {
        let services = ServiceRegistry::new(Vec::new());
        assert!(!frame_may_belong_to_service(
            &ipv4_tcp(40000, 8080, 0),
            &services,
            true,
            Some(false),
        ));
    }

    #[test]
    fn obvious_off_service_ipv4_is_rejected_before_full_decode() {
        let services = registry(8080);
        assert!(!frame_may_belong_to_service(
            &ipv4_tcp(40000, 9999, 0),
            &services,
            true,
            Some(false),
        ));
    }

    #[test]
    fn service_request_and_reverse_packet_are_decode_candidates() {
        let services = registry(8080);
        assert!(frame_may_belong_to_service(
            &ipv4_tcp(40000, 8080, 0),
            &services,
            true,
            Some(false),
        ));
        assert!(frame_may_belong_to_service(
            &ipv4_tcp(8080, 40000, 0),
            &services,
            true,
            Some(true),
        ));
    }

    #[test]
    fn hostile_source_port_collision_is_rejected_on_remote_ingress() {
        let services = registry(8080);
        assert!(!frame_may_belong_to_service(
            &ipv4_tcp(8080, 49999, 0),
            &services,
            true,
            Some(false),
        ));
    }

    #[test]
    fn offline_pcap_preserves_both_service_directions() {
        let services = registry(8080);
        assert!(frame_may_belong_to_service(
            &ipv4_tcp(40000, 8080, 0),
            &services,
            true,
            None,
        ));
        assert!(frame_may_belong_to_service(
            &ipv4_tcp(8080, 40000, 0),
            &services,
            true,
            None,
        ));
        assert!(!frame_may_belong_to_service(
            &ipv4_tcp(40000, 49999, 0),
            &services,
            true,
            None,
        ));
    }

    #[test]
    fn post_decode_live_direction_rejects_remote_source_port_collision() {
        let source_only = ServicePacketScope {
            destination: false,
            flow: true,
        };
        let destination = ServicePacketScope {
            destination: true,
            flow: true,
        };
        assert!(!service_flow_visible(source_only, CaptureMode::PcapLive, false));
        assert!(!service_flow_visible(source_only, CaptureMode::AfXdp, false));
        assert!(service_flow_visible(destination, CaptureMode::PcapLive, false));
        assert!(service_flow_visible(source_only, CaptureMode::PcapLive, true));
        assert!(service_flow_visible(source_only, CaptureMode::PcapFile, false));
    }

    #[test]
    fn fragments_stay_conservative_until_reassembly() {
        let services = registry(8080);
        // MF flag set. Port bytes in a later/non-first fragment are not
        // authoritative, so the bounded decoder must make the final decision.
        assert!(frame_may_belong_to_service(
            &ipv4_tcp(40000, 9999, 0x2000),
            &services,
            true,
            Some(false),
        ));
    }
}
