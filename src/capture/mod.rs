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
    config::{CaptureMode, Config},
    flow::FlowIngress,
    http::ServiceRegistry,
    metrics::Metrics,
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

pub trait FrameSource: Send {
    fn receive_batch(&mut self, max: usize, out: &mut Vec<CapturedFrame>) -> Result<usize>;

    fn stats(&mut self) -> Result<Option<SourceStats>> {
        Ok(None)
    }

    /// Install/update an early capture filter for configured service ports when
    /// the backend supports it. AF_XDP currently keeps the userspace allow-list
    /// as the authoritative guard; libpcap compiles this to kernel BPF.
    fn configure_port_filter(&mut self, _ports: &[u16], _extra: Option<&str>) -> Result<()> {
        Ok(())
    }
}

pub struct CaptureRuntime {
    capture_handles: Vec<std::thread::JoinHandle<()>>,
    raw_handles: Vec<std::thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
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

    pub fn critical_worker_finished(&self) -> bool {
        self.capture_handles
            .iter()
            .chain(self.raw_handles.iter())
            .any(std::thread::JoinHandle::is_finished)
    }
}

pub fn spawn_capture_workers(
    cfg: Arc<Config>,
    flow_tx: FlowIngress,
    metrics: Arc<Metrics>,
    services: Arc<ServiceRegistry>,
    shutdown: Arc<AtomicBool>,
) -> Result<CaptureRuntime> {
    if cfg.capture_mode == CaptureMode::Disabled {
        return Ok(CaptureRuntime {
            capture_handles: Vec::new(),
            raw_handles: Vec::new(),
            shutdown,
        });
    }

    // Prepare capture backends before any worker starts consuming traffic. AF_XDP
    // is deliberately all-or-nothing across the configured RX queues: silently
    // disabling one failed queue loses exactly the RSS bucket mapped to it.
    let mut prepared = Vec::<(u32, Box<dyn FrameSource>)>::new();
    match cfg.capture_mode {
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
                                Ok(()) => {
                                    tracing::info!(queue_id, ?ports, "capture service-port filter updated");
                                }
                                Err(error) => {
                                    // A failed dynamic filter update can leave an old
                                    // kernel BPF installed. Warn loudly because new
                                    // service ports could otherwise look like packet loss.
                                    tracing::warn!(queue_id, %error, "cannot update early capture filter; disable BAZALT_EARLY_PORT_FILTER to avoid stale-BPF packet loss");
                                }
                            }
                        } else {
                            tracing::info!(queue_id, ?ports, "early capture BPF disabled; userspace service allow-list active");
                        }
                        service_generation = generation;
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
                                // Source-level metrics are updated before parsing and before
                                // the service allow-list. With early BPF disabled (default)
                                // this answers the first capture diagnostic question: did the
                                // selected interface deliver any frames at all?
                                metrics.capture_frames.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                metrics.capture_frame_bytes.fetch_add(frame.wire_len as u64, std::sync::atomic::Ordering::Relaxed);

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

                                match decoder.decode(frame) {
                                    Ok(DecodeOutcome::Packet(packet)) => {
                                        // Services are the capture allow-list. This check is
                                        // lock-free (ArcSwap snapshot) and happens after any
                                        // required IP/tunnel reassembly so non-first fragments
                                        // cannot bypass or be lost to a port-only decision.
                                        if !services.accepts_flow(&packet.key) {
                                            metrics.packets_filtered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            continue;
                                        }
                                        metrics.packets_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        metrics.packet_bytes.fetch_add(packet.wire_len as u64, std::sync::atomic::Ordering::Relaxed);

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

                }
            })?);
    }
    Ok(CaptureRuntime {
        capture_handles,
        raw_handles,
        shutdown,
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
