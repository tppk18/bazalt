use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Debug, Default)]
pub struct Metrics {
    /// Wall-clock nanoseconds of the last successful stage-loop observation.
    /// This is a liveness signal only; traffic timestamps never use it.
    pub pipeline_last_progress_ns: AtomicU64,
    pub capture_frames: AtomicU64,
    pub capture_frame_bytes: AtomicU64,
    pub packets_received: AtomicU64,
    pub packet_bytes: AtomicU64,
    pub packet_parse_errors: AtomicU64,
    pub capture_truncated_packets: AtomicU64,
    pub ip_fragments_received: AtomicU64,
    pub ip_fragments_reassembled: AtomicU64,
    pub ip_fragment_overlap_drops: AtomicU64,
    pub ip_fragment_expired: AtomicU64,
    pub ip_fragment_evicted: AtomicU64,
    pub packets_ignored: AtomicU64,
    pub packets_filtered: AtomicU64,
    pub capture_drops: AtomicU64,
    pub capture_backend_drops: AtomicU64,
    pub capture_backend_invalid_descs: AtomicU64,
    pub raw_capture_drops: AtomicU64,
    pub flow_queue_depth: AtomicU64,
    pub flow_queue_capacity: AtomicU64,
    pub flow_queue_high_watermark: AtomicU64,
    pub l7_queue_depth: AtomicU64,
    pub l7_queue_capacity: AtomicU64,
    pub l7_queue_high_watermark: AtomicU64,
    pub match_queue_depth: AtomicU64,
    pub match_queue_capacity: AtomicU64,
    pub match_queue_high_watermark: AtomicU64,
    pub matcher_queue_backpressure: AtomicU64,
    pub matcher_queue_drops: AtomicU64,
    pub matcher_housekeeping_drops: AtomicU64,
    pub storage_queue_depth: AtomicU64,
    pub storage_queue_capacity: AtomicU64,
    pub storage_queue_high_watermark: AtomicU64,
    pub segment_queue_depth: AtomicU64,
    pub segment_queue_capacity: AtomicU64,
    pub segment_queue_high_watermark: AtomicU64,
    pub metadata_spool_bytes: AtomicU64,
    pub metadata_spool_capacity: AtomicU64,
    pub active_flows: AtomicU64,
    pub flow_state_rejections: AtomicU64,
    pub flow_prefix_rejections: AtomicU64,
    pub flows_completed: AtomicU64,
    pub tcp_retransmits: AtomicU64,
    pub tcp_out_of_order: AtomicU64,
    pub tcp_gap_events: AtomicU64,
    pub tcp_gap_bytes: AtomicU64,
    pub tcp_rejected_resets: AtomicU64,
    pub http_requests: AtomicU64,
    pub http_responses: AtomicU64,
    pub http_parse_errors: AtomicU64,
    pub matcher_bytes: AtomicU64,
    pub matcher_matches: AtomicU64,
    pub matcher_match_limit_events: AtomicU64,
    pub segment_bytes: AtomicU64,
    pub segment_disk_bytes: AtomicU64,
    pub segment_disk_capacity: AtomicU64,
    pub replay_bytes: AtomicU64,
    pub replay_matches: AtomicU64,
    pub replay_active: AtomicU64,
    pub pattern_generation: AtomicU64,
    pub cpu_available: AtomicU64,
    pub cpu_budget: AtomicU64,
    pub tokio_workers: AtomicU64,
    pub flow_workers: AtomicU64,
    pub l7_workers: AtomicU64,
    pub matcher_workers: AtomicU64,
    pub replay_workers: AtomicU64,
}

impl Metrics {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn touch_progress(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        self.pipeline_last_progress_ns.store(now, Ordering::Release);
    }

    pub fn progress_stale(&self, timeout: std::time::Duration) -> bool {
        let last = self.pipeline_last_progress_ns.load(Ordering::Acquire);
        if last == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        now.saturating_sub(last as u128) > timeout.as_nanos()
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        macro_rules! load {
            ($f:ident) => {
                self.$f.load(Ordering::Relaxed)
            };
        }
        MetricsSnapshot {
            pipeline_last_progress_ns: load!(pipeline_last_progress_ns),
            capture_frames: load!(capture_frames),
            capture_frame_bytes: load!(capture_frame_bytes),
            packets_received: load!(packets_received),
            packet_bytes: load!(packet_bytes),
            packet_parse_errors: load!(packet_parse_errors),
            capture_truncated_packets: load!(capture_truncated_packets),
            ip_fragments_received: load!(ip_fragments_received),
            ip_fragments_reassembled: load!(ip_fragments_reassembled),
            ip_fragment_overlap_drops: load!(ip_fragment_overlap_drops),
            ip_fragment_expired: load!(ip_fragment_expired),
            ip_fragment_evicted: load!(ip_fragment_evicted),
            packets_ignored: load!(packets_ignored),
            packets_filtered: load!(packets_filtered),
            capture_drops: load!(capture_drops),
            capture_backend_drops: load!(capture_backend_drops),
            capture_backend_invalid_descs: load!(capture_backend_invalid_descs),
            raw_capture_drops: load!(raw_capture_drops),
            flow_queue_depth: load!(flow_queue_depth),
            flow_queue_capacity: load!(flow_queue_capacity),
            flow_queue_high_watermark: load!(flow_queue_high_watermark),
            l7_queue_depth: load!(l7_queue_depth),
            l7_queue_capacity: load!(l7_queue_capacity),
            l7_queue_high_watermark: load!(l7_queue_high_watermark),
            match_queue_depth: load!(match_queue_depth),
            match_queue_capacity: load!(match_queue_capacity),
            match_queue_high_watermark: load!(match_queue_high_watermark),
            matcher_queue_backpressure: load!(matcher_queue_backpressure),
            matcher_queue_drops: load!(matcher_queue_drops),
            matcher_housekeeping_drops: load!(matcher_housekeeping_drops),
            storage_queue_depth: load!(storage_queue_depth),
            storage_queue_capacity: load!(storage_queue_capacity),
            storage_queue_high_watermark: load!(storage_queue_high_watermark),
            segment_queue_depth: load!(segment_queue_depth),
            segment_queue_capacity: load!(segment_queue_capacity),
            segment_queue_high_watermark: load!(segment_queue_high_watermark),
            metadata_spool_bytes: load!(metadata_spool_bytes),
            metadata_spool_capacity: load!(metadata_spool_capacity),
            active_flows: load!(active_flows),
            flow_state_rejections: load!(flow_state_rejections),
            flow_prefix_rejections: load!(flow_prefix_rejections),
            flows_completed: load!(flows_completed),
            tcp_retransmits: load!(tcp_retransmits),
            tcp_out_of_order: load!(tcp_out_of_order),
            tcp_gap_events: load!(tcp_gap_events),
            tcp_gap_bytes: load!(tcp_gap_bytes),
            tcp_rejected_resets: load!(tcp_rejected_resets),
            http_requests: load!(http_requests),
            http_responses: load!(http_responses),
            http_parse_errors: load!(http_parse_errors),
            matcher_bytes: load!(matcher_bytes),
            matcher_matches: load!(matcher_matches),
            matcher_match_limit_events: load!(matcher_match_limit_events),
            segment_bytes: load!(segment_bytes),
            segment_disk_bytes: load!(segment_disk_bytes),
            segment_disk_capacity: load!(segment_disk_capacity),
            replay_bytes: load!(replay_bytes),
            replay_matches: load!(replay_matches),
            replay_active: load!(replay_active),
            pattern_generation: load!(pattern_generation),
            cpu_available: load!(cpu_available),
            cpu_budget: load!(cpu_budget),
            tokio_workers: load!(tokio_workers),
            flow_workers: load!(flow_workers),
            l7_workers: load!(l7_workers),
            matcher_workers: load!(matcher_workers),
            replay_workers: load!(replay_workers),
        }
    }

    pub fn observe_queue(depth: &AtomicU64, high_watermark: &AtomicU64, value: u64) {
        depth.store(value, Ordering::Relaxed);
        high_watermark.fetch_max(value, Ordering::Relaxed);
    }

    /// Update a global queue gauge on successful enqueue. Unlike sampling an
    /// individual shard's `Receiver::len()`, this is exact across all shards and
    /// therefore safe to use for replay throttling.
    pub fn queue_enqueued(depth: &AtomicU64, high_watermark: &AtomicU64) -> u64 {
        let value = depth.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        high_watermark.fetch_max(value, Ordering::Relaxed);
        value
    }

    pub fn queue_dequeued(depth: &AtomicU64) {
        let _ = depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_sub(1))
        });
    }

    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        let mut out = String::with_capacity(4096);
        macro_rules! metric {
            ($name:literal, $value:expr, $kind:literal) => {{
                out.push_str(concat!("# TYPE bazalt_", $name, " ", $kind, "\n"));
                out.push_str(concat!("bazalt_", $name, " "));
                out.push_str(&$value.to_string());
                out.push('\n');
            }};
        }
        metric!("capture_frames_total", s.capture_frames, "counter");
        metric!(
            "capture_frame_bytes_total",
            s.capture_frame_bytes,
            "counter"
        );
        metric!("packets_received_total", s.packets_received, "counter");
        metric!("packet_bytes_total", s.packet_bytes, "counter");
        metric!(
            "packet_parse_errors_total",
            s.packet_parse_errors,
            "counter"
        );
        metric!(
            "capture_truncated_packets_total",
            s.capture_truncated_packets,
            "counter"
        );
        metric!(
            "ip_fragments_received_total",
            s.ip_fragments_received,
            "counter"
        );
        metric!(
            "ip_fragments_reassembled_total",
            s.ip_fragments_reassembled,
            "counter"
        );
        metric!(
            "ip_fragment_overlap_drops_total",
            s.ip_fragment_overlap_drops,
            "counter"
        );
        metric!(
            "ip_fragment_expired_total",
            s.ip_fragment_expired,
            "counter"
        );
        metric!(
            "ip_fragment_evicted_total",
            s.ip_fragment_evicted,
            "counter"
        );
        metric!("packets_ignored_total", s.packets_ignored, "counter");
        metric!("packets_filtered_total", s.packets_filtered, "counter");
        metric!("capture_drops_total", s.capture_drops, "counter");
        metric!(
            "capture_backend_drops_total",
            s.capture_backend_drops,
            "counter"
        );
        metric!(
            "capture_backend_invalid_descs_total",
            s.capture_backend_invalid_descs,
            "counter"
        );
        metric!("raw_capture_drops_total", s.raw_capture_drops, "counter");
        metric!("flow_queue_depth", s.flow_queue_depth, "gauge");
        metric!("flow_queue_capacity", s.flow_queue_capacity, "gauge");
        metric!(
            "flow_queue_high_watermark",
            s.flow_queue_high_watermark,
            "gauge"
        );
        metric!("l7_queue_depth", s.l7_queue_depth, "gauge");
        metric!("l7_queue_capacity", s.l7_queue_capacity, "gauge");
        metric!(
            "l7_queue_high_watermark",
            s.l7_queue_high_watermark,
            "gauge"
        );
        metric!("match_queue_depth", s.match_queue_depth, "gauge");
        metric!("match_queue_capacity", s.match_queue_capacity, "gauge");
        metric!(
            "match_queue_high_watermark",
            s.match_queue_high_watermark,
            "gauge"
        );
        metric!(
            "matcher_queue_backpressure_total",
            s.matcher_queue_backpressure,
            "counter"
        );
        metric!(
            "matcher_queue_drops_total",
            s.matcher_queue_drops,
            "counter"
        );
        metric!(
            "matcher_housekeeping_drops_total",
            s.matcher_housekeeping_drops,
            "counter"
        );
        metric!("storage_queue_depth", s.storage_queue_depth, "gauge");
        metric!("storage_queue_capacity", s.storage_queue_capacity, "gauge");
        metric!(
            "storage_queue_high_watermark",
            s.storage_queue_high_watermark,
            "gauge"
        );
        metric!("segment_queue_depth", s.segment_queue_depth, "gauge");
        metric!("segment_queue_capacity", s.segment_queue_capacity, "gauge");
        metric!(
            "segment_queue_high_watermark",
            s.segment_queue_high_watermark,
            "gauge"
        );
        metric!("metadata_spool_bytes", s.metadata_spool_bytes, "gauge");
        metric!(
            "metadata_spool_capacity",
            s.metadata_spool_capacity,
            "gauge"
        );
        metric!("active_flows", s.active_flows, "gauge");
        metric!(
            "flow_state_rejections_total",
            s.flow_state_rejections,
            "counter"
        );
        metric!("flows_completed_total", s.flows_completed, "counter");
        metric!("tcp_retransmits_total", s.tcp_retransmits, "counter");
        metric!("tcp_out_of_order_total", s.tcp_out_of_order, "counter");
        metric!("tcp_gap_events_total", s.tcp_gap_events, "counter");
        metric!("tcp_gap_bytes_total", s.tcp_gap_bytes, "counter");
        metric!(
            "tcp_rejected_resets_total",
            s.tcp_rejected_resets,
            "counter"
        );
        metric!("http_requests_total", s.http_requests, "counter");
        metric!("http_responses_total", s.http_responses, "counter");
        metric!("http_parse_errors_total", s.http_parse_errors, "counter");
        metric!("matcher_bytes_total", s.matcher_bytes, "counter");
        metric!("matcher_matches_total", s.matcher_matches, "counter");
        metric!(
            "matcher_match_limit_events_total",
            s.matcher_match_limit_events,
            "counter"
        );
        metric!("segment_bytes_total", s.segment_bytes, "counter");
        metric!("segment_disk_bytes", s.segment_disk_bytes, "gauge");
        metric!("segment_disk_capacity", s.segment_disk_capacity, "gauge");
        metric!("replay_bytes_total", s.replay_bytes, "counter");
        metric!("replay_matches_total", s.replay_matches, "counter");
        metric!("replay_active", s.replay_active, "gauge");
        metric!("pattern_generation", s.pattern_generation, "gauge");
        metric!("cpu_available", s.cpu_available, "gauge");
        metric!("cpu_budget", s.cpu_budget, "gauge");
        metric!("tokio_workers", s.tokio_workers, "gauge");
        metric!("flow_workers", s.flow_workers, "gauge");
        metric!("l7_workers", s.l7_workers, "gauge");
        metric!("matcher_workers", s.matcher_workers, "gauge");
        metric!("replay_workers", s.replay_workers, "gauge");
        metric!("live_pressure_pct", self.live_pressure_pct(), "gauge");
        out
    }

    pub fn live_pressure_pct(&self) -> u64 {
        let pairs = [
            (
                self.flow_queue_depth.load(Ordering::Relaxed),
                self.flow_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                self.l7_queue_depth.load(Ordering::Relaxed),
                self.l7_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                self.match_queue_depth.load(Ordering::Relaxed),
                self.match_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                self.storage_queue_depth.load(Ordering::Relaxed),
                self.storage_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                self.segment_queue_depth.load(Ordering::Relaxed),
                self.segment_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                self.metadata_spool_bytes.load(Ordering::Relaxed),
                self.metadata_spool_capacity.load(Ordering::Relaxed),
            ),
        ];
        pairs
            .into_iter()
            .filter(|(_, cap)| *cap > 0)
            .map(|(depth, cap)| depth.saturating_mul(100) / cap)
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;
    use std::sync::atomic::Ordering;

    #[test]
    fn live_pressure_accounts_for_segment_queue() {
        let metrics = Metrics::default();
        metrics.segment_queue_capacity.store(10, Ordering::Relaxed);
        metrics.segment_queue_depth.store(8, Ordering::Relaxed);
        assert_eq!(metrics.live_pressure_pct(), 80);
    }
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub pipeline_last_progress_ns: u64,
    pub capture_frames: u64,
    pub capture_frame_bytes: u64,
    pub packets_received: u64,
    pub packet_bytes: u64,
    pub packet_parse_errors: u64,
    pub capture_truncated_packets: u64,
    pub ip_fragments_received: u64,
    pub ip_fragments_reassembled: u64,
    pub ip_fragment_overlap_drops: u64,
    pub ip_fragment_expired: u64,
    pub ip_fragment_evicted: u64,
    pub packets_ignored: u64,
    pub packets_filtered: u64,
    pub capture_drops: u64,
    pub capture_backend_drops: u64,
    pub capture_backend_invalid_descs: u64,
    pub raw_capture_drops: u64,
    pub flow_queue_depth: u64,
    pub flow_queue_capacity: u64,
    pub flow_queue_high_watermark: u64,
    pub l7_queue_depth: u64,
    pub l7_queue_capacity: u64,
    pub l7_queue_high_watermark: u64,
    pub match_queue_depth: u64,
    pub match_queue_capacity: u64,
    pub match_queue_high_watermark: u64,
    pub matcher_queue_backpressure: u64,
    pub matcher_queue_drops: u64,
    pub matcher_housekeeping_drops: u64,
    pub storage_queue_depth: u64,
    pub storage_queue_capacity: u64,
    pub storage_queue_high_watermark: u64,
    pub segment_queue_depth: u64,
    pub segment_queue_capacity: u64,
    pub segment_queue_high_watermark: u64,
    pub metadata_spool_bytes: u64,
    pub metadata_spool_capacity: u64,
    pub active_flows: u64,
    pub flow_state_rejections: u64,
    pub flow_prefix_rejections: u64,
    pub flows_completed: u64,
    pub tcp_retransmits: u64,
    pub tcp_out_of_order: u64,
    pub tcp_gap_events: u64,
    pub tcp_gap_bytes: u64,
    pub tcp_rejected_resets: u64,
    pub http_requests: u64,
    pub http_responses: u64,
    pub http_parse_errors: u64,
    pub matcher_bytes: u64,
    pub matcher_matches: u64,
    pub matcher_match_limit_events: u64,
    pub segment_bytes: u64,
    pub segment_disk_bytes: u64,
    pub segment_disk_capacity: u64,
    pub replay_bytes: u64,
    pub replay_matches: u64,
    pub replay_active: u64,
    pub pattern_generation: u64,
    pub cpu_available: u64,
    pub cpu_budget: u64,
    pub tokio_workers: u64,
    pub flow_workers: u64,
    pub l7_workers: u64,
    pub matcher_workers: u64,
    pub replay_workers: u64,
}
