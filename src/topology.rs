use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ahash::AHashMap;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;

const RATE_WINDOW_SECS: u64 = 5;
const LOCAL_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const MAX_LOCAL_SOURCES_BEFORE_FLUSH: usize = 4096;
const MAX_AUDIT_ENTRIES: usize = 512;
const MAX_TOPOLOGY_GC_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SNAPSHOT_GROUPS: usize = 256;
const MAX_SNAPSHOT_SOURCES: usize = 2_048;
pub const MAX_THROTTLE_TTL_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, Copy, Default)]
struct PendingCounters {
    packets: u64,
    bytes: u64,
    last_packet_ts_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct RateBucket {
    second: u64,
    packets: u64,
    bytes: u64,
}

#[derive(Debug)]
struct SourceState {
    packets_total: u64,
    bytes_total: u64,
    last_packet_ts_ns: u64,
    last_observed: Instant,
    buckets: VecDeque<RateBucket>,
}

impl SourceState {
    fn new(now: Instant) -> Self {
        Self {
            packets_total: 0,
            bytes_total: 0,
            last_packet_ts_ns: 0,
            last_observed: now,
            buckets: VecDeque::with_capacity((RATE_WINDOW_SECS + 1) as usize),
        }
    }

    fn merge(&mut self, counters: PendingCounters, second: u64, now: Instant) {
        self.packets_total = self.packets_total.saturating_add(counters.packets);
        self.bytes_total = self.bytes_total.saturating_add(counters.bytes);
        self.last_packet_ts_ns = self.last_packet_ts_ns.max(counters.last_packet_ts_ns);
        self.last_observed = now;
        if let Some(bucket) = self.buckets.back_mut().filter(|bucket| bucket.second == second) {
            bucket.packets = bucket.packets.saturating_add(counters.packets);
            bucket.bytes = bucket.bytes.saturating_add(counters.bytes);
        } else {
            self.buckets.push_back(RateBucket {
                second,
                packets: counters.packets,
                bytes: counters.bytes,
            });
        }
        self.trim_buckets(second);
    }

    fn trim_buckets(&mut self, now_second: u64) {
        while self
            .buckets
            .front()
            .is_some_and(|bucket| now_second.saturating_sub(bucket.second) >= RATE_WINDOW_SECS)
        {
            self.buckets.pop_front();
        }
    }

    fn rates(&mut self, now_second: u64) -> (f64, f64) {
        self.trim_buckets(now_second);
        let packets = self.buckets.iter().map(|bucket| bucket.packets).sum::<u64>();
        let bytes = self.buckets.iter().map(|bucket| bucket.bytes).sum::<u64>();
        let seconds = self
            .buckets
            .front()
            .map(|bucket| now_second.saturating_sub(bucket.second).saturating_add(1))
            .unwrap_or(1)
            .clamp(1, RATE_WINDOW_SECS);
        (
            packets as f64 / seconds as f64,
            (bytes as f64 * 8.0) / seconds as f64,
        )
    }
}

#[derive(Debug, Default)]
struct TopologyState {
    sources: AHashMap<Ipv4Addr, SourceState>,
    overflow: Option<SourceState>,
    last_gc: Option<Instant>,
}

#[derive(Debug)]
pub struct TopologyTracker {
    group_prefix_v4: u8,
    source_ttl: Duration,
    max_sources: usize,
    state: Mutex<TopologyState>,
}

impl TopologyTracker {
    pub fn new(group_prefix_v4: u8, source_ttl: Duration, max_sources: usize) -> Arc<Self> {
        Arc::new(Self {
            group_prefix_v4,
            source_ttl,
            max_sources: max_sources.max(1),
            state: Mutex::new(TopologyState::default()),
        })
    }

    pub fn local_observer(self: &Arc<Self>) -> LocalTopologyObserver {
        self.local_observer_ignoring_source_mac(None)
    }

    pub fn local_observer_ignoring_source_mac(
        self: &Arc<Self>,
        ignored_source_mac: Option<[u8; 6]>,
    ) -> LocalTopologyObserver {
        LocalTopologyObserver {
            shared: self.clone(),
            pending: AHashMap::new(),
            last_flush: Instant::now(),
            ignored_source_mac,
        }
    }

    pub fn canonical_throttle_target(&self, value: &str) -> std::result::Result<String, String> {
        let target = Ipv4Target::parse(value).map_err(|error| error.to_string())?;
        if target.prefix != self.group_prefix_v4 && target.prefix != 32 {
            return Err(format!(
                "throttle target must be an automatic /{} group or one IPv4 source (/32), got /{}",
                self.group_prefix_v4, target.prefix
            ));
        }
        Ok(target.canonical())
    }

    fn merge_batch(&self, pending: &mut AHashMap<Ipv4Addr, PendingCounters>) {
        if pending.is_empty() {
            return;
        }
        let now = Instant::now();
        let second = unix_now_secs();
        let mut state = self.state.lock();
        let gc_interval = self.source_ttl.min(MAX_TOPOLOGY_GC_INTERVAL);
        if state
            .last_gc
            .is_none_or(|last_gc| now.duration_since(last_gc) >= gc_interval)
        {
            state
                .sources
                .retain(|_, source| now.duration_since(source.last_observed) <= self.source_ttl);
            state.last_gc = Some(now);
        }
        for (ip, counters) in pending.drain() {
            if let Some(source) = state.sources.get_mut(&ip) {
                source.merge(counters, second, now);
            } else if state.sources.len() < self.max_sources {
                let mut source = SourceState::new(now);
                source.merge(counters, second, now);
                state.sources.insert(ip, source);
            } else {
                state
                    .overflow
                    .get_or_insert_with(|| SourceState::new(now))
                    .merge(counters, second, now);
            }
        }
    }

    pub fn snapshot(&self) -> TopologySnapshot {
        let now = Instant::now();
        let now_second = unix_now_secs();
        let (
            source_rows,
            source_count,
            source_capacity_saturated,
            untracked_packets_total,
            untracked_bytes_total,
            untracked_pps,
            untracked_bps,
        ) = {
            let mut state = self.state.lock();
            state
                .sources
                .retain(|_, source| now.duration_since(source.last_observed) <= self.source_ttl);
            state.last_gc = Some(now);

            let mut rows = Vec::with_capacity(state.sources.len());
            for (ip, source) in &mut state.sources {
                let (pps, bps) = source.rates(now_second);
                rows.push((
                    *ip,
                    source.packets_total,
                    source.bytes_total,
                    pps,
                    bps,
                    source.last_packet_ts_ns,
                ));
            }
            let overflow = if let Some(overflow) = state.overflow.as_mut() {
                let (pps, bps) = overflow.rates(now_second);
                (overflow.packets_total, overflow.bytes_total, pps, bps)
            } else {
                (0, 0, 0.0, 0.0)
            };
            let source_count = state.sources.len();
            (
                rows,
                source_count,
                source_count >= self.max_sources,
                overflow.0,
                overflow.1,
                overflow.2,
                overflow.3,
            )
        };

        let mut groups = AHashMap::<Ipv4Addr, TopologyGroupSnapshot>::new();
        let mut packets_total = untracked_packets_total;
        let mut bytes_total = untracked_bytes_total;
        let mut packets_per_second = untracked_pps;
        let mut bits_per_second = untracked_bps;

        for (ip, source_packets, source_bytes, pps, bps, last_packet_ts_ns) in source_rows {
            let network = network_for(ip, self.group_prefix_v4);
            let source_snapshot = TopologySourceSnapshot {
                ip: ip.to_string(),
                packets_total: source_packets,
                bytes_total: source_bytes,
                packets_per_second: pps,
                bits_per_second: bps,
                last_packet_ts_ns,
            };
            let group = groups.entry(network).or_insert_with(|| TopologyGroupSnapshot {
                cidr: format!("{network}/{}", self.group_prefix_v4),
                source_count: 0,
                sources_truncated: false,
                packets_total: 0,
                bytes_total: 0,
                packets_per_second: 0.0,
                bits_per_second: 0.0,
                sources: Vec::new(),
            });
            group.source_count = group.source_count.saturating_add(1);
            group.packets_total = group.packets_total.saturating_add(source_packets);
            group.bytes_total = group.bytes_total.saturating_add(source_bytes);
            group.packets_per_second += pps;
            group.bits_per_second += bps;
            group.sources.push(source_snapshot);

            packets_total = packets_total.saturating_add(source_packets);
            bytes_total = bytes_total.saturating_add(source_bytes);
            packets_per_second += pps;
            bits_per_second += bps;
        }

        let mut groups = groups.into_values().collect::<Vec<_>>();
        for group in &mut groups {
            group.sources.sort_by(|a, b| {
                b.bits_per_second
                    .total_cmp(&a.bits_per_second)
                    .then_with(|| a.ip.cmp(&b.ip))
            });
        }
        groups.sort_by(|a, b| {
            b.bits_per_second
                .total_cmp(&a.bits_per_second)
                .then_with(|| a.cidr.cmp(&b.cidr))
        });

        let group_count = groups.len();
        groups.truncate(MAX_SNAPSHOT_GROUPS);
        let mut source_budget = MAX_SNAPSHOT_SOURCES;
        let mut returned_source_count = 0usize;
        let mut returned_groups = Vec::with_capacity(groups.len());
        for mut group in groups {
            if source_budget == 0 {
                break;
            }
            if group.sources.len() > source_budget {
                group.sources.truncate(source_budget);
                group.sources_truncated = true;
            }
            source_budget = source_budget.saturating_sub(group.sources.len());
            returned_source_count = returned_source_count.saturating_add(group.sources.len());
            returned_groups.push(group);
        }
        let returned_group_count = returned_groups.len();
        let view_truncated =
            returned_group_count < group_count || returned_source_count < source_count;

        TopologySnapshot {
            generated_at: Utc::now(),
            group_prefix_v4: self.group_prefix_v4,
            rate_window_seconds: RATE_WINDOW_SECS,
            source_ttl_seconds: self.source_ttl.as_secs(),
            source_capacity: self.max_sources,
            source_capacity_saturated,
            source_count,
            untracked_packets_total,
            untracked_bytes_total,
            untracked_packets_per_second: untracked_pps,
            untracked_bits_per_second: untracked_bps,
            group_count,
            returned_group_count,
            returned_source_count,
            view_truncated,
            packets_total,
            bytes_total,
            packets_per_second,
            bits_per_second,
            groups: returned_groups,
        }
    }

}

pub struct LocalTopologyObserver {
    shared: Arc<TopologyTracker>,
    pending: AHashMap<Ipv4Addr, PendingCounters>,
    last_flush: Instant,
    ignored_source_mac: Option<[u8; 6]>,
}

impl LocalTopologyObserver {
    /// Passive libpcap can expose locally transmitted Ethernet frames. Keep the
    /// direction check separate from packet accounting so capture can first
    /// perform the authoritative service-destination decision after decoding.
    #[inline]
    pub fn ignores_ethernet_frame(&self, frame: &[u8]) -> bool {
        self.ignored_source_mac
            .is_some_and(|mac| ethernet_source_mac(frame) == Some(mac))
    }

    /// Account one IPv4 packet that has already passed the service-destination
    /// gate. Throttle enforcement is intentionally *not* consulted here: once
    /// a source is penalized, the XDP rule applies to all traffic from that IP,
    /// while topology visibility remains scoped to configured service ports.
    #[inline]
    pub fn observe_ipv4_source(&mut self, ts_ns: u64, wire_len: usize, ip: Ipv4Addr) {
        let entry = self.pending.entry(ip).or_default();
        entry.packets = entry.packets.saturating_add(1);
        entry.bytes = entry.bytes.saturating_add(wire_len as u64);
        entry.last_packet_ts_ns = entry.last_packet_ts_ns.max(ts_ns);
        if self.pending.len() >= MAX_LOCAL_SOURCES_BEFORE_FLUSH
            || self.last_flush.elapsed() >= LOCAL_FLUSH_INTERVAL
        {
            self.flush();
        }
    }

    #[inline]
    pub fn flush_if_due(&mut self) {
        if !self.pending.is_empty() && self.last_flush.elapsed() >= LOCAL_FLUSH_INTERVAL {
            self.flush();
        }
    }

    fn flush(&mut self) {
        self.shared.merge_batch(&mut self.pending);
        self.last_flush = Instant::now();
    }
}

impl Drop for LocalTopologyObserver {
    fn drop(&mut self) {
        self.flush();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologySnapshot {
    pub generated_at: DateTime<Utc>,
    pub group_prefix_v4: u8,
    pub rate_window_seconds: u64,
    pub source_ttl_seconds: u64,
    pub source_capacity: usize,
    pub source_capacity_saturated: bool,
    pub source_count: usize,
    pub untracked_packets_total: u64,
    pub untracked_bytes_total: u64,
    pub untracked_packets_per_second: f64,
    pub untracked_bits_per_second: f64,
    pub group_count: usize,
    pub returned_group_count: usize,
    pub returned_source_count: usize,
    pub view_truncated: bool,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
    pub groups: Vec<TopologyGroupSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyGroupSnapshot {
    pub cidr: String,
    pub source_count: usize,
    pub sources_truncated: bool,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
    pub sources: Vec<TopologySourceSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologySourceSnapshot {
    pub ip: String,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
    pub last_packet_ts_ns: u64,
}


#[inline]
fn ethernet_source_mac(frame: &[u8]) -> Option<[u8; 6]> {
    let bytes = frame.get(6..12)?;
    Some(bytes.try_into().ok()?)
}

fn network_for(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let value = u32::from(ip);
    let mask = match prefix {
        0 => 0,
        32 => u32::MAX,
        bits => u32::MAX << (32 - bits),
    };
    Ipv4Addr::from(value & mask)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv4Target {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Target {
    fn parse(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        let (ip_raw, prefix) = match trimmed.split_once('/') {
            Some((ip, prefix)) => {
                let prefix = prefix
                    .parse::<u8>()
                    .with_context(|| format!("invalid IPv4 prefix in {trimmed}"))?;
                if prefix > 32 {
                    anyhow::bail!("IPv4 prefix must be between 0 and 32");
                }
                (ip, prefix)
            }
            None => (trimmed, 32),
        };
        let ip = ip_raw
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 address: {ip_raw}"))?;
        Ok(Self {
            network: network_for(ip, prefix),
            prefix,
        })
    }

    fn canonical(self) -> String {
        if self.prefix == 32 {
            self.network.to_string()
        } else {
            format!("{}/{}", self.network, self.prefix)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThrottleRuleSnapshot {
    pub target: String,
    pub drop_percent: u8,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub seen_packets: u64,
    pub seen_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThrottleAuditEntry {
    pub at: DateTime<Utc>,
    pub action: String,
    pub target: String,
    pub drop_percent: u8,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThrottleSnapshot {
    pub available: bool,
    pub interface: Option<String>,
    pub attach_mode: Option<String>,
    pub rules: Vec<ThrottleRuleSnapshot>,
    pub audit: Vec<ThrottleAuditEntry>,
}

#[derive(Debug, Clone)]
struct ActiveRule {
    target: Ipv4Target,
    drop_percent: u8,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    expires_instant: Instant,
}

#[derive(Debug, Default)]
struct RuleBook {
    rules: AHashMap<Ipv4Target, ActiveRule>,
    audit: VecDeque<ThrottleAuditEntry>,
}

#[derive(Clone)]
pub struct ThrottleManager {
    inner: Arc<ThrottleInner>,
}

struct ThrottleInner {
    interface: Option<String>,
    backend: Option<XdpThrottleBackend>,
    book: Mutex<RuleBook>,
    operations: Mutex<()>,
}

impl ThrottleManager {
    pub fn new(enabled: bool, interface: &str) -> Result<Self> {
        let interface = interface.trim();
        if enabled && interface.is_empty() {
            anyhow::bail!("BAZALT_INTERFACE cannot be empty when throttle is enabled");
        }
        let backend = enabled.then(|| XdpThrottleBackend::open(interface)).transpose()?;
        Ok(Self {
            inner: Arc::new(ThrottleInner {
                interface: enabled.then(|| interface.to_owned()),
                backend,
                book: Mutex::new(RuleBook::default()),
                operations: Mutex::new(()),
            }),
        })
    }

    pub fn available(&self) -> bool {
        self.inner.backend.is_some()
    }

    pub fn attach_mode(&self) -> Option<&'static str> {
        self.inner.backend.as_ref().map(XdpThrottleBackend::attach_mode)
    }

    pub fn set_rule(
        &self,
        target: &str,
        drop_percent: u8,
        ttl_seconds: u64,
    ) -> Result<ThrottleRuleSnapshot> {
        if !(1..=100).contains(&drop_percent) {
            anyhow::bail!("drop_percent must be between 1 and 100");
        }
        if !(1..=MAX_THROTTLE_TTL_SECS).contains(&ttl_seconds) {
            anyhow::bail!(
                "throttle TTL must be between 1 and {MAX_THROTTLE_TTL_SECS} seconds"
            );
        }
        let backend = self
            .inner
            .backend
            .as_ref()
            .context("traffic enforcement is not configured")?;
        let target = Ipv4Target::parse(target)?;
        let now = Utc::now();
        let expires_at = now
            .checked_add_signed(chrono::Duration::seconds(ttl_seconds as i64))
            .context("throttle TTL overflow")?;
        let expires_instant = Instant::now()
            .checked_add(Duration::from_secs(ttl_seconds))
            .context("throttle TTL overflow")?;

        // Kernel and in-memory rulebook are serialized as one control-plane
        // operation. Compute all fallible metadata first so we never install a
        // kernel rule that cannot be represented in the rulebook.
        let _operation = self.inner.operations.lock();
        self.prune_expired_locked();
        backend.set_rule(target, drop_percent, ttl_seconds)?;
        let rule = ActiveRule {
            target,
            drop_percent,
            created_at: now.clone(),
            expires_at,
            expires_instant,
        };
        let mut book = self.inner.book.lock();
        book.rules.insert(target, rule.clone());
        push_audit(
            &mut book.audit,
            ThrottleAuditEntry {
                at: now,
                action: "set".to_owned(),
                target: target.canonical(),
                drop_percent,
                ttl_seconds: Some(ttl_seconds),
            },
        );
        drop(book);
        Ok(self.rule_snapshot(&rule))
    }

    pub fn clear_rule(&self, target: &str) -> Result<bool> {
        let backend = self
            .inner
            .backend
            .as_ref()
            .context("traffic enforcement is not configured")?;
        let _operation = self.inner.operations.lock();
        let target = Ipv4Target::parse(target)?;
        backend.delete_rule(target)?;
        let mut book = self.inner.book.lock();
        let removed = book.rules.remove(&target).is_some();
        push_audit(
            &mut book.audit,
            ThrottleAuditEntry {
                at: Utc::now(),
                action: "clear".to_owned(),
                target: target.canonical(),
                drop_percent: 0,
                ttl_seconds: None,
            },
        );
        Ok(removed)
    }

    pub fn snapshot(&self) -> ThrottleSnapshot {
        let _operation = self.inner.operations.lock();
        self.prune_expired_locked();
        let (active_rules, audit) = {
            let book = self.inner.book.lock();
            (
                book.rules.values().cloned().collect::<Vec<_>>(),
                book.audit.iter().rev().take(32).cloned().collect::<Vec<_>>(),
            )
        };
        let mut rules = active_rules
            .iter()
            .map(|rule| self.rule_snapshot(rule))
            .collect::<Vec<_>>();
        rules.sort_by(|a, b| a.target.cmp(&b.target));
        ThrottleSnapshot {
            available: self.available(),
            interface: self.inner.interface.clone(),
            attach_mode: self.attach_mode().map(str::to_owned),
            rules,
            audit,
        }
    }

    fn prune_expired_locked(&self) {
        let now = Instant::now();
        let expired = {
            let book = self.inner.book.lock();
            book.rules
                .iter()
                .filter_map(|(target, rule)| (rule.expires_instant <= now).then_some(*target))
                .collect::<Vec<_>>()
        };
        if expired.is_empty() {
            return;
        }

        let mut removable = Vec::with_capacity(expired.len());
        if let Some(backend) = &self.inner.backend {
            for target in expired {
                match backend.delete_rule(target) {
                    Ok(()) => removable.push(target),
                    Err(error) => {
                        tracing::warn!(
                            target=%target.canonical(),
                            %error,
                            "cannot remove expired XDP throttle rule; will retry"
                        );
                    }
                }
            }
        } else {
            removable = expired;
        }

        let mut book = self.inner.book.lock();
        for target in removable {
            if book.rules.remove(&target).is_some() {
                push_audit(
                    &mut book.audit,
                    ThrottleAuditEntry {
                        at: Utc::now(),
                        action: "expire".to_owned(),
                        target: target.canonical(),
                        drop_percent: 0,
                        ttl_seconds: None,
                    },
                );
            }
        }
    }

    fn rule_snapshot(&self, rule: &ActiveRule) -> ThrottleRuleSnapshot {
        let stats = self
            .inner
            .backend
            .as_ref()
            .and_then(|backend| backend.rule_stats(rule.target).ok())
            .unwrap_or_default();
        ThrottleRuleSnapshot {
            target: rule.target.canonical(),
            drop_percent: rule.drop_percent,
            created_at: rule.created_at.clone(),
            expires_at: Some(rule.expires_at.clone()),
            seen_packets: stats.seen_packets,
            seen_bytes: stats.seen_bytes,
            dropped_packets: stats.dropped_packets,
            dropped_bytes: stats.dropped_bytes,
        }
    }
}

fn push_audit(audit: &mut VecDeque<ThrottleAuditEntry>, entry: ThrottleAuditEntry) {
    if audit.len() >= MAX_AUDIT_ENTRIES {
        audit.pop_front();
    }
    audit.push_back(entry);
}

#[derive(Debug, Clone, Copy, Default)]
struct RuleStats {
    seen_packets: u64,
    seen_bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
struct XdpThrottleBackend {
    handle: std::ptr::NonNull<PmThrottleHandle>,
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
unsafe impl Send for XdpThrottleBackend {}
#[cfg(all(target_os = "linux", feature = "afxdp"))]
unsafe impl Sync for XdpThrottleBackend {}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
#[repr(C)]
struct PmThrottleHandle {
    _opaque: [u8; 0],
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
extern "C" {
    fn pm_throttle_open(
        ifname: *const std::os::raw::c_char,
        object_data: *const u8,
        object_len: usize,
    ) -> *mut PmThrottleHandle;
    fn pm_throttle_attach_mode(handle: *mut PmThrottleHandle) -> std::os::raw::c_int;
    fn pm_throttle_set_rule(
        handle: *mut PmThrottleHandle,
        addr: *const u8,
        prefix_len: u32,
        drop_percent: u32,
        ttl_seconds: u64,
    ) -> std::os::raw::c_int;
    fn pm_throttle_delete_rule(
        handle: *mut PmThrottleHandle,
        addr: *const u8,
        prefix_len: u32,
    ) -> std::os::raw::c_int;
    fn pm_throttle_get_rule_stats(
        handle: *mut PmThrottleHandle,
        addr: *const u8,
        prefix_len: u32,
        seen_packets: *mut u64,
        seen_bytes: *mut u64,
        dropped_packets: *mut u64,
        dropped_bytes: *mut u64,
    ) -> std::os::raw::c_int;
    fn pm_throttle_last_error() -> *const std::os::raw::c_char;
    fn pm_throttle_close(handle: *mut PmThrottleHandle);
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
impl XdpThrottleBackend {
    fn open(interface: &str) -> Result<Self> {
        let ifname = std::ffi::CString::new(interface)?;
        static OBJECT: &[u8] = include_bytes!(env!("BAZALT_THROTTLE_BPF_OBJECT"));
        let raw = unsafe { pm_throttle_open(ifname.as_ptr(), OBJECT.as_ptr(), OBJECT.len()) };
        let handle = std::ptr::NonNull::new(raw)
            .ok_or_else(|| anyhow::anyhow!(throttle_last_error()))?;
        Ok(Self { handle })
    }

    fn attach_mode(&self) -> &'static str {
        match unsafe { pm_throttle_attach_mode(self.handle.as_ptr()) } {
            1 => "native-link",
            2 => "native-netlink",
            3 => "generic-skb-netlink",
            _ => "unknown",
        }
    }

    fn set_rule(
        &self,
        target: Ipv4Target,
        drop_percent: u8,
        ttl_seconds: u64,
    ) -> Result<()> {
        let octets = target.network.octets();
        let rc = unsafe {
            pm_throttle_set_rule(
                self.handle.as_ptr(),
                octets.as_ptr(),
                target.prefix as u32,
                drop_percent as u32,
                ttl_seconds,
            )
        };
        if rc < 0 {
            anyhow::bail!("cannot install throttle rule: {}", throttle_last_error());
        }
        Ok(())
    }

    fn delete_rule(&self, target: Ipv4Target) -> Result<()> {
        let octets = target.network.octets();
        let rc = unsafe {
            pm_throttle_delete_rule(self.handle.as_ptr(), octets.as_ptr(), target.prefix as u32)
        };
        if rc < 0 && rc != -libc::ENOENT {
            anyhow::bail!("cannot remove throttle rule: {}", throttle_last_error());
        }
        Ok(())
    }

    fn rule_stats(&self, target: Ipv4Target) -> Result<RuleStats> {
        let octets = target.network.octets();
        let mut stats = RuleStats::default();
        let rc = unsafe {
            pm_throttle_get_rule_stats(
                self.handle.as_ptr(),
                octets.as_ptr(),
                target.prefix as u32,
                &mut stats.seen_packets,
                &mut stats.seen_bytes,
                &mut stats.dropped_packets,
                &mut stats.dropped_bytes,
            )
        };
        if rc < 0 {
            anyhow::bail!("cannot read throttle statistics: {}", throttle_last_error());
        }
        Ok(stats)
    }
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
impl Drop for XdpThrottleBackend {
    fn drop(&mut self) {
        unsafe { pm_throttle_close(self.handle.as_ptr()) };
    }
}

#[cfg(all(target_os = "linux", feature = "afxdp"))]
fn throttle_last_error() -> String {
    unsafe {
        let ptr = pm_throttle_last_error();
        if ptr.is_null() {
            return "unknown libbpf error".to_owned();
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

#[cfg(not(all(target_os = "linux", feature = "afxdp")))]
struct XdpThrottleBackend;

#[cfg(not(all(target_os = "linux", feature = "afxdp")))]
impl XdpThrottleBackend {
    fn open(_interface: &str) -> Result<Self> {
        anyhow::bail!("XDP traffic enforcement requires a Linux build with the afxdp feature")
    }

    fn attach_mode(&self) -> &'static str {
        "unavailable"
    }

    fn set_rule(
        &self,
        _target: Ipv4Target,
        _drop_percent: u8,
        _ttl_seconds: u64,
    ) -> Result<()> {
        anyhow::bail!("XDP traffic enforcement is unavailable")
    }

    fn delete_rule(&self, _target: Ipv4Target) -> Result<()> {
        anyhow::bail!("XDP traffic enforcement is unavailable")
    }

    fn rule_stats(&self, _target: Ipv4Target) -> Result<RuleStats> {
        anyhow::bail!("XDP traffic enforcement is unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4(src: Ipv4Addr, dst: Ipv4Addr, vlan: Option<u16>) -> Vec<u8> {
        let l2_len = if vlan.is_some() { 18 } else { 14 };
        let mut frame = vec![0u8; l2_len + 20];
        if let Some(vlan) = vlan {
            frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            frame[14..16].copy_from_slice(&(vlan & 0x0fff).to_be_bytes());
            frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        } else {
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        }
        frame[l2_len] = 0x45;
        frame[l2_len + 12..l2_len + 16].copy_from_slice(&src.octets());
        frame[l2_len + 16..l2_len + 20].copy_from_slice(&dst.octets());
        frame
    }

    #[test]
    fn passive_topology_can_ignore_local_egress_mac() {
        let tracker = TopologyTracker::new(24, Duration::from_secs(60), 1024);
        let local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut outgoing = ethernet_ipv4(
            Ipv4Addr::new(10, 10, 99, 5),
            Ipv4Addr::new(10, 10, 1, 5),
            None,
        );
        outgoing[6..12].copy_from_slice(&local_mac);
        let mut incoming = ethernet_ipv4(
            Ipv4Addr::new(10, 10, 1, 5),
            Ipv4Addr::new(10, 10, 99, 5),
            None,
        );
        incoming[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);

        let mut observer = tracker.local_observer_ignoring_source_mac(Some(local_mac));
        assert!(observer.ignores_ethernet_frame(&outgoing));
        assert!(!observer.ignores_ethernet_frame(&incoming));
        observer.observe_ipv4_source(2, incoming.len(), Ipv4Addr::new(10, 10, 1, 5));
        observer.flush();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.source_count, 1);
        assert_eq!(snapshot.groups[0].sources[0].ip, "10.10.1.5");
    }

    #[test]
    fn automatically_groups_ipv4_sources_by_prefix() {
        let tracker = TopologyTracker::new(24, Duration::from_secs(60), 1024);
        let mut observer = tracker.local_observer();
        observer.observe_ipv4_source(123, 100, Ipv4Addr::new(10, 10, 1, 4));
        observer.observe_ipv4_source(124, 200, Ipv4Addr::new(10, 10, 1, 99));
        observer.observe_ipv4_source(125, 300, Ipv4Addr::new(10, 10, 2, 7));
        observer.flush();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.group_count, 2);
        assert_eq!(snapshot.source_count, 3);
        assert!(snapshot
            .groups
            .iter()
            .any(|group| group.cidr == "10.10.1.0/24" && group.sources.len() == 2));
        assert!(snapshot
            .groups
            .iter()
            .any(|group| group.cidr == "10.10.2.0/24" && group.sources.len() == 1));
        assert_eq!(snapshot.bytes_total, 600);
    }

    #[test]
    fn source_table_is_bounded_and_overflow_is_counted() {
        let tracker = TopologyTracker::new(24, Duration::from_secs(60), 1);
        let mut observer = tracker.local_observer();
        observer.observe_ipv4_source(1, 100, Ipv4Addr::new(10, 10, 1, 1));
        observer.flush();
        observer.observe_ipv4_source(2, 200, Ipv4Addr::new(10, 10, 2, 1));
        observer.flush();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.source_count, 1);
        assert_eq!(snapshot.source_capacity, 1);
        assert!(snapshot.source_capacity_saturated);
        assert_eq!(snapshot.untracked_packets_total, 1);
        assert_eq!(snapshot.untracked_bytes_total, 200);
        assert_eq!(snapshot.packets_total, 2);
        assert_eq!(snapshot.bytes_total, 300);
    }

    #[test]
    fn topology_snapshot_caps_groups_without_losing_totals() {
        let tracker = TopologyTracker::new(32, Duration::from_secs(60), 1024);
        let mut observer = tracker.local_observer();
        for i in 0..300u32 {
            let third = ((i / 254) % 256) as u8;
            let fourth = (i % 254 + 1) as u8;
            observer.observe_ipv4_source(
                i as u64 + 1,
                100,
                Ipv4Addr::new(10, 42, third, fourth),
            );
        }
        observer.flush();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.group_count, 300);
        assert_eq!(snapshot.returned_group_count, MAX_SNAPSHOT_GROUPS);
        assert_eq!(snapshot.source_count, 300);
        assert_eq!(snapshot.packets_total, 300);
        assert_eq!(snapshot.bytes_total, 30_000);
        assert!(snapshot.view_truncated);
    }

    #[test]
    fn topology_snapshot_caps_source_rows_and_preserves_group_cardinality() {
        let tracker = TopologyTracker::new(0, Duration::from_secs(60), 4096);
        let mut observer = tracker.local_observer();
        for i in 0..2200u32 {
            let second = ((i / (254 * 254)) % 254 + 1) as u8;
            let third = ((i / 254) % 254 + 1) as u8;
            let fourth = (i % 254 + 1) as u8;
            observer.observe_ipv4_source(
                i as u64 + 1,
                64,
                Ipv4Addr::new(10, second, third, fourth),
            );
        }
        observer.flush();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.group_count, 1);
        assert_eq!(snapshot.returned_group_count, 1);
        assert_eq!(snapshot.source_count, 2200);
        assert_eq!(snapshot.returned_source_count, MAX_SNAPSHOT_SOURCES);
        assert_eq!(snapshot.groups[0].source_count, 2200);
        assert_eq!(snapshot.groups[0].sources.len(), MAX_SNAPSHOT_SOURCES);
        assert!(snapshot.groups[0].sources_truncated);
        assert!(snapshot.view_truncated);
        assert_eq!(snapshot.packets_total, 2200);
    }

    #[test]
    fn throttle_targets_are_canonicalized_and_cannot_escape_auto_group_scope() {
        let tracker = TopologyTracker::new(24, Duration::from_secs(60), 1024);
        assert_eq!(
            tracker.canonical_throttle_target("10.10.1.123/24").unwrap(),
            "10.10.1.0/24"
        );
        assert_eq!(
            tracker.canonical_throttle_target("10.10.10.10").unwrap(),
            "10.10.10.10"
        );
        assert!(tracker.canonical_throttle_target("10.10.0.0/16").is_err());
        assert!(tracker.canonical_throttle_target("10.10.1.128/25").is_err());
        assert!(tracker.canonical_throttle_target("10.10.1.1/33").is_err());
        assert!(tracker.canonical_throttle_target("not-an-ip").is_err());
    }
}
