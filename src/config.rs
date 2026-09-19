use std::{env, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};

#[derive(Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub username: String,
    pub password: String,
    pub session_ttl: Duration,
    pub cookie_secure: bool,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("session_ttl", &self.session_ttl)
            .field("cookie_secure", &self.cookie_secure)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    AfXdp,
    PcapLive,
    PcapFile,
    Disabled,
}

impl CaptureMode {
    pub fn parse(v: &str) -> Result<Self> {
        match v.to_ascii_lowercase().as_str() {
            "afxdp" => Ok(Self::AfXdp),
            "pcap" | "pcap-live" => Ok(Self::PcapLive),
            "file" | "pcap-file" => Ok(Self::PcapFile),
            "disabled" | "view" => Ok(Self::Disabled),
            other => anyhow::bail!("unsupported capture mode: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub capture_mode: CaptureMode,
    pub interface: String,
    pub queue_id: u32,
    pub queue_ids: Vec<u32>,
    pub cpu_auto: bool,
    pub cpu_available: usize,
    pub cpu_budget: usize,
    pub tokio_workers: usize,
    pub capture_cpus: Vec<usize>,
    pub flow_cpus: Vec<usize>,
    pub l7_cpus: Vec<usize>,
    pub matcher_cpus: Vec<usize>,
    pub pcap_file: Option<PathBuf>,
    pub bpf_filter: Option<String>,
    pub snaplen: i32,
    pub capture_batch: usize,
    pub capture_enqueue_timeout: Duration,
    pub capture_fallback_pcap: bool,
    pub early_port_filter: bool,
    pub capture_to_flow_capacity: usize,
    pub flow_to_l7_capacity: usize,
    pub l7_to_match_capacity: usize,
    pub storage_capacity: usize,
    /// Content writes have their own budget: metadata pressure and segment I/O
    /// are independent failure domains.
    pub segment_queue_capacity: usize,
    pub metadata_spool_dir: PathBuf,
    pub metadata_spool_max_bytes: u64,
    pub clickhouse_request_timeout: Duration,
    pub flow_shards: usize,
    pub l7_workers: usize,
    pub matcher_workers: usize,
    pub tcp_idle_timeout: Duration,
    /// Maximum age of a visible TCP sequence hole before BAZALT emits an
    /// explicit stream gap and resumes from buffered later bytes. Checked only
    /// while OOO state exists, so ordered traffic pays no timer/syscall cost.
    pub tcp_gap_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub live_flow_update_interval: Duration,
    /// Legacy compatibility knob. v0.4 no longer kills TCP reassembly after a
    /// byte count; bounded memory is enforced by OOO/fragment caches instead.
    pub max_flow_bytes: usize,
    /// Hard global admission limit for concurrently tracked flow states. The
    /// check runs only on creation of a previously unseen 5-tuple, so the
    /// ordered-packet hot path remains unchanged.
    pub max_active_flows: usize,
    /// Per-source-prefix flow admission budget, consulted only for new tuples.
    pub max_flows_per_source_prefix: usize,
    pub max_ooo_bytes: usize,
    pub max_ooo_segments: usize,
    pub ip_fragment_cache_bytes: usize,
    pub ip_fragment_max_datagrams: usize,
    pub ip_fragment_timeout: Duration,
    pub tunnel_decapsulation: bool,
    pub http_max_header_bytes: usize,
    pub http_max_body_bytes: usize,
    pub http_max_decode_bytes: usize,
    pub http_max_decode_ratio: usize,
    pub matcher_overlap_bytes: usize,
    pub matcher_max_hits_per_pattern: usize,
    pub matcher_max_hits_per_record: usize,
    pub segment_dir: PathBuf,
    pub segment_max_bytes: u64,
    /// Hard retained payload budget. Exhaustion is a visible fatal condition,
    /// never an implicit traffic eviction policy.
    pub segment_store_max_bytes: u64,
    pub segment_max_record_bytes: usize,
    pub raw_capture_enabled: bool,
    pub raw_segment_dir: PathBuf,
    /// Automatic IPv4 topology grouping prefix. /24 matches the usual A/D team subnet layout.
    pub topology_group_prefix_v4: u8,
    /// Remove silent source nodes from the live topology after this idle period.
    pub topology_source_ttl: Duration,
    /// Bound source-cardinality state so spoofed source floods cannot grow memory indefinitely.
    pub topology_max_sources: usize,
    /// Optional ingress interface where the XDP throttle program is attached.
    /// In AF_XDP mode this must differ from the capture interface so enforcement cannot
    /// replace or disrupt the XSK capture program.
    pub throttle_interface: Option<String>,
    pub postgres_url: String,
    pub clickhouse_url: String,
    pub clickhouse_database: String,
    pub clickhouse_username: Option<String>,
    pub clickhouse_password: Option<String>,
    pub replay_workers: usize,
    pub replay_live_queue_pause_pct: u64,
    pub replay_poll_ms: u64,
    pub worker_stall_timeout: Duration,
    pub packet_logging: bool,
    pub auth: AuthConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen = env_or("PACKMATE_LISTEN", "0.0.0.0:65000")
            .parse()
            .context("BAZALT_LISTEN must be a socket address")?;
        let capture_mode = CaptureMode::parse(&env_or("PACKMATE_CAPTURE_MODE", "afxdp"))?;
        let interface = env_or("PACKMATE_INTERFACE", "eth0");
        let pcap_file = env_os("PACKMATE_PCAP_FILE").map(PathBuf::from);
        if capture_mode == CaptureMode::PcapFile && pcap_file.is_none() {
            anyhow::bail!("BAZALT_PCAP_FILE is required in pcap-file mode");
        }

        let queue_ids = parse_queue_ids(&interface, capture_mode)?;
        let cpu_auto = parse_bool_env("PACKMATE_CPU_AUTO", true)?;
        let requested_budget = parse_optional_env::<usize>("PACKMATE_CPU_BUDGET")?;
        let capture_hint = match capture_mode {
            CaptureMode::Disabled => 0,
            CaptureMode::PcapLive | CaptureMode::PcapFile => 1,
            CaptureMode::AfXdp => queue_ids.len().max(1),
        };
        let auto_plan = crate::affinity::adaptive_plan(capture_hint, requested_budget);

        let (
            flow_shards,
            l7_workers,
            matcher_workers,
            replay_workers,
            tokio_workers,
            capture_cpus,
            flow_cpus,
            l7_cpus,
            matcher_cpus,
            cpu_budget,
        ) = if cpu_auto {
            (
                auto_plan.flow_workers,
                auto_plan.l7_workers,
                auto_plan.matcher_workers,
                auto_plan.replay_workers,
                auto_plan.tokio_workers,
                auto_plan.capture_cpus.clone(),
                auto_plan.flow_cpus.clone(),
                auto_plan.l7_cpus.clone(),
                auto_plan.matcher_cpus.clone(),
                auto_plan.budget,
            )
        } else {
            let flow = parse_env("PACKMATE_FLOW_SHARDS", default_parallelism())?;
            let l7 = parse_env("PACKMATE_L7_WORKERS", default_parallelism())?;
            let matcher = parse_env("PACKMATE_MATCHER_WORKERS", default_parallelism())?;
            let replay = parse_env("PACKMATE_REPLAY_WORKERS", 1usize)?;
            if flow == 0 || l7 == 0 || matcher == 0 || replay == 0 {
                anyhow::bail!("manual worker counts must be > 0");
            }
            (
                flow,
                l7,
                matcher,
                replay,
                parse_env("PACKMATE_TOKIO_WORKERS", auto_plan.tokio_workers)?,
                parse_usize_list("PACKMATE_CAPTURE_CPUS")?,
                parse_usize_list("PACKMATE_FLOW_CPUS")?,
                parse_usize_list("PACKMATE_L7_CPUS")?,
                parse_usize_list("PACKMATE_MATCHER_CPUS")?,
                requested_budget
                    .filter(|v| *v > 0)
                    .map(|v| v.min(auto_plan.allowed.len()))
                    .unwrap_or(auto_plan.budget),
            )
        };
        if tokio_workers == 0 {
            anyhow::bail!("BAZALT_TOKIO_WORKERS must be > 0");
        }

        let auth_enabled = parse_bool_env("PACKMATE_AUTH_ENABLED", true)?;
        let auth_username = env_value("PACKMATE_AUTH_USERNAME").unwrap_or_default();
        let auth_password = env_value("PACKMATE_AUTH_PASSWORD").unwrap_or_default();
        if auth_enabled && (auth_username.is_empty() || auth_password.is_empty()) {
            anyhow::bail!("BAZALT_AUTH_USERNAME and BAZALT_AUTH_PASSWORD are required when BAZALT_AUTH_ENABLED=true");
        }
        if auth_enabled && auth_username.contains(':') {
            anyhow::bail!("BAZALT_AUTH_USERNAME must not contain ':' because HTTP Basic uses ':' as the username/password separator");
        }
        let auth = AuthConfig {
            enabled: auth_enabled,
            username: auth_username,
            password: auth_password,
            session_ttl: Duration::from_secs(parse_env("PACKMATE_AUTH_SESSION_SECS", 43_200u64)?),
            cookie_secure: parse_bool_env("PACKMATE_AUTH_COOKIE_SECURE", false)?,
        };

        let max_active_flows = parse_env("PACKMATE_MAX_ACTIVE_FLOWS", 262_144usize)?;
        if max_active_flows == 0 {
            anyhow::bail!("BAZALT_MAX_ACTIVE_FLOWS must be > 0");
        }
        let max_flows_per_source_prefix =
            parse_env("PACKMATE_MAX_FLOWS_PER_SOURCE_PREFIX", 4096usize)?;
        if max_flows_per_source_prefix == 0 {
            anyhow::bail!("BAZALT_MAX_FLOWS_PER_SOURCE_PREFIX must be > 0");
        }
        let matcher_max_hits_per_pattern =
            parse_env("PACKMATE_MATCH_MAX_HITS_PER_PATTERN", 128usize)?;
        let matcher_max_hits_per_record =
            parse_env("PACKMATE_MATCH_MAX_HITS_PER_RECORD", 1024usize)?;
        if matcher_max_hits_per_pattern == 0 || matcher_max_hits_per_record == 0 {
            anyhow::bail!("BAZALT_MATCH_MAX_HITS_PER_PATTERN and BAZALT_MATCH_MAX_HITS_PER_RECORD must be > 0");
        }
        let http_max_decode_ratio = parse_env("PACKMATE_HTTP_MAX_DECODE_RATIO", 32usize)?;
        if http_max_decode_ratio == 0 {
            anyhow::bail!("BAZALT_HTTP_MAX_DECODE_RATIO must be > 0");
        }
        let segment_max_bytes = parse_env("PACKMATE_SEGMENT_MAX_BYTES", 512 * 1024 * 1024u64)?;
        let segment_max_record_bytes = match env_value("PACKMATE_SEGMENT_MAX_RECORD_BYTES") {
            Some(value) => value
                .parse::<usize>()
                .map_err(|e| anyhow::anyhow!("invalid BAZALT_SEGMENT_MAX_RECORD_BYTES: {e}"))?,
            None => (256 * 1024 * 1024usize).min(segment_max_bytes.min(usize::MAX as u64) as usize),
        };
        if segment_max_record_bytes == 0 {
            anyhow::bail!("BAZALT_SEGMENT_MAX_RECORD_BYTES must be > 0");
        }
        if segment_max_record_bytes as u64 > segment_max_bytes {
            anyhow::bail!(
                "BAZALT_SEGMENT_MAX_RECORD_BYTES must not exceed BAZALT_SEGMENT_MAX_BYTES"
            );
        }
        let segment_store_max_bytes = parse_env(
            "PACKMATE_SEGMENT_STORE_MAX_BYTES",
            50 * 1024 * 1024 * 1024u64,
        )?;
        if segment_store_max_bytes < segment_max_bytes {
            anyhow::bail!(
                "BAZALT_SEGMENT_STORE_MAX_BYTES must be at least BAZALT_SEGMENT_MAX_BYTES"
            );
        }
        let topology_group_prefix_v4 = parse_env("PACKMATE_TOPOLOGY_GROUP_PREFIX_V4", 24u8)?;
        if topology_group_prefix_v4 > 32 {
            anyhow::bail!("BAZALT_TOPOLOGY_GROUP_PREFIX_V4 must be between 0 and 32");
        }
        let topology_source_ttl_secs = parse_env("PACKMATE_TOPOLOGY_SOURCE_TTL_SECS", 300u64)?;
        if topology_source_ttl_secs == 0 {
            anyhow::bail!("BAZALT_TOPOLOGY_SOURCE_TTL_SECS must be greater than zero");
        }
        let topology_max_sources = parse_env("PACKMATE_TOPOLOGY_MAX_SOURCES", 65_536usize)?;
        if topology_max_sources == 0 {
            anyhow::bail!("BAZALT_TOPOLOGY_MAX_SOURCES must be greater than zero");
        }
        let throttle_interface = env_value("PACKMATE_THROTTLE_INTERFACE");
        if capture_mode == CaptureMode::AfXdp
            && throttle_interface.as_deref() == Some(interface.as_str())
        {
            anyhow::bail!(
                "BAZALT_THROTTLE_INTERFACE must differ from BAZALT_INTERFACE in AF_XDP mode; attach enforcement at the real ingress/forwarding point, not the capture XSK interface"
            );
        }

        Ok(Self {
            listen,
            capture_mode,
            interface,
            queue_id: parse_env("PACKMATE_QUEUE_ID", 0)?,
            queue_ids,
            cpu_auto,
            cpu_available: auto_plan.allowed.len(),
            cpu_budget,
            tokio_workers,
            capture_cpus,
            flow_cpus,
            l7_cpus,
            matcher_cpus,
            pcap_file,
            bpf_filter: env_value("PACKMATE_BPF_FILTER").filter(|s| !s.trim().is_empty()),
            snaplen: parse_env("PACKMATE_SNAPLEN", 65535)?,
            capture_batch: parse_env("PACKMATE_CAPTURE_BATCH", 64)?,
            // A zero timeout preserves the historical drop-immediately behavior.
            // The default absorbs scheduler jitter/microbursts before declaring
            // the capture->flow edge overloaded. Sustained overload still drops
            // explicitly and increments capture_drops.
            capture_enqueue_timeout: Duration::from_micros(parse_env(
                "PACKMATE_CAPTURE_ENQUEUE_TIMEOUT_US",
                250u64,
            )?),
            capture_fallback_pcap: parse_bool_env("PACKMATE_CAPTURE_FALLBACK_PCAP", true)?,
            // Keep the service-port allow-list authoritative in userspace by default.
            // Early libpcap BPF is optional because a backend/link-layer mismatch can
            // otherwise make capture look completely dead (zero frames, zero parse errors).
            early_port_filter: parse_bool_env("PACKMATE_EARLY_PORT_FILTER", false)?,
            capture_to_flow_capacity: parse_env("PACKMATE_CAPTURE_QUEUE", 32768)?,
            flow_to_l7_capacity: parse_env("PACKMATE_FLOW_QUEUE", 16384)?,
            l7_to_match_capacity: parse_env("PACKMATE_MATCH_QUEUE", 16384)?,
            storage_capacity: parse_env("PACKMATE_STORAGE_QUEUE", 16384)?,
            segment_queue_capacity: parse_env("PACKMATE_SEGMENT_QUEUE", 16384)?,
            metadata_spool_dir: PathBuf::from(env_or(
                "PACKMATE_METADATA_SPOOL_DIR",
                "/data/metadata-spool",
            )),
            metadata_spool_max_bytes: parse_env(
                "PACKMATE_METADATA_SPOOL_MAX_BYTES",
                2 * 1024 * 1024 * 1024u64,
            )?,
            clickhouse_request_timeout: Duration::from_millis(parse_env(
                "PACKMATE_CLICKHOUSE_TIMEOUT_MS",
                5000u64,
            )?),
            flow_shards,
            l7_workers,
            matcher_workers,
            tcp_idle_timeout: Duration::from_secs(parse_env("PACKMATE_TCP_IDLE_SECS", 45)?),
            tcp_gap_timeout: Duration::from_millis(parse_env(
                "PACKMATE_TCP_GAP_TIMEOUT_MS",
                1000u64,
            )?),
            udp_idle_timeout: Duration::from_secs(parse_env("PACKMATE_UDP_IDLE_SECS", 15)?),
            live_flow_update_interval: Duration::from_millis(parse_env(
                "PACKMATE_LIVE_FLOW_UPDATE_MS",
                1000u64,
            )?),
            // Kept for environment compatibility; v0.4 does not stop sequence
            // tracking at this threshold because that silently loses long flows.
            max_flow_bytes: parse_env("PACKMATE_MAX_FLOW_BYTES", 0usize)?,
            max_active_flows,
            max_flows_per_source_prefix,
            max_ooo_bytes: parse_env("PACKMATE_MAX_OOO_BYTES", 4 * 1024 * 1024)?,
            max_ooo_segments: parse_env("PACKMATE_MAX_OOO_SEGMENTS", 8192usize)?,
            ip_fragment_cache_bytes: parse_env(
                "PACKMATE_IP_FRAGMENT_CACHE_BYTES",
                16 * 1024 * 1024,
            )?,
            ip_fragment_max_datagrams: parse_env("PACKMATE_IP_FRAGMENT_MAX_DATAGRAMS", 4096usize)?,
            ip_fragment_timeout: Duration::from_secs(parse_env(
                "PACKMATE_IP_FRAGMENT_TIMEOUT_SECS",
                30u64,
            )?),
            tunnel_decapsulation: parse_bool_env("PACKMATE_TUNNEL_DECAPSULATION", true)?,
            http_max_header_bytes: parse_env("PACKMATE_HTTP_MAX_HEADER_BYTES", 128 * 1024)?,
            http_max_body_bytes: parse_env("PACKMATE_HTTP_MAX_BODY_BYTES", 64 * 1024 * 1024)?,
            http_max_decode_bytes: parse_env("PACKMATE_HTTP_MAX_DECODE_BYTES", 16 * 1024 * 1024)?,
            http_max_decode_ratio,
            matcher_overlap_bytes: parse_env("PACKMATE_MATCH_OVERLAP_BYTES", 8192)?,
            matcher_max_hits_per_pattern,
            matcher_max_hits_per_record,
            segment_dir: PathBuf::from(env_or("PACKMATE_SEGMENT_DIR", "/data/segments")),
            segment_max_bytes,
            segment_store_max_bytes,
            segment_max_record_bytes,
            raw_capture_enabled: parse_bool_env("PACKMATE_RAW_CAPTURE", false)?,
            raw_segment_dir: PathBuf::from(env_or("PACKMATE_RAW_SEGMENT_DIR", "/data/raw")),
            topology_group_prefix_v4,
            topology_source_ttl: Duration::from_secs(topology_source_ttl_secs),
            topology_max_sources,
            throttle_interface,
            postgres_url: env_or(
                "PACKMATE_POSTGRES_URL",
                "postgres://packmate:packmate@127.0.0.1:65001/packmate",
            ),
            clickhouse_url: env_or("PACKMATE_CLICKHOUSE_URL", "http://127.0.0.1:65002"),
            clickhouse_database: env_or("PACKMATE_CLICKHOUSE_DATABASE", "packmate"),
            clickhouse_username: env_value("PACKMATE_CLICKHOUSE_USERNAME"),
            clickhouse_password: env_value("PACKMATE_CLICKHOUSE_PASSWORD"),
            replay_workers,
            replay_live_queue_pause_pct: parse_env("PACKMATE_REPLAY_PAUSE_PCT", 70)?,
            replay_poll_ms: parse_env("PACKMATE_REPLAY_POLL_MS", 100)?,
            worker_stall_timeout: Duration::from_secs(parse_env(
                "PACKMATE_WORKER_STALL_SECS",
                30u64,
            )?),
            // Packet/payload logging is deliberately opt-in. Metadata logging is controlled by RUST_LOG.
            packet_logging: parse_bool_env("PACKMATE_PACKET_LOGGING", false)?,
            auth,
        })
    }
}

fn bazalt_key(legacy_key: &str) -> String {
    match legacy_key.strip_prefix("PACKMATE_") {
        Some(suffix) => format!("BAZALT_{suffix}"),
        None => legacy_key.to_owned(),
    }
}

fn env_value(legacy_key: &str) -> Option<String> {
    let primary = bazalt_key(legacy_key);
    env::var(primary)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var(legacy_key)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn env_os(legacy_key: &str) -> Option<std::ffi::OsString> {
    let primary = bazalt_key(legacy_key);
    env::var_os(primary)
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os(legacy_key).filter(|value| !value.is_empty()))
}

fn env_or(legacy_key: &str, default: &str) -> String {
    env_value(legacy_key).unwrap_or_else(|| default.to_owned())
}

fn parse_env<T>(legacy_key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_value(legacy_key) {
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {}: {e}", bazalt_key(legacy_key))),
        None => Ok(default),
    }
}

fn parse_optional_env<T>(legacy_key: &str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_value(legacy_key) {
        Some(v) => Ok(Some(v.parse().map_err(|e| {
            anyhow::anyhow!("invalid {}: {e}", bazalt_key(legacy_key))
        })?)),
        None => Ok(None),
    }
}

fn parse_queue_ids(interface: &str, capture_mode: CaptureMode) -> Result<Vec<u32>> {
    if let Some(raw) = env_value("PACKMATE_QUEUE_IDS") {
        let mut ids = Vec::new();
        for part in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            ids.push(
                part.parse()
                    .map_err(|e| anyhow::anyhow!("invalid BAZALT_QUEUE_IDS value {part}: {e}"))?,
            );
        }
        ids.sort_unstable();
        ids.dedup();
        if !ids.is_empty() {
            return Ok(ids);
        }
    }

    let fallback = parse_env("PACKMATE_QUEUE_ID", 0)?;
    if capture_mode != CaptureMode::AfXdp {
        return Ok(vec![fallback]);
    }

    // AF_XDP sockets are bound to a single RX queue. Defaulting silently to
    // queue 0 on a multi-queue NIC loses every packet steered to the other
    // queues. When the operator did not provide BAZALT_QUEUE_IDS, enumerate
    // the interface RX queues from sysfs and cover all of them.
    #[cfg(target_os = "linux")]
    {
        let queue_root = PathBuf::from("/sys/class/net")
            .join(interface)
            .join("queues");
        if let Ok(entries) = fs::read_dir(&queue_root) {
            let mut ids = entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|name| name.strip_prefix("rx-").and_then(|v| v.parse::<u32>().ok()))
                .collect::<Vec<_>>();
            ids.sort_unstable();
            ids.dedup();
            if !ids.is_empty() {
                tracing::info!(interface, queues=?ids, "auto-detected AF_XDP RX queues");
                return Ok(ids);
            }
        }
    }

    tracing::warn!(
        interface,
        queue_id = fallback,
        "could not auto-detect AF_XDP RX queues; using one queue only"
    );
    Ok(vec![fallback])
}

fn parse_usize_list(legacy_key: &str) -> Result<Vec<usize>> {
    let Some(raw) = env_value(legacy_key) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        out.push(part.parse().map_err(|e| {
            anyhow::anyhow!("invalid {} value {part}: {e}", bazalt_key(legacy_key))
        })?);
    }
    Ok(out)
}

fn parse_bool_env(legacy_key: &str, default: bool) -> Result<bool> {
    let Some(value) = env_value(legacy_key) else {
        return Ok(default);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!(
            "invalid {} boolean value {value:?}; expected true/false, 1/0, yes/no, or on/off",
            bazalt_key(legacy_key)
        ),
    }
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2)
        / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capture_modes() {
        assert_eq!(CaptureMode::parse("afxdp").unwrap(), CaptureMode::AfXdp);
        assert_eq!(
            CaptureMode::parse("pcap-file").unwrap(),
            CaptureMode::PcapFile
        );
        assert!(CaptureMode::parse("bogus").is_err());
    }
}
