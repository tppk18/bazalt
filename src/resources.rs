use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ResourceSnapshot {
    pub supported: bool,
    pub process_cpu_seconds: f64,
    pub process_rss_bytes: u64,
    pub process_virtual_bytes: u64,
    pub process_threads: u64,
    pub process_uptime_seconds: f64,
    pub open_fds: u64,
    pub logical_cpus: u64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub host_memory_total_bytes: u64,
    pub host_memory_available_bytes: u64,
    pub memory_scope_used_bytes: u64,
    pub memory_scope_limit_bytes: u64,
    pub memory_scope: &'static str,
}

impl Default for ResourceSnapshot {
    fn default() -> Self {
        Self {
            supported: false,
            process_cpu_seconds: 0.0,
            process_rss_bytes: 0,
            process_virtual_bytes: 0,
            process_threads: 0,
            process_uptime_seconds: 0.0,
            open_fds: 0,
            logical_cpus: std::thread::available_parallelism()
                .map(|value| value.get() as u64)
                .unwrap_or(1),
            load_1m: 0.0,
            load_5m: 0.0,
            load_15m: 0.0,
            host_memory_total_bytes: 0,
            host_memory_available_bytes: 0,
            memory_scope_used_bytes: 0,
            memory_scope_limit_bytes: 0,
            memory_scope: "unavailable",
        }
    }
}

#[cfg(target_os = "linux")]
pub fn snapshot() -> ResourceSnapshot {
    use std::fs;

    let mut out = ResourceSnapshot {
        supported: true,
        ..ResourceSnapshot::default()
    };

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = parse_kib_line(line, "VmRSS:") {
                out.process_rss_bytes = value;
            } else if let Some(value) = parse_kib_line(line, "VmSize:") {
                out.process_virtual_bytes = value;
            } else if let Some(value) = line.strip_prefix("Threads:") {
                out.process_threads = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second > 0 {
        let ticks_per_second = ticks_per_second as f64;
        if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
            if let Some((cpu_ticks, start_ticks)) = parse_proc_stat(&stat) {
                out.process_cpu_seconds = cpu_ticks as f64 / ticks_per_second;
                if let Ok(uptime) = fs::read_to_string("/proc/uptime") {
                    if let Some(host_uptime) = uptime.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()) {
                        let started_at = start_ticks as f64 / ticks_per_second;
                        out.process_uptime_seconds = (host_uptime - started_at).max(0.0);
                    }
                }
            }
        }
    }

    out.open_fds = fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(Result::ok).count() as u64)
        .unwrap_or(0);

    if let Ok(loadavg) = fs::read_to_string("/proc/loadavg") {
        let mut fields = loadavg.split_whitespace();
        out.load_1m = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        out.load_5m = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        out.load_15m = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    }

    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(value) = parse_kib_line(line, "MemTotal:") {
                out.host_memory_total_bytes = value;
            } else if let Some(value) = parse_kib_line(line, "MemAvailable:") {
                out.host_memory_available_bytes = value;
            }
        }
    }

    let host_used = out
        .host_memory_total_bytes
        .saturating_sub(out.host_memory_available_bytes);
    out.memory_scope_used_bytes = host_used;
    out.memory_scope_limit_bytes = out.host_memory_total_bytes;
    out.memory_scope = "host";

    if let Some((current, limit)) = cgroup_memory() {
        // A cgroup with an effectively unlimited value is not useful for the UI;
        // fall back to host memory in that case. Docker/systemd finite limits are
        // normally lower than physical RAM and therefore win here.
        if limit > 0 && (out.host_memory_total_bytes == 0 || limit < out.host_memory_total_bytes) {
            out.memory_scope_used_bytes = current;
            out.memory_scope_limit_bytes = limit;
            out.memory_scope = "cgroup";
        }
    }

    out
}

#[cfg(not(target_os = "linux"))]
pub fn snapshot() -> ResourceSnapshot {
    ResourceSnapshot::default()
}

#[cfg(target_os = "linux")]
fn parse_kib_line(line: &str, prefix: &str) -> Option<u64> {
    let value = line.strip_prefix(prefix)?.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(value.saturating_mul(1024))
}

#[cfg(target_os = "linux")]
fn parse_proc_stat(stat: &str) -> Option<(u64, u64)> {
    // comm is wrapped in parentheses and can contain spaces. Split after the
    // final ')' rather than using whitespace over the whole record.
    let close = stat.rfind(')')?;
    let fields = stat.get(close + 1..)?.split_whitespace().collect::<Vec<_>>();
    // fields[0] == state (proc field 3). utime/stime are fields 14/15 and
    // starttime is field 22, hence indexes 11/12/19 after removing pid+comm.
    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    let starttime = fields.get(19)?.parse::<u64>().ok()?;
    Some((utime.saturating_add(stime), starttime))
}

#[cfg(target_os = "linux")]
fn cgroup_memory() -> Option<(u64, u64)> {
    use std::fs;
    use std::path::Path;

    let cgroups = fs::read_to_string("/proc/self/cgroup").ok()?;

    // cgroup v2: 0::/some/path
    if let Some(path) = cgroups.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        (hierarchy == "0" && controllers.is_empty()).then_some(path)
    }) {
        for base in cgroup_candidates(Path::new("/sys/fs/cgroup"), path) {
            let current = read_u64(base.join("memory.current"));
            let limit = read_limit(base.join("memory.max"));
            if let (Some(current), Some(limit)) = (current, limit) {
                return Some((current, limit));
            }
        }
    }

    // cgroup v1 memory controller.
    if let Some(path) = cgroups.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "memory")
            .then_some(path)
    }) {
        for root in [Path::new("/sys/fs/cgroup/memory"), Path::new("/sys/fs/cgroup")] {
            for base in cgroup_candidates(root, path) {
                let current = read_u64(base.join("memory.usage_in_bytes"));
                let limit = read_limit(base.join("memory.limit_in_bytes"));
                if let (Some(current), Some(limit)) = (current, limit) {
                    return Some((current, limit));
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn cgroup_candidates(root: &std::path::Path, path: &str) -> [std::path::PathBuf; 2] {
    let relative = path.trim_start_matches('/');
    [root.join(relative), root.to_path_buf()]
}

#[cfg(target_os = "linux")]
fn read_u64(path: std::path::PathBuf) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn read_limit(path: std::path::PathBuf) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw == "max" {
        None
    } else {
        raw.parse().ok()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{parse_kib_line, parse_proc_stat};

    #[test]
    fn parses_status_kib_values() {
        assert_eq!(parse_kib_line("VmRSS:\t  1234 kB", "VmRSS:"), Some(1_263_616));
    }

    #[test]
    fn parses_proc_stat_with_spaces_in_comm() {
        let mut fields = vec!["S".to_string(); 22];
        fields[11] = "100".into();
        fields[12] = "40".into();
        fields[19] = "5000".into();
        let stat = format!("123 (bazalt worker) {}", fields.join(" "));
        assert_eq!(parse_proc_stat(&stat), Some((140, 5000)));
    }
}
