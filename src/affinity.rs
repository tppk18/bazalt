use anyhow::Result;

#[derive(Debug, Clone)]
pub struct CpuPlan {
    pub allowed: Vec<usize>,
    pub budget: usize,
    pub capture_cpus: Vec<usize>,
    pub flow_cpus: Vec<usize>,
    pub l7_cpus: Vec<usize>,
    pub matcher_cpus: Vec<usize>,
    pub flow_workers: usize,
    pub l7_workers: usize,
    pub matcher_workers: usize,
    pub replay_workers: usize,
    pub tokio_workers: usize,
}

/// Return CPUs that the current process is actually allowed to run on. This
/// respects Docker/cgroup cpusets; `available_parallelism()` alone does not tell
/// us whether a configured host CPU number is valid inside the container.
#[cfg(target_os = "linux")]
pub fn allowed_cpus() -> Result<Vec<usize>> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        let rc = libc::sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut set,
        );
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut cpus = Vec::new();
        for cpu in 0..(std::mem::size_of::<libc::cpu_set_t>() * 8) {
            if libc::CPU_ISSET(cpu, &set) {
                cpus.push(cpu);
            }
        }
        if cpus.is_empty() {
            anyhow::bail!("empty CPU affinity mask");
        }
        Ok(cpus)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn allowed_cpus() -> Result<Vec<usize>> {
    Ok((0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)).collect())
}

/// Build a machine-adaptive worker layout. The plan deliberately keeps the
/// number of CPU-heavy post-capture workers within a single shared budget
/// rather than giving every stage `N CPUs`. This prevents 4+4+4 style
/// oversubscription on small A/D boxes.
///
/// `capture_hint` is only a reservation hint; capture implementation/queue
/// behavior is unchanged by this planner.
pub fn adaptive_plan(capture_hint: usize, requested_budget: Option<usize>) -> CpuPlan {
    let mut allowed = allowed_cpus().unwrap_or_else(|_| {
        let n = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
        (0..n.max(1)).collect()
    });
    if allowed.is_empty() {
        allowed.push(0);
    }

    // `sched_getaffinity()` captures cpusets, while `available_parallelism()`
    // also reflects common CPU-quota/cgroup configurations. Use the stricter
    // value so `--cpus=2` on a 32-core host does not create a 32-core plan.
    let quota_hint = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(allowed.len());
    let effective = allowed.len().min(quota_hint.max(1));
    allowed.truncate(effective);

    let budget = requested_budget
        .filter(|v| *v > 0)
        .map(|v| v.min(allowed.len()))
        .unwrap_or_else(|| default_cpu_budget(allowed.len()))
        .max(1);
    let cpu_pool = &allowed[..budget];

    // Control-plane tasks are predominantly IO-bound. One Tokio worker is
    // enough on small hosts; two is sufficient for most medium/large A/D boxes.
    let tokio_workers = if budget >= 8 { 2 } else { 1 };

    // Do not let capture reservation consume the whole machine. On AF_XDP
    // hosts this normally maps to RX queues; on libpcap fallback it collapses
    // naturally to one active worker.
    let capture_cap = (budget / 4).clamp(1, 4);
    let capture_reserve = if capture_hint == 0 { 0 } else { capture_hint.min(capture_cap) };

    let reserved = capture_reserve.saturating_add(tokio_workers);
    let post_budget = budget.saturating_sub(reserved);

    // Flow/L7/matcher keep flow-affine state and therefore remain separate
    // stages. With <5 CPUs we accept one thread of oversubscription rather than
    // losing a stage; otherwise their combined worker count fits the budget.
    let stage_budget = post_budget.max(3);
    let (flow_workers, l7_workers, matcher_workers) = distribute_stage_workers(stage_budget);

    let capture_cpus = take_wrapping(cpu_pool, 0, capture_reserve.max((capture_hint > 0) as usize));
    let stage_start = capture_reserve.min(cpu_pool.len());
    let flow_cpus = take_wrapping(cpu_pool, stage_start, flow_workers);
    let l7_cpus = take_wrapping(cpu_pool, stage_start + flow_workers, l7_workers);
    let matcher_cpus = take_wrapping(cpu_pool, stage_start + flow_workers + l7_workers, matcher_workers);

    // Replay is intentionally conservative and remains pressure-throttled.
    let replay_workers = if budget >= 24 { 3 } else if budget >= 12 { 2 } else { 1 };

    CpuPlan {
        allowed,
        budget,
        capture_cpus,
        flow_cpus,
        l7_cpus,
        matcher_cpus,
        flow_workers,
        l7_workers,
        matcher_workers,
        replay_workers,
        tokio_workers,
    }
}

fn default_cpu_budget(available: usize) -> usize {
    let available = available.max(1);
    if available <= 4 {
        available
    } else {
        // BAZALT normally shares the host with ClickHouse/PostgreSQL and the
        // kernel network stack. Leave roughly 25% of logical CPUs as headroom
        // unless the operator explicitly sets BAZALT_CPU_BUDGET.
        ((available * 3 + 3) / 4).clamp(4, available)
    }
}

fn distribute_stage_workers(total: usize) -> (usize, usize, usize) {
    let total = total.max(3);
    let weights = [30usize, 40usize, 30usize];
    let mut counts = [
        (total * weights[0] / 100).max(1),
        (total * weights[1] / 100).max(1),
        (total * weights[2] / 100).max(1),
    ];
    while counts.iter().sum::<usize>() < total {
        let mut best = 0usize;
        let mut best_deficit = isize::MIN;
        for i in 0..3 {
            let deficit = (weights[i] * total) as isize - (counts[i] * 100) as isize;
            if deficit > best_deficit {
                best = i;
                best_deficit = deficit;
            }
        }
        counts[best] += 1;
    }
    while counts.iter().sum::<usize>() > total {
        let mut best = None;
        let mut best_surplus = isize::MIN;
        for i in 0..3 {
            if counts[i] <= 1 { continue; }
            let surplus = (counts[i] * 100) as isize - (weights[i] * total) as isize;
            if surplus > best_surplus {
                best = Some(i);
                best_surplus = surplus;
            }
        }
        if let Some(i) = best { counts[i] -= 1; } else { break; }
    }
    (counts[0], counts[1], counts[2])
}

fn take_wrapping(cpus: &[usize], start: usize, count: usize) -> Vec<usize> {
    if cpus.is_empty() || count == 0 {
        return Vec::new();
    }
    (0..count).map(|i| cpus[(start + i) % cpus.len()]).collect()
}

/// Pin the current thread to `requested` when it belongs to the current cgroup
/// cpuset. Otherwise deterministically map it to one of the allowed CPUs.
/// Returns the CPU that was actually selected.
#[cfg(target_os = "linux")]
pub fn pin_current(requested: usize) -> Result<usize> {
    let allowed = allowed_cpus()?;
    let target = if allowed.contains(&requested) {
        requested
    } else {
        allowed[requested % allowed.len()]
    };
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(target, &mut set);
        let rc = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc).into());
        }
    }
    Ok(target)
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current(requested: usize) -> Result<usize> { Ok(requested) }

/// Lower scheduling priority of background CPU work (historical replay).
/// Linux applies nice values per task/thread, so this does not penalize live
/// flow/L7/matcher workers in the same process.
#[cfg(target_os = "linux")]
pub fn lower_current_priority(nice: i32) -> Result<()> {
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    if rc != 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn lower_current_priority(_nice: i32) -> Result<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_cpu_list_is_not_empty() {
        assert!(!allowed_cpus().unwrap().is_empty());
    }

    #[test]
    fn adaptive_plan_never_drops_a_processing_stage() {
        let p = adaptive_plan(1, Some(1));
        assert!(p.flow_workers >= 1);
        assert!(p.l7_workers >= 1);
        assert!(p.matcher_workers >= 1);
        assert!(p.tokio_workers >= 1);
    }

    #[test]
    fn auto_budget_leaves_database_and_os_headroom_on_larger_hosts() {
        assert_eq!(default_cpu_budget(1), 1);
        assert_eq!(default_cpu_budget(4), 4);
        assert_eq!(default_cpu_budget(8), 6);
        assert_eq!(default_cpu_budget(16), 12);
        assert_eq!(default_cpu_budget(32), 24);
    }

    #[test]
    fn stage_distribution_is_http_weighted_without_oversubscription() {
        assert_eq!(distribute_stage_workers(3), (1, 1, 1));
        assert_eq!(distribute_stage_workers(4), (1, 2, 1));
        let (f, l, m) = distribute_stage_workers(12);
        assert_eq!(f + l + m, 12);
        assert!(l >= f && l >= m);
    }
}
