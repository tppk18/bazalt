use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn"));
    fmt().with_env_filter(filter).json().init();

    let cfg = bazalt::config::Config::from_env()?;
    if cfg.packet_logging {
        tracing::warn!("packet-level metadata logging is ENABLED; this is disabled by default because it is expensive and may expose payload context");
    }

    tracing::info!(
        cpu_auto = cfg.cpu_auto,
        cpu_available = cfg.cpu_available,
        cpu_budget = cfg.cpu_budget,
        tokio_workers = cfg.tokio_workers,
        flow_workers = cfg.flow_shards,
        l7_workers = cfg.l7_workers,
        matcher_workers = cfg.matcher_workers,
        replay_workers = cfg.replay_workers,
        flow_cpus = ?cfg.flow_cpus,
        l7_cpus = ?cfg.l7_cpus,
        matcher_cpus = ?cfg.matcher_cpus,
        "adaptive CPU plan"
    );

    // The control plane is mostly IO-bound. Building Tokio explicitly keeps it
    // inside the same machine-wide CPU budget as the native data-plane workers.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.tokio_workers.max(1))
        .thread_name("bazalt-ctl")
        .enable_all()
        .build()?;
    rt.block_on(bazalt::runtime::run(cfg))
}
