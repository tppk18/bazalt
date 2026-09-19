use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::Result;
use tokio::sync::{broadcast, watch};

use crate::{
    api::{self, ApiState},
    capture,
    config::Config,
    flow::FlowRuntime,
    http::{self, ServiceRegistry},
    matching::{self, PatternManager},
    metrics::Metrics,
    replay,
    storage::StorageRuntime,
    topology::{ThrottleManager, TopologyTracker},
};

pub async fn run(cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    let metrics = Metrics::shared();
    metrics
        .cpu_available
        .store(cfg.cpu_available as u64, Ordering::Relaxed);
    metrics
        .cpu_budget
        .store(cfg.cpu_budget as u64, Ordering::Relaxed);
    metrics
        .tokio_workers
        .store(cfg.tokio_workers as u64, Ordering::Relaxed);
    metrics
        .flow_workers
        .store(cfg.flow_shards as u64, Ordering::Relaxed);
    metrics
        .l7_workers
        .store(cfg.l7_workers as u64, Ordering::Relaxed);
    metrics
        .matcher_workers
        .store(cfg.matcher_workers as u64, Ordering::Relaxed);
    metrics
        .replay_workers
        .store(cfg.replay_workers as u64, Ordering::Relaxed);
    metrics.touch_progress();
    let shutdown = Arc::new(AtomicBool::new(false));
    let healthy = Arc::new(AtomicBool::new(false));
    let maintenance = Arc::new(tokio::sync::RwLock::new(()));
    let auth = crate::auth::AuthManager::new(cfg.auth.clone());
    let topology = TopologyTracker::new(
        cfg.topology_group_prefix_v4,
        cfg.topology_source_ttl,
        cfg.topology_max_sources,
    );
    let throttle = ThrottleManager::new(cfg.throttle_interface.as_deref())?;
    if let Some(interface) = cfg.throttle_interface.as_deref() {
        tracing::info!(%interface, "IPv4 XDP traffic enforcement enabled");
    } else {
        tracing::info!("IPv4 traffic topology enabled; XDP enforcement disabled until BAZALT_THROTTLE_INTERFACE is set");
    }

    let (live_events, _) = broadcast::channel(2048);
    let storage = StorageRuntime::start(cfg.clone(), metrics.clone(), live_events.clone()).await?;
    let services = ServiceRegistry::new(storage.postgres.list_services().await?);
    let patterns = PatternManager::load(storage.postgres.clone(), metrics.clone()).await?;

    let matcher = matching::spawn_live_matcher(
        patterns.clone(),
        storage.metadata_tx.clone(),
        live_events.clone(),
        cfg.matcher_overlap_bytes,
        cfg.matcher_max_hits_per_pattern,
        cfg.matcher_max_hits_per_record,
        cfg.matcher_workers,
        cfg.matcher_cpus.clone(),
        cfg.l7_to_match_capacity,
        metrics.clone(),
    )?;
    tracing::info!(
        workers = matcher.worker_count(),
        "live matcher runtime started"
    );

    let l7 = http::spawn_l7(
        cfg.clone(),
        matcher.input.clone(),
        storage.segments.clone(),
        storage.metadata_tx.clone(),
        services.clone(),
        metrics.clone(),
    )?;
    tracing::info!(workers = l7.worker_count(), "L7 runtime started");

    let flow = FlowRuntime::spawn(cfg.clone(), metrics.clone(), l7.input.clone())?;
    tracing::info!(workers = flow.handle_count(), "flow runtime started");

    let (replay, replay_task) = replay::start(
        cfg.clone(),
        storage.postgres.clone(),
        storage.segments.clone(),
        storage.metadata_tx.clone(),
        metrics.clone(),
        shutdown.clone(),
        maintenance.clone(),
    );

    let state = ApiState {
        metrics: metrics.clone(),
        auth,
        metadata: storage.metadata_tx.clone(),
        maintenance,
        postgres: storage.postgres.clone(),
        clickhouse: storage.clickhouse.clone(),
        segments: storage.segments.clone(),
        patterns,
        replay,
        services: services.clone(),
        live_events,
        missing_segments_warned: Arc::new(
            parking_lot::Mutex::new(std::collections::HashSet::new()),
        ),
        healthy: healthy.clone(),
        topology: topology.clone(),
        throttle: throttle.clone(),
    };

    let (api_shutdown_tx, api_shutdown_rx) = watch::channel(false);
    let listen = cfg.listen;
    let mut api_task =
        tokio::spawn(async move { api::serve(listen, state, api_shutdown_rx).await });

    let capture = capture::spawn_capture_workers(
        cfg.clone(),
        flow.input.clone(),
        metrics.clone(),
        services.clone(),
        topology.clone(),
        shutdown.clone(),
    )?;
    tracing::info!(workers=capture.worker_count(), mode=?cfg.capture_mode, "capture runtime started");
    healthy.store(true, Ordering::Release);

    let supervise_capture = matches!(
        cfg.capture_mode,
        crate::config::CaptureMode::AfXdp | crate::config::CaptureMode::PcapLive
    );
    let mut supervisor_tick = tokio::time::interval(std::time::Duration::from_millis(250));
    // Consume the immediate first interval tick so liveness checks happen after
    // workers have had a chance to enter their receive loops.
    supervisor_tick.tick().await;
    let signal = termination_signal();
    tokio::pin!(signal);

    let mut api_already_joined = false;
    let mut api_result: Option<anyhow::Result<()>> = None;
    let mut fatal_result: Option<anyhow::Error> = None;
    loop {
        tokio::select! {
            r = &mut api_task => {
                api_already_joined = true;
                api_result = Some(match r { Ok(inner) => inner, Err(e) => Err(e.into()) });
                tracing::warn!("API server exited; shutting down data plane");
                break;
            }
            signal_result = &mut signal => {
                signal_result?;
                tracing::info!("shutdown signal received");
                break;
            }
            _ = supervisor_tick.tick() => {
                let failed = storage.critical_worker_finished()
                    || flow.critical_worker_finished()
                    || l7.critical_worker_finished()
                    || matcher.critical_worker_finished()
                    || (supervise_capture && capture.critical_worker_finished());
                if failed || metrics.progress_stale(cfg.worker_stall_timeout) {
                    let error = anyhow::anyhow!("critical data-plane worker exited unexpectedly");
                    tracing::error!(%error, "critical worker failure; shutting down");
                    fatal_result = Some(error);
                    break;
                }
            }
        }
    }

    healthy.store(false, Ordering::Release);
    // Ordered shutdown: stop ingress, drain accepted packets, stop replay/API,
    // then flush immutable segments and columnar metadata.
    shutdown.store(true, Ordering::Release);
    let _ = api_shutdown_tx.send(true);

    tokio::task::spawn_blocking(move || capture.shutdown_and_join()).await??;
    tokio::task::spawn_blocking(move || flow.shutdown_and_join()).await??;
    tokio::task::spawn_blocking(move || l7.join()).await??;
    tokio::task::spawn_blocking(move || matcher.join()).await??;

    replay_task.await.map_err(anyhow::Error::from)?;
    if !api_already_joined {
        api_task.await??;
    }

    storage.shutdown().await?;
    tracing::info!("shutdown complete");
    if let Some(result) = api_result {
        result?;
    }
    if let Some(error) = fatal_result {
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
async fn termination_signal() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = term.recv() => {},
    }
    Ok(())
}

#[cfg(not(unix))]
async fn termination_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}
