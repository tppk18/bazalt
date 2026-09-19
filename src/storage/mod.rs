pub mod clickhouse;
pub mod postgres;
pub mod segment;
mod spool;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use ahash::AHashSet;
use anyhow::Result;
use chrono::Utc;
use crossbeam_channel::{bounded, Sender};
use tokio::sync::broadcast;
use tracing::warn;

use crate::{
    config::Config,
    metrics::Metrics,
    model::{LiveEvent, MetadataEvent},
};

use spool::MetadataSpool;

const CONTENT_INDEX_RECOVERY_MARKER: &str = ".content-index-recovery-v2";

fn recovery_marker_valid(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|value| value == "v2\n")
        .unwrap_or(false)
}

fn write_recovery_marker(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(b"v2\n")?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug)]
enum MetadataCommand {
    Event(MetadataEvent),
    Barrier {
        projected: bool,
        reply: Sender<std::result::Result<(), String>>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataSendError;

impl std::fmt::Display for MetadataSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("metadata writer stopped")
    }
}

impl std::error::Error for MetadataSendError {}

#[derive(Clone)]
pub struct MetadataSink {
    tx: Sender<MetadataCommand>,
}

impl MetadataSink {
    pub fn send(&self, event: MetadataEvent) -> std::result::Result<(), MetadataSendError> {
        self.tx
            .send(MetadataCommand::Event(event))
            .map_err(|_| MetadataSendError)
    }

    /// Wait until every event ordered before this barrier has been projected
    /// into ClickHouse. Destructive retention uses this stronger barrier.
    pub fn barrier(&self) -> Result<()> {
        self.barrier_inner(true)
    }

    /// Wait until every event ordered before this barrier is durably persisted
    /// in the local metadata spool. Historical replay checkpoints use this so a
    /// ClickHouse outage cannot stall the capture/replay data plane.
    pub fn durable_barrier(&self) -> Result<()> {
        self.barrier_inner(false)
    }

    fn barrier_inner(&self, projected: bool) -> Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(MetadataCommand::Barrier {
                projected,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("metadata writer stopped"))?;
        match reply_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!(error)),
            Err(error) => Err(anyhow::anyhow!("metadata barrier reply failed: {error}")),
        }
    }

    pub fn len(&self) -> usize {
        self.tx.len()
    }
}

pub struct StorageRuntime {
    pub metadata_tx: MetadataSink,
    pub segments: Arc<segment::SegmentStore>,
    pub postgres: postgres::PostgresStore,
    pub clickhouse: clickhouse::ClickHouseStore,
    metadata_handle: tokio::task::JoinHandle<()>,
    projector_handle: tokio::task::JoinHandle<()>,
    projector_shutdown: Arc<AtomicBool>,
}

impl StorageRuntime {
    pub fn critical_worker_finished(&self) -> bool {
        self.metadata_handle.is_finished()
            || self.projector_handle.is_finished()
            || self.segments.writer_finished()
    }

    pub async fn start(
        cfg: Arc<Config>,
        metrics: Arc<Metrics>,
        live_events: broadcast::Sender<LiveEvent>,
    ) -> Result<Self> {
        let postgres = postgres::PostgresStore::connect_retry(&cfg.postgres_url).await?;
        postgres.migrate().await?;

        let clickhouse = clickhouse::ClickHouseStore::new(
            &cfg.clickhouse_url,
            &cfg.clickhouse_database,
            cfg.clickhouse_username.clone(),
            cfg.clickhouse_password.clone(),
            cfg.clickhouse_request_timeout,
        )?;
        // ClickHouse is a projection target, not part of capture acceptance.
        // Startup continues if it is unavailable; the projector initializes and
        // drains the local durable spool when the service recovers.
        if let Err(error) = clickhouse.init_once().await {
            warn!(%error, "ClickHouse unavailable at startup; metadata will spool locally");
        }

        let spool =
            MetadataSpool::open(cfg.metadata_spool_dir.clone(), cfg.metadata_spool_max_bytes)?;
        metrics
            .metadata_spool_capacity
            .store(cfg.metadata_spool_max_bytes, Ordering::Relaxed);
        metrics
            .metadata_spool_bytes
            .store(spool.bytes(), Ordering::Relaxed);
        let recovered_max_sequence = spool.max_sequence()?;
        let recovered_first_sequence = spool.first_sequence()?;
        let initial_projected = recovered_first_sequence
            .map(|sequence| sequence.saturating_sub(1))
            .unwrap_or(recovered_max_sequence);
        let next_projector_sequence = recovered_first_sequence
            .unwrap_or_else(|| recovered_max_sequence.saturating_add(1).max(1));
        let durable_sequence_max = Arc::new(AtomicU64::new(recovered_max_sequence));
        let projected_sequence = Arc::new(AtomicU64::new(initial_projected));
        let projector_alive = Arc::new(AtomicBool::new(true));
        let projector_shutdown = Arc::new(AtomicBool::new(false));

        let projector_spool = spool.clone();
        let projector_ch = clickhouse.clone();
        let projector_events = live_events.clone();
        let projector_sequence = projected_sequence.clone();
        let projector_durable_sequence = durable_sequence_max.clone();
        let projector_alive_flag = projector_alive.clone();
        let projector_shutdown_flag = projector_shutdown.clone();
        let projector_metrics = metrics.clone();
        let projector_handle = tokio::spawn(async move {
            let mut clickhouse_ready = false;
            let mut sequence = next_projector_sequence;
            'projector: loop {
                if projector_shutdown_flag.load(Ordering::Acquire) {
                    break;
                }
                if sequence > projector_durable_sequence.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                let path = projector_spool.path_for_sequence(sequence);
                if !path.exists() {
                    tracing::error!(sequence, path=%path.display(), "committed metadata spool sequence is missing");
                    break;
                }

                let batch = match tokio::task::spawn_blocking({
                    let spool = projector_spool.clone();
                    let path = path.clone();
                    move || spool.read(&path)
                })
                .await
                {
                    Ok(Ok(batch)) => batch,
                    Ok(Err(error)) => {
                        tracing::error!(%error, path=%path.display(), "metadata spool batch is unreadable");
                        break;
                    }
                    Err(error) => {
                        tracing::error!(%error, path=%path.display(), "metadata spool read worker failed");
                        break;
                    }
                };

                let mut delay = Duration::from_millis(250);
                loop {
                    if projector_shutdown_flag.load(Ordering::Acquire) {
                        break 'projector;
                    }
                    if !clickhouse_ready {
                        match projector_ch.init_once().await {
                            Ok(()) => clickhouse_ready = true,
                            Err(error) => {
                                warn!(%error, retry_ms=delay.as_millis(), "ClickHouse init failed; metadata remains durably spooled");
                                if projector_shutdown_flag.load(Ordering::Acquire) {
                                    break 'projector;
                                }
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(5));
                                continue;
                            }
                        }
                    }

                    match projector_ch.insert_events(&batch).await {
                        Ok(()) => break,
                        Err(error) => {
                            warn!(%error, count=batch.len(), retry_ms=delay.as_millis(), "ClickHouse projection failed; retrying from durable spool");
                            if projector_shutdown_flag.load(Ordering::Acquire) {
                                break 'projector;
                            }
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(Duration::from_secs(5));
                        }
                    }
                }

                if let Err(error) = tokio::task::spawn_blocking({
                    let spool = projector_spool.clone();
                    let path = path.clone();
                    move || spool.remove(&path)
                })
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
                {
                    tracing::error!(%error, path=%path.display(), "cannot retire projected metadata spool batch");
                    break 'projector;
                }
                projector_metrics
                    .metadata_spool_bytes
                    .store(projector_spool.bytes(), Ordering::Relaxed);
                projector_sequence.store(sequence, Ordering::Release);
                sequence = sequence.saturating_add(1);

                let mut changed_flows = AHashSet::new();
                for event in &batch {
                    let flow_id = match event {
                        MetadataEvent::Flow(value) => value.flow_id,
                        MetadataEvent::Http(value) => value.flow_id,
                        MetadataEvent::Match(value) => value.flow_id,
                        MetadataEvent::ContentIndex(value) => value.flow_id,
                    };
                    changed_flows.insert(flow_id);
                }
                for flow_id in changed_flows {
                    let _ = projector_events.send(LiveEvent {
                        event: "flow_update".into(),
                        flow_id,
                        pattern_id: None,
                        timestamp: Utc::now(),
                        service: None,
                    });
                }
            }
            projector_alive_flag.store(false, Ordering::Release);
        });

        let (command_tx, rx) = bounded::<MetadataCommand>(cfg.storage_capacity);
        let tx = MetadataSink { tx: command_tx };
        metrics
            .storage_queue_capacity
            .store(cfg.storage_capacity as u64, Ordering::Relaxed);

        let metadata_spool = spool.clone();
        let metadata_durable_sequence = durable_sequence_max.clone();
        let metadata_projected = projected_sequence.clone();
        let metadata_projector_alive = projector_alive.clone();
        let metrics2 = metrics.clone();
        let metadata_handle = tokio::spawn(async move {
            let mut next_sequence = recovered_max_sequence.saturating_add(1).max(1);
            loop {
                metrics2.touch_progress();
                let received = tokio::task::spawn_blocking({
                    let rx = rx.clone();
                    move || {
                        let first = rx.recv().ok()?;
                        let mut batch = Vec::with_capacity(2048);
                        let mut barrier = None;
                        match first {
                            MetadataCommand::Event(event) => batch.push(event),
                            MetadataCommand::Barrier { projected, reply } => {
                                barrier = Some((projected, reply));
                            }
                        }
                        if barrier.is_none() {
                            let deadline = std::time::Instant::now() + Duration::from_millis(2);
                            while batch.len() < 2048 {
                                let now = std::time::Instant::now();
                                if now >= deadline {
                                    break;
                                }
                                match rx.recv_timeout(deadline.saturating_duration_since(now)) {
                                    Ok(MetadataCommand::Event(event)) => batch.push(event),
                                    Ok(MetadataCommand::Barrier { projected, reply }) => {
                                        barrier = Some((projected, reply));
                                        break;
                                    }
                                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => break,
                                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                                }
                            }
                        }
                        Some((batch, barrier))
                    }
                })
                .await;

                let (batch, barrier) = match received {
                    Ok(Some(value)) => value,
                    _ => break,
                };
                Metrics::observe_queue(
                    &metrics2.storage_queue_depth,
                    &metrics2.storage_queue_high_watermark,
                    rx.len() as u64,
                );

                let mut durable_sequence = next_sequence.saturating_sub(1);
                if !batch.is_empty() {
                    let sequence = next_sequence;
                    let append_result = tokio::task::spawn_blocking({
                        let spool = metadata_spool.clone();
                        move || spool.append(sequence, &batch)
                    })
                    .await;
                    match append_result {
                        Ok(Ok(())) => {
                            metrics2
                                .metadata_spool_bytes
                                .store(metadata_spool.bytes(), Ordering::Relaxed);
                            metadata_durable_sequence.store(sequence, Ordering::Release);
                            durable_sequence = sequence;
                            next_sequence = next_sequence.saturating_add(1);
                        }
                        Ok(Err(error)) => {
                            tracing::error!(%error, sequence, "metadata spool append failed");
                            break;
                        }
                        Err(error) => {
                            tracing::error!(%error, sequence, "metadata spool append worker failed");
                            break;
                        }
                    }
                }

                if let Some((projected, reply)) = barrier {
                    if !projected {
                        let _ = reply.send(Ok(()));
                    } else {
                        let projected_sequence = metadata_projected.clone();
                        let projector_alive = metadata_projector_alive.clone();
                        tokio::spawn(async move {
                            loop {
                                if projected_sequence.load(Ordering::Acquire) >= durable_sequence {
                                    let _ = reply.send(Ok(()));
                                    break;
                                }
                                if !projector_alive.load(Ordering::Acquire) {
                                    let _ = reply.send(Err("metadata projector stopped".into()));
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        });
                    }
                }
            }
        });

        let recovery_segment = segment::latest_segment_path(&cfg.segment_dir)?;
        let recovery_marker = cfg.segment_dir.join(CONTENT_INDEX_RECOVERY_MARKER);
        let requires_full_index_recovery = !recovery_marker_valid(&recovery_marker);
        let segments = segment::SegmentStore::open(
            cfg.segment_dir.clone(),
            cfg.segment_max_bytes,
            cfg.segment_max_record_bytes,
            cfg.segment_store_max_bytes,
            cfg.segment_queue_capacity,
            metrics,
            tx.clone(),
        )?;

        if requires_full_index_recovery {
            // Older releases could rotate a payload segment before its entire
            // content-index batch was durably spooled.  Heal that historical
            // crash window exactly once by rebuilding every retained segment.
            // Duplicate rows are safe (content_index is replacing/deduplicated).
            let recovery_segments = segments.clone();
            let recovery_metadata = tx.clone();
            let rebuilt = tokio::task::spawn_blocking(move || {
                recovery_segments.rebuild_index(&recovery_metadata)
            })
            .await??;
            let recovery_barrier = tx.clone();
            tokio::task::spawn_blocking(move || recovery_barrier.durable_barrier()).await??;
            let marker = recovery_marker.clone();
            tokio::task::spawn_blocking(move || write_recovery_marker(&marker)).await??;
            tracing::info!(rebuilt, "completed one-time full content-index recovery");
        } else if let Some(path) = recovery_segment.filter(|path| path.exists()) {
            // With crash-consistent rotation, only the segment that was active
            // at the last crash can have bytes newer than durable index rows.
            let recovery_segments = segments.clone();
            let recovery_metadata = tx.clone();
            tokio::task::spawn_blocking(move || {
                recovery_segments.rebuild_index_path(&path, &recovery_metadata)
            })
            .await??;
        }
        let recovery_barrier = tx.clone();
        tokio::task::spawn_blocking(move || recovery_barrier.durable_barrier()).await??;

        Ok(Self {
            metadata_tx: tx,
            segments,
            postgres,
            clickhouse,
            metadata_handle,
            projector_handle,
            projector_shutdown,
        })
    }

    /// Flush segment and metadata writers. Call only after capture/L7/matcher/
    /// replay/API producers have stopped.
    pub async fn shutdown(self) -> Result<()> {
        let Self {
            metadata_tx,
            segments,
            postgres: _,
            clickhouse: _,
            metadata_handle,
            projector_handle,
            projector_shutdown,
        } = self;

        let segment_for_join = segments.clone();
        let segment_result =
            tokio::task::spawn_blocking(move || segment_for_join.shutdown_and_join())
                .await
                .map_err(anyhow::Error::from)?;
        drop(segments);

        // A clean process shutdown requires local durability, not ClickHouse
        // availability. Unprojected batches remain in the spool and are drained
        // on the next startup. This prevents SIGTERM from hanging indefinitely
        // during a ClickHouse outage.
        let barrier_sink = metadata_tx.clone();
        let barrier_result = tokio::task::spawn_blocking(move || barrier_sink.durable_barrier())
            .await
            .map_err(anyhow::Error::from)?;
        drop(metadata_tx);
        let metadata_result = metadata_handle.await.map_err(anyhow::Error::from);

        projector_shutdown.store(true, Ordering::Release);
        let projector_result = projector_handle.await.map_err(anyhow::Error::from);

        segment_result?;
        barrier_result?;
        metadata_result?;
        projector_result?;
        Ok(())
    }
}
