pub mod clickhouse;
pub mod postgres;
pub mod segment;

use std::{sync::{atomic::Ordering, Arc}, time::Duration};

use ahash::AHashSet;

use anyhow::Result;
use chrono::Utc;
use crossbeam_channel::{bounded, Sender};
use tokio::sync::broadcast;
use tracing::warn;

use crate::{config::Config, metrics::Metrics, model::{LiveEvent, MetadataEvent}};

#[derive(Debug)]
enum MetadataCommand {
    Event(MetadataEvent),
    Barrier(Sender<std::result::Result<(), String>>),
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
        self.tx.send(MetadataCommand::Event(event)).map_err(|_| MetadataSendError)
    }

    /// Wait until every metadata event ordered before this barrier has been
    /// durably accepted by ClickHouse. This is used by retention before a
    /// mutation so queued old rows cannot be inserted after deletion.
    pub fn barrier(&self) -> Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx.send(MetadataCommand::Barrier(reply_tx)).map_err(|_| anyhow::anyhow!("metadata writer stopped"))?;
        match reply_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!(error)),
            Err(error) => Err(anyhow::anyhow!("metadata barrier reply failed: {error}")),
        }
    }

    pub fn len(&self) -> usize { self.tx.len() }
}

pub struct StorageRuntime {
    pub metadata_tx: MetadataSink,
    pub segments: Arc<segment::SegmentStore>,
    pub postgres: postgres::PostgresStore,
    pub clickhouse: clickhouse::ClickHouseStore,
    metadata_handle: tokio::task::JoinHandle<()>,
}

impl StorageRuntime {
    pub async fn start(
        cfg: Arc<Config>,
        metrics: Arc<Metrics>,
        live_events: broadcast::Sender<LiveEvent>,
    ) -> Result<Self> {
        let postgres = postgres::PostgresStore::connect_retry(&cfg.postgres_url).await?;
        postgres.migrate().await?;
        let clickhouse = clickhouse::ClickHouseStore::new(&cfg.clickhouse_url, &cfg.clickhouse_database);
        clickhouse.init_retry().await?;

        let (command_tx, rx) = bounded::<MetadataCommand>(cfg.storage_capacity);
        let tx = MetadataSink { tx: command_tx };
        metrics.storage_queue_capacity.store(cfg.storage_capacity as u64, Ordering::Relaxed);

        let segments = segment::SegmentStore::open(
            cfg.segment_dir.clone(),
            cfg.segment_max_bytes,
            metrics.clone(),
            tx.clone(),
        )?;
        let ch = clickhouse.clone();
        let metrics2 = metrics.clone();
        let metadata_handle = tokio::spawn(async move {
            loop {
                let received = tokio::task::spawn_blocking({
                    let rx = rx.clone();
                    move || {
                        let first = rx.recv().ok()?;
                        let mut batch = Vec::with_capacity(2048);
                        let mut barrier = None;
                        match first {
                            MetadataCommand::Event(event) => batch.push(event),
                            MetadataCommand::Barrier(reply) => barrier = Some(reply),
                        }
                        if barrier.is_none() {
                            let deadline = std::time::Instant::now() + Duration::from_millis(2);
                            while batch.len() < 2048 {
                                let now = std::time::Instant::now();
                                if now >= deadline { break; }
                                match rx.recv_timeout(deadline.saturating_duration_since(now)) {
                                    Ok(MetadataCommand::Event(event)) => batch.push(event),
                                    Ok(MetadataCommand::Barrier(reply)) => { barrier = Some(reply); break; }
                                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => break,
                                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                                }
                            }
                        }
                        Some((batch, barrier))
                    }
                }).await;
                let (batch, barrier) = match received {
                    Ok(Some(v)) => v,
                    _ => break,
                };

                Metrics::observe_queue(&metrics2.storage_queue_depth, &metrics2.storage_queue_high_watermark, rx.len() as u64);
                if !batch.is_empty() {
                    let mut delay = Duration::from_millis(250);
                    loop {
                        match ch.insert_events(&batch).await {
                            Ok(()) => {
                                let mut changed_flows = AHashSet::new();
                                for event in &batch {
                                    let flow_id = match event {
                                        MetadataEvent::Flow(v) => v.flow_id,
                                        MetadataEvent::Http(v) => v.flow_id,
                                        MetadataEvent::Match(v) => v.flow_id,
                                        MetadataEvent::ContentIndex(v) => v.flow_id,
                                    };
                                    changed_flows.insert(flow_id);
                                }
                                for flow_id in changed_flows {
                                    let _ = live_events.send(LiveEvent {
                                        event: "flow_update".into(),
                                        flow_id,
                                        pattern_id: None,
                                        timestamp: Utc::now(),
                                        service: None,
                                    });
                                }
                                break;
                            }
                            Err(e) => {
                                Metrics::observe_queue(&metrics2.storage_queue_depth, &metrics2.storage_queue_high_watermark, rx.len() as u64);
                                warn!(error = %e, count = batch.len(), retry_ms = delay.as_millis(), "metadata batch insert failed; retrying");
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(5));
                            }
                        }
                    }
                }
                if let Some(reply) = barrier {
                    let _ = reply.send(Ok(()));
                }
            }
        });

        Ok(Self { metadata_tx: tx, segments, postgres, clickhouse, metadata_handle })
    }

    /// Flush segment and metadata writers. Call only after capture/L7/matcher/
    /// replay/API producers have stopped.
    pub async fn shutdown(self) -> Result<()> {
        let Self { metadata_tx, segments, postgres: _, clickhouse: _, metadata_handle } = self;
        let segment_for_join = segments.clone();
        tokio::task::spawn_blocking(move || segment_for_join.shutdown_and_join()).await??;
        drop(segments);
        drop(metadata_tx);
        metadata_handle.await.map_err(anyhow::Error::from)?;
        Ok(())
    }
}
