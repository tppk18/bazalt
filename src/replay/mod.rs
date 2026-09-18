use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender};
use tokio::sync::mpsc;
use tracing::info;

use crate::{
    config::Config,
    matching::ReplayScanner,
    metrics::Metrics,
    model::{MetadataEvent, PatternRevision, ReplayJob},
    storage::{postgres::PostgresStore, segment::SegmentStore},
};

#[derive(Clone)]
pub struct ReplayHandle {
    tx: mpsc::Sender<PatternRevision>,
    postgres: PostgresStore,
}

impl ReplayHandle {
    pub async fn enqueue(&self, pattern: PatternRevision) -> Result<()> {
        self.tx
            .send(pattern)
            .await
            .map_err(|_| anyhow::anyhow!("replay scheduler stopped"))
    }

    pub async fn jobs(&self) -> Result<Vec<ReplayJob>> {
        self.postgres.list_replay_jobs(100).await
    }
}

#[derive(Debug)]
struct ReplayProgress {
    segments_done: i64,
    bytes_processed: i64,
    matches_found: i64,
}

enum ReplayWork {
    Record(crate::model::ContentRecord),
    Barrier(Sender<()>),
}

enum ReplayHit {
    Match(crate::model::MatchRecord),
    Barrier(Sender<i64>),
}

pub fn start(
    cfg: Arc<Config>,
    postgres: PostgresStore,
    segments: Arc<SegmentStore>,
    metadata_tx: crate::storage::MetadataSink,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    maintenance: Arc<tokio::sync::RwLock<()>>,
) -> (ReplayHandle, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<PatternRevision>(256);
    let handle = ReplayHandle {
        tx,
        postgres: postgres.clone(),
    };

    let task = tokio::spawn(async move {
        // Recover persistent queued/running jobs before accepting newly coalesced
        // backfills. Each job stores exact pattern revisions and a segment cutoff.
        match postgres.list_replay_jobs(1000).await {
            Ok(mut jobs) => {
                jobs.sort_by_key(|j| j.created_at);
                for job in jobs
                    .into_iter()
                    .filter(|j| j.status == "queued" || j.status == "running")
                {
                    if shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let _maintenance_guard = maintenance.read().await;
                    match recover_job_patterns(&postgres, &job).await {
                        Ok(patterns) if !patterns.is_empty() => {
                            match replay_paths_for_job(&segments, &job) {
                                Ok(paths) => {
                                    if let Err(e) = execute_job(
                                        cfg.clone(),
                                        postgres.clone(),
                                        segments.clone(),
                                        metadata_tx.clone(),
                                        metrics.clone(),
                                        shutdown.clone(),
                                        job.clone(),
                                        patterns,
                                        paths,
                                    )
                                    .await
                                    {
                                        tracing::error!(job_id=%job.id, error=%e, "recovered replay failed");
                                    }
                                }
                                Err(e) => {
                                    let msg = e.to_string();
                                    let _ = postgres
                                        .update_replay_progress(
                                            job.id,
                                            "failed",
                                            job.segments_done,
                                            job.bytes_processed,
                                            job.matches_found,
                                            Some(&msg),
                                        )
                                        .await;
                                }
                            }
                        }
                        Ok(_) => {
                            let msg = "replay job has no resolvable pattern revisions";
                            let _ = postgres
                                .update_replay_progress(
                                    job.id,
                                    "failed",
                                    job.segments_done,
                                    job.bytes_processed,
                                    job.matches_found,
                                    Some(msg),
                                )
                                .await;
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            let _ = postgres
                                .update_replay_progress(
                                    job.id,
                                    "failed",
                                    job.segments_done,
                                    job.bytes_processed,
                                    job.matches_found,
                                    Some(&msg),
                                )
                                .await;
                        }
                    }
                }
            }
            Err(e) => tracing::error!(error=%e, "cannot enumerate persistent replay jobs"),
        }

        while !shutdown.load(Ordering::Acquire) {
            let first = tokio::select! {
                value = rx.recv() => match value { Some(v) => v, None => break },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if shutdown.load(Ordering::Acquire) { break; }
                    continue;
                }
            };
            // Small coalescing window: patterns created together are scanned in
            // one sequential pass over historical storage.
            let mut patterns = vec![first];
            let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(p)) => patterns.push(p),
                    _ => break,
                }
            }
            patterns.retain(|p| p.enabled);
            if patterns.is_empty() {
                continue;
            }

            // Retention takes the write side of this gate. Holding a read guard
            // across snapshot + replay prevents cleanup from deleting immutable
            // segment files while a historical scan is using them.
            let _maintenance_guard = maintenance.read().await;
            let segments_for_snapshot = segments.clone();
            let paths = match tokio::task::spawn_blocking(move || {
                segments_for_snapshot.snapshot_for_replay()
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::error!(error=%e, "cannot seal replay snapshot");
                    continue;
                }
                Err(e) => {
                    tracing::error!(error=%e, "replay snapshot worker failed");
                    continue;
                }
            };
            let job = match postgres.create_replay_job(&patterns, &paths).await {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(error=%e, "cannot create replay job");
                    continue;
                }
            };
            if let Err(e) = execute_job(
                cfg.clone(),
                postgres.clone(),
                segments.clone(),
                metadata_tx.clone(),
                metrics.clone(),
                shutdown.clone(),
                job.clone(),
                patterns,
                paths,
            )
            .await
            {
                tracing::error!(job_id=%job.id, error=%e, "historical replay execution failed");
            }
        }
    });
    (handle, task)
}

async fn recover_job_patterns(
    postgres: &PostgresStore,
    job: &ReplayJob,
) -> Result<Vec<PatternRevision>> {
    let mut out = Vec::new();
    if !job.pattern_revisions.is_empty() {
        for p in &job.pattern_revisions {
            let revision = postgres
                .pattern_revision(p.id, p.revision)
                .await?
                .with_context(|| format!("missing pattern {} revision {}", p.id, p.revision))?;
            out.push(revision);
        }
    } else {
        // Backward-compatible recovery for jobs written before revision pinning.
        for id in &job.pattern_ids {
            if let Some(p) = postgres.latest_pattern(*id).await? {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn replay_paths_for_job(segments: &SegmentStore, job: &ReplayJob) -> Result<Vec<PathBuf>> {
    let mut paths = if !job.segment_paths.is_empty() {
        job.segment_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>()
    } else {
        // Compatibility with jobs created by early builds that only persisted a
        // segment cutoff/count. New jobs always persist the exact immutable set.
        let mut legacy = segments.segment_paths()?;
        if let Some(cutoff) = &job.segment_cutoff {
            legacy.retain(|p| p.to_string_lossy().as_ref() <= cutoff.as_str());
        } else if job.segments_total >= 0 {
            legacy.truncate(job.segments_total as usize);
        }
        legacy
    };
    let missing = paths.iter().filter(|p| !p.exists()).count();
    if missing != 0 || paths.len() < job.segments_total as usize {
        anyhow::bail!(
            "historical segment set is incomplete: expected {}, found {}, missing {} (retention may have deleted data)",
            job.segments_total,
            paths.len(),
            missing
        );
    }
    paths.truncate(job.segments_total.max(0) as usize);
    let done = job.segments_done.max(0) as usize;
    Ok(paths.into_iter().skip(done).collect())
}

async fn execute_job(
    cfg: Arc<Config>,
    postgres: PostgresStore,
    segments: Arc<SegmentStore>,
    metadata_tx: crate::storage::MetadataSink,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    job: ReplayJob,
    patterns: Vec<PatternRevision>,
    paths: Vec<PathBuf>,
) -> Result<()> {
    postgres
        .update_replay_progress(
            job.id,
            "running",
            job.segments_done,
            job.bytes_processed,
            job.matches_found,
            None,
        )
        .await?;
    metrics.replay_active.fetch_add(1, Ordering::Relaxed);
    info!(job_id=%job.id, patterns=patterns.len(), remaining_segments=paths.len(), "historical replay started");

    let (progress_tx, mut progress_rx) = mpsc::channel::<ReplayProgress>(32);
    let cfg2 = cfg.clone();
    let segments2 = segments.clone();
    let metadata2 = metadata_tx.clone();
    let metrics2 = metrics.clone();
    let initial_segments = job.segments_done;
    let initial_bytes = job.bytes_processed;
    let initial_matches = job.matches_found;
    let shutdown_worker = shutdown.clone();
    let task = tokio::task::spawn_blocking(move || {
        run_replay(
            cfg2,
            segments2,
            paths,
            patterns,
            metadata2,
            metrics2,
            shutdown_worker,
            progress_tx,
            initial_segments,
            initial_bytes,
            initial_matches,
        )
    });

    let mut last = ReplayProgress {
        segments_done: job.segments_done,
        bytes_processed: job.bytes_processed,
        matches_found: job.matches_found,
    };
    tokio::pin!(task);
    let result = loop {
        tokio::select! {
            p = progress_rx.recv() => {
                if let Some(p) = p {
                    last = p;
                    let _ = postgres.update_replay_progress(
                        job.id, "running", last.segments_done, last.bytes_processed, last.matches_found, None
                    ).await;
                }
            }
            r = &mut task => break r,
        }
    };

    // The worker sends a final progress record immediately before returning;
    // drain it in case task completion won the select race.
    while let Ok(p) = progress_rx.try_recv() {
        last = p;
    }

    metrics.replay_active.fetch_sub(1, Ordering::Relaxed);
    if shutdown.load(Ordering::Acquire) {
        postgres
            .update_replay_progress(
                job.id,
                "queued",
                last.segments_done,
                last.bytes_processed,
                last.matches_found,
                None,
            )
            .await?;
        info!(job_id=%job.id, "historical replay paused for shutdown");
        return Ok(());
    }
    match result {
        Ok(Ok(())) => {
            postgres
                .update_replay_progress(
                    job.id,
                    "completed",
                    last.segments_done,
                    last.bytes_processed,
                    last.matches_found,
                    None,
                )
                .await?;
            info!(job_id=%job.id, matches=last.matches_found, "historical replay completed");
            Ok(())
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            postgres
                .update_replay_progress(
                    job.id,
                    "failed",
                    last.segments_done,
                    last.bytes_processed,
                    last.matches_found,
                    Some(&msg),
                )
                .await?;
            Err(e)
        }
        Err(e) => {
            let msg = e.to_string();
            postgres
                .update_replay_progress(
                    job.id,
                    "failed",
                    last.segments_done,
                    last.bytes_processed,
                    last.matches_found,
                    Some(&msg),
                )
                .await?;
            Err(e.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_replay(
    cfg: Arc<Config>,
    segments: Arc<SegmentStore>,
    paths: Vec<PathBuf>,
    patterns: Vec<PatternRevision>,
    metadata_tx: crate::storage::MetadataSink,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    progress_tx: mpsc::Sender<ReplayProgress>,
    initial_segments_done: i64,
    initial_bytes_processed: i64,
    initial_matches_found: i64,
) -> Result<()> {
    let _ = crate::affinity::lower_current_priority(10);
    let worker_count = cfg.replay_workers.max(1);
    let mut txs = Vec::with_capacity(worker_count);
    let (hit_tx, hit_rx) = bounded::<ReplayHit>(16_384);
    let mut workers = Vec::with_capacity(worker_count);

    for i in 0..worker_count {
        let (tx, rx) = bounded::<ReplayWork>(4096);
        txs.push(tx);
        let patterns2 = patterns.clone();
        let hit_tx2 = hit_tx.clone();
        let overlap = cfg.matcher_overlap_bytes;
        let max_hits_per_pattern = cfg.matcher_max_hits_per_pattern;
        let max_hits_per_record = cfg.matcher_max_hits_per_record;
        let worker_metrics = metrics.clone();
        workers.push(std::thread::Builder::new().name(format!("replay-match-{i}")).spawn(move || -> Result<()> {
            if let Err(e) = crate::affinity::lower_current_priority(10) {
                tracing::debug!(worker_id=i, error=%e, "cannot lower replay worker priority");
            }
            let mut scanner = ReplayScanner::new(
                &patterns2,
                overlap,
                max_hits_per_pattern,
                max_hits_per_record,
            )?;
            while let Ok(work) = rx.recv() {
                match work {
                    ReplayWork::Record(record) => {
                        let scan = scanner.scan_record(&record);
                        if scan.limited {
                            worker_metrics.matcher_match_limit_events.fetch_add(1, Ordering::Relaxed);
                        }
                        for hit in scan.hits {
                            if hit_tx2.send(ReplayHit::Match(hit)).is_err() { return Ok(()); }
                        }
                    }
                    ReplayWork::Barrier(reply) => {
                        let _ = reply.send(());
                    }
                }
            }
            Ok(())
        })?);
    }

    let meta2 = metadata_tx.clone();
    let metrics2 = metrics.clone();
    let hit_collector = std::thread::Builder::new()
        .name("replay-hit-writer".into())
        .spawn(move || {
            let _ = crate::affinity::lower_current_priority(10);
            let mut matches = 0i64;
            while let Ok(item) = hit_rx.recv() {
                match item {
                    ReplayHit::Match(hit) => {
                        matches += 1;
                        metrics2.replay_matches.fetch_add(1, Ordering::Relaxed);
                        // Bounded metadata storage intentionally backpressures replay; live
                        // capture always has priority because replay also watches live pressure.
                        if meta2.send(MetadataEvent::Match(hit)).is_err() {
                            break;
                        }
                    }
                    ReplayHit::Barrier(reply) => {
                        let _ = reply.send(matches);
                    }
                }
            }
            matches
        })?;

    let mut bytes_processed = initial_bytes_processed;
    let mut segments_done = initial_segments_done;
    for path in paths {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        while metrics.live_pressure_pct() >= cfg.replay_live_queue_pause_pct
            && !shutdown.load(Ordering::Acquire)
        {
            std::thread::sleep(Duration::from_millis(cfg.replay_poll_ms));
        }
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let file_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as i64;
        let scan_result = segments.scan_path(&path, |record| {
            if shutdown.load(Ordering::Acquire) {
                anyhow::bail!("shutdown");
            }
            while metrics.live_pressure_pct() >= cfg.replay_live_queue_pause_pct
                && !shutdown.load(Ordering::Acquire)
            {
                std::thread::sleep(Duration::from_millis(cfg.replay_poll_ms));
            }
            if shutdown.load(Ordering::Acquire) {
                anyhow::bail!("shutdown");
            }
            let idx = (record.flow_id.as_u128() as usize) % txs.len();
            txs[idx]
                .send(ReplayWork::Record(record))
                .map_err(|_| anyhow::anyhow!("replay worker stopped"))?;
            Ok(())
        });
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        scan_result?;

        // A replay checkpoint is a commit point, not merely a scan point. Wait
        // until every worker has consumed all records from this segment, then
        // until the hit collector has enqueued all resulting Match events, and
        // finally until the metadata writer confirms those events in ClickHouse.
        let (worker_ack_tx, worker_ack_rx) = bounded::<()>(worker_count);
        for tx in &txs {
            tx.send(ReplayWork::Barrier(worker_ack_tx.clone()))
                .map_err(|_| anyhow::anyhow!("replay worker stopped before segment barrier"))?;
        }
        drop(worker_ack_tx);
        for _ in 0..worker_count {
            worker_ack_rx
                .recv()
                .map_err(|_| anyhow::anyhow!("replay worker barrier failed"))?;
        }

        let (hit_ack_tx, hit_ack_rx) = bounded::<i64>(1);
        hit_tx
            .send(ReplayHit::Barrier(hit_ack_tx))
            .map_err(|_| anyhow::anyhow!("replay hit collector stopped before segment barrier"))?;
        let matches_so_far = hit_ack_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("replay hit collector barrier failed"))?;
        metadata_tx.durable_barrier()?;

        bytes_processed += file_bytes;
        segments_done += 1;
        metrics
            .replay_bytes
            .fetch_add(file_bytes as u64, Ordering::Relaxed);
        let _ = progress_tx.blocking_send(ReplayProgress {
            segments_done,
            bytes_processed,
            matches_found: initial_matches_found.saturating_add(matches_so_far),
        });
    }

    drop(txs);
    for worker in workers {
        match worker.join() {
            Ok(r) => r?,
            Err(_) => anyhow::bail!("replay worker panicked"),
        }
    }
    drop(hit_tx);
    let new_matches = hit_collector
        .join()
        .map_err(|_| anyhow::anyhow!("replay hit collector panicked"))?;
    if !shutdown.load(Ordering::Acquire) {
        // Defensive final barrier: normal completion already committed each
        // segment individually, but completed status must never race metadata.
        metadata_tx.durable_barrier()?;
    }
    let _ = progress_tx.blocking_send(ReplayProgress {
        segments_done,
        bytes_processed,
        matches_found: initial_matches_found.saturating_add(new_matches),
    });
    Ok(())
}
