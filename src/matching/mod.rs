use std::{
    hash::{Hash, Hasher},
    sync::{atomic::{AtomicU64, Ordering}, Arc},
};

use ahash::AHashMap;
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, Sender};
use regex::bytes::{Regex, RegexSet};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    metrics::Metrics,
    model::{
        ContentRecord, ContentView, Direction, LiveEvent, MatchInput, MatchRecord, MetadataEvent,
        NewPattern, PatternAction, PatternDirection, PatternKind, PatternRevision,
    },
    storage::postgres::PostgresStore,
};

#[derive(Clone)]
pub struct PatternManager {
    postgres: PostgresStore,
    active: Arc<ArcSwap<CompiledPatternSet>>,
    interest_mask: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
}

impl PatternManager {
    pub async fn load(postgres: PostgresStore, metrics: Arc<Metrics>) -> Result<Self> {
        let patterns = postgres.list_enabled_patterns().await?;
        let compiled = CompiledPatternSet::compile(&patterns)?;
        let interest_mask = Arc::new(AtomicU64::new(compiled.interest_mask()));
        metrics.pattern_generation.store(1, Ordering::Relaxed);
        Ok(Self {
            postgres,
            active: Arc::new(ArcSwap::from_pointee(compiled)),
            interest_mask,
            metrics,
        })
    }

    pub fn postgres(&self) -> &PostgresStore { &self.postgres }

    pub async fn list(&self) -> Result<Vec<PatternRevision>> {
        self.postgres.list_patterns().await
    }

    pub async fn create(&self, new_pattern: NewPattern) -> Result<PatternRevision> {
        validate_new_pattern(&new_pattern)?;
        let created = self.postgres.create_pattern(new_pattern).await?;
        self.rebuild().await?;
        Ok(created)
    }

    pub async fn delete(&self, id: Uuid) -> Result<bool> {
        let deleted = self.postgres.delete_pattern(id).await?;
        if deleted { self.rebuild().await?; }
        Ok(deleted)
    }

    pub async fn set_enabled(&self, id: Uuid, enabled: bool) -> Result<PatternRevision> {
        let p = self.postgres.set_pattern_enabled(id, enabled).await?;
        self.rebuild().await?;
        Ok(p)
    }

    pub async fn update(&self, id: Uuid, new_pattern: NewPattern, enabled: bool) -> Result<PatternRevision> {
        validate_new_pattern(&new_pattern)?;
        let p = self.postgres.update_pattern(id, new_pattern, enabled).await?;
        self.rebuild().await?;
        Ok(p)
    }

    pub async fn rebuild(&self) -> Result<()> {
        let patterns = self.postgres.list_enabled_patterns().await?;
        let compiled = tokio::task::spawn_blocking(move || CompiledPatternSet::compile(&patterns)).await??;
        let interest_mask = compiled.interest_mask();
        self.active.store(Arc::new(compiled));
        self.interest_mask.store(interest_mask, Ordering::Release);
        self.metrics.pattern_generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<CompiledPatternSet> {
        self.active.load_full()
    }

    fn interest_mask_handle(&self) -> Arc<AtomicU64> {
        self.interest_mask.clone()
    }

    pub fn active_ignore_revisions(&self) -> Vec<(Uuid, i64)> {
        self.active.load().ignore_revisions.clone()
    }
}

fn validate_new_pattern(p: &NewPattern) -> Result<()> {
    if p.name.trim().is_empty() { anyhow::bail!("pattern name is empty"); }
    if p.expression.is_empty() { anyhow::bail!("pattern expression is empty"); }
    match p.kind {
        PatternKind::Binary => { decode_binary(&p.expression).context("invalid binary pattern")?; }
        PatternKind::Regex => { regex::bytes::Regex::new(&p.expression).context("invalid regex")?; }
        PatternKind::Text => {}
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct CompiledMeta {
    pattern: PatternRevision,
}

struct CompiledGroup {
    literal_ac: Option<AhoCorasick>,
    literal_meta: Vec<CompiledMeta>,
    regex_set: Option<RegexSet>,
    regex_compiled: Vec<Regex>,
    regex_meta: Vec<CompiledMeta>,
    max_literal_len: usize,
}

impl CompiledGroup {
    fn compile(patterns: &[PatternRevision]) -> Result<Self> {
        let mut literal_bytes = Vec::<Vec<u8>>::new();
        let mut literal_meta = Vec::<CompiledMeta>::new();
        let mut regexes = Vec::<String>::new();
        let mut regex_meta = Vec::<CompiledMeta>::new();
        let mut max_literal_len = 0usize;

        for p in patterns {
            match p.kind {
                PatternKind::Text => {
                    let bytes = p.expression.as_bytes().to_vec();
                    max_literal_len = max_literal_len.max(bytes.len());
                    literal_bytes.push(bytes);
                    literal_meta.push(CompiledMeta { pattern: p.clone() });
                }
                PatternKind::Binary => {
                    let bytes = decode_binary(&p.expression)?;
                    max_literal_len = max_literal_len.max(bytes.len());
                    literal_bytes.push(bytes);
                    literal_meta.push(CompiledMeta { pattern: p.clone() });
                }
                PatternKind::Regex => {
                    regexes.push(p.expression.clone());
                    regex_meta.push(CompiledMeta { pattern: p.clone() });
                }
            }
        }

        let literal_ac = if literal_bytes.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(literal_bytes.iter().map(|v| v.as_slice()))?)
        };
        let regex_set = if regexes.is_empty() { None } else { Some(RegexSet::new(&regexes)?) };
        let regex_compiled = regexes
            .iter()
            .map(|r| Regex::new(r))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self { literal_ac, literal_meta, regex_set, regex_compiled, regex_meta, max_literal_len })
    }

    fn required_overlap(&self, regex_overlap: usize) -> usize {
        let literal = self.max_literal_len.saturating_sub(1);
        if self.regex_set.is_some() { literal.max(regex_overlap) } else { literal }
    }

    fn scan_into(
        &self,
        record: &ContentRecord,
        prefix: &[u8],
        historical: bool,
        out: &mut Vec<MatchRecord>,
    ) {
        if let Some(ac) = &self.literal_ac {
            // Scan the current chunk directly: no full `prefix + data` copy is
            // needed for literal/binary rules. A tiny bridge buffer is used
            // only for matches that actually cross the chunk boundary.
            if !prefix.is_empty() && self.max_literal_len > 1 {
                let literal_keep = self.max_literal_len.saturating_sub(1);
                let prefix_start = prefix.len().saturating_sub(literal_keep);
                let literal_prefix = &prefix[prefix_start..];
                let bridge_current = literal_keep.min(record.data.len());
                let mut bridge = Vec::with_capacity(literal_prefix.len() + bridge_current);
                bridge.extend_from_slice(literal_prefix);
                bridge.extend_from_slice(&record.data[..bridge_current]);
                let base_offset = record.stream_offset.saturating_sub(literal_prefix.len() as u64);
                for m in ac.find_iter(&bridge) {
                    let meta = &self.literal_meta[m.pattern().as_usize()].pattern;
                    let start = base_offset + m.start() as u64;
                    let end = base_offset + m.end() as u64;
                    if start < record.stream_offset && end > record.stream_offset {
                        out.push(match_record(meta, record, start, end, historical));
                    }
                }
            }
            for m in ac.find_iter(&record.data) {
                let meta = &self.literal_meta[m.pattern().as_usize()].pattern;
                let start = record.stream_offset + m.start() as u64;
                let end = record.stream_offset + m.end() as u64;
                out.push(match_record(meta, record, start, end, historical));
            }
        }

        if let Some(set) = &self.regex_set {
            // Regexes can span an arbitrary amount of the configured overlap,
            // so keep the bounded combined window for regex groups only.
            let mut combined_storage = Vec::new();
            let (combined, base_offset, boundary) = if prefix.is_empty() {
                (record.data.as_ref(), record.stream_offset, None)
            } else {
                combined_storage.reserve(prefix.len() + record.data.len());
                combined_storage.extend_from_slice(prefix);
                combined_storage.extend_from_slice(&record.data);
                (
                    combined_storage.as_slice(),
                    record.stream_offset.saturating_sub(prefix.len() as u64),
                    Some(record.stream_offset),
                )
            };
            // RegexSet is a cheap prefilter. Only regexes that matched run a
            // second pass to recover exact offsets.
            let matched = set.matches(combined);
            for idx in matched.iter() {
                let meta = &self.regex_meta[idx].pattern;
                let re = &self.regex_compiled[idx];
                for m in re.find_iter(combined) {
                    let start = base_offset + m.start() as u64;
                    let end = base_offset + m.end() as u64;
                    if boundary.is_some_and(|new_data_start| end <= new_data_start) { continue; }
                    out.push(match_record(meta, record, start, end, historical));
                }
            }
        }
    }
}

pub struct CompiledPatternSet {
    // A record scans at most two groups: global rules for this exact content
    // view and rules scoped to the record's service. This keeps unrelated
    // service/request/response patterns out of the CPU hot path.
    global_groups: AHashMap<ContentView, CompiledGroup>,
    service_groups: AHashMap<String, AHashMap<ContentView, CompiledGroup>>,
    ignore_revisions: Vec<(Uuid, i64)>,
}

impl CompiledPatternSet {
    pub fn compile(patterns: &[PatternRevision]) -> Result<Self> {
        let ignore_revisions = patterns.iter()
            .filter(|p| p.enabled && p.action == PatternAction::Ignore)
            .map(|p| (p.id, p.revision))
            .collect::<Vec<_>>();

        let mut global_buckets: AHashMap<ContentView, Vec<PatternRevision>> = AHashMap::new();
        let mut service_buckets: AHashMap<String, AHashMap<ContentView, Vec<PatternRevision>>> = AHashMap::new();

        for p in patterns.iter().filter(|p| p.enabled) {
            for view in views_for_pattern(p) {
                if let Some(service) = &p.service {
                    service_buckets
                        .entry(service.clone())
                        .or_default()
                        .entry(view)
                        .or_default()
                        .push(p.clone());
                } else {
                    global_buckets.entry(view).or_default().push(p.clone());
                }
            }
        }

        let mut global_groups = AHashMap::new();
        for (view, bucket) in global_buckets {
            global_groups.insert(view, CompiledGroup::compile(&bucket)?);
        }
        let mut service_groups = AHashMap::new();
        for (service, buckets) in service_buckets {
            let mut compiled = AHashMap::new();
            for (view, bucket) in buckets {
                compiled.insert(view, CompiledGroup::compile(&bucket)?);
            }
            service_groups.insert(service, compiled);
        }

        Ok(Self { global_groups, service_groups, ignore_revisions })
    }

    fn interest_mask(&self) -> u64 {
        let mut mask = 0u64;
        for view in self.global_groups.keys() {
            mask |= content_view_bit(*view);
        }
        for groups in self.service_groups.values() {
            for view in groups.keys() {
                mask |= content_view_bit(*view);
            }
        }
        mask
    }

    fn groups_for<'a>(&'a self, record: &ContentRecord) -> (Option<&'a CompiledGroup>, Option<&'a CompiledGroup>) {
        let global = self.global_groups.get(&record.view);
        let service = record.service.as_ref()
            .and_then(|name| self.service_groups.get(name))
            .and_then(|groups| groups.get(&record.view));
        (global, service)
    }

    fn is_interested(&self, record: &ContentRecord) -> bool {
        let (global, service) = self.groups_for(record);
        global.is_some() || service.is_some()
    }

    fn required_overlap(&self, record: &ContentRecord, regex_overlap: usize) -> usize {
        let (global, service) = self.groups_for(record);
        global.into_iter()
            .chain(service)
            .map(|group| group.required_overlap(regex_overlap))
            .max()
            .unwrap_or(0)
    }

    pub fn scan(&self, record: &ContentRecord, prefix: &[u8], historical: bool) -> Vec<MatchRecord> {
        let (global, service) = self.groups_for(record);
        if global.is_none() && service.is_none() {
            return Vec::new();
        }

        let mut out = Vec::new();
        if let Some(group) = global {
            group.scan_into(record, prefix, historical, &mut out);
        }
        if let Some(group) = service {
            group.scan_into(record, prefix, historical, &mut out);
        }
        out
    }
}

fn content_view_bit(view: ContentView) -> u64 {
    1u64 << match view {
        ContentView::TcpRaw => 0,
        ContentView::HttpRequestHeaders => 1,
        ContentView::HttpRequestBody => 2,
        ContentView::HttpRequestDecodedBody => 3,
        ContentView::HttpResponseHeaders => 4,
        ContentView::HttpResponseBody => 5,
        ContentView::HttpResponseDecodedBody => 6,
    }
}

fn views_for_pattern(pattern: &PatternRevision) -> Vec<ContentView> {
    if let Some(view) = pattern.view {
        let compatible = match pattern.direction_type {
            PatternDirection::Both => true,
            PatternDirection::Input => matches!(view,
                ContentView::HttpRequestHeaders | ContentView::HttpRequestBody | ContentView::HttpRequestDecodedBody
            ),
            PatternDirection::Output => matches!(view,
                ContentView::HttpResponseHeaders | ContentView::HttpResponseBody | ContentView::HttpResponseDecodedBody
            ),
        };
        return if compatible { vec![view] } else { Vec::new() };
    }
    match pattern.direction_type {
        PatternDirection::Input => vec![
            ContentView::HttpRequestHeaders,
            ContentView::HttpRequestBody,
            ContentView::HttpRequestDecodedBody,
        ],
        PatternDirection::Output => vec![
            ContentView::HttpResponseHeaders,
            ContentView::HttpResponseBody,
            ContentView::HttpResponseDecodedBody,
        ],
        PatternDirection::Both => vec![
            ContentView::TcpRaw,
            ContentView::HttpRequestDecodedBody,
            ContentView::HttpResponseDecodedBody,
        ],
    }
}

fn match_record(
    p: &PatternRevision,
    record: &ContentRecord,
    start: u64,
    end: u64,
    historical: bool,
) -> MatchRecord {
    MatchRecord {
        timestamp: chrono::Utc::now(),
        pattern_id: p.id,
        pattern_revision: p.revision,
        flow_id: record.flow_id,
        content_id: record.id,
        view: record.view,
        action: p.action,
        offset_start: start,
        offset_end: end,
        historical,
    }
}

#[derive(Clone, Eq)]
struct StreamKey {
    flow_id: Uuid,
    direction: Direction,
    view: ContentView,
}
impl PartialEq for StreamKey { fn eq(&self, o:&Self)->bool{self.flow_id==o.flow_id&&self.direction==o.direction&&self.view==o.view} }
impl Hash for StreamKey { fn hash<H:Hasher>(&self,h:&mut H){self.flow_id.hash(h);self.direction.hash(h);self.view.hash(h);} }

#[derive(Default)]
struct TailState {
    data: Vec<u8>,
    end_offset: u64,
}

impl TailState {
    fn prefix_for(&self, record: &ContentRecord) -> &[u8] {
        // HTTP semantic views are sparse in the canonical TCP offset space
        // (headers/body and separate messages have gaps). Never allow a pattern
        // to bridge such a semantic gap merely because two records share the
        // same flow/direction/view key.
        if self.end_offset == record.stream_offset { &self.data } else { &[] }
    }
}

fn build_tail(previous: &[u8], data: &[u8], keep: usize) -> Vec<u8> {
    if keep == 0 { return Vec::new(); }
    if data.len() >= keep {
        return data[data.len() - keep..].to_vec();
    }
    let previous_keep = keep.saturating_sub(data.len()).min(previous.len());
    let mut out = Vec::with_capacity(previous_keep + data.len());
    out.extend_from_slice(&previous[previous.len().saturating_sub(previous_keep)..]);
    out.extend_from_slice(data);
    out
}

#[derive(Clone)]
pub struct MatcherIngress {
    shard_txs: Arc<Vec<Sender<MatchInput>>>,
    interest_mask: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
}

impl MatcherIngress {
    pub fn is_interested_view(&self, view: ContentView) -> bool {
        self.interest_mask.load(Ordering::Acquire) & content_view_bit(view) != 0
    }

    pub fn send(&self, input: MatchInput) -> std::result::Result<usize, crossbeam_channel::SendError<MatchInput>> {
        let flow_id = match &input {
            MatchInput::Content(record) => {
                // Coarse lock-free prefilter: if no active global or service
                // group can ever consume this content view, do not clone/wake a
                // matcher worker just so it can immediately discard the record.
                if self.interest_mask.load(Ordering::Acquire) & content_view_bit(record.view) == 0 {
                    return Ok(self.metrics.match_queue_depth.load(Ordering::Relaxed) as usize);
                }
                record.flow_id
            }
            MatchInput::FlowClosed(id) => *id,
        };
        let idx = (flow_id.as_u128() as usize) % self.shard_txs.len();
        let tx = &self.shard_txs[idx];
        tx.send(input)?;
        Ok(Metrics::queue_enqueued(&self.metrics.match_queue_depth, &self.metrics.match_queue_high_watermark) as usize)
    }
}

pub struct MatcherRuntime {
    pub input: MatcherIngress,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl MatcherRuntime {
    pub fn worker_count(&self) -> usize { self.handles.len() }

    pub fn join(self) -> anyhow::Result<()> {
        let MatcherRuntime { input, handles } = self;
        drop(input);
        for handle in handles {
            handle.join().map_err(|_| anyhow::anyhow!("matcher worker panicked"))?;
        }
        Ok(())
    }
}

pub fn spawn_live_matcher(
    manager: PatternManager,
    metadata_tx: crate::storage::MetadataSink,
    live_events: broadcast::Sender<LiveEvent>,
    overlap_limit: usize,
    worker_count: usize,
    worker_cpus: Vec<usize>,
    queue_capacity: usize,
    metrics: Arc<Metrics>,
) -> anyhow::Result<MatcherRuntime> {
    let worker_count = worker_count.max(1);
    let per_worker_capacity = (queue_capacity / worker_count).max(1);
    metrics.match_queue_capacity.store((per_worker_capacity * worker_count) as u64, Ordering::Relaxed);
    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut handles = Vec::with_capacity(worker_count);

    for worker_id in 0..worker_count {
        let (tx, worker_rx) = crossbeam_channel::bounded::<MatchInput>(per_worker_capacity);
        worker_txs.push(tx);
        let manager2 = manager.clone();
        let metadata2 = metadata_tx.clone();
        let events2 = live_events.clone();
        let metrics2 = metrics.clone();
        let matcher_cpu = if worker_cpus.is_empty() { None } else { Some(worker_cpus[worker_id % worker_cpus.len()]) };
        handles.push(std::thread::Builder::new()
            .name(format!("live-matcher-{worker_id}"))
            .spawn(move || {
                if let Some(cpu) = matcher_cpu {
                    match crate::affinity::pin_current(cpu) {
                        Ok(actual) if actual != cpu => tracing::info!(worker_id, requested_cpu=cpu, actual_cpu=actual, "matcher worker CPU remapped to container cpuset"),
                        Ok(_) => {},
                        Err(e) => tracing::warn!(worker_id, cpu, error=%e, "cannot pin matcher worker"),
                    }
                }
                matcher_worker_loop(manager2, worker_rx, metadata2, events2, overlap_limit, metrics2)
            })?);
    }

    let interest_mask = manager.interest_mask_handle();
    Ok(MatcherRuntime {
        input: MatcherIngress { shard_txs: Arc::new(worker_txs), interest_mask, metrics },
        handles,
    })
}

fn matcher_worker_loop(
    manager: PatternManager,
    rx: Receiver<MatchInput>,
    metadata_tx: crate::storage::MetadataSink,
    live_events: broadcast::Sender<LiveEvent>,
    overlap_limit: usize,
    metrics: Arc<Metrics>,
) {
    let mut tails: AHashMap<StreamKey, TailState> = AHashMap::new();
    // Keep the small set of matcher stream keys belonging to each flow. This
    // makes FlowClosed cleanup O(views-per-flow) instead of retain()-scanning
    // every active matcher tail on every short-lived HTTP connection.
    let mut flow_tail_keys: AHashMap<Uuid, Vec<StreamKey>> = AHashMap::new();
    let mut generation = metrics.pattern_generation.load(Ordering::Acquire);
    let mut snapshot = manager.snapshot();
    while let Ok(input) = rx.recv() {
        Metrics::queue_dequeued(&metrics.match_queue_depth);
        match input {
            MatchInput::FlowClosed(id) => {
                if let Some(keys) = flow_tail_keys.remove(&id) {
                    for key in keys {
                        tails.remove(&key);
                    }
                }
            }
            MatchInput::Content(record) => {
                let current_generation = metrics.pattern_generation.load(Ordering::Acquire);
                if current_generation != generation {
                    snapshot = manager.snapshot();
                    generation = current_generation;
                }
                let key = StreamKey { flow_id: record.flow_id, direction: record.direction, view: record.view };
                if !snapshot.is_interested(&record) {
                    tails.remove(&key);
                    continue;
                }

                metrics.matcher_bytes.fetch_add(record.data.len() as u64, Ordering::Relaxed);
                let keep = snapshot.required_overlap(&record, overlap_limit);
                let tail_state = tails.get(&key);
                let tail_exists = tail_state.is_some();
                let tail = tail_state.map(|state| state.prefix_for(&record)).unwrap_or(&[]);
                for hit in snapshot.scan(&record, tail, false) {
                    metrics.matcher_matches.fetch_add(1, Ordering::Relaxed);
                    if metadata_tx.send(MetadataEvent::Match(hit.clone())).is_err() { return; }
                    if hit.action == PatternAction::Find {
                        let _ = live_events.send(LiveEvent {
                            event: "new_match".into(),
                            flow_id: hit.flow_id,
                            pattern_id: Some(hit.pattern_id),
                            timestamp: hit.timestamp,
                            service: record.service.clone(),
                        });
                    }
                }
                if keep == 0 {
                    tails.remove(&key);
                } else {
                    let next_tail = build_tail(tail, &record.data, keep);
                    if !tail_exists {
                        let tracked = flow_tail_keys.get(&record.flow_id)
                            .is_some_and(|keys| keys.iter().any(|tracked| tracked == &key));
                        if !tracked {
                            flow_tail_keys.entry(record.flow_id).or_default().push(key.clone());
                        }
                    }
                    tails.insert(key, TailState {
                        data: next_tail,
                        end_offset: record.stream_offset.saturating_add(record.data.len() as u64),
                    });
                }
            }
        }
    }
}

pub struct ReplayScanner {
    patterns: CompiledPatternSet,
    tails: AHashMap<StreamKey, TailState>,
    last_seen_ns: AHashMap<StreamKey, u64>,
    overlap_limit: usize,
    scanned_records: u64,
}

impl ReplayScanner {
    pub fn new(patterns: &[PatternRevision], overlap_limit: usize) -> Result<Self> {
        Ok(Self { patterns: CompiledPatternSet::compile(patterns)?, tails: AHashMap::new(), last_seen_ns: AHashMap::new(), overlap_limit, scanned_records: 0 })
    }

    pub fn scan_record(&mut self, record: &ContentRecord) -> Vec<MatchRecord> {
        let key = StreamKey { flow_id: record.flow_id, direction: record.direction, view: record.view };
        if !self.patterns.is_interested(record) {
            self.tails.remove(&key);
            self.last_seen_ns.remove(&key);
            return Vec::new();
        }
        let keep = self.patterns.required_overlap(record, self.overlap_limit);
        let tail = self.tails.get(&key).map(|state| state.prefix_for(record)).unwrap_or(&[]);
        let hits = self.patterns.scan(record, tail, true);
        if keep == 0 {
            self.tails.remove(&key);
        } else {
            let next_tail = build_tail(tail, &record.data, keep);
            self.tails.insert(key.clone(), TailState {
                data: next_tail,
                end_offset: record.stream_offset.saturating_add(record.data.len() as u64),
            });
        }
        self.last_seen_ns.insert(key, record.ts_ns);
        self.scanned_records = self.scanned_records.wrapping_add(1);
        // Segment files are append-only and approximately time ordered. Bound replay
        // memory even when millions of closed flows were seen before this worker.
        if self.scanned_records % 4096 == 0 {
            let cutoff = record.ts_ns.saturating_sub(300_000_000_000);
            let stale = self.last_seen_ns.iter()
                .filter_map(|(k, ts)| (*ts < cutoff).then_some(k.clone()))
                .collect::<Vec<_>>();
            for k in stale {
                self.last_seen_ns.remove(&k);
                self.tails.remove(&k);
            }
        }
        hits
    }
}

fn decode_binary(v: &str) -> Result<Vec<u8>> {
    let compact: String = v.chars().filter(|c| !c.is_ascii_whitespace() && *c != ':').collect();
    let bytes = hex::decode(compact)?;
    if bytes.is_empty() { anyhow::bail!("binary pattern is empty"); }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentView, Direction};

    fn p(expr:&str, kind:PatternKind)->PatternRevision{PatternRevision{id:Uuid::new_v4(),revision:1,name:"x".into(),expression:expr.into(),kind,action:PatternAction::Find,color:"#FF7474".into(),direction_type:PatternDirection::Both,service:None,view:None,enabled:true,created_at:chrono::Utc::now()}}
    fn r(data:&[u8], offset:u64)->ContentRecord{ContentRecord{id:Uuid::new_v4(),flow_id:Uuid::nil(),ts_ns:0,service:None,direction:Direction::AToB,view:ContentView::TcpRaw,stream_offset:offset,data:bytes::Bytes::copy_from_slice(data)}}
    fn rv(data:&[u8], offset:u64, view:ContentView)->ContentRecord{ContentRecord{id:Uuid::new_v4(),flow_id:Uuid::nil(),ts_ns:0,service:None,direction:Direction::AToB,view,stream_offset:offset,data:bytes::Bytes::copy_from_slice(data)}}

    #[test]
    fn literal_crosses_chunk_boundary() {
        let set=CompiledPatternSet::compile(&[p("FLAG{",PatternKind::Text)]).unwrap();
        let first=r(b"AAFL",0); assert!(set.scan(&first,&[],false).is_empty());
        let second=r(b"AG{x}",4); let hits=set.scan(&second,b"AAFL",false); assert_eq!(hits.len(),1); assert_eq!(hits[0].offset_start,2);
    }

    #[test]
    fn anywhere_uses_canonical_raw_stream_not_duplicate_http_wire_view(){
        let pattern=p("needle",PatternKind::Text);
        let set=CompiledPatternSet::compile(&[pattern]).unwrap();
        assert_eq!(set.scan(&rv(b"needle",0,ContentView::TcpRaw),&[],false).len(),1);
        assert!(set.scan(&rv(b"needle",0,ContentView::HttpRequestHeaders),&[],false).is_empty());
    }

    #[test]
    fn request_scope_uses_http_semantic_view(){
        let mut pattern=p("needle",PatternKind::Text);
        pattern.direction_type=PatternDirection::Input;
        let set=CompiledPatternSet::compile(&[pattern]).unwrap();
        assert_eq!(set.scan(&rv(b"needle",0,ContentView::HttpRequestBody),&[],false).len(),1);
        assert!(set.scan(&rv(b"needle",0,ContentView::TcpRaw),&[],false).is_empty());
    }

    #[test]
    fn service_scoped_patterns_do_not_enter_other_service_hot_paths(){
        let mut pattern=p("needle",PatternKind::Text);
        pattern.service=Some("svc-a".into());
        let set=CompiledPatternSet::compile(&[pattern]).unwrap();
        let mut other=rv(b"needle",0,ContentView::TcpRaw);
        other.service=Some("svc-b".into());
        assert!(!set.is_interested(&other));
        assert!(set.scan(&other,&[],false).is_empty());
        other.service=Some("svc-a".into());
        assert!(set.is_interested(&other));
        assert_eq!(set.scan(&other,&[],false).len(),1);
    }

    #[test]
    fn literal_overlap_is_pattern_sized_but_regex_keeps_bounded_window(){
        let literal=CompiledPatternSet::compile(&[p("ABCDE",PatternKind::Text)]).unwrap();
        let raw=r(b"x",0);
        assert_eq!(literal.required_overlap(&raw,8192),4);
        let regex=CompiledPatternSet::compile(&[p("A.*Z",PatternKind::Regex)]).unwrap();
        assert_eq!(regex.required_overlap(&raw,8192),8192);
    }

    #[test]
    fn exact_view_still_respects_request_response_direction(){
        let mut pattern=p("needle",PatternKind::Text);
        pattern.direction_type=PatternDirection::Input;
        pattern.view=Some(ContentView::HttpResponseBody);
        let set=CompiledPatternSet::compile(&[pattern]).unwrap();
        assert!(set.scan(&rv(b"needle",0,ContentView::HttpResponseBody),&[],false).is_empty());
    }

    #[test]
    fn semantic_tail_is_not_reused_across_stream_offset_gap(){
        let first = rv(b"AB", 0, ContentView::HttpRequestBody);
        let second = rv(b"CD", 10, ContentView::HttpRequestBody);
        let state = TailState { data: b"AB".to_vec(), end_offset: 2 };
        assert_eq!(state.prefix_for(&first), &[] as &[u8]);
        assert_eq!(state.prefix_for(&second), &[] as &[u8]);
        let contiguous = rv(b"CD", 2, ContentView::HttpRequestBody);
        assert_eq!(state.prefix_for(&contiguous), b"AB");
    }

    #[test]
    fn binary_pattern_decodes_hex(){assert_eq!(decode_binary("41 42:43").unwrap(),b"ABC");}
}
