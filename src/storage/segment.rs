use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use anyhow::{bail, Context, Result};
use crc32fast::Hasher;
use crossbeam_channel::{bounded, RecvTimeoutError, Sender};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::{
    metrics::Metrics,
    model::{ContentIndexRecord, ContentRecord, ContentView, Direction, MetadataEvent},
};

const MAGIC: &[u8; 8] = b"PMSEG001";
const RECORD_MAGIC: u32 = 0x504d5243;
const HEADER_SIZE: u64 = 8 + 4 + 8;

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct SegmentDiskStats {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct SegmentDeleteStats {
    pub files: u64,
    pub bytes: u64,
}

/// Immutable append-only payload store. It intentionally does not keep a
/// process-wide content catalog: at high packet rates such a catalog grows
/// linearly with retained traffic. Durable lookup metadata is published only
/// after the corresponding segment bytes have been flushed from userspace so
/// API/replay readers never observe an index pointing at a BufWriter-only tail.
enum SegmentCommand {
    Record(ContentRecord),
    Flush(Sender<std::result::Result<(), String>>),
    Seal(Sender<std::result::Result<Vec<PathBuf>, String>>),
}

pub struct SegmentStore {
    root: PathBuf,
    max_record_bytes: usize,
    tx: Sender<SegmentCommand>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    writer: Mutex<Option<thread::JoinHandle<()>>>,
}

impl SegmentStore {
    pub fn open(
        root: PathBuf,
        max_bytes: u64,
        max_record_bytes: usize,
        store_max_bytes: u64,
        queue_capacity: usize,
        metrics: Arc<Metrics>,
        metadata_tx: crate::storage::MetadataSink,
    ) -> Result<Arc<Self>> {
        fs::create_dir_all(&root)?;
        recover_last_segment_tail(&root, max_record_bytes)?;
        let retained_bytes = directory_bytes(&root)?;
        if retained_bytes > store_max_bytes {
            bail!("segment store already exceeds configured disk budget: {retained_bytes} > {store_max_bytes}");
        }
        metrics
            .segment_disk_capacity
            .store(store_max_bytes, Ordering::Relaxed);
        metrics
            .segment_disk_bytes
            .store(retained_bytes, Ordering::Relaxed);
        let queue_capacity = queue_capacity.max(1);
        let (tx, rx) = bounded::<SegmentCommand>(queue_capacity);
        metrics
            .segment_queue_capacity
            .store(queue_capacity as u64, Ordering::Relaxed);
        let writer_metrics = metrics.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();
        let writer_root = root.clone();
        let writer_handle = thread::Builder::new().name("segment-writer".into()).spawn(move || {
            let mut writer = match ActiveWriter::new(&writer_root, max_bytes, max_record_bytes, store_max_bytes, retained_bytes) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "segment writer init failed");
                    return;
                }
            };
            let mut pending_index = Vec::<ContentIndexRecord>::with_capacity(512);
            let mut fatal = false;
            loop {
                writer_metrics.touch_progress();
                match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(SegmentCommand::Record(record)) => {
                        Metrics::observe_queue(
                            &writer_metrics.segment_queue_depth,
                            &writer_metrics.segment_queue_high_watermark,
                            rx.len() as u64,
                        );
                        match writer.write_record(&record) {
                            Ok((path, offset, bytes)) => {
                                writer_metrics.segment_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                                writer_metrics.segment_disk_bytes.store(writer.retained_bytes, Ordering::Relaxed);
                                pending_index.push(ContentIndexRecord {
                                    content_id: record.id,
                                    flow_id: record.flow_id,
                                    ts_ns: record.ts_ns,
                                    service: record.service.clone(),
                                    direction: record.direction,
                                    view: record.view,
                                    stream_offset: record.stream_offset,
                                    payload_len: record.data.len().min(u32::MAX as usize) as u32,
                                    segment_path: path.to_string_lossy().into_owned(),
                                    segment_offset: offset,
                                });
                                if pending_index.len() >= 512 {
                                    if let Err(e) = flush_and_publish(&mut writer, &mut pending_index, &metadata_tx, false) {
                                        tracing::error!(error=%e, "segment visibility flush failed");
                                        fatal = true;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(error = %e, content_id = %record.id, "segment write failed");
                                fatal = true;
                            }
                        }
                    }
                    Ok(SegmentCommand::Flush(reply)) => {
                        let result = flush_and_publish(&mut writer, &mut pending_index, &metadata_tx, false)
                            .map_err(|e| e.to_string());
                        fatal |= result.is_err();
                        let _ = reply.send(result);
                    }
                    Ok(SegmentCommand::Seal(reply)) => {
                        let result = (|| -> Result<Vec<PathBuf>> {
                            flush_and_publish(&mut writer, &mut pending_index, &metadata_tx, true)?;
                            writer.rotate()?;
                            let active = writer.path.clone();
                            let mut paths = list_segments(&writer.root)?;
                            paths.retain(|p| p != &active);
                            Ok(paths)
                        })().map_err(|e| e.to_string());
                        fatal |= result.is_err();
                        let _ = reply.send(result);
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if !pending_index.is_empty() {
                            if let Err(e) = flush_and_publish(&mut writer, &mut pending_index, &metadata_tx, false) {
                                tracing::error!(error=%e, "periodic segment visibility flush failed");
                                fatal = true;
                            }
                        }
                        if shutdown2.load(Ordering::Acquire) && rx.is_empty() { break; }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                if fatal { break; }
            }
            if let Err(e) = flush_and_publish(&mut writer, &mut pending_index, &metadata_tx, true) {
                tracing::error!(error=%e, "final segment flush failed");
            }
        })?;
        Ok(Arc::new(Self {
            root,
            max_record_bytes,
            tx,
            metrics,
            shutdown,
            writer: Mutex::new(Some(writer_handle)),
        }))
    }

    pub fn shutdown_and_join(&self) -> Result<()> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.writer.lock().take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("segment writer panicked"))?;
        }
        Ok(())
    }

    pub fn writer_finished(&self) -> bool {
        self.writer
            .lock()
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
    }

    /// Enqueue content into the bounded durable segment pipeline. Blocking here
    /// intentionally pushes overload back toward capture, where drops are counted,
    /// rather than silently losing an already-accepted payload.
    pub fn append(&self, record: ContentRecord) -> Result<()> {
        self.tx
            .send(SegmentCommand::Record(record))
            .map_err(|e| anyhow::anyhow!("segment writer stopped: {e}"))?;
        Metrics::observe_queue(
            &self.metrics.segment_queue_depth,
            &self.metrics.segment_queue_high_watermark,
            self.tx.len() as u64,
        );
        Ok(())
    }

    /// Establish a visibility barrier: every record accepted before this call is
    /// readable through a new file descriptor and its content-index event has
    /// been published to the metadata pipeline. Replay uses this before freezing
    /// its historical segment set.
    pub fn flush_visible(&self) -> Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(SegmentCommand::Flush(reply_tx))
            .map_err(|e| anyhow::anyhow!("segment writer stopped: {e}"))?;
        match reply_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(anyhow::anyhow!(e)),
            Err(e) => Err(anyhow::anyhow!("segment flush reply failed: {e}")),
        }
    }

    /// Seal the current segment at an exact point in the writer queue and
    /// return the immutable historical segment set. Records accepted after the
    /// barrier go to a newly created active segment and cannot leak into this
    /// replay snapshot.
    pub fn snapshot_for_replay(&self) -> Result<Vec<PathBuf>> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(SegmentCommand::Seal(reply_tx))
            .map_err(|e| anyhow::anyhow!("segment writer stopped: {e}"))?;
        match reply_rx.recv() {
            Ok(Ok(paths)) => Ok(paths),
            Ok(Err(e)) => Err(anyhow::anyhow!(e)),
            Err(e) => Err(anyhow::anyhow!("segment seal reply failed: {e}")),
        }
    }

    pub fn read_at(&self, path: &Path, offset: u64) -> Result<ContentRecord> {
        // Only permit reads inside the configured segment root. This prevents a
        // corrupted/forged metadata row from becoming an arbitrary-file read.
        let canonical_root = self
            .root
            .canonicalize()
            .context("canonicalize segment root")?;
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("canonicalize {}", path.display()))?;
        if !canonical_path.starts_with(&canonical_root) {
            bail!("segment path is outside configured store");
        }
        read_record_at(&canonical_path, offset, self.max_record_bytes)
    }

    /// Read many records from one segment with a single canonicalization/open.
    /// The result order matches `offsets`; individual corrupt records do not
    /// prevent the remaining offsets from being attempted.
    pub fn read_many_at(
        &self,
        path: &Path,
        offsets: &[u64],
    ) -> Result<Vec<(u64, Result<ContentRecord>)>> {
        let canonical_root = self
            .root
            .canonicalize()
            .context("canonicalize segment root")?;
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("canonicalize {}", path.display()))?;
        if !canonical_path.starts_with(&canonical_root) {
            bail!("segment path is outside configured store");
        }
        let mut reader = BufReader::new(File::open(&canonical_path)?);
        let file_len = reader.get_ref().metadata()?.len();
        let mut out = Vec::with_capacity(offsets.len());
        for &offset in offsets {
            let result = (|| -> Result<ContentRecord> {
                reader.seek(SeekFrom::Start(offset))?;
                read_record(
                    &mut reader,
                    self.max_record_bytes,
                    Some(file_len.saturating_sub(offset)),
                )?
                .map(|v| v.0)
                .context("record missing")
            })();
            out.push((offset, result));
        }
        Ok(out)
    }

    pub fn segment_paths(&self) -> Result<Vec<PathBuf>> {
        list_segments(&self.root)
    }

    pub fn disk_stats(&self) -> Result<SegmentDiskStats> {
        let paths = self.segment_paths()?;
        let mut bytes = 0u64;
        for path in &paths {
            bytes = bytes.saturating_add(fs::metadata(path).map(|m| m.len()).unwrap_or(0));
        }
        Ok(SegmentDiskStats {
            files: paths.len() as u64,
            bytes,
        })
    }

    /// Seal the active writer and identify immutable segment files containing
    /// only records older than `cutoff_ns`. Mixed-age segments are retained so
    /// retention never removes payload for a newer content-index row.
    pub fn retention_candidates(&self, cutoff_ns: u64) -> Result<Vec<PathBuf>> {
        let paths = self.snapshot_for_replay()?;
        let mut out = Vec::new();
        for path in paths {
            let mut newest = 0u64;
            let mut records = 0u64;
            self.scan_path(&path, |record| {
                newest = newest.max(record.ts_ns);
                records = records.saturating_add(1);
                Ok(())
            })?;
            if records == 0 || newest < cutoff_ns {
                out.push(path);
            }
        }
        Ok(out)
    }

    pub fn delete_segments(&self, paths: &[PathBuf]) -> Result<SegmentDeleteStats> {
        let canonical_root = self
            .root
            .canonicalize()
            .context("canonicalize segment root")?;
        let mut files = 0u64;
        let mut bytes = 0u64;
        for path in paths {
            let canonical = path
                .canonicalize()
                .with_context(|| format!("canonicalize {}", path.display()))?;
            if !canonical.starts_with(&canonical_root) {
                bail!("segment path is outside configured store");
            }
            let len = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
            fs::remove_file(&canonical)
                .with_context(|| format!("delete segment {}", canonical.display()))?;
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(len);
        }
        Ok(SegmentDeleteStats { files, bytes })
    }

    pub fn scan_path<F>(&self, path: &Path, mut f: F) -> Result<u64>
    where
        F: FnMut(ContentRecord) -> Result<()>,
    {
        let mut reader = BufReader::new(File::open(path)?);
        let file_len = reader.get_ref().metadata()?.len();
        read_header(&mut reader)?;
        let mut bytes = HEADER_SIZE;
        loop {
            let pos = reader.stream_position()?;
            match read_record(
                &mut reader,
                self.max_record_bytes,
                Some(file_len.saturating_sub(pos)),
            ) {
                Ok(Some((record, consumed))) => {
                    bytes += consumed;
                    f(record)?;
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("corrupt segment {} at offset {pos}", path.display())
                    })
                }
            }
        }
        Ok(bytes)
    }

    /// Rebuild index rows for one known immutable/recovered segment. Duplicate
    /// rows are safe because ClickHouse content_index is a ReplacingMergeTree.
    pub fn rebuild_index_path(
        &self,
        path: &Path,
        metadata_tx: &crate::storage::MetadataSink,
    ) -> Result<u64> {
        let path_s = path.to_string_lossy().into_owned();
        let mut reader = BufReader::new(File::open(path)?);
        let file_len = reader.get_ref().metadata()?.len();
        read_header(&mut reader)
            .with_context(|| format!("corrupt segment header {}", path.display()))?;
        let mut count = 0u64;
        loop {
            let offset = reader.stream_position()?;
            match read_record(
                &mut reader,
                self.max_record_bytes,
                Some(file_len.saturating_sub(offset)),
            ) {
                Ok(Some((record, _))) => {
                    let index = ContentIndexRecord {
                        content_id: record.id,
                        flow_id: record.flow_id,
                        ts_ns: record.ts_ns,
                        service: record.service.clone(),
                        direction: record.direction,
                        view: record.view,
                        stream_offset: record.stream_offset,
                        payload_len: record.data.len().min(u32::MAX as usize) as u32,
                        segment_path: path_s.clone(),
                        segment_offset: offset,
                    };
                    metadata_tx.send(MetadataEvent::ContentIndex(index))?;
                    count = count.saturating_add(1);
                }
                Ok(None) => break,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("corrupt segment {} at offset {offset}", path.display())
                    });
                }
            }
        }
        Ok(count)
    }

    /// Scan every segment and emit durable index rows. Intended for explicit
    /// recovery/maintenance, not for the hot startup path.
    pub fn rebuild_index(&self, metadata_tx: &crate::storage::MetadataSink) -> Result<u64> {
        self.flush_visible()?;
        let mut count = 0u64;
        for path in self.segment_paths()? {
            count = count.saturating_add(self.rebuild_index_path(&path, metadata_tx)?);
        }
        Ok(count)
    }
}

fn flush_and_publish(
    writer: &mut ActiveWriter,
    pending: &mut Vec<ContentIndexRecord>,
    metadata_tx: &crate::storage::MetadataSink,
    durable: bool,
) -> Result<()> {
    if durable {
        writer.flush_sync()?;
    } else {
        writer.flush_visible()?;
    }
    for index in pending.drain(..) {
        metadata_tx
            .send(MetadataEvent::ContentIndex(index))
            .map_err(|e| anyhow::anyhow!("metadata writer stopped: {e}"))?;
    }
    Ok(())
}

struct ActiveWriter {
    root: PathBuf,
    max_bytes: u64,
    max_record_bytes: usize,
    file: BufWriter<File>,
    path: PathBuf,
    bytes: u64,
    retained_bytes: u64,
    store_max_bytes: u64,
}

impl ActiveWriter {
    fn new(
        root: &Path,
        max_bytes: u64,
        max_record_bytes: usize,
        store_max_bytes: u64,
        retained_bytes: u64,
    ) -> Result<Self> {
        fs::create_dir_all(root)?;
        let (path, file) = create_segment(root)?;
        let mut file = BufWriter::with_capacity(4 * 1024 * 1024, file);
        write_header(&mut file)?;
        Ok(Self {
            root: root.to_path_buf(),
            max_bytes,
            max_record_bytes,
            file,
            path,
            bytes: HEADER_SIZE,
            retained_bytes: retained_bytes.saturating_add(HEADER_SIZE),
            store_max_bytes,
        })
    }

    fn rotate(&mut self) -> Result<()> {
        self.flush_sync()?;
        let (path, file) = create_segment(&self.root)?;
        let mut file = BufWriter::with_capacity(4 * 1024 * 1024, file);
        write_header(&mut file)?;
        self.path = path;
        self.file = file;
        self.bytes = HEADER_SIZE;
        Ok(())
    }

    fn write_record(&mut self, record: &ContentRecord) -> Result<(PathBuf, u64, usize)> {
        let prefix = encode_record_prefix(record)?;
        let payload_len = prefix.len().saturating_add(record.data.len());
        if payload_len > u32::MAX as usize {
            bail!("content record too large");
        }
        if payload_len > self.max_record_bytes {
            bail!(
                "content record exceeds configured segment record limit: {payload_len} > {}",
                self.max_record_bytes
            );
        }
        let encoded_len = 12 + payload_len;
        if self.retained_bytes.saturating_add(encoded_len as u64) > self.store_max_bytes {
            bail!(
                "segment disk budget exhausted: {} + {} > {}",
                self.retained_bytes,
                encoded_len,
                self.store_max_bytes
            );
        }
        if self.bytes > HEADER_SIZE && self.bytes + encoded_len as u64 > self.max_bytes {
            self.rotate()?;
        }
        let offset = self.file.stream_position()?;
        let mut crc = Hasher::new();
        crc.update(&prefix);
        crc.update(&record.data);
        self.file.write_all(&RECORD_MAGIC.to_le_bytes())?;
        self.file.write_all(&(payload_len as u32).to_le_bytes())?;
        self.file.write_all(&crc.finalize().to_le_bytes())?;
        self.file.write_all(&prefix)?;
        self.file.write_all(&record.data)?;
        self.bytes += encoded_len as u64;
        self.retained_bytes = self.retained_bytes.saturating_add(encoded_len as u64);
        Ok((self.path.clone(), offset, encoded_len))
    }

    fn flush_visible(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    fn flush_sync(&mut self) -> Result<()> {
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        Ok(())
    }
}

fn directory_bytes(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}

fn create_segment(root: &Path) -> Result<(PathBuf, File)> {
    let name = format!(
        "segment-{}-{}.seg",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
        Uuid::new_v4()
    );
    let path = root.join(name);
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    Ok((path, file))
}

fn write_header<W: Write>(w: &mut W) -> Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&1u32.to_le_bytes())?;
    w.write_all(&(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64).to_le_bytes())?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<()> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("bad segment magic");
    }
    let version = read_u32(r)?;
    if version != 1 {
        bail!("unsupported segment version {version}");
    }
    let _created = read_u64(r)?;
    Ok(())
}

fn encode_record_prefix(r: &ContentRecord) -> Result<Vec<u8>> {
    let service = r.service.as_deref().unwrap_or("").as_bytes();
    if service.len() > u16::MAX as usize {
        bail!("service name too long");
    }
    if r.data.len() > u32::MAX as usize {
        bail!("content record too large");
    }
    let mut v = Vec::with_capacity(64 + service.len());
    v.extend_from_slice(r.id.as_bytes());
    v.extend_from_slice(r.flow_id.as_bytes());
    v.extend_from_slice(&r.ts_ns.to_le_bytes());
    v.extend_from_slice(&(service.len() as u16).to_le_bytes());
    v.extend_from_slice(service);
    v.push(direction_to_u8(r.direction));
    v.push(view_to_u8(r.view));
    v.extend_from_slice(&r.stream_offset.to_le_bytes());
    v.extend_from_slice(&(r.data.len() as u32).to_le_bytes());
    Ok(v)
}

#[cfg(test)]
fn encode_record(r: &ContentRecord) -> Result<Vec<u8>> {
    let mut v = encode_record_prefix(r)?;
    v.extend_from_slice(&r.data);
    Ok(v)
}

fn decode_record(mut data: &[u8]) -> Result<ContentRecord> {
    if data.len() < 16 + 16 + 8 + 2 + 1 + 1 + 8 + 4 {
        bail!("record too short");
    }
    let id = Uuid::from_slice(take(&mut data, 16)?)?;
    let flow_id = Uuid::from_slice(take(&mut data, 16)?)?;
    let ts_ns = take_u64(&mut data)?;
    let service_len = take_u16(&mut data)? as usize;
    let service_bytes = take(&mut data, service_len)?;
    let service = if service_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(service_bytes).into_owned())
    };
    let direction = u8_to_direction(take(&mut data, 1)?[0])?;
    let view = u8_to_view(take(&mut data, 1)?[0])?;
    let stream_offset = take_u64(&mut data)?;
    let len = take_u32(&mut data)? as usize;
    let payload = take(&mut data, len)?.to_vec();
    if !data.is_empty() {
        bail!("unexpected record trailer");
    }
    Ok(ContentRecord {
        id,
        flow_id,
        ts_ns,
        service,
        direction,
        view,
        stream_offset,
        data: bytes::Bytes::from(payload),
    })
}

fn read_record_at(path: &Path, offset: u64, max_record_bytes: usize) -> Result<ContentRecord> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut f = BufReader::new(file);
    f.seek(SeekFrom::Start(offset))?;
    read_record(
        &mut f,
        max_record_bytes,
        Some(file_len.saturating_sub(offset)),
    )?
    .map(|v| v.0)
    .context("record missing")
}

fn read_record<R: Read>(
    r: &mut R,
    max_record_bytes: usize,
    available_bytes: Option<u64>,
) -> Result<Option<(ContentRecord, u64)>> {
    let mut hdr = [0u8; 12];
    let mut got = 0usize;
    while got < hdr.len() {
        match r.read(&mut hdr[got..])? {
            0 if got == 0 => return Ok(None),
            0 => bail!("partial record header"),
            n => got += n,
        }
    }
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if magic != RECORD_MAGIC {
        bail!("bad record magic");
    }
    let len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
    if len > max_record_bytes {
        bail!("segment record length {len} exceeds configured maximum {max_record_bytes}");
    }
    if let Some(available_bytes) = available_bytes {
        let encoded_len = 12u64.saturating_add(len as u64);
        if encoded_len > available_bytes {
            bail!(
                "segment record length {len} exceeds remaining file payload bytes {}",
                available_bytes.saturating_sub(12),
            );
        }
    }
    let expected_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    let mut crc = Hasher::new();
    crc.update(&payload);
    if crc.finalize() != expected_crc {
        bail!("record crc mismatch");
    }
    Ok(Some((decode_record(&payload)?, (12 + len) as u64)))
}

/// Recover only the physical tail of the newest segment left by an interrupted
/// writer. Once BAZALT starts, every pre-existing segment is immutable and all
/// normal scans are strict: CRC/magic/encoding errors propagate to callers.
///
/// We truncate only states that can be produced by a crash during append:
/// an incomplete record header or an incomplete final payload at physical EOF.
/// A complete record with a bad magic/CRC/encoding is corruption and fails
/// startup instead of being silently discarded.
fn recover_last_segment_tail(root: &Path, max_record_bytes: usize) -> Result<()> {
    let Some(path) = list_segments(root)?.into_iter().last() else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open newest segment {} for recovery", path.display()))?;
    let file_len = file.metadata()?.len();

    if file_len < HEADER_SIZE {
        drop(file);
        fs::remove_file(&path)
            .with_context(|| format!("remove incomplete segment header {}", path.display()))?;
        tracing::warn!(path=%path.display(), bytes=file_len, "removed crash-incomplete segment header");
        return Ok(());
    }

    read_header(&mut file)
        .with_context(|| format!("invalid newest segment header {}", path.display()))?;
    loop {
        let offset = file.stream_position()?;
        if offset == file_len {
            return Ok(());
        }
        let remaining = file_len.saturating_sub(offset);
        if remaining < 12 {
            file.set_len(offset)?;
            file.sync_data()?;
            tracing::warn!(path=%path.display(), old_bytes=file_len, new_bytes=offset, "truncated crash-incomplete record header");
            return Ok(());
        }

        let mut hdr = [0u8; 12];
        file.read_exact(&mut hdr)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != RECORD_MAGIC {
            bail!(
                "corrupt newest segment {} at offset {offset}: bad record magic",
                path.display()
            );
        }
        let len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if len > max_record_bytes {
            bail!(
                "corrupt newest segment {} at offset {offset}: record length {len} exceeds configured maximum {max_record_bytes}",
                path.display()
            );
        }
        let record_end = offset.saturating_add(12).saturating_add(len as u64);
        if record_end > file_len {
            file.set_len(offset)?;
            file.sync_data()?;
            tracing::warn!(path=%path.display(), old_bytes=file_len, new_bytes=offset, "truncated crash-incomplete record payload");
            return Ok(());
        }

        let expected_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let mut payload = vec![0u8; len];
        file.read_exact(&mut payload)?;
        let mut crc = Hasher::new();
        crc.update(&payload);
        if crc.finalize() != expected_crc {
            bail!(
                "corrupt newest segment {} at offset {offset}: record crc mismatch",
                path.display()
            );
        }
        decode_record(&payload).with_context(|| {
            format!(
                "corrupt newest segment {} at offset {offset}: invalid record encoding",
                path.display()
            )
        })?;
    }
}

pub fn latest_segment_path(root: &Path) -> Result<Option<PathBuf>> {
    Ok(list_segments(root)?.into_iter().last())
}

fn list_segments(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().and_then(|v| v.to_str()) == Some("seg") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn take<'a>(d: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if d.len() < n {
        bail!("truncated field")
    }
    let (a, b) = d.split_at(n);
    *d = b;
    Ok(a)
}
fn take_u16(d: &mut &[u8]) -> Result<u16> {
    Ok(u16::from_le_bytes(take(d, 2)?.try_into().unwrap()))
}
fn take_u32(d: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(take(d, 4)?.try_into().unwrap()))
}
fn take_u64(d: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(take(d, 8)?.try_into().unwrap()))
}
fn direction_to_u8(v: Direction) -> u8 {
    match v {
        Direction::AToB => 0,
        Direction::BToA => 1,
    }
}
fn u8_to_direction(v: u8) -> Result<Direction> {
    match v {
        0 => Ok(Direction::AToB),
        1 => Ok(Direction::BToA),
        _ => bail!("bad direction"),
    }
}
fn view_to_u8(v: ContentView) -> u8 {
    match v {
        ContentView::TcpRaw => 0,
        ContentView::HttpRequestHeaders => 1,
        ContentView::HttpRequestBody => 2,
        ContentView::HttpRequestDecodedBody => 3,
        ContentView::HttpResponseHeaders => 4,
        ContentView::HttpResponseBody => 5,
        ContentView::HttpResponseDecodedBody => 6,
    }
}
fn u8_to_view(v: u8) -> Result<ContentView> {
    match v {
        0 => Ok(ContentView::TcpRaw),
        1 => Ok(ContentView::HttpRequestHeaders),
        2 => Ok(ContentView::HttpRequestBody),
        3 => Ok(ContentView::HttpRequestDecodedBody),
        4 => Ok(ContentView::HttpResponseHeaders),
        5 => Ok(ContentView::HttpResponseBody),
        6 => Ok(ContentView::HttpResponseDecodedBody),
        _ => bail!("bad view"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    fn write_record_envelope(
        mut out: impl Write,
        record: &ContentRecord,
        corrupt_crc: bool,
    ) -> usize {
        let payload = encode_record(record).unwrap();
        let mut crc = Hasher::new();
        crc.update(&payload);
        let checksum = if corrupt_crc {
            crc.finalize() ^ u32::MAX
        } else {
            crc.finalize()
        };
        out.write_all(&RECORD_MAGIC.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        out.write_all(&checksum.to_le_bytes()).unwrap();
        out.write_all(&payload).unwrap();
        12 + payload.len()
    }

    #[test]
    fn record_roundtrip() {
        let r = ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            ts_ns: 123,
            service: Some("http".into()),
            direction: Direction::AToB,
            view: ContentView::HttpRequestBody,
            stream_offset: 42,
            data: bytes::Bytes::from_static(b"abc"),
        };
        let encoded = encode_record(&r).unwrap();
        let d = decode_record(&encoded).unwrap();
        assert_eq!(d.id, r.id);
        assert_eq!(d.data.as_ref(), b"abc");
        assert_eq!(d.stream_offset, 42);
    }

    #[test]
    fn append_updates_the_bounded_segment_pressure_gauge() {
        let dir = tempdir().unwrap();
        let metrics = Metrics::shared();
        let (command_tx, _command_rx) = crossbeam_channel::bounded(8);
        let metadata_tx = crate::storage::MetadataSink { tx: command_tx };
        let store = SegmentStore::open(
            dir.path().to_path_buf(),
            1024 * 1024,
            512 * 1024,
            16 * 1024 * 1024,
            1,
            metrics.clone(),
            metadata_tx,
        )
        .unwrap();
        store
            .append(ContentRecord {
                id: Uuid::new_v4(),
                flow_id: Uuid::new_v4(),
                ts_ns: 1,
                service: None,
                direction: Direction::AToB,
                view: ContentView::TcpRaw,
                stream_offset: 0,
                data: bytes::Bytes::from_static(b"payload"),
            })
            .unwrap();
        assert_eq!(metrics.segment_queue_capacity.load(Ordering::Relaxed), 1);
        assert!(metrics.segment_queue_depth.load(Ordering::Relaxed) <= 1);
        store.shutdown_and_join().unwrap();
    }

    #[test]
    fn store_writes_index_and_reads_by_location() {
        let dir = tempdir().unwrap();
        let m = Metrics::shared();
        let (command_tx, command_rx) = crossbeam_channel::bounded(8);
        let metadata_tx = crate::storage::MetadataSink { tx: command_tx };
        let store = SegmentStore::open(
            dir.path().to_path_buf(),
            1024 * 1024,
            512 * 1024,
            16 * 1024 * 1024,
            16,
            m,
            metadata_tx,
        )
        .unwrap();
        let r = ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            ts_ns: 1,
            service: None,
            direction: Direction::AToB,
            view: ContentView::TcpRaw,
            stream_offset: 0,
            data: bytes::Bytes::from_static(b"payload"),
        };
        let id = r.id;
        store.append(r).unwrap();
        let index = match command_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
        {
            crate::storage::MetadataCommand::Event(MetadataEvent::ContentIndex(v)) => v,
            other => panic!("unexpected metadata command: {other:?}"),
        };
        assert_eq!(index.content_id, id);
        let got = store
            .read_at(Path::new(&index.segment_path), index.segment_offset)
            .unwrap();
        assert_eq!(got.data.as_ref(), b"payload");
    }

    #[test]
    fn record_length_limit_is_checked_before_payload_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&RECORD_MAGIC.to_le_bytes());
        encoded.extend_from_slice(&1024u32.to_le_bytes());
        encoded.extend_from_slice(&0u32.to_le_bytes());
        let available = encoded.len() as u64;
        let err = read_record(&mut Cursor::new(encoded), 64, Some(available)).unwrap_err();
        assert!(err.to_string().contains("exceeds configured maximum"));
    }

    #[test]
    fn record_length_is_checked_against_physical_file_before_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&RECORD_MAGIC.to_le_bytes());
        encoded.extend_from_slice(&1024u32.to_le_bytes());
        encoded.extend_from_slice(&0u32.to_le_bytes());
        let available = encoded.len() as u64;
        let err = read_record(&mut Cursor::new(encoded), 2048, Some(available)).unwrap_err();
        assert!(err
            .to_string()
            .contains("exceeds remaining file payload bytes"));
    }

    #[test]
    fn strict_scan_propagates_interior_corruption() {
        let dir = tempdir().unwrap();
        let m = Metrics::shared();
        let (command_tx, _command_rx) = crossbeam_channel::bounded(8);
        let metadata_tx = crate::storage::MetadataSink { tx: command_tx };
        let store = SegmentStore::open(
            dir.path().to_path_buf(),
            1024 * 1024,
            512 * 1024,
            16 * 1024 * 1024,
            16,
            m,
            metadata_tx,
        )
        .unwrap();

        let path = dir.path().join("zzz-corrupt.seg");
        let mut file = File::create(&path).unwrap();
        write_header(&mut file).unwrap();
        let r = ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            ts_ns: 7,
            service: None,
            direction: Direction::AToB,
            view: ContentView::TcpRaw,
            stream_offset: 0,
            data: bytes::Bytes::from_static(b"payload"),
        };
        write_record_envelope(&mut file, &r, true);
        file.sync_all().unwrap();

        let err = store.scan_path(&path, |_| Ok(())).unwrap_err();
        assert!(err.to_string().contains("corrupt segment"));
        store.shutdown_and_join().unwrap();
    }

    #[test]
    fn startup_recovery_truncates_only_incomplete_tail() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment-recovery.seg");
        let mut file = File::create(&path).unwrap();
        write_header(&mut file).unwrap();
        let r = ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            ts_ns: 9,
            service: None,
            direction: Direction::AToB,
            view: ContentView::TcpRaw,
            stream_offset: 0,
            data: bytes::Bytes::from_static(b"ok"),
        };
        let record_bytes = write_record_envelope(&mut file, &r, false);
        file.write_all(&RECORD_MAGIC.to_le_bytes()[..3]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        recover_last_segment_tail(dir.path(), 512 * 1024).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            HEADER_SIZE + record_bytes as u64
        );
    }

    #[test]
    fn startup_recovery_refuses_complete_bad_crc_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment-corrupt.seg");
        let mut file = File::create(&path).unwrap();
        write_header(&mut file).unwrap();
        let r = ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            ts_ns: 10,
            service: None,
            direction: Direction::AToB,
            view: ContentView::TcpRaw,
            stream_offset: 0,
            data: bytes::Bytes::from_static(b"bad"),
        };
        write_record_envelope(&mut file, &r, true);
        file.sync_all().unwrap();
        drop(file);
        let before = fs::metadata(&path).unwrap().len();

        let err = recover_last_segment_tail(dir.path(), 512 * 1024).unwrap_err();
        assert!(err.to_string().contains("record crc mismatch"));
        assert_eq!(fs::metadata(&path).unwrap().len(), before);
    }
}
