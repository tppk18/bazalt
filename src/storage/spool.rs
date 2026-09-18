use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};

use crate::model::MetadataEvent;

#[derive(Clone)]
pub(crate) struct MetadataSpool {
    root: Arc<PathBuf>,
    max_bytes: u64,
    bytes: Arc<AtomicU64>,
}

impl MetadataSpool {
    pub(crate) fn open(root: PathBuf, max_bytes: u64) -> Result<Self> {
        if max_bytes == 0 {
            anyhow::bail!("metadata spool maximum must be greater than zero");
        }
        fs::create_dir_all(&root)
            .with_context(|| format!("create metadata spool {}", root.display()))?;
        // A .tmp file can only be left before the atomic rename. It is not a
        // committed batch, so remove stale crash artifacts instead of letting
        // them consume unaccounted disk indefinitely.
        for entry in fs::read_dir(&root)
            .with_context(|| format!("list metadata spool {}", root.display()))?
        {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if name.starts_with('.') && name.contains(".tmp-") {
                fs::remove_file(&path).with_context(|| {
                    format!("remove stale metadata spool temp {}", path.display())
                })?;
            }
        }
        let mut bytes = 0u64;
        for (_, path) in list_entries(&root)? {
            bytes = bytes.saturating_add(fs::metadata(path)?.len());
        }
        if bytes > max_bytes {
            anyhow::bail!(
                "metadata spool already contains {bytes} bytes, above configured maximum {max_bytes}"
            );
        }
        Ok(Self {
            root: Arc::new(root),
            max_bytes,
            bytes: Arc::new(AtomicU64::new(bytes)),
        })
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Acquire)
    }

    pub(crate) fn entries(&self) -> Result<Vec<(u64, PathBuf)>> {
        list_entries(&self.root)
    }

    pub(crate) fn max_sequence(&self) -> Result<u64> {
        Ok(self.entries()?.last().map(|(seq, _)| *seq).unwrap_or(0))
    }

    pub(crate) fn first_sequence(&self) -> Result<Option<u64>> {
        Ok(self.entries()?.first().map(|(seq, _)| *seq))
    }

    pub(crate) fn path_for_sequence(&self, sequence: u64) -> PathBuf {
        self.root.join(format!("{sequence:020}.json"))
    }

    pub(crate) fn append(&self, sequence: u64, events: &[MetadataEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_vec(events).context("serialize metadata spool batch")?;
        let payload_len = payload.len() as u64;
        let current = self.bytes.load(Ordering::Acquire);
        if current.saturating_add(payload_len) > self.max_bytes {
            anyhow::bail!(
                "metadata spool quota exceeded: current={current} batch={payload_len} max={} ",
                self.max_bytes
            );
        }

        let final_path = self.path_for_sequence(sequence);
        let tmp_path = self.root.join(format!(
            ".{sequence:020}.tmp-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result = (|| -> Result<()> {
            let mut file = File::create(&tmp_path)
                .with_context(|| format!("create metadata spool temp {}", tmp_path.display()))?;
            file.write_all(&payload)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp_path, &final_path).with_context(|| {
                format!(
                    "publish metadata spool batch {} -> {}",
                    tmp_path.display(),
                    final_path.display()
                )
            })?;
            // Persist the directory entry as part of the local durability barrier.
            File::open(self.root.as_path())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
            return result;
        }
        self.bytes.fetch_add(payload_len, Ordering::Release);
        Ok(())
    }

    pub(crate) fn read(&self, path: &Path) -> Result<Vec<MetadataEvent>> {
        let payload =
            fs::read(path).with_context(|| format!("read metadata spool {}", path.display()))?;
        serde_json::from_slice(&payload)
            .with_context(|| format!("decode metadata spool {}", path.display()))
    }

    pub(crate) fn remove(&self, path: &Path) -> Result<()> {
        let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        fs::remove_file(path)
            .with_context(|| format!("remove metadata spool {}", path.display()))?;
        File::open(self.root.as_path())?.sync_all()?;
        let _ = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(len))
            });
        Ok(())
    }
}

fn list_entries(root: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut out = Vec::new();
    for entry in
        fs::read_dir(root).with_context(|| format!("list metadata spool {}", root.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(sequence) = stem.parse::<u64>() else {
            continue;
        };
        out.push((sequence, path));
    }
    out.sort_by_key(|(sequence, _)| *sequence);
    Ok(out)
}
