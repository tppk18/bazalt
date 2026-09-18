use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    thread,
};

use anyhow::Result;
use crossbeam_channel::{bounded, Sender};
use uuid::Uuid;

use super::CapturedFrame;

const RAW_QUEUE: usize = 8192;
const PCAP_GLOBAL_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond pcap magic
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00, // thiszone
    0x00, 0x00, 0x00, 0x00, // sigfigs
    0xff, 0xff, 0x00, 0x00, // snaplen 65535
    0x01, 0x00, 0x00, 0x00, // LINKTYPE_ETHERNET
];

pub fn spawn_raw_writer(
    root: PathBuf,
    queue_id: u32,
    max_bytes: u64,
) -> Result<(Sender<CapturedFrame>, thread::JoinHandle<()>)> {
    fs::create_dir_all(&root)?;
    let (tx, rx) = bounded::<CapturedFrame>(RAW_QUEUE);
    let handle = thread::Builder::new()
        .name(format!("raw-pcap-{queue_id}"))
        .spawn(move || {
            let mut writer = match PcapWriter::new(&root, queue_id, max_bytes) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(queue_id, error=%e, "raw PCAP writer init failed");
                    return;
                }
            };
            while let Ok(frame) = rx.recv() {
                if let Err(e) = writer.write(&frame) {
                    tracing::error!(queue_id, error=%e, "raw PCAP write failed");
                }
            }
            let _ = writer.flush_sync();
        })?;
    Ok((tx, handle))
}

struct PcapWriter {
    root: PathBuf,
    queue_id: u32,
    max_bytes: u64,
    file: BufWriter<File>,
    bytes: u64,
}

impl PcapWriter {
    fn new(root: &Path, queue_id: u32, max_bytes: u64) -> Result<Self> {
        let mut file = open_file(root, queue_id)?;
        file.write_all(&PCAP_GLOBAL_HEADER)?;
        Ok(Self {
            root: root.to_path_buf(),
            queue_id,
            max_bytes: max_bytes.max(1024 * 1024),
            file,
            bytes: PCAP_GLOBAL_HEADER.len() as u64,
        })
    }

    fn rotate(&mut self) -> Result<()> {
        self.flush_sync()?;
        let mut file = open_file(&self.root, self.queue_id)?;
        file.write_all(&PCAP_GLOBAL_HEADER)?;
        self.file = file;
        self.bytes = PCAP_GLOBAL_HEADER.len() as u64;
        Ok(())
    }

    fn write(&mut self, frame: &CapturedFrame) -> Result<()> {
        let incl = frame.data.len().min(u32::MAX as usize) as u32;
        let record_len = 16u64 + incl as u64;
        if self.bytes > PCAP_GLOBAL_HEADER.len() as u64
            && self.bytes.saturating_add(record_len) > self.max_bytes
        {
            self.rotate()?;
        }
        let sec = frame.ts_ns / 1_000_000_000;
        let usec = (frame.ts_ns % 1_000_000_000) / 1000;
        self.file
            .write_all(&(sec.min(u32::MAX as u64) as u32).to_le_bytes())?;
        self.file.write_all(&(usec as u32).to_le_bytes())?;
        self.file.write_all(&incl.to_le_bytes())?;
        self.file
            .write_all(&(frame.wire_len.min(u32::MAX as usize) as u32).to_le_bytes())?;
        self.file.write_all(&frame.data[..incl as usize])?;
        self.bytes += record_len;
        Ok(())
    }

    fn flush_sync(&mut self) -> Result<()> {
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        Ok(())
    }
}

fn open_file(root: &Path, queue_id: u32) -> Result<BufWriter<File>> {
    let path = root.join(format!(
        "raw-q{}-{}-{}.pcap",
        queue_id,
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
        Uuid::new_v4()
    ));
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    Ok(BufWriter::with_capacity(4 * 1024 * 1024, file))
}
