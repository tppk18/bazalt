use std::{
    ffi::CString,
    os::raw::{c_char, c_int, c_uint},
    ptr::NonNull,
};

use anyhow::{bail, Result};
use bytes::BytesMut;

use super::{unix_now_ns, CapturedFrame, FrameSource, SourceStats};

const MAX_BATCH: usize = 256;
const XDP_PKT_CONTD: u32 = 1;
const AF_XDP_FRAME_SIZE: usize = 2048;

#[repr(C)]
#[derive(Clone, Copy)]
struct PmXdpFrame {
    data: *const u8,
    len: u32,
    addr: u64,
    options: u32,
}

#[repr(C)]
struct PmXdpHandle {
    _opaque: [u8; 0],
}

extern "C" {
    fn pm_xdp_open(
        ifname: *const c_char,
        queue_id: c_uint,
        prefer_zerocopy: c_int,
    ) -> *mut PmXdpHandle;
    fn pm_xdp_fd(handle: *mut PmXdpHandle) -> c_int;
    fn pm_xdp_multibuf_enabled(handle: *mut PmXdpHandle) -> c_int;
    fn pm_xdp_peek(handle: *mut PmXdpHandle, frames: *mut PmXdpFrame, max_frames: c_uint) -> c_int;
    fn pm_xdp_release(handle: *mut PmXdpHandle, frames: *const PmXdpFrame, count: c_uint) -> c_int;
    fn pm_xdp_stats(
        handle: *mut PmXdpHandle,
        rx_dropped: *mut u64,
        rx_invalid_descs: *mut u64,
    ) -> c_int;
    fn pm_xdp_last_error() -> *const c_char;
    fn pm_xdp_close(handle: *mut PmXdpHandle);
    fn poll(fds: *mut libc::pollfd, nfds: libc::nfds_t, timeout: c_int) -> c_int;
}

pub struct AfXdpSource {
    handle: NonNull<PmXdpHandle>,
    fd: c_int,
    frames: [PmXdpFrame; MAX_BATCH],
    pending_multibuf: BytesMut,
    pending_wire_len: usize,
}

unsafe impl Send for AfXdpSource {}

impl AfXdpSource {
    pub fn open(interface: &str, queue_id: u32) -> Result<Self> {
        let ifname = CString::new(interface)?;
        let raw = unsafe { pm_xdp_open(ifname.as_ptr(), queue_id, 1) };
        let handle = NonNull::new(raw).ok_or_else(|| anyhow::anyhow!(last_error()))?;
        let fd = unsafe { pm_xdp_fd(handle.as_ptr()) };
        if fd < 0 {
            unsafe { pm_xdp_close(handle.as_ptr()) };
            bail!("AF_XDP returned invalid fd: {}", last_error());
        }
        let multibuf_enabled = unsafe { pm_xdp_multibuf_enabled(handle.as_ptr()) } != 0;
        if !multibuf_enabled {
            let mtu_path = format!("/sys/class/net/{interface}/mtu");
            if let Ok(raw_mtu) = std::fs::read_to_string(&mtu_path) {
                if let Ok(mtu) = raw_mtu.trim().parse::<usize>() {
                    // Ethernet header + up to two VLAN tags. If this cannot fit
                    // in one UMEM frame and XDP_USE_SG was unavailable, AF_XDP
                    // would drop the packet before Rust can stitch descriptors.
                    if mtu.saturating_add(22) > AF_XDP_FRAME_SIZE {
                        unsafe { pm_xdp_close(handle.as_ptr()) };
                        bail!(
                            "AF_XDP multi-buffer unavailable for MTU {mtu}; refusing lossy single-buffer capture"
                        );
                    }
                }
            }
        }
        Ok(Self {
            handle,
            fd,
            frames: [PmXdpFrame {
                data: std::ptr::null(),
                len: 0,
                addr: 0,
                options: 0,
            }; MAX_BATCH],
            pending_multibuf: BytesMut::new(),
            pending_wire_len: 0,
        })
    }
}

impl Drop for AfXdpSource {
    fn drop(&mut self) {
        unsafe { pm_xdp_close(self.handle.as_ptr()) };
    }
}

impl FrameSource for AfXdpSource {
    fn receive_batch(&mut self, max: usize, out: &mut Vec<CapturedFrame>) -> Result<usize> {
        let out_before = out.len();
        let max = max.min(MAX_BATCH) as u32;

        // Fast path: peek first and avoid one poll(2) syscall per non-empty RX
        // batch. Poll is only used when the ring is empty.
        let mut n = unsafe { pm_xdp_peek(self.handle.as_ptr(), self.frames.as_mut_ptr(), max) };
        if n < 0 {
            bail!("AF_XDP receive: {}", last_error());
        }
        if n == 0 {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { poll(&mut pfd, 1, 10) };
            if polled < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if polled == 0 {
                return Ok(0);
            }
            n = unsafe { pm_xdp_peek(self.handle.as_ptr(), self.frames.as_mut_ptr(), max) };
            if n < 0 {
                bail!("AF_XDP receive after poll: {}", last_error());
            }
        }
        let n = n as usize;
        if n == 0 {
            return Ok(0);
        }

        // Copy the whole descriptor batch into one userspace allocation, then
        // publish zero-copy Bytes slices into the pipeline. This returns every
        // UMEM frame immediately without paying one allocator call per packet.
        let total = self.frames[..n]
            .iter()
            .filter(|d| !d.data.is_null())
            .map(|d| d.len as usize)
            .sum();
        let mut batch = BytesMut::with_capacity(total);
        let mut ranges = [(0usize, 0usize); MAX_BATCH];
        for (i, desc) in self.frames[..n].iter().enumerate() {
            if desc.data.is_null() || desc.len == 0 {
                continue;
            }
            let data = unsafe { std::slice::from_raw_parts(desc.data, desc.len as usize) };
            let start = batch.len();
            batch.extend_from_slice(data);
            ranges[i] = (start, data.len());
        }
        let batch = batch.freeze();
        let ts_ns = unix_now_ns();
        for (i, (start, len)) in ranges[..n].iter().copied().enumerate() {
            if len == 0 {
                continue;
            }
            let continued = self.frames[i].options & XDP_PKT_CONTD != 0;
            if self.pending_multibuf.is_empty() && !continued {
                out.push(CapturedFrame {
                    ts_ns,
                    wire_len: len,
                    data: batch.slice(start..start + len),
                });
            } else {
                self.pending_multibuf
                    .extend_from_slice(&batch[start..start + len]);
                self.pending_wire_len = self.pending_wire_len.saturating_add(len);
                if !continued {
                    out.push(CapturedFrame {
                        ts_ns,
                        wire_len: std::mem::take(&mut self.pending_wire_len),
                        data: self.pending_multibuf.split().freeze(),
                    });
                }
            }
        }

        let rc = unsafe { pm_xdp_release(self.handle.as_ptr(), self.frames.as_ptr(), n as u32) };
        if rc < 0 {
            bail!("AF_XDP recycle: {}", last_error());
        }
        Ok(out.len() - out_before)
    }

    fn stats(&mut self) -> Result<Option<SourceStats>> {
        let mut dropped = 0u64;
        let mut invalid_descs = 0u64;
        let rc = unsafe {
            pm_xdp_stats(
                self.handle.as_ptr(),
                &mut dropped as *mut u64,
                &mut invalid_descs as *mut u64,
            )
        };
        if rc < 0 {
            bail!("AF_XDP statistics: {}", last_error());
        }
        Ok(Some(SourceStats {
            dropped,
            invalid_descs,
        }))
    }
}

fn last_error() -> String {
    unsafe {
        let ptr = pm_xdp_last_error();
        if ptr.is_null() {
            return "unknown libxdp error".to_owned();
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}
