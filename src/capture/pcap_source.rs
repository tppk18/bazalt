use anyhow::{Context, Result};
use bytes::Bytes;
use pcap::{Active, Capture, Offline};

use crate::{capture::CapturedFrame, config::Config};

use super::{interface_mac, FrameSource, PortFilterMode, SourceStats};

pub struct PcapLiveSource {
    cap: Capture<Active>,
    local_mac: Option<[u8; 6]>,
}

impl PcapLiveSource {
    pub fn open(cfg: &Config) -> Result<Self> {
        let cap = Capture::from_device(cfg.interface.as_str())
            .context("pcap device lookup")?
            .promisc(true)
            // libpcap defaults to roughly a 1 MB capture buffer, which is too
            // small for A/D bursts. Keep packet batching enabled and give the
            // kernel enough room to absorb short downstream stalls.
            .buffer_size(64 * 1024 * 1024)
            .snaplen(cfg.snaplen)
            .timeout(10)
            .open()
            .context("open live pcap capture")?;
        Ok(Self {
            cap,
            local_mac: interface_mac(&cfg.interface),
        })
    }
}

impl FrameSource for PcapLiveSource {
    fn configure_port_filter(
        &mut self,
        ports: &[u16],
        extra: Option<&str>,
    ) -> Result<PortFilterMode> {
        let requested = live_port_filter_expression(ports, extra, self.local_mac);
        match self.cap.filter(&requested, true) {
            Ok(()) => Ok(PortFilterMode::Optimized),
            Err(primary) => {
                // Never leave a stale restrictive filter active after a
                // dynamic service update.  Widen capture and let the cheap
                // userspace directional classifier remain authoritative.
                let fail_open = live_fail_open_expression();
                self.cap.filter(&fail_open, true).with_context(|| {
                    format!(
                        "service BPF update failed ({primary}); fail-open BPF install also failed"
                    )
                })?;
                tracing::warn!(
                    error = %primary,
                    "dynamic service BPF rejected; installed broad fail-open capture filter"
                );
                Ok(PortFilterMode::FailOpen)
            }
        }
    }

    fn receive_batch(&mut self, max: usize, out: &mut Vec<CapturedFrame>) -> Result<usize> {
        // pcap_dispatch processes one kernel/libpcap buffer per syscall instead
        // of issuing next_packet() once per frame. The pcap crate explicitly
        // recommends this path for high-traffic capture because it reduces the
        // chance that the capture buffer overflows between reads.
        let n = self.cap.dispatch(Some(max), |packet| {
            let ts = packet.header.ts;
            let ts_ns = (ts.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add((ts.tv_usec as u64).saturating_mul(1_000));
            out.push(CapturedFrame {
                ts_ns,
                wire_len: packet.header.len as usize,
                data: Bytes::copy_from_slice(packet.data),
            });
        })?;
        Ok(n)
    }

    fn stats(&mut self) -> Result<Option<SourceStats>> {
        let stats = self.cap.stats().context("read live pcap statistics")?;
        Ok(Some(SourceStats {
            dropped: (stats.dropped as u64).saturating_add(stats.if_dropped as u64),
            invalid_descs: 0,
        }))
    }
}

pub struct PcapFileSource {
    cap: Capture<Offline>,
    exhausted: bool,
}

impl PcapFileSource {
    pub fn open(cfg: &Config) -> Result<Self> {
        let path = cfg.pcap_file.as_ref().context("missing pcap file")?;
        let cap = Capture::from_file(path).with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            cap,
            exhausted: false,
        })
    }
}

impl FrameSource for PcapFileSource {
    fn configure_port_filter(
        &mut self,
        ports: &[u16],
        extra: Option<&str>,
    ) -> Result<PortFilterMode> {
        self.cap
            .filter(&port_filter_expression(ports, extra), true)
            .context("install dynamic offline BPF filter")?;
        Ok(PortFilterMode::Optimized)
    }

    fn receive_batch(&mut self, max: usize, out: &mut Vec<CapturedFrame>) -> Result<usize> {
        if self.exhausted {
            return Ok(0);
        }
        for _ in 0..max {
            match self.cap.next_packet() {
                Ok(packet) => {
                    let ts = packet.header.ts;
                    let ts_ns = (ts.tv_sec as u64)
                        .saturating_mul(1_000_000_000)
                        .saturating_add((ts.tv_usec as u64).saturating_mul(1_000));
                    out.push(CapturedFrame {
                        ts_ns,
                        wire_len: packet.header.len as usize,
                        data: Bytes::copy_from_slice(packet.data),
                    });
                }
                Err(pcap::Error::NoMorePackets) => {
                    self.exhausted = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out.len())
    }
}

fn port_filter_expression(ports: &[u16], extra: Option<&str>) -> String {
    if ports.is_empty() {
        // The authoritative service allow-list is empty, so no reconstructed
        // packet can be admitted. Drop everything in-kernel instead of letting
        // fragment/tunnel bypass clauses become an unauthenticated work source.
        return "ip and not ip".to_owned();
    }
    let ports_expr = ports
        .iter()
        .map(|p| format!("port {p}"))
        .collect::<Vec<_>>()
        .join(" or ");

    // Non-first fragments do not contain TCP/UDP ports. If early BPF is
    // enabled, explicitly admit IPv4 fragments and IPv6 fragment-header
    // traffic so userspace can make the service-port decision *after* bounded
    // reassembly. `protochain` is a libpcap primitive and handles extension
    // headers before the IPv6 Fragment header.
    let fragments_expr = "(ip and (ip[6:2] & 0x3fff != 0)) or (ip6 protochain 44)";
    // The service port may exist only on the *inner* packet. Preserve supported
    // encapsulations through optional early BPF; userspace performs the actual
    // service-port decision after decapsulation/reassembly. Early BPF is opt-in,
    // so this bounded over-capture is preferable to silently losing tunnelled A/D
    // traffic.
    let tunnels_expr = "(udp port 4789 or udp port 8472) or (ip proto 47) or (ip6 protochain 47) or (ip proto 4) or (ip6 protochain 4) or (ip proto 41) or (ip6 protochain 41)";
    // Classic BPF transport offsets are not uniformly VLAN-aware across
    // libpcap/kernel combinations. Preserve all tagged frames and apply the
    // authoritative service allow-list after bounded userspace decoding. Early
    // BPF is opt-in, so bounded over-capture is safer than silent VLAN loss.
    let tagged_expr = "(ether proto 0x8100) or (ether proto 0x88a8) or (ether proto 0x9100) or (ether proto 0x9200)";
    match extra.map(str::trim).filter(|v| !v.is_empty()) {
        // A custom expression such as `tcp` cannot be evaluated on non-first
        // fragments or on an encapsulated inner packet. Apply it only to the
        // normal service-port clause.
        Some(extra) => format!(
            "(({ports_expr}) and ({extra})) or {fragments_expr} or {tunnels_expr} or {tagged_expr}"
        ),
        None => format!("({ports_expr}) or {fragments_expr} or {tunnels_expr} or {tagged_expr}"),
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Linux live-capture service filter with directional semantics matching the
/// userspace gate.  Remote ingress is selected by destination port; responses
/// emitted by this host are selected by source port and local source MAC.
///
/// IPv6 is deliberately admitted broadly here.  Some kernels reject classic
/// BPF programs generated for `protochain`; correctness is more important than
/// an IPv6 micro-optimization and userspace still applies the exact service
/// policy after decoding.
fn live_port_filter_expression(
    ports: &[u16],
    extra: Option<&str>,
    local_mac: Option<[u8; 6]>,
) -> String {
    if ports.is_empty() {
        return "ip and not ip".to_owned();
    }

    let dst_ports = ports
        .iter()
        .map(|p| format!("dst port {p}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let src_ports = ports
        .iter()
        .map(|p| format!("src port {p}"))
        .collect::<Vec<_>>()
        .join(" or ");

    let service = match local_mac {
        Some(mac) => format!(
            "({dst_ports}) or ((ether src {}) and ({src_ports}))",
            format_mac(mac)
        ),
        // If L2 identity is unavailable, preserve bidirectional service
        // fidelity; the userspace classifier still rejects hostile remote
        // source-port collisions before full decode.
        None => format!("({dst_ports}) or ({src_ports})"),
    };

    let normal = match extra.map(str::trim).filter(|v| !v.is_empty()) {
        Some(extra) => format!("(({service}) and ({extra}))"),
        None => format!("({service})"),
    };
    let fragments = "(ip and (ip[6:2] & 0x3fff != 0))";
    let tunnels = "(udp dst port 4789 or udp dst port 8472) or (ip proto 47) or (ip proto 4) or (ip proto 41)";
    let tagged = "(ether proto 0x8100) or (ether proto 0x88a8) or (ether proto 0x9100) or (ether proto 0x9200)";
    format!("{normal} or {fragments} or {tunnels} or {tagged} or ip6")
}

fn live_fail_open_expression() -> String {
    // Keep this intentionally simple so a kernel that rejected an optimized
    // service filter is very likely to accept the fallback.  Non-IP traffic is
    // irrelevant to the current decoder and can stay excluded.
    "ip or ip6 or (ether proto 0x8100) or (ether proto 0x88a8) or (ether proto 0x9100) or (ether proto 0x9200)".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{live_fail_open_expression, live_port_filter_expression, port_filter_expression};

    #[test]
    fn empty_service_set_drops_everything_even_with_bypass_protocols() {
        assert_eq!(port_filter_expression(&[], None), "ip and not ip");
        assert_eq!(port_filter_expression(&[], Some("tcp")), "ip and not ip");
    }

    #[test]
    fn builds_service_port_bpf() {
        let f = port_filter_expression(&[80, 443], None);
        assert!(f.contains("port 80 or port 443"));
        assert!(f.contains("ip[6:2] & 0x3fff"));
        assert!(f.contains("ip6 protochain 44"));
        assert!(f.contains("udp port 4789"));
        assert!(f.contains("ip proto 47"));
        assert!(f.contains("ether proto 0x8100"));
        let e = port_filter_expression(&[8080], Some("tcp"));
        assert!(e.contains("((port 8080) and (tcp))"));
        assert!(e.contains("ip[6:2] & 0x3fff"));
        assert!(e.contains("ip6 protochain 44"));
        assert!(e.contains("udp port 4789"));
        assert!(e.contains("ip6 protochain 47"));
        assert!(e.contains("ether proto 0x88a8"));
    }

    #[test]
    fn live_filter_is_directional_when_local_mac_is_known() {
        let f = live_port_filter_expression(
            &[8000],
            None,
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        );
        assert!(f.contains("dst port 8000"));
        assert!(f.contains("src port 8000"));
        assert!(f.contains("ether src 02:00:00:00:00:01"));
        assert!(!f.contains("protochain"));
        assert!(f.contains("or ip6"));
    }

    #[test]
    fn live_filter_has_simple_fail_open_fallback() {
        let f = live_fail_open_expression();
        assert!(f.contains("ip or ip6"));
        assert!(!f.contains("port "));
    }
}
