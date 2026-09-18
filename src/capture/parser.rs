use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{bail, Result};
use bytes::Bytes;

use crate::{
    config::Config,
    metrics::Metrics,
    model::{FlowKey, ParsedPacket, TcpFlags, TransportProtocol},
};

use super::{
    fragment::{FragmentInsert, FragmentKey, SharedFragmentCache},
    CapturedFrame,
};

const MAX_TUNNEL_DEPTH: usize = 3;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_TEB: u16 = 0x6558;

#[derive(Debug)]
pub enum DecodeOutcome {
    Packet(ParsedPacket),
    PendingFragment,
    Ignored,
}

#[derive(Debug)]
enum InnerOutcome {
    Packet(ParsedPacket),
    PendingFragment,
    Ignored,
}

/// Stateful per-capture-worker decoder. Fragment state is shared across capture
/// workers so fragments remain reassemblable even when NIC RSS distributes
/// them across RX queues. Ordinary unfragmented traffic never touches a lock.
pub struct PacketDecoder {
    fragments: SharedFragmentCache,
    metrics: Option<Arc<Metrics>>,
    tunnel_decapsulation: bool,
}

impl PacketDecoder {
    pub fn new(cfg: &Config, metrics: Arc<Metrics>, fragments: SharedFragmentCache) -> Self {
        Self {
            fragments,
            metrics: Some(metrics),
            tunnel_decapsulation: cfg.tunnel_decapsulation,
        }
    }

    fn stateless() -> Self {
        Self {
            fragments: SharedFragmentCache::new(64 * 1024, 64, std::time::Duration::from_secs(1)),
            metrics: None,
            tunnel_decapsulation: true,
        }
    }

    pub fn decode(&mut self, frame: CapturedFrame) -> Result<DecodeOutcome> {
        let outcome = self.decode_ethernet_bytes(frame.ts_ns, frame.wire_len, frame.data, 0, 0)?;
        Ok(match outcome {
            InnerOutcome::Packet(packet) => DecodeOutcome::Packet(packet),
            InnerOutcome::PendingFragment => DecodeOutcome::PendingFragment,
            InnerOutcome::Ignored => DecodeOutcome::Ignored,
        })
    }

    fn decode_ethernet_bytes(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        frame: Bytes,
        inherited_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        if depth > MAX_TUNNEL_DEPTH {
            return Ok(InnerOutcome::Ignored);
        }
        if frame.len() < 14 {
            self.mark_truncated();
            bail!("truncated ethernet header");
        }
        let mut l3_offset = 14usize;
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let mut domain = inherited_domain;

        // VLAN/QinQ is cheap to parse and identity is retained in FlowKey. Four
        // tags covers ordinary provider stacking while keeping a strict bound.
        for _ in 0..4 {
            if matches!(ethertype, 0x8100 | 0x88a8 | 0x9100 | 0x9200) {
                if frame.len() < l3_offset + 4 {
                    self.mark_truncated();
                    bail!("truncated vlan header");
                }
                let tci = u16::from_be_bytes([frame[l3_offset], frame[l3_offset + 1]]);
                domain = mix_domain(domain, 0x564c_414e, (tci & 0x0fff) as u64);
                ethertype = u16::from_be_bytes([frame[l3_offset + 2], frame[l3_offset + 3]]);
                l3_offset += 4;
            } else {
                break;
            }
        }

        let l3 = frame.slice(l3_offset..);
        match ethertype {
            ETHERTYPE_IPV4 => self.decode_ipv4(ts_ns, wire_len, l3, domain, depth),
            ETHERTYPE_IPV6 => self.decode_ipv6(ts_ns, wire_len, l3, domain, depth),
            _ => Ok(InnerOutcome::Ignored),
        }
    }

    fn decode_ipv4(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        packet: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        if packet.len() < 20 {
            self.mark_truncated();
            bail!("truncated ipv4 header");
        }
        if packet[0] >> 4 != 4 {
            bail!("invalid ipv4 version");
        }
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if ihl < 20 {
            bail!("invalid ipv4 ihl");
        }
        if packet.len() < ihl {
            self.mark_truncated();
            bail!("truncated ipv4 options/header");
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len < ihl {
            bail!("invalid ipv4 total length");
        }
        if total_len > packet.len() {
            self.mark_truncated();
            bail!(
                "truncated ipv4 packet: declared {total_len}, captured {}",
                packet.len()
            );
        }

        let src = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let dst = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        let protocol = packet[9];
        let frag = u16::from_be_bytes([packet[6], packet[7]]);
        let offset = ((frag & 0x1fff) as usize) * 8;
        let more = frag & 0x2000 != 0;
        let payload = packet.slice(ihl..total_len);

        if offset != 0 || more {
            self.fragment_received();
            let key = FragmentKey {
                version: 4,
                l2_domain,
                src,
                dst,
                id: u16::from_be_bytes([packet[4], packet[5]]) as u32,
                next_header: protocol,
            };
            let (result, maintenance) = self.fragments.insert(key, offset, more, payload, wire_len);
            self.apply_fragment_maintenance(maintenance);
            return match result {
                FragmentInsert::Pending => Ok(InnerOutcome::PendingFragment),
                FragmentInsert::DroppedOverlap => {
                    self.fragment_overlap_drop();
                    Ok(InnerOutcome::Ignored)
                }
                FragmentInsert::DroppedInvalid => Ok(InnerOutcome::Ignored),
                FragmentInsert::Complete {
                    payload,
                    wire_bytes,
                } => {
                    self.fragment_reassembled();
                    self.decode_ip_payload(
                        ts_ns, wire_bytes, src, dst, protocol, payload, l2_domain, depth,
                    )
                }
            };
        }

        self.decode_ip_payload(
            ts_ns, wire_len, src, dst, protocol, payload, l2_domain, depth,
        )
    }

    fn decode_ipv6(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        packet: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        if packet.len() < 40 {
            self.mark_truncated();
            bail!("truncated ipv6 header");
        }
        if packet[0] >> 4 != 6 {
            bail!("invalid ipv6 version");
        }
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let ip_len = 40usize.saturating_add(payload_len);
        if ip_len > packet.len() {
            self.mark_truncated();
            bail!(
                "truncated ipv6 packet: declared {ip_len}, captured {}",
                packet.len()
            );
        }
        let src = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).expect("slice length"),
        ));
        let dst = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).expect("slice length"),
        ));
        let mut next = packet[6];
        let mut offset = 40usize;

        loop {
            match next {
                0 | 43 | 60 => {
                    if offset + 2 > ip_len {
                        self.mark_truncated();
                        bail!("truncated ipv6 extension header");
                    }
                    let current = next;
                    next = packet[offset];
                    let len = (packet[offset + 1] as usize + 1) * 8;
                    if offset + len > ip_len {
                        self.mark_truncated();
                        bail!("truncated ipv6 extension body type {current}");
                    }
                    offset += len;
                }
                51 => {
                    if offset + 2 > ip_len {
                        self.mark_truncated();
                        bail!("truncated ipv6 auth header");
                    }
                    next = packet[offset];
                    let len = (packet[offset + 1] as usize + 2) * 4;
                    if offset + len > ip_len {
                        self.mark_truncated();
                        bail!("truncated ipv6 auth body");
                    }
                    offset += len;
                }
                44 => {
                    if offset + 8 > ip_len {
                        self.mark_truncated();
                        bail!("truncated ipv6 fragment header");
                    }
                    let frag_next = packet[offset];
                    let frag = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                    let fragment_offset = (frag & 0xfff8) as usize;
                    let more = frag & 1 != 0;
                    let id = u32::from_be_bytes([
                        packet[offset + 4],
                        packet[offset + 5],
                        packet[offset + 6],
                        packet[offset + 7],
                    ]);
                    let fragment_payload = packet.slice(offset + 8..ip_len);

                    // RFC 6946 atomic fragments are already complete; strip only
                    // the fragment header and continue extension/L4 parsing.
                    if fragment_offset == 0 && !more {
                        return self.decode_ipv6_post_fragment(
                            ts_ns,
                            wire_len,
                            src,
                            dst,
                            frag_next,
                            fragment_payload,
                            l2_domain,
                            depth,
                        );
                    }

                    self.fragment_received();
                    let key = FragmentKey {
                        version: 6,
                        l2_domain,
                        src,
                        dst,
                        id,
                        next_header: frag_next,
                    };
                    let (result, maintenance) = self.fragments.insert(
                        key,
                        fragment_offset,
                        more,
                        fragment_payload,
                        wire_len,
                    );
                    self.apply_fragment_maintenance(maintenance);
                    return match result {
                        FragmentInsert::Pending => Ok(InnerOutcome::PendingFragment),
                        FragmentInsert::DroppedOverlap => {
                            self.fragment_overlap_drop();
                            Ok(InnerOutcome::Ignored)
                        }
                        FragmentInsert::DroppedInvalid => Ok(InnerOutcome::Ignored),
                        FragmentInsert::Complete {
                            payload,
                            wire_bytes,
                        } => {
                            self.fragment_reassembled();
                            self.decode_ipv6_post_fragment(
                                ts_ns, wire_bytes, src, dst, frag_next, payload, l2_domain, depth,
                            )
                        }
                    };
                }
                _ => break,
            }
        }

        if offset > ip_len {
            bail!("invalid ipv6 payload offset");
        }
        self.decode_ip_payload(
            ts_ns,
            wire_len,
            src,
            dst,
            next,
            packet.slice(offset..ip_len),
            l2_domain,
            depth,
        )
    }

    fn decode_ipv6_post_fragment(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        src: IpAddr,
        dst: IpAddr,
        mut next: u8,
        payload: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        let mut offset = 0usize;
        loop {
            match next {
                0 | 43 | 60 => {
                    if offset + 2 > payload.len() {
                        self.mark_truncated();
                        bail!("truncated reassembled ipv6 extension");
                    }
                    next = payload[offset];
                    let len = (payload[offset + 1] as usize + 1) * 8;
                    if offset + len > payload.len() {
                        self.mark_truncated();
                        bail!("truncated reassembled ipv6 extension body");
                    }
                    offset += len;
                }
                51 => {
                    if offset + 2 > payload.len() {
                        self.mark_truncated();
                        bail!("truncated reassembled ipv6 auth header");
                    }
                    next = payload[offset];
                    let len = (payload[offset + 1] as usize + 2) * 4;
                    if offset + len > payload.len() {
                        self.mark_truncated();
                        bail!("truncated reassembled ipv6 auth body");
                    }
                    offset += len;
                }
                44 => return Ok(InnerOutcome::Ignored), // nested fragment header: do not guess
                _ => break,
            }
        }
        self.decode_ip_payload(
            ts_ns,
            wire_len,
            src,
            dst,
            next,
            payload.slice(offset..),
            l2_domain,
            depth,
        )
    }

    fn decode_ip_payload(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        payload: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        match protocol {
            6 => self
                .parse_tcp(ts_ns, wire_len, src, dst, payload, l2_domain)
                .map(InnerOutcome::Packet),
            17 => self.decode_udp(ts_ns, wire_len, src, dst, payload, l2_domain, depth),
            47 if self.tunnel_decapsulation && depth < MAX_TUNNEL_DEPTH => {
                self.decode_gre(ts_ns, wire_len, src, dst, payload, l2_domain, depth)
            }
            4 if self.tunnel_decapsulation && depth < MAX_TUNNEL_DEPTH => {
                let domain = mix_tunnel_domain(l2_domain, 0x4950_4950, src, dst, 4);
                self.decode_ipv4(ts_ns, wire_len, payload, domain, depth + 1)
            }
            41 if self.tunnel_decapsulation && depth < MAX_TUNNEL_DEPTH => {
                let domain = mix_tunnel_domain(l2_domain, 0x4950_4950, src, dst, 6);
                self.decode_ipv6(ts_ns, wire_len, payload, domain, depth + 1)
            }
            _ => Ok(InnerOutcome::Ignored),
        }
    }

    fn parse_tcp(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        src: IpAddr,
        dst: IpAddr,
        tcp: Bytes,
        l2_domain: u64,
    ) -> Result<ParsedPacket> {
        if tcp.len() < 20 {
            self.mark_truncated();
            bail!("truncated tcp header");
        }
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        if data_offset < 20 {
            bail!("invalid tcp data offset");
        }
        if data_offset > tcp.len() {
            self.mark_truncated();
            bail!("truncated tcp options/header");
        }
        let bits = tcp[13];
        let flags = TcpFlags {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
        };
        let (key, direction) = FlowKey::canonical_with_domain(
            src,
            src_port,
            dst,
            dst_port,
            TransportProtocol::Tcp,
            l2_domain,
        );
        Ok(ParsedPacket {
            ts_ns,
            key,
            direction,
            seq: Some(seq),
            ack: Some(ack),
            flags,
            payload: tcp.slice(data_offset..),
            wire_len,
        })
    }

    fn decode_udp(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        src: IpAddr,
        dst: IpAddr,
        udp: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        if udp.len() < 8 {
            self.mark_truncated();
            bail!("truncated udp header");
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if udp_len < 8 {
            bail!("invalid udp length");
        }
        if udp_len > udp.len() {
            self.mark_truncated();
            bail!(
                "truncated udp datagram: declared {udp_len}, captured {}",
                udp.len()
            );
        }

        if self.tunnel_decapsulation && depth < MAX_TUNNEL_DEPTH && matches!(dst_port, 4789 | 8472)
        {
            let vxlan = udp.slice(8..udp_len);
            if vxlan.len() >= 8 && vxlan[0] & 0x08 != 0 {
                let vni = ((vxlan[4] as u64) << 16) | ((vxlan[5] as u64) << 8) | vxlan[6] as u64;
                let domain = mix_tunnel_domain(l2_domain, 0x5658_4c41, src, dst, vni);
                return self.decode_ethernet_bytes(
                    ts_ns,
                    wire_len,
                    vxlan.slice(8..),
                    domain,
                    depth + 1,
                );
            }
        }

        let (key, direction) = FlowKey::canonical_with_domain(
            src,
            src_port,
            dst,
            dst_port,
            TransportProtocol::Udp,
            l2_domain,
        );
        Ok(InnerOutcome::Packet(ParsedPacket {
            ts_ns,
            key,
            direction,
            seq: None,
            ack: None,
            flags: TcpFlags::default(),
            payload: udp.slice(8..udp_len),
            wire_len,
        }))
    }

    fn decode_gre(
        &mut self,
        ts_ns: u64,
        wire_len: usize,
        outer_src: IpAddr,
        outer_dst: IpAddr,
        gre: Bytes,
        l2_domain: u64,
        depth: usize,
    ) -> Result<InnerOutcome> {
        if depth >= MAX_TUNNEL_DEPTH {
            return Ok(InnerOutcome::Ignored);
        }
        if gre.len() < 4 {
            self.mark_truncated();
            bail!("truncated GRE header");
        }
        let flags = u16::from_be_bytes([gre[0], gre[1]]);
        let version = flags & 0x0007;
        if version != 0 {
            return Ok(InnerOutcome::Ignored);
        }
        let proto = u16::from_be_bytes([gre[2], gre[3]]);
        let mut offset = 4usize;
        if flags & 0xc000 != 0 {
            // checksum or routing-present share the checksum/reserved word
            offset = offset.saturating_add(4);
        }
        let mut gre_key = 0u64;
        if flags & 0x2000 != 0 {
            if offset + 4 > gre.len() {
                self.mark_truncated();
                bail!("truncated GRE key");
            }
            gre_key = u32::from_be_bytes([
                gre[offset],
                gre[offset + 1],
                gre[offset + 2],
                gre[offset + 3],
            ]) as u64;
            offset += 4;
        }
        if flags & 0x1000 != 0 {
            offset = offset.saturating_add(4);
        }
        if flags & 0x4000 != 0 {
            // Source-route entries: AF(2), offset(1), len(1), payload(len),
            // terminated by AF=0,len=0. This is tunnel slow-path only.
            loop {
                if offset + 4 > gre.len() {
                    self.mark_truncated();
                    bail!("truncated GRE routing entry");
                }
                let af = u16::from_be_bytes([gre[offset], gre[offset + 1]]);
                let len = gre[offset + 3] as usize;
                offset += 4;
                if af == 0 && len == 0 {
                    break;
                }
                if offset + len > gre.len() {
                    self.mark_truncated();
                    bail!("truncated GRE routing data");
                }
                offset += len;
            }
        }
        if offset > gre.len() {
            self.mark_truncated();
            bail!("truncated GRE header");
        }
        let domain = mix_tunnel_domain(l2_domain, 0x4752_4520, outer_src, outer_dst, gre_key);
        let inner = gre.slice(offset..);
        match proto {
            ETHERTYPE_IPV4 => self.decode_ipv4(ts_ns, wire_len, inner, domain, depth + 1),
            ETHERTYPE_IPV6 => self.decode_ipv6(ts_ns, wire_len, inner, domain, depth + 1),
            ETHERTYPE_TEB => self.decode_ethernet_bytes(ts_ns, wire_len, inner, domain, depth + 1),
            _ => Ok(InnerOutcome::Ignored),
        }
    }

    #[inline]
    fn mark_truncated(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .capture_truncated_packets
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[inline]
    fn fragment_received(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .ip_fragments_received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[inline]
    fn fragment_reassembled(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .ip_fragments_reassembled
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[inline]
    fn fragment_overlap_drop(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .ip_fragment_overlap_drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn apply_fragment_maintenance(&self, maintenance: super::fragment::FragmentMaintenance) {
        if let Some(metrics) = &self.metrics {
            if maintenance.expired != 0 {
                metrics
                    .ip_fragment_expired
                    .fetch_add(maintenance.expired, std::sync::atomic::Ordering::Relaxed);
            }
            if maintenance.evicted != 0 {
                metrics
                    .ip_fragment_evicted
                    .fetch_add(maintenance.evicted, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[inline]
fn mix_tunnel_domain(mut domain: u64, kind: u64, src: IpAddr, dst: IpAddr, id: u64) -> u64 {
    // Tunnel identity must be direction-independent so inner packets from both
    // directions land in one FlowKey, while separate outer tunnels cannot mix
    // identical inner 4-tuples. This runs only on decapsulation slow paths.
    let (first, second) = if src <= dst { (src, dst) } else { (dst, src) };
    domain = mix_domain(domain, kind, id);
    for (tag, ip) in [(0x5352_4301u64, first), (0x4453_5402u64, second)] {
        match ip {
            IpAddr::V4(v4) => {
                domain = mix_domain(domain, kind ^ tag, u32::from_be_bytes(v4.octets()) as u64);
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let hi = u64::from_be_bytes(o[..8].try_into().expect("IPv6 high half"));
                let lo = u64::from_be_bytes(o[8..].try_into().expect("IPv6 low half"));
                domain = mix_domain(domain, kind ^ tag, hi);
                domain = mix_domain(domain, kind ^ tag.rotate_left(7), lo);
            }
        }
    }
    domain
}

#[inline]
fn mix_domain(domain: u64, kind: u64, value: u64) -> u64 {
    let mut z = domain ^ kind.rotate_left(17) ^ value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z ^= z >> 30;
    z = z.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31) | 1 // any tagged/tunnel domain stays non-zero
}

/// Compatibility helper used by unit tests and external callers. Stateful IP
/// fragmentation requires `PacketDecoder`; this helper parses one standalone
/// frame and returns `None` while a fragmented datagram would be incomplete.
pub fn parse_ethernet_frame(
    ts_ns: u64,
    wire_len: usize,
    frame: Bytes,
) -> Result<Option<ParsedPacket>> {
    let mut decoder = PacketDecoder::stateless();
    let captured = CapturedFrame {
        ts_ns,
        wire_len,
        data: frame,
    };
    Ok(match decoder.decode(captured)? {
        DecodeOutcome::Packet(packet) => Some(packet),
        DecodeOutcome::PendingFragment | DecodeOutcome::Ignored => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_frame(seq: u32, payload: &[u8]) -> Bytes {
        let total = 14 + 20 + 20 + payload.len();
        let mut f = vec![0u8; total];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = 14;
        f[ip] = 0x45;
        f[ip + 2..ip + 4].copy_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
        f[ip + 8] = 64;
        f[ip + 9] = 6;
        f[ip + 12..ip + 16].copy_from_slice(&[10, 0, 0, 1]);
        f[ip + 16..ip + 20].copy_from_slice(&[10, 0, 0, 2]);
        let tcp = ip + 20;
        f[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
        f[tcp + 2..tcp + 4].copy_from_slice(&80u16.to_be_bytes());
        f[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        f[tcp + 12] = 5 << 4;
        f[tcp + 13] = 0x18;
        f[tcp + 20..].copy_from_slice(payload);
        Bytes::from(f)
    }

    #[test]
    fn parses_ipv4_tcp_payload_as_zero_copy_slice() {
        let f = ipv4_tcp_frame(100, b"test");
        let wire_len = f.len();
        let p = parse_ethernet_frame(1, wire_len, f).unwrap().unwrap();
        assert_eq!(p.payload.as_ref(), b"test");
        assert_eq!(p.seq, Some(100));
        assert_eq!(p.wire_len, wire_len);
    }

    #[test]
    fn rejects_snaplen_truncated_ipv4_instead_of_advancing_tcp_sequence() {
        let full = ipv4_tcp_frame(100, b"abcdefgh");
        let truncated = full.slice(..full.len() - 4);
        assert!(parse_ethernet_frame(1, full.len(), truncated).is_err());
    }

    fn ipv4_fragment(id: u16, offset_bytes: usize, more: bool, payload: &[u8]) -> Bytes {
        assert_eq!(offset_bytes % 8, 0);
        let total = 14 + 20 + payload.len();
        let mut f = vec![0u8; total];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = 14;
        f[ip] = 0x45;
        f[ip + 2..ip + 4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        f[ip + 4..ip + 6].copy_from_slice(&id.to_be_bytes());
        let mut frag = (offset_bytes / 8) as u16;
        if more {
            frag |= 0x2000;
        }
        f[ip + 6..ip + 8].copy_from_slice(&frag.to_be_bytes());
        f[ip + 8] = 64;
        f[ip + 9] = 6;
        f[ip + 12..ip + 16].copy_from_slice(&[10, 1, 0, 1]);
        f[ip + 16..ip + 20].copy_from_slice(&[10, 1, 0, 2]);
        f[ip + 20..].copy_from_slice(payload);
        Bytes::from(f)
    }

    fn tcp_segment(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20 + payload.len()];
        tcp[..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&8000u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x18;
        tcp[20..].copy_from_slice(payload);
        tcp
    }

    fn ipv6_fragment(id: u32, offset_bytes: usize, more: bool, payload: &[u8]) -> Bytes {
        assert_eq!(offset_bytes % 8, 0);
        let total = 14 + 40 + 8 + payload.len();
        let mut f = vec![0u8; total];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = 14;
        f[ip] = 0x60;
        f[ip + 4..ip + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f[ip + 6] = 44;
        f[ip + 7] = 64;
        f[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        f[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        let fh = ip + 40;
        f[fh] = 6;
        let mut off_field = offset_bytes as u16;
        if more {
            off_field |= 1;
        }
        f[fh + 2..fh + 4].copy_from_slice(&off_field.to_be_bytes());
        f[fh + 4..fh + 8].copy_from_slice(&id.to_be_bytes());
        f[fh + 8..].copy_from_slice(payload);
        Bytes::from(f)
    }

    #[test]
    fn reassembles_ipv4_fragments_arriving_out_of_order() {
        let tcp = tcp_segment(77, b"abcdefghijkl");
        assert_eq!(tcp.len(), 32);
        let first = ipv4_fragment(0x1234, 0, true, &tcp[..24]);
        let last = ipv4_fragment(0x1234, 24, false, &tcp[24..]);
        let mut decoder = PacketDecoder::stateless();
        let r1 = decoder
            .decode(CapturedFrame {
                ts_ns: 1,
                wire_len: last.len(),
                data: last,
            })
            .unwrap();
        assert!(matches!(r1, DecodeOutcome::PendingFragment));
        let r2 = decoder
            .decode(CapturedFrame {
                ts_ns: 2,
                wire_len: first.len(),
                data: first,
            })
            .unwrap();
        let DecodeOutcome::Packet(packet) = r2 else {
            panic!("ipv4 fragments did not reassemble");
        };
        assert_eq!(packet.seq, Some(77));
        assert_eq!(packet.payload.as_ref(), b"abcdefghijkl");
    }

    #[test]
    fn reassembles_ipv6_fragments_arriving_out_of_order() {
        let tcp = tcp_segment(88, b"abcdefghijkl");
        let first = ipv6_fragment(0x11223344, 0, true, &tcp[..24]);
        let last = ipv6_fragment(0x11223344, 24, false, &tcp[24..]);
        let mut decoder = PacketDecoder::stateless();
        let r1 = decoder
            .decode(CapturedFrame {
                ts_ns: 1,
                wire_len: last.len(),
                data: last,
            })
            .unwrap();
        assert!(matches!(r1, DecodeOutcome::PendingFragment));
        let r2 = decoder
            .decode(CapturedFrame {
                ts_ns: 2,
                wire_len: first.len(),
                data: first,
            })
            .unwrap();
        let DecodeOutcome::Packet(packet) = r2 else {
            panic!("ipv6 fragments did not reassemble");
        };
        assert_eq!(packet.seq, Some(88));
        assert_eq!(packet.payload.as_ref(), b"abcdefghijkl");
    }

    #[test]
    fn tunnel_domain_is_direction_symmetric_and_endpoint_specific() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let c = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let ab = mix_tunnel_domain(0, 0x4752_4520, a, b, 7);
        let ba = mix_tunnel_domain(0, 0x4752_4520, b, a, 7);
        let ac = mix_tunnel_domain(0, 0x4752_4520, a, c, 7);
        assert_eq!(ab, ba);
        assert_ne!(ab, ac);
    }

    #[test]
    fn decapsulates_vxlan_and_retains_vni_in_flow_domain() {
        let inner = ipv4_tcp_frame(321, b"vxlan");
        let udp_payload_len = 8 + inner.len();
        let total = 14 + 20 + 8 + udp_payload_len;
        let mut outer = vec![0u8; total];
        outer[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = 14;
        outer[ip] = 0x45;
        outer[ip + 2..ip + 4].copy_from_slice(&((20 + 8 + udp_payload_len) as u16).to_be_bytes());
        outer[ip + 8] = 64;
        outer[ip + 9] = 17;
        outer[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 1]);
        outer[ip + 16..ip + 20].copy_from_slice(&[192, 0, 2, 2]);
        let udp = ip + 20;
        outer[udp..udp + 2].copy_from_slice(&40000u16.to_be_bytes());
        outer[udp + 2..udp + 4].copy_from_slice(&4789u16.to_be_bytes());
        outer[udp + 4..udp + 6].copy_from_slice(&((8 + udp_payload_len) as u16).to_be_bytes());
        let vx = udp + 8;
        outer[vx] = 0x08;
        outer[vx + 4..vx + 7].copy_from_slice(&[0x01, 0x02, 0x03]);
        outer[vx + 8..].copy_from_slice(&inner);

        let packet = parse_ethernet_frame(1, total, Bytes::from(outer))
            .unwrap()
            .unwrap();
        assert_eq!(packet.seq, Some(321));
        assert_eq!(packet.payload.as_ref(), b"vxlan");
        assert_ne!(packet.key.l2_domain, 0);
    }

    #[test]
    fn vlan_identity_changes_flow_key() {
        let plain = ipv4_tcp_frame(100, b"x");
        let mut tagged = Vec::with_capacity(plain.len() + 4);
        tagged.extend_from_slice(&plain[..12]);
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&100u16.to_be_bytes());
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend_from_slice(&plain[14..]);
        let a = parse_ethernet_frame(1, plain.len(), plain)
            .unwrap()
            .unwrap();
        let b = parse_ethernet_frame(1, tagged.len(), Bytes::from(tagged))
            .unwrap()
            .unwrap();
        assert_ne!(a.key.l2_domain, b.key.l2_domain);
    }
}
