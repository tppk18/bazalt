use bytes::Bytes;
use std::collections::BTreeMap;

// Start the internal 64-bit sequence epoch one full 32-bit turn above zero.
// That leaves room to extend packets that arrive slightly "before" the first
// observed sequence (capture started mid-flow / reordering around wrap).
const INITIAL_SEQ_EPOCH: u64 = 1u64 << 32;

#[derive(Debug)]
struct BufferedSegment {
    data: Bytes,
    ts_ns: u64,
}

impl BufferedSegment {
    #[inline]
    fn end(&self, start: u64) -> u64 {
        start.saturating_add(self.data.len() as u64)
    }
}

#[derive(Debug, Clone)]
pub struct ReassembledChunk {
    pub offset: u64,
    pub ts_ns: u64,
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamGap {
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Default)]
pub struct ReassemblyOutcome {
    pub emitted: Vec<ReassembledChunk>,
    pub gaps: Vec<StreamGap>,
    pub retransmit: bool,
    pub out_of_order: bool,
    pub fin_consumed: bool,
}

#[derive(Debug, Default)]
pub struct TcpHalf {
    // Absolute/extended TCP sequence number expected next. SYN/FIN consume TCP
    // sequence space but do not consume the application stream offset.
    next_abs: Option<u64>,
    stream_offset: u64,
    out_of_order: BTreeMap<u64, BufferedSegment>,
    out_of_order_bytes: usize,
    pending_fin: Option<u64>,
    // An out-of-order FIN may have been outside the real receiver window and
    // discarded by the endpoint. Do not let it truncate later payload until a
    // peer ACK covers FIN or FIN is observed again at the contiguous position.
    pending_fin_requires_ack: bool,
    fin_consumed: bool,
    initial_syn_seq: Option<u32>,
    // Highest cumulative ACK observed from the peer for this half. Keeping the
    // watermark costs one extend/compare per ACK and lets a later OOO segment
    // immediately recover a gap even when the inference ACK arrived first.
    peer_ack_abs: Option<u64>,
    // Capture timestamp at which the current unresolved OOO hole first became
    // visible. This exists only for the slow path; in-order streams leave it None.
    gap_started_ts_ns: Option<u64>,
}

impl TcpHalf {
    /// Observe TCP sequence space even for control-only packets. The hot path is
    /// just the `Option` check after the first packet in a direction.
    pub fn observe(&mut self, seq: u32, syn: bool) {
        if self.next_abs.is_none() {
            let payload_seq = seq.wrapping_add(u32::from(syn));
            self.next_abs = Some(INITIAL_SEQ_EPOCH + payload_seq as u64);
        }
        if syn && self.initial_syn_seq.is_none() {
            self.initial_syn_seq = Some(seq);
        }
    }

    pub fn initial_syn_seq(&self) -> Option<u32> {
        self.initial_syn_seq
    }

    #[inline]
    pub fn fin_consumed(&self) -> bool {
        self.fin_consumed
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.next_abs.is_some()
    }

    /// Modern synchronized TCP stacks accept an RST as an immediate reset only
    /// when its sequence number matches RCV.NXT (otherwise it is ignored or
    /// challenge-ACKed). This conservative check prevents an off-sequence
    /// injected RST from tearing down analyzer state.
    #[inline]
    pub fn rst_matches_next(&self, seq: u32) -> bool {
        match self.next_abs {
            None => true,
            Some(expected) => extend_seq(seq, expected) == expected,
        }
    }

    /// Accept one TCP segment. In-order traffic never touches the BTreeMap and
    /// keeps the same allocation profile as the old implementation. Only OOO
    /// traffic enters interval normalization/copying.
    pub fn accept(
        &mut self,
        seq: u32,
        syn: bool,
        fin: bool,
        ts_ns: u64,
        data: Bytes,
        max_ooo: usize,
        max_ooo_segments: usize,
        gap_timeout_ns: u64,
    ) -> ReassemblyOutcome {
        let mut out = ReassemblyOutcome::default();
        self.observe(seq, syn);
        if self.fin_consumed {
            // Once FIN was consumed in sequence space this half-generation has
            // no application bytes left. A delayed retransmission must not
            // reopen the stream while the opposite half is still closing.
            if !data.is_empty() {
                out.retransmit = true;
            }
            return out;
        }

        let expected = self.next_abs.expect("observe initializes next_abs");
        let payload_seq = seq.wrapping_add(u32::from(syn));
        let start_abs = extend_seq(payload_seq, expected);
        let end_abs = start_abs.saturating_add(data.len() as u64);

        if fin && end_abs >= expected {
            // FIN follows payload in sequence space. A FIN first seen ahead of
            // RCV.NXT is tentative: without the receiver window we cannot know
            // whether the endpoint queued it or discarded it as out-of-window.
            // A retransmitted FIN observed at/before RCV.NXT validates the marker.
            match self.pending_fin {
                None => {
                    self.pending_fin = Some(end_abs);
                    self.pending_fin_requires_ack = start_abs > expected;
                }
                Some(existing) if existing == end_abs && start_abs <= expected => {
                    self.pending_fin_requires_ack = false;
                }
                Some(_) if self.pending_fin_requires_ack && start_abs <= expected => {
                    self.pending_fin = Some(end_abs);
                    self.pending_fin_requires_ack = false;
                }
                Some(_) => {}
            }
        }

        // A validated FIN is a hard upper bound for application data. For a
        // tentative OOO FIN, later observed payload beyond the marker is stronger
        // evidence that the endpoint continued the stream; discard the tentative
        // marker instead of truncating real bytes. This branch is cold because
        // ordinary streams have no pending FIN while payload is flowing.
        let data = if let Some(fin_abs) = self.pending_fin {
            if end_abs > fin_abs {
                let fin_acked = self.peer_ack_abs.is_some_and(|ack| ack > fin_abs);
                if self.pending_fin_requires_ack && !fin_acked {
                    self.pending_fin = None;
                    self.pending_fin_requires_ack = false;
                    data
                } else if start_abs >= fin_abs {
                    if !data.is_empty() {
                        out.retransmit = true;
                    }
                    Bytes::new()
                } else {
                    out.retransmit = true;
                    data.slice(..(fin_abs - start_abs) as usize)
                }
            } else {
                data
            }
        } else {
            data
        };

        if !data.is_empty() {
            if start_abs > expected {
                out.out_of_order = true;
                self.insert_ooo_first_seen(start_abs, ts_ns, data, &mut out);
                // A cumulative ACK can arrive before the later segment that
                // makes the capture hole visible. Apply the remembered ACK
                // inference before falling back to timeout/pressure recovery.
                self.recover_known_ack(ts_ns, &mut out);
                self.recover_ooo_pressure(max_ooo, max_ooo_segments, ts_ns, &mut out);
            } else {
                let mut start = 0usize;
                if start_abs < expected {
                    let overlap = expected.saturating_sub(start_abs) as usize;
                    if overlap >= data.len() {
                        out.retransmit = true;
                    } else {
                        out.retransmit = true;
                        start = overlap;
                    }
                }
                if start < data.len() {
                    let tail = if start == 0 {
                        data
                    } else {
                        data.slice(start..)
                    };
                    let tail_abs = start_abs.saturating_add(start as u64);
                    if self.out_of_order.is_empty() {
                        // Dominant fast path: in-order traffic stays zero-copy and
                        // never touches the interval tree.
                        self.emit(tail, ts_ns, &mut out);
                    } else {
                        // Once reordering exists, already buffered bytes may overlap
                        // this bridging segment. Normalize it through the first-seen
                        // interval set so a later in-order arrival cannot overwrite
                        // bytes BAZALT observed earlier. This slow path may copy.
                        self.insert_ooo_first_seen(tail_abs, ts_ns, tail, &mut out);
                        self.flush_ooo(&mut out);
                        self.recover_known_ack(ts_ns, &mut out);
                        self.recover_ooo_pressure(max_ooo, max_ooo_segments, ts_ns, &mut out);
                    }
                }
            }
        }

        if self.pending_fin.is_some() && !self.fin_consumed {
            self.recover_known_ack(ts_ns, &mut out);
        }
        self.recover_ooo_timeout(gap_timeout_ns, ts_ns, &mut out);
        self.consume_fin_if_ready(&mut out);
        out
    }

    /// A cumulative ACK is a strong inference that the peer accepted sequence
    /// bytes below `ack`. Remember the highest watermark even when there is
    /// no OOO data yet: the packet that exposes the capture hole can arrive after
    /// its cumulative ACK. Timeout/pressure recovery remains independent of ACKs.
    pub fn acknowledge(&mut self, ack: u32, ts_ns: u64, gap_timeout_ns: u64) -> ReassemblyOutcome {
        let mut out = ReassemblyOutcome::default();
        let Some(expected) = self.next_abs else {
            return out;
        };
        let ack_abs = extend_seq(ack, expected);
        if ack_abs > expected
            && self
                .peer_ack_abs
                .map(|current| ack_abs > current)
                .unwrap_or(true)
        {
            self.peer_ack_abs = Some(ack_abs);
        }
        if self.out_of_order.is_empty() && self.pending_fin.is_none() {
            return out;
        }
        self.recover_known_ack(ts_ns, &mut out);
        self.recover_ooo_timeout(gap_timeout_ns, ts_ns, &mut out);
        self.consume_fin_if_ready(&mut out);
        out
    }

    fn recover_known_ack(&mut self, ts_ns: u64, out: &mut ReassemblyOutcome) {
        let Some(ack_abs) = self.peer_ack_abs else {
            return;
        };
        loop {
            let Some(expected) = self.next_abs else {
                return;
            };
            if expected >= ack_abs {
                return;
            }
            let first = self.out_of_order.first_key_value().map(|(&start, _)| start);
            if first.is_none() {
                // A FIN is itself a sequence-space landmark. If the peer ACKed
                // beyond an observed out-of-order FIN, bytes before FIN are a
                // strong inferred capture gap even when there is no buffered payload.
                if let Some(fin) = self.pending_fin {
                    if fin > expected && ack_abs > fin {
                        self.emit_gap_to(fin, ts_ns, out);
                        self.consume_fin_if_ready(out);
                    }
                }
                return;
            }
            let first = first.expect("checked above");

            // Treat the cumulative ACK as an inference for bytes below ack_abs.
            // Even when the first buffered segment starts after this ACK, only
            // advance to the ACK itself; bytes above it remain unresolved.
            if first > expected {
                self.emit_gap_to(first.min(ack_abs), ts_ns, out);
            }
            if self.next_abs.expect("initialized") >= ack_abs {
                return;
            }

            let before_seq = self.next_abs;
            let before_bytes = self.out_of_order_bytes;
            self.flush_ooo(out);
            if self.fin_consumed {
                return;
            }
            if self.next_abs == before_seq && self.out_of_order_bytes == before_bytes {
                return;
            }
        }
    }

    fn recover_ooo_timeout(&mut self, max_age_ns: u64, ts_ns: u64, out: &mut ReassemblyOutcome) {
        let Some(expected) = self.next_abs else {
            self.gap_started_ts_ns = None;
            return;
        };
        let Some((&first, _)) = self.out_of_order.first_key_value() else {
            self.gap_started_ts_ns = None;
            return;
        };
        if first <= expected {
            self.gap_started_ts_ns = None;
            self.flush_ooo(out);
            return;
        }

        let started = match self.gap_started_ts_ns {
            Some(started) => started,
            None => {
                self.gap_started_ts_ns = Some(ts_ns);
                return;
            }
        };
        if ts_ns.saturating_sub(started) < max_age_ns {
            return;
        }

        // The hole remained unresolved long enough that retaining all later
        // bytes is worse than an explicit discontinuity. Advance only to the
        // first byte we actually observed, then continue normally.
        self.emit_gap_to(first, ts_ns, out);
        self.flush_ooo(out);
        self.gap_started_ts_ns = None;

        // If flushing exposed another independent hole, start a fresh timeout
        // window instead of charging it the age of the previous gap.
        if let (Some(next), Some(expected)) = (
            self.out_of_order.first_key_value().map(|(&start, _)| start),
            self.next_abs,
        ) {
            if next > expected {
                self.gap_started_ts_ns = Some(ts_ns);
            }
        }
    }

    /// Drain known later bytes when a flow is explicitly closed/expired. This
    /// never invents payload: holes become stream-offset gaps and only captured
    /// OOO bytes are emitted. Close is a cold path, so complete draining here
    /// has no steady-state packet cost.
    pub fn finalize(&mut self, ts_ns: u64) -> ReassemblyOutcome {
        let mut out = ReassemblyOutcome::default();
        loop {
            let Some(expected) = self.next_abs else {
                break;
            };
            let Some((&first, _)) = self.out_of_order.first_key_value() else {
                break;
            };
            if first > expected {
                self.emit_gap_to(first, ts_ns, &mut out);
            }
            let before_seq = self.next_abs;
            let before_bytes = self.out_of_order_bytes;
            self.flush_ooo(&mut out);
            if self.fin_consumed {
                break;
            }
            if self.next_abs == before_seq && self.out_of_order_bytes == before_bytes {
                break;
            }
        }
        // If only a future FIN remains with no captured bytes after the hole,
        // there is nothing useful to salvage at close. Do not invent a giant
        // application-stream gap merely to consume that control marker.
        self.consume_fin_if_ready(&mut out);
        self.gap_started_ts_ns = None;
        out
    }

    pub fn reserve_udp_offset(&mut self, len: usize) -> u64 {
        let offset = self.stream_offset;
        self.stream_offset = self.stream_offset.saturating_add(len as u64);
        offset
    }

    fn insert_ooo_first_seen(
        &mut self,
        start: u64,
        ts_ns: u64,
        data: Bytes,
        out: &mut ReassemblyOutcome,
    ) {
        let end = start.saturating_add(data.len() as u64);
        let mut cursor = start;

        while cursor < end {
            // If an existing first-seen interval covers cursor, skip its bytes.
            if let Some((&existing_start, existing)) =
                self.out_of_order.range(..=cursor).next_back()
            {
                let existing_end = existing.end(existing_start);
                if existing_end > cursor {
                    out.retransmit = true;
                    cursor = existing_end.min(end);
                    continue;
                }
            }

            // Insert only the uncovered prefix before the next existing range.
            let next = self
                .out_of_order
                .range(cursor..end)
                .next()
                .map(|(&s, seg)| (s, seg.end(s)));
            let piece_end = next.map(|(s, _)| s).unwrap_or(end).min(end);
            if piece_end > cursor {
                let from = (cursor - start) as usize;
                let to = (piece_end - start) as usize;
                // OOO data is compacted so a tiny slice cannot pin an entire RX
                // batch. In-order traffic remains zero-copy.
                let compact = Bytes::copy_from_slice(&data[from..to]);
                self.out_of_order_bytes = self.out_of_order_bytes.saturating_add(compact.len());
                self.out_of_order.insert(
                    cursor,
                    BufferedSegment {
                        data: compact,
                        ts_ns,
                    },
                );
                cursor = piece_end;
            }

            if let Some((next_start, next_end)) = next {
                if next_start <= cursor && next_end > cursor {
                    out.retransmit = true;
                    cursor = next_end.min(end);
                }
            }
        }
    }

    fn recover_ooo_pressure(
        &mut self,
        max_ooo: usize,
        max_segments: usize,
        ts_ns: u64,
        out: &mut ReassemblyOutcome,
    ) {
        while self.out_of_order_bytes > max_ooo || self.out_of_order.len() > max_segments {
            let Some((&first, _)) = self.out_of_order.first_key_value() else {
                break;
            };
            let expected = self.next_abs.expect("initialized");
            if first > expected {
                self.emit_gap_to(first, ts_ns, out);
            }
            let before = self.out_of_order_bytes;
            self.flush_ooo(out);
            if self.fin_consumed || self.out_of_order_bytes >= before {
                break;
            }
        }
    }

    fn emit(&mut self, data: Bytes, ts_ns: u64, out: &mut ReassemblyOutcome) {
        if data.is_empty() {
            return;
        }
        let offset = self.stream_offset;
        self.stream_offset = self.stream_offset.saturating_add(data.len() as u64);
        self.next_abs = Some(
            self.next_abs
                .expect("initialized")
                .saturating_add(data.len() as u64),
        );
        out.emitted.push(ReassembledChunk {
            offset,
            ts_ns,
            data,
        });
        self.consume_fin_if_ready(out);
    }

    fn emit_gap_to(&mut self, mut target: u64, _ts_ns: u64, out: &mut ReassemblyOutcome) {
        let expected = self.next_abs.expect("initialized");
        if let Some(fin) = self.pending_fin {
            // Never synthesize sequence bytes across a FIN marker.
            target = target.min(fin);
        }
        if target <= expected {
            return;
        }
        let len = target - expected;
        let offset = self.stream_offset;
        self.stream_offset = self.stream_offset.saturating_add(len);
        self.next_abs = Some(target);
        out.gaps.push(StreamGap { offset, len });
        self.consume_fin_if_ready(out);
    }

    fn flush_ooo(&mut self, out: &mut ReassemblyOutcome) {
        loop {
            if self.fin_consumed {
                return;
            }
            let expected = match self.next_abs {
                Some(v) => v,
                None => return,
            };
            let first_key = match self.out_of_order.first_key_value().map(|(&k, _)| k) {
                Some(v) => v,
                None => return,
            };
            if first_key > expected {
                return;
            }
            let segment = self.out_of_order.remove(&first_key).expect("key exists");
            self.out_of_order_bytes = self.out_of_order_bytes.saturating_sub(segment.data.len());
            if first_key < expected {
                let overlap = expected.saturating_sub(first_key) as usize;
                if overlap >= segment.data.len() {
                    continue;
                }
                self.emit(segment.data.slice(overlap..), segment.ts_ns, out);
            } else {
                self.emit(segment.data, segment.ts_ns, out);
            }
        }
    }

    fn consume_fin_if_ready(&mut self, out: &mut ReassemblyOutcome) {
        if self.fin_consumed {
            return;
        }
        let (Some(fin), Some(next)) = (self.pending_fin, self.next_abs) else {
            return;
        };
        if fin <= next {
            if fin == next {
                if self.pending_fin_requires_ack && !self.peer_ack_abs.is_some_and(|ack| ack > fin)
                {
                    return;
                }
                self.next_abs = Some(next.saturating_add(1));
            }
            self.fin_consumed = true;
            self.pending_fin_requires_ack = false;
            out.fin_consumed = true;
            // Bytes after an observed FIN do not belong to this half-generation.
            self.out_of_order.clear();
            self.out_of_order_bytes = 0;
            self.gap_started_ts_ns = None;
        }
    }
}

#[inline]
fn extend_seq(seq: u32, reference: u64) -> u64 {
    let delta = seq.wrapping_sub(reference as u32) as i32 as i64;
    if delta >= 0 {
        reference.saturating_add(delta as u64)
    } else {
        reference.saturating_sub((-delta) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_out_of_order_and_preserves_timestamp() {
        let mut h = TcpHalf::default();
        let a = h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        assert_eq!(a.emitted[0].data.as_ref(), b"abcd");
        let b = h.accept(
            108,
            false,
            false,
            2,
            Bytes::from_static(b"ijkl"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(b.emitted.is_empty());
        let c = h.accept(
            104,
            false,
            false,
            3,
            Bytes::from_static(b"efgh"),
            1024,
            128,
            1_000_000_000,
        );
        assert_eq!(c.emitted.len(), 2);
        assert_eq!(c.emitted[0].data.as_ref(), b"efgh");
        assert_eq!(c.emitted[0].ts_ns, 3);
        assert_eq!(c.emitted[1].data.as_ref(), b"ijkl");
        assert_eq!(c.emitted[1].ts_ns, 2);
    }

    #[test]
    fn suppresses_retransmit_and_keeps_new_tail() {
        let mut h = TcpHalf::default();
        h.accept(
            10,
            false,
            false,
            1,
            Bytes::from_static(b"abcdef"),
            1024,
            128,
            1_000_000_000,
        );
        let r = h.accept(
            12,
            false,
            false,
            2,
            Bytes::from_static(b"cdefGH"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(r.retransmit);
        assert_eq!(r.emitted[0].data.as_ref(), b"GH");
        assert_eq!(r.emitted[0].offset, 6);
    }

    #[test]
    fn syn_observation_prevents_first_ooo_payload_from_becoming_stream_start() {
        let mut h = TcpHalf::default();
        h.observe(100, true);
        let late = h.accept(
            105,
            false,
            false,
            2,
            Bytes::from_static(b"efgh"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(late.out_of_order);
        assert!(late.emitted.is_empty());
        let early = h.accept(
            101,
            false,
            false,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        assert_eq!(early.emitted.len(), 2);
        assert_eq!(early.emitted[0].data.as_ref(), b"abcd");
        assert_eq!(early.emitted[1].data.as_ref(), b"efgh");
    }

    #[test]
    fn conflicting_ooo_overlap_is_first_seen_wins() {
        let mut h = TcpHalf::default();
        h.observe(100, false);
        h.accept(
            110,
            false,
            false,
            1,
            Bytes::from_static(b"BBBB"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(
            108,
            false,
            false,
            2,
            Bytes::from_static(b"AAXXXX"),
            1024,
            128,
            1_000_000_000,
        );
        let gap = h.accept(
            100,
            false,
            false,
            3,
            Bytes::from_static(b"abcdefgh"),
            1024,
            128,
            1_000_000_000,
        );
        let joined = gap
            .emitted
            .iter()
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&joined, b"abcdefghAABBBB");
    }

    #[test]
    fn bridging_in_order_segment_cannot_overwrite_first_seen_ooo_bytes() {
        let mut h = TcpHalf::default();
        h.observe(100, false);
        h.accept(
            110,
            false,
            false,
            1,
            Bytes::from_static(b"BBBB"),
            1024,
            128,
            1_000_000_000,
        );
        let r = h.accept(
            100,
            false,
            false,
            2,
            Bytes::from_static(b"abcdefghijXXXXtail"),
            1024,
            128,
            1_000_000_000,
        );
        let joined = r
            .emitted
            .iter()
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&joined, b"abcdefghijBBBBtail");
        assert!(r.retransmit);
    }

    #[test]
    fn wraparound_ooo_uses_extended_sequence_order() {
        let mut h = TcpHalf::default();
        h.observe(0xffff_fff0, false);
        h.accept(
            0x0000_0000,
            false,
            false,
            2,
            Bytes::from_static(b"BBBB"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(
            0xffff_fff8,
            false,
            false,
            1,
            Bytes::from_static(b"AAAAAAAA"),
            1024,
            128,
            1_000_000_000,
        );
        let first = h.accept(
            0xffff_fff0,
            false,
            false,
            0,
            Bytes::from_static(b"12345678"),
            1024,
            128,
            1_000_000_000,
        );
        let joined = first
            .emitted
            .iter()
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&joined, b"12345678AAAAAAAABBBB");
    }

    #[test]
    fn opposite_ack_recovers_confirmed_capture_gap() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(
            108,
            false,
            false,
            2,
            Bytes::from_static(b"cccc"),
            1024,
            128,
            1_000_000_000,
        );
        let r = h.acknowledge(112, 3, 1_000_000_000);
        assert_eq!(r.gaps, vec![StreamGap { offset: 4, len: 4 }]);
        assert_eq!(r.emitted.len(), 1);
        assert_eq!(r.emitted[0].offset, 8);
        assert_eq!(r.emitted[0].data.as_ref(), b"cccc");
    }

    #[test]
    fn ack_arriving_before_ooo_is_remembered_for_later_gap_recovery() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            1_000_000_000,
        );
        let ack = h.acknowledge(108, 2, 1_000_000_000);
        assert!(ack.gaps.is_empty());
        let later = h.accept(
            108,
            false,
            false,
            3,
            Bytes::from_static(b"cccc"),
            1024,
            128,
            1_000_000_000,
        );
        assert_eq!(later.gaps, vec![StreamGap { offset: 4, len: 4 }]);
        assert_eq!(later.emitted.len(), 1);
        assert_eq!(later.emitted[0].data.as_ref(), b"cccc");
    }

    #[test]
    fn ack_before_first_ooo_still_advances_inferred_gap_prefix() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(
            120,
            false,
            false,
            2,
            Bytes::from_static(b"zzzz"),
            1024,
            128,
            1_000_000_000,
        );
        let r = h.acknowledge(112, 3, 1_000_000_000);
        assert_eq!(r.gaps, vec![StreamGap { offset: 4, len: 8 }]);
        assert!(r.emitted.is_empty());
        let r2 = h.acknowledge(124, 4, 1_000_000_000);
        assert_eq!(r2.gaps, vec![StreamGap { offset: 12, len: 8 }]);
        assert_eq!(r2.emitted[0].offset, 20);
        assert_eq!(r2.emitted[0].data.as_ref(), b"zzzz");
    }

    #[test]
    fn ooo_interval_count_limit_bounds_tiny_segment_metadata() {
        let mut h = TcpHalf::default();
        h.observe(100, false);
        let _ = h.accept(
            200,
            false,
            false,
            1,
            Bytes::from_static(b"a"),
            1024,
            1,
            1_000_000_000,
        );
        let r = h.accept(
            202,
            false,
            false,
            2,
            Bytes::from_static(b"b"),
            1024,
            1,
            1_000_000_000,
        );
        assert!(!r.gaps.is_empty());
        assert!(!r.emitted.is_empty());
    }

    #[test]
    fn ooo_limit_resyncs_instead_of_killing_stream() {
        let mut h = TcpHalf::default();
        h.observe(100, false);
        let r = h.accept(
            200,
            false,
            false,
            1,
            Bytes::from_static(b"payload"),
            1,
            128,
            1_000_000_000,
        );
        assert_eq!(r.gaps.len(), 1);
        assert_eq!(r.emitted[0].data.as_ref(), b"payload");
        let n = h.accept(
            207,
            false,
            false,
            2,
            Bytes::from_static(b"next"),
            1,
            128,
            1_000_000_000,
        );
        assert_eq!(n.emitted[0].data.as_ref(), b"next");
    }

    #[test]
    fn acknowledged_out_of_order_fin_recovers_missing_tail_without_fake_fin_byte() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            1_000_000_000,
        );
        let ack = h.acknowledge(109, 2, 1_000_000_000);
        assert!(ack.gaps.is_empty());
        let fin = h.accept(108, false, true, 3, Bytes::new(), 1024, 128, 1_000_000_000);
        assert_eq!(fin.gaps, vec![StreamGap { offset: 4, len: 4 }]);
        assert!(fin.fin_consumed);
        assert!(h.fin_consumed());
    }

    #[test]
    fn off_sequence_rst_does_not_match_receive_next() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(h.rst_matches_next(104));
        assert!(!h.rst_matches_next(4000));
    }

    #[test]
    fn small_gap_recovers_after_timeout_without_ack_or_pressure() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1_000,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            100,
        );
        let first_ooo = h.accept(
            108,
            false,
            false,
            1_010,
            Bytes::from_static(b"cccc"),
            1024,
            128,
            100,
        );
        assert!(first_ooo.gaps.is_empty());
        let timed = h.accept(
            112,
            false,
            false,
            1_200,
            Bytes::from_static(b"dddd"),
            1024,
            128,
            100,
        );
        assert_eq!(timed.gaps, vec![StreamGap { offset: 4, len: 4 }]);
        let joined = timed
            .emitted
            .iter()
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&joined, b"ccccdddd");
    }

    #[test]
    fn finalize_drains_buffered_bytes_with_explicit_gap() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"aaaa"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(
            108,
            false,
            false,
            2,
            Bytes::from_static(b"cccc"),
            1024,
            128,
            1_000_000_000,
        );
        let final_out = h.finalize(3);
        assert_eq!(final_out.gaps, vec![StreamGap { offset: 4, len: 4 }]);
        assert_eq!(final_out.emitted[0].data.as_ref(), b"cccc");
    }

    #[test]
    fn stale_fin_behind_rcv_next_does_not_close_half() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"abcdefgh"),
            1024,
            128,
            1_000_000_000,
        );
        let stale = h.accept(99, false, true, 2, Bytes::new(), 1024, 128, 1_000_000_000);
        assert!(!stale.fin_consumed);
        assert!(!h.fin_consumed());
    }

    #[test]
    fn payload_beyond_unacked_ooo_fin_invalidates_tentative_fin() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        let fin = h.accept(108, false, true, 2, Bytes::new(), 1024, 128, 1_000_000_000);
        assert!(!fin.fin_consumed);
        let bridge = h.accept(
            104,
            false,
            false,
            3,
            Bytes::from_static(b"efghXXXX"),
            1024,
            128,
            1_000_000_000,
        );
        let emitted = bridge
            .emitted
            .iter()
            .flat_map(|c| c.data.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&emitted, b"efghXXXX");
        assert!(!bridge.fin_consumed);
        assert!(!h.fin_consumed());
    }

    #[test]
    fn acked_ooo_fin_is_a_hard_payload_boundary() {
        let mut h = TcpHalf::default();
        h.accept(
            100,
            false,
            false,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        h.accept(108, false, true, 2, Bytes::new(), 1024, 128, 1_000_000_000);
        let _ = h.acknowledge(109, 3, 1_000_000_000);
        assert!(h.fin_consumed());
        let late = h.accept(
            104,
            false,
            false,
            4,
            Bytes::from_static(b"efghXXXX"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(late.emitted.is_empty());
    }

    #[test]
    fn payload_after_consumed_fin_is_ignored() {
        let mut h = TcpHalf::default();
        let first = h.accept(
            100,
            false,
            true,
            1,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(first.fin_consumed);
        let late = h.accept(
            105,
            false,
            false,
            2,
            Bytes::from_static(b"late"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(late.emitted.is_empty());
        assert!(late.retransmit);
    }

    #[test]
    fn ooo_fin_waits_for_peer_ack_after_missing_data_arrives() {
        let mut h = TcpHalf::default();
        h.observe(100, false);
        let fin = h.accept(104, false, true, 2, Bytes::new(), 1024, 128, 1_000_000_000);
        assert!(!fin.fin_consumed);
        let data = h.accept(
            100,
            false,
            false,
            3,
            Bytes::from_static(b"abcd"),
            1024,
            128,
            1_000_000_000,
        );
        assert!(!data.fin_consumed);
        assert!(!h.fin_consumed());
        let ack = h.acknowledge(105, 4, 1_000_000_000);
        assert!(ack.fin_consumed);
        assert!(h.fin_consumed());
    }
}
