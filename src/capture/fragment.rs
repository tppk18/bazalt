use std::{
    collections::BTreeMap,
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::hash_map::RandomState;

const FRAGMENT_SHARDS: usize = 64;
// Cache accounting includes conservative metadata charges so tiny-fragment
// floods cannot hide millions of BTree nodes behind a small payload-byte sum.
const FRAGMENT_DATAGRAM_OVERHEAD: usize = 256;
const FRAGMENT_PIECE_OVERHEAD: usize = 64;

/// Shared across capture workers so NIC RSS differences between first and
/// non-first fragments cannot split one datagram. Locks are touched only for
/// actual fragmented packets; the unfragmented hot path does not synchronize.
#[derive(Clone)]
pub struct SharedFragmentCache {
    shards: Arc<Vec<Mutex<FragmentCache>>>,
    // Randomized shard selection prevents an attacker from deliberately
    // concentrating fragment IDs into one lock/cache shard. This hash is only
    // computed for fragmented traffic.
    shard_hash: RandomState,
}

impl SharedFragmentCache {
    pub fn new(max_bytes: usize, max_datagrams: usize, timeout: Duration) -> Self {
        let per_bytes = (max_bytes / FRAGMENT_SHARDS).max(64 * 1024);
        let per_datagrams = (max_datagrams / FRAGMENT_SHARDS).max(1);
        let shards = (0..FRAGMENT_SHARDS)
            .map(|_| Mutex::new(FragmentCache::new(per_bytes, per_datagrams, timeout)))
            .collect();
        Self {
            shards: Arc::new(shards),
            shard_hash: RandomState::new(),
        }
    }

    pub fn insert(
        &self,
        key: FragmentKey,
        offset: usize,
        more: bool,
        payload: Bytes,
        wire_len: usize,
    ) -> (FragmentInsert, FragmentMaintenance) {
        let mut hasher = self.shard_hash.build_hasher();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) & (FRAGMENT_SHARDS - 1);
        self.shards[idx]
            .lock()
            .insert(key, offset, more, payload, wire_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub version: u8,
    pub l2_domain: u64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub next_header: u8,
}

#[derive(Debug)]
struct FragmentPiece {
    data: Bytes,
    more: bool,
}

#[derive(Debug)]
struct FragmentState {
    pieces: BTreeMap<usize, FragmentPiece>,
    bytes: usize,
    total_len: Option<usize>,
    last_seen: Instant,
    wire_bytes: usize,
}

impl FragmentState {
    fn new(now: Instant) -> Self {
        Self {
            pieces: BTreeMap::new(),
            bytes: FRAGMENT_DATAGRAM_OVERHEAD,
            total_len: None,
            last_seen: now,
            wire_bytes: 0,
        }
    }
}

#[derive(Debug)]
pub enum FragmentInsert {
    Pending,
    Complete { payload: Bytes, wire_bytes: usize },
    DroppedOverlap,
    DroppedInvalid,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FragmentMaintenance {
    pub expired: u64,
    pub evicted: u64,
}

/// One shard of the shared fragment cache. The outer `SharedFragmentCache`
/// serializes only actual fragment traffic; ordinary packets never touch it.
pub struct FragmentCache {
    states: AHashMap<FragmentKey, FragmentState>,
    bytes: usize,
    max_bytes: usize,
    max_datagrams: usize,
    timeout: Duration,
    last_cleanup: Instant,
}

impl FragmentCache {
    pub fn new(max_bytes: usize, max_datagrams: usize, timeout: Duration) -> Self {
        Self {
            states: AHashMap::new(),
            bytes: 0,
            max_bytes: max_bytes.max(64 * 1024),
            max_datagrams: max_datagrams.max(1),
            timeout,
            last_cleanup: Instant::now(),
        }
    }

    pub fn insert(
        &mut self,
        key: FragmentKey,
        offset: usize,
        more: bool,
        payload: Bytes,
        wire_len: usize,
    ) -> (FragmentInsert, FragmentMaintenance) {
        let now = Instant::now();
        let mut maintenance = self.maintenance(now);

        // IPv4/IPv6 non-final fragment payloads must end on an 8-byte boundary.
        // A bounded 64 KiB datagram also prevents pathological allocation.
        let Some(end) = offset.checked_add(payload.len()) else {
            return (FragmentInsert::DroppedInvalid, maintenance);
        };
        if end > 65_535 || (more && (payload.is_empty() || payload.len() % 8 != 0)) {
            self.remove_key(&key);
            return (FragmentInsert::DroppedInvalid, maintenance);
        }

        if !self.states.contains_key(&key) {
            self.states.insert(key.clone(), FragmentState::new(now));
            self.bytes = self.bytes.saturating_add(FRAGMENT_DATAGRAM_OVERHEAD);
        }

        #[derive(Clone, Copy)]
        enum Reject {
            Invalid,
            Overlap,
        }
        let mut reject = None::<Reject>;
        let mut duplicate = false;
        let mut added_len = 0usize;

        // Keep the map-entry borrow scoped. Removal/eviction needs `&mut self`
        // again and must happen only after this borrow has ended.
        {
            let state = self.states.get_mut(&key).expect("fragment state exists");
            state.last_seen = now;

            if !more {
                match state.total_len {
                    Some(existing) if existing != end => reject = Some(Reject::Invalid),
                    _ => state.total_len = Some(end),
                }
                // A final fragment cannot retroactively place already-seen
                // bytes beyond the datagram boundary it declares.
                if reject.is_none()
                    && state
                        .pieces
                        .iter()
                        .any(|(&start, piece)| start.saturating_add(piece.data.len()) > end)
                {
                    reject = Some(Reject::Invalid);
                }
            }
            if reject.is_none() {
                if let Some(total) = state.total_len {
                    if end > total || (more && end >= total) {
                        reject = Some(Reject::Invalid);
                    }
                }
            }

            if reject.is_none() {
                // Exact duplicate fragments are harmless. Any partial or
                // conflicting overlap invalidates the whole datagram. This is
                // deterministic and avoids endpoint/analyzer overlap differentials.
                if let Some(existing) = state.pieces.get(&offset) {
                    if existing.more == more && existing.data.as_ref() == payload.as_ref() {
                        duplicate = true;
                    } else {
                        // Same sequence range with different MF semantics or
                        // bytes is not an exact retransmission. Drop the whole
                        // datagram rather than let a later fragment redefine it.
                        reject = Some(Reject::Overlap);
                    }
                }
            }
            if reject.is_none() && !duplicate {
                if let Some((&prev_start, prev)) = state.pieces.range(..offset).next_back() {
                    if prev_start.saturating_add(prev.data.len()) > offset {
                        reject = Some(Reject::Overlap);
                    }
                }
            }
            if reject.is_none() && !duplicate {
                if let Some((&next_start, _)) = state.pieces.range(offset..).next() {
                    if next_start < end {
                        reject = Some(Reject::Overlap);
                    }
                }
            }

            if reject.is_none() && !duplicate {
                let compact = Bytes::copy_from_slice(&payload);
                added_len = compact.len().saturating_add(FRAGMENT_PIECE_OVERHEAD);
                state.bytes = state.bytes.saturating_add(added_len);
                state.wire_bytes = state.wire_bytes.saturating_add(wire_len);
                state.pieces.insert(
                    offset,
                    FragmentPiece {
                        data: compact,
                        more,
                    },
                );
            }
        }

        if let Some(reason) = reject {
            self.remove_key(&key);
            return (
                match reason {
                    Reject::Invalid => FragmentInsert::DroppedInvalid,
                    Reject::Overlap => FragmentInsert::DroppedOverlap,
                },
                maintenance,
            );
        }
        if duplicate {
            return (self.try_complete(&key), maintenance);
        }

        self.bytes = self.bytes.saturating_add(added_len);
        let completed = self.try_complete(&key);
        if !matches!(completed, FragmentInsert::Pending) {
            return (completed, maintenance);
        }

        while self.bytes > self.max_bytes || self.states.len() > self.max_datagrams {
            if !self.evict_oldest() {
                break;
            }
            maintenance.evicted = maintenance.evicted.saturating_add(1);
        }
        (FragmentInsert::Pending, maintenance)
    }

    fn try_complete(&mut self, key: &FragmentKey) -> FragmentInsert {
        let Some(state) = self.states.get(key) else {
            return FragmentInsert::Pending;
        };
        let Some(total) = state.total_len else {
            return FragmentInsert::Pending;
        };
        let mut cursor = 0usize;
        for (&start, piece) in &state.pieces {
            if start != cursor {
                return FragmentInsert::Pending;
            }
            cursor = cursor.saturating_add(piece.data.len());
        }
        if cursor != total {
            return FragmentInsert::Pending;
        }

        let state = self.states.remove(key).expect("state exists");
        self.bytes = self.bytes.saturating_sub(state.bytes);
        let mut out = Vec::with_capacity(total);
        for (_, piece) in state.pieces {
            out.extend_from_slice(&piece.data);
        }
        FragmentInsert::Complete {
            payload: Bytes::from(out),
            wire_bytes: state.wire_bytes,
        }
    }

    fn maintenance(&mut self, now: Instant) -> FragmentMaintenance {
        if now.duration_since(self.last_cleanup) < Duration::from_secs(1) {
            return FragmentMaintenance::default();
        }
        self.last_cleanup = now;
        let timeout = self.timeout;
        let expired = self
            .states
            .iter()
            .filter_map(|(k, v)| (now.duration_since(v.last_seen) >= timeout).then_some(k.clone()))
            .collect::<Vec<_>>();
        let count = expired.len() as u64;
        for key in expired {
            self.remove_key(&key);
        }
        FragmentMaintenance {
            expired: count,
            evicted: 0,
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(key) = self
            .states
            .iter()
            .min_by_key(|(_, v)| v.last_seen)
            .map(|(k, _)| k.clone())
        else {
            return false;
        };
        self.remove_key(&key);
        true
    }

    fn remove_key(&mut self, key: &FragmentKey) {
        if let Some(state) = self.states.remove(key) {
            self.bytes = self.bytes.saturating_sub(state.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key() -> FragmentKey {
        FragmentKey {
            version: 4,
            l2_domain: 0,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            id: 7,
            next_header: 6,
        }
    }

    #[test]
    fn reassembles_non_overlapping_fragments() {
        let mut c = FragmentCache::new(1 << 20, 16, Duration::from_secs(30));
        let (a, _) = c.insert(key(), 8, false, Bytes::from_static(b"ijklmnop"), 28);
        assert!(matches!(a, FragmentInsert::Pending));
        let (b, _) = c.insert(key(), 0, true, Bytes::from_static(b"abcdefgh"), 28);
        match b {
            FragmentInsert::Complete { payload, .. } => {
                assert_eq!(payload.as_ref(), b"abcdefghijklmnop")
            }
            _ => panic!("not complete"),
        }
    }

    #[test]
    fn late_final_fragment_cannot_shrink_below_existing_bytes() {
        let mut c = FragmentCache::new(1 << 20, 16, Duration::from_secs(30));
        let _ = c.insert(key(), 16, true, Bytes::from_static(b"ijklmnop"), 28);
        let (r, _) = c.insert(key(), 0, false, Bytes::from_static(b"abcdefgh"), 28);
        assert!(matches!(r, FragmentInsert::DroppedInvalid));
    }

    #[test]
    fn same_payload_with_conflicting_more_flag_is_not_an_exact_duplicate() {
        let mut c = FragmentCache::new(1 << 20, 16, Duration::from_secs(30));
        let _ = c.insert(key(), 0, true, Bytes::from_static(b"abcdefgh"), 28);
        let (r, _) = c.insert(key(), 0, false, Bytes::from_static(b"abcdefgh"), 28);
        assert!(matches!(r, FragmentInsert::DroppedOverlap));
    }

    #[test]
    fn empty_final_fragment_can_close_an_existing_range() {
        let mut c = FragmentCache::new(1 << 20, 16, Duration::from_secs(30));
        let _ = c.insert(key(), 0, true, Bytes::from_static(b"abcdefgh"), 28);
        let (r, _) = c.insert(key(), 8, false, Bytes::new(), 20);
        match r {
            FragmentInsert::Complete { payload, .. } => assert_eq!(payload.as_ref(), b"abcdefgh"),
            _ => panic!("not complete"),
        }
    }

    #[test]
    fn rejects_partial_overlap() {
        let mut c = FragmentCache::new(1 << 20, 16, Duration::from_secs(30));
        let _ = c.insert(key(), 0, true, Bytes::from_static(b"abcdefgh"), 28);
        let (b, _) = c.insert(key(), 4, false, Bytes::from_static(b"XXXXXXXX"), 28);
        assert!(matches!(b, FragmentInsert::DroppedOverlap));
    }
}
