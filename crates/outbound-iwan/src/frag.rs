//! IPFRAG reassembly (spec §7): pieces are placed by offset into one slot per
//! group ID; a group completes when its last piece has arrived and every byte
//! before the end of that piece is covered.

use std::time::{Duration, Instant};

use crate::packet::Fragment;

/// Groups reassembled at once; a new group beyond this evicts the oldest.
pub const MAX_GROUPS: usize = 10;
/// Largest reassembled packet.
pub const MAX_PACKET: usize = 4096;
/// A group without a new piece for this long is dropped.
pub const GROUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Group {
    id: [u8; 4],
    data: Vec<u8>,
    covered: Vec<bool>,
    end: Option<usize>,
    updated: Instant,
}

impl Group {
    fn new(id: [u8; 4], now: Instant) -> Self {
        Self {
            id,
            data: vec![0; MAX_PACKET],
            covered: vec![false; MAX_PACKET],
            end: None,
            updated: now,
        }
    }

    fn complete(&self) -> Option<usize> {
        let end = self.end?;
        self.covered[..end].iter().all(|byte| *byte).then_some(end)
    }
}

#[derive(Default)]
pub struct Reassembler {
    groups: Vec<Group>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one piece; returns the whole packet once its group is complete.
    /// Pieces that end past [`MAX_PACKET`] are dropped.
    pub fn push(&mut self, now: Instant, fragment: Fragment<'_>) -> Option<Vec<u8>> {
        self.expire(now);
        let end = fragment.offset + fragment.data.len();
        if fragment.data.is_empty() || end > MAX_PACKET {
            return None;
        }
        let index = match self.groups.iter().position(|g| g.id == fragment.group) {
            Some(index) => index,
            None => {
                if self.groups.len() >= MAX_GROUPS {
                    let oldest = self
                        .groups
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, group)| group.updated)
                        .map(|(index, _)| index)?;
                    self.groups.swap_remove(oldest);
                }
                self.groups.push(Group::new(fragment.group, now));
                self.groups.len() - 1
            }
        };
        let group = &mut self.groups[index];
        group.updated = now;
        group.data[fragment.offset..end].copy_from_slice(fragment.data);
        group.covered[fragment.offset..end].fill(true);
        if fragment.last {
            group.end = Some(end);
        }
        let len = group.complete()?;
        let mut group = self.groups.swap_remove(index);
        group.data.truncate(len);
        Some(group.data)
    }

    /// Drops groups that have waited longer than [`GROUP_TIMEOUT`].
    pub fn expire(&mut self, now: Instant) {
        self.groups
            .retain(|group| now.saturating_duration_since(group.updated) <= GROUP_TIMEOUT);
    }

    pub fn clear(&mut self) {
        self.groups.clear();
    }

    pub fn pending(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(group: u8, offset: usize, last: bool, data: &[u8]) -> Fragment<'_> {
        Fragment {
            group: [group; 4],
            offset,
            last,
            data,
        }
    }

    #[test]
    fn reassembles_out_of_order_pieces() {
        let now = Instant::now();
        let mut frags = Reassembler::new();
        assert_eq!(frags.push(now, piece(1, 4, true, &[5, 6])), None);
        assert_eq!(frags.push(now, piece(2, 0, false, &[9])), None);
        assert_eq!(
            frags.push(now, piece(1, 0, false, &[1, 2, 3, 4])),
            Some(vec![1, 2, 3, 4, 5, 6])
        );
        assert_eq!(frags.pending(), 1);
    }

    #[test]
    fn waits_for_gaps_before_the_last_piece() {
        let now = Instant::now();
        let mut frags = Reassembler::new();
        assert_eq!(frags.push(now, piece(1, 0, false, &[1, 2])), None);
        assert_eq!(frags.push(now, piece(1, 4, true, &[5])), None);
        assert_eq!(
            frags.push(now, piece(1, 2, false, &[3, 4])),
            Some(vec![1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn drops_oversized_and_stale_groups() {
        let now = Instant::now();
        let mut frags = Reassembler::new();
        assert_eq!(
            frags.push(now, piece(1, MAX_PACKET - 1, true, &[1, 2])),
            None
        );
        assert_eq!(frags.pending(), 0);
        assert_eq!(frags.push(now, piece(1, 2, true, &[3])), None);
        let later = now + GROUP_TIMEOUT + Duration::from_secs(1);
        assert_eq!(frags.push(later, piece(1, 0, false, &[1, 2])), None);
        assert_eq!(frags.pending(), 1);
    }

    #[test]
    fn evicts_the_oldest_group_when_full() {
        let start = Instant::now();
        let mut frags = Reassembler::new();
        for group in 0..MAX_GROUPS as u8 {
            let now = start + Duration::from_millis(u64::from(group));
            assert_eq!(frags.push(now, piece(group, 1, true, &[2])), None);
        }
        let now = start + Duration::from_millis(100);
        assert_eq!(frags.push(now, piece(200, 1, true, &[2])), None);
        assert_eq!(frags.pending(), MAX_GROUPS);
        assert_eq!(frags.push(now, piece(1, 0, false, &[1])), Some(vec![1, 2]));
        // Group 0 was evicted, so its first byte starts a new group.
        assert_eq!(frags.push(now, piece(0, 0, false, &[1])), None);
    }
}
