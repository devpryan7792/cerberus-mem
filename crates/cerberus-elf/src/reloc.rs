//! Relocation exemption masks for differential memory comparison.

use crate::disk::RelocationRecord;

/// One byte interval that the dynamic linker is allowed to rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationInterval {
    /// Offset relative to the start of the compared segment.
    pub offset_in_segment: usize,
    /// Length of the exempted interval.
    pub length: usize,
}

/// A collection of relocation intervals applied before hashing or diffing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationMask {
    /// Exempted intervals.
    pub intervals: Vec<RelocationInterval>,
}

impl RelocationMask {
    /// Create an empty mask.
    pub fn new() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    /// Add one exempted interval.
    pub fn add_interval(&mut self, offset: usize, length: usize) {
        self.intervals.push(RelocationInterval {
            offset_in_segment: offset,
            length,
        });
    }

    /// Build a mask from relocations that fall inside a text section.
    pub fn from_relocations(relocations: &[RelocationRecord]) -> Self {
        let mut mask = Self::new();
        for relocation in relocations {
            let Ok(offset) = usize::try_from(relocation.offset_in_text) else {
                continue;
            };
            mask.add_interval(offset, relocation.width);
        }
        mask
    }

    /// Zero every exempted interval, clamping to the buffer length.
    pub fn apply_mask(&self, buffer: &mut [u8]) {
        for interval in &self.intervals {
            let start = interval.offset_in_segment;
            if start >= buffer.len() {
                continue;
            }
            let end = match start.checked_add(interval.length) {
                Some(end) => end.min(buffer.len()),
                None => buffer.len(),
            };
            buffer[start..end].fill(0);
        }
    }

    /// Compare two buffers while ignoring exempted intervals.
    ///
    /// Both slices must start at the same segment offset. Intervals are
    /// clamped to the compared length, and overlapping or unsorted intervals
    /// are handled by merging them through a cursor.
    pub fn masked_eq(&self, left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        let len = left.len();
        let mut intervals: Vec<(usize, usize)> = self
            .intervals
            .iter()
            .map(|interval| {
                let start = interval.offset_in_segment.min(len);
                let end = start.saturating_add(interval.length).min(len);
                (start, end)
            })
            .collect();
        intervals.sort_unstable();

        let mut cursor = 0usize;
        for (start, end) in intervals {
            if start > cursor && left[cursor..start] != right[cursor..start] {
                return false;
            }
            cursor = cursor.max(end);
        }
        left[cursor..] == right[cursor..]
    }

    /// Whether the mask contains no intervals.
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }
}
