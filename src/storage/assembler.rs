use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyHolesError;

/// A contiguous chunk of absent data, followed by a contiguous chunk of present data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Contig {
    hole_size: usize,
    data_size: usize
}

impl fmt::Display for Contig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.has_hole() { write!(f, "({})", self.hole_size)?; }
        if self.has_hole() && self.has_data() { write!(f, " ")?; }
        if self.has_data() { write!(f, "{}",   self.data_size)?; }
        Ok(())
    }
}

impl Contig {
    fn empty() -> Contig {
        Contig { hole_size: 0, data_size: 0 }
    }

    fn hole(size: usize) -> Contig {
        Contig { hole_size: size, data_size: 0 }
    }

    fn hole_and_data(hole_size: usize, data_size: usize) -> Contig {
        Contig { hole_size, data_size }
    }

    fn has_hole(&self) -> bool {
        self.hole_size != 0
    }

    fn has_data(&self) -> bool {
        self.data_size != 0
    }

    fn total_size(&self) -> usize {
        self.hole_size + self.data_size
    }

    fn is_empty(&self) -> bool {
        self.total_size() == 0
    }

    fn expand_data_by(&mut self, size: usize) {
        self.data_size += size;
    }

    fn shrink_hole_by(&mut self, size: usize) {
        self.hole_size -= size;
    }

    fn shrink_hole_to(&mut self, size: usize) {
        debug_assert!(self.hole_size >= size);

        let total_size = self.total_size();
        self.hole_size = size;
        self.data_size = total_size - size;
    }
}

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", feature = "alloc"))]
const CONTIG_COUNT: usize = 32;

#[cfg(not(any(feature = "std", feature = "alloc")))]
const CONTIG_COUNT: usize = 4;

/// A buffer (re)assembler.
///
/// Currently, up to a hardcoded limit of 4 or 32 holes can be tracked in the buffer.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq, Clone))]
pub struct Assembler {
    #[cfg(not(any(feature = "std", feature = "alloc")))]
    contigs: [Contig; CONTIG_COUNT],
    #[cfg(any(feature = "std", feature = "alloc"))]
    contigs: Box<[Contig; CONTIG_COUNT]>,
}

impl fmt::Display for Assembler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[ ")?;
        for contig in self.contigs.iter() {
            if contig.is_empty() { break }
            write!(f, "{} ", contig)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl Assembler {
    /// Create a new buffer assembler for buffers of the given size.
    pub fn new(size: usize) -> Assembler {
        #[cfg(not(any(feature = "std", feature = "alloc")))]
        let mut contigs = [Contig::empty(); CONTIG_COUNT];
        #[cfg(any(feature = "std", feature = "alloc"))]
        let mut contigs = Box::new([Contig::empty(); CONTIG_COUNT]);
        contigs[0] = Contig::hole(size);
        Assembler { contigs }
    }

    /// FIXME(whitequark): remove this once I'm certain enough that the assembler works well.
    #[allow(dead_code)]
    pub(crate) fn total_size(&self) -> usize {
        self.contigs
            .iter()
            .map(|contig| contig.total_size())
            .sum()
    }

    /// Returns true if the next call to self.add could either fill the assembler or return
    /// TooManyHolesError. Used in ensure there's space for adding a contig with 0 offset.
    pub(crate) fn could_saturate(&self) -> bool {
        self.contigs[self.contigs.len() - 2].has_data()
    }

    fn front(&self) -> Contig {
        self.contigs[0]
    }

    fn back(&self) -> Contig {
        self.contigs[self.contigs.len() - 1]
    }

    /// Return whether the assembler contains no data.
    pub fn is_empty(&self) -> bool {
        !self.front().has_data()
    }

    /// Remove a contig at the given index, and return a pointer to the first contig
    /// without data.
    fn remove_contig_at(&mut self, at: usize) -> &mut Contig {
        debug_assert!(!self.contigs[at].is_empty());

        for i in at..self.contigs.len() - 1 {
            self.contigs[i] = self.contigs[i + 1];
            if !self.contigs[i].has_data() {
                self.contigs[i + 1] = Contig::empty();
                return &mut self.contigs[i]
            }
        }

        // Removing the last one.
        self.contigs[at] = Contig::empty();
        &mut self.contigs[at]
    }

    /// Add a contig at the given index, and return a pointer to it.
    fn add_contig_at(&mut self, at: usize) -> Result<&mut Contig, TooManyHolesError> {
        debug_assert!(!self.contigs[at].is_empty());

        if !self.back().is_empty() { return Err(TooManyHolesError) }

        for i in (at + 1..self.contigs.len()).rev() {
            self.contigs[i] = self.contigs[i - 1];
        }

        self.contigs[at] = Contig::empty();
        Ok(&mut self.contigs[at])
    }

    pub fn replace_start_with_hole(&mut self, size: usize) {
        let total_size = self.total_size();
        let removed = self.remove_beginning(size, false);
        self.contigs[0].hole_size += removed;
        if total_size != self.total_size() {
            debug_assert!(false);
        }
    }

    pub fn shift_offset(&mut self, size: usize) {
        let total_size = self.total_size();
        self.remove_beginning(size, true);
        if total_size != self.total_size() {
            debug_assert!(false);
        }
    }

    fn remove_beginning(&mut self, mut size: usize, add_to_end: bool) -> usize {
        let mut contigs_to_remove = 0;
        let mut removed = 0;

        while contigs_to_remove != self.contigs.len() {
            let contig = &mut self.contigs[contigs_to_remove];

            if size <= contig.hole_size {
                removed += size;
                contig.hole_size -= size;
                break;
            }

            removed += contig.hole_size;
            size -= contig.hole_size;
            contig.hole_size = 0;

            if size < contig.data_size {
                contig.data_size -= size;
                removed += size;
                break;
            }

            removed += contig.data_size;
            size -= contig.data_size;
            contigs_to_remove += 1;

            if size == 0 {
                break;
            }
        }

        if contigs_to_remove == 0 {
            if add_to_end {
                for i in 0..self.contigs.len() - contigs_to_remove {
                    if !self.contigs[i].has_data() {
                        self.contigs[i].hole_size += removed;
                        break;
                    }
                }
            }
            return removed;
        }

        for i in 0..self.contigs.len() - contigs_to_remove {
            self.contigs[i] = self.contigs[i + contigs_to_remove];
            if !self.contigs[i].has_data() {
                self.contigs[i + contigs_to_remove] = if add_to_end {
                    Contig::hole(removed)
                } else {
                    Contig::empty()
                };
                return removed;
            }
        }

        removed
    }

    /// Add a new contiguous range to the assembler, and return `Ok(())`,
    /// or return `Err(())` if too many discontiguities are already recorded.
    pub fn add(&mut self, offset: usize, size: usize) -> Result<(), TooManyHolesError> {
        self.add_or_extend(offset, size, false)
    }

    /// Add a new contiguous range to the assembler, and return `Ok(())`,
    /// or return `Err(())` if too many discontiguities are already recorded.
    pub fn add_or_extend(&mut self, mut offset: usize, mut size: usize, extend_only: bool) -> Result<(), TooManyHolesError> {
        let mut index = 0;
        while index != self.contigs.len() && size != 0 {
            let contig = self.contigs[index];

            if offset >= contig.total_size() {
                // The range being added does not cover this contig, skip it.
                index += 1;
            } else if offset == 0 && size >= contig.hole_size && index > 0 {
                // The range being added covers the entire hole in this contig, merge it
                // into the previous config.
                self.contigs[index - 1].expand_data_by(contig.total_size());
                self.remove_contig_at(index);
                index += 0;
            } else if offset == 0 && size < contig.hole_size && index > 0 {
                // The range being added covers a part of the hole in this contig starting
                // at the beginning, shrink the hole in this contig and expand data in
                // the previous contig.
                self.contigs[index - 1].expand_data_by(size);
                self.contigs[index].shrink_hole_by(size);
                index += 1;
            } else if offset <= contig.hole_size && offset + size >= contig.hole_size {
                // The range being added covers both a part of the hole and a part of the data
                // in this contig, shrink the hole in this contig.
                self.contigs[index].shrink_hole_to(offset);
                index += 1;
            } else if offset + size >= contig.hole_size {
                // The range being added covers only a part of the data in this contig, skip it.
                index += 1;
            } else if offset + size < contig.hole_size {
                if extend_only {
                    return Err(TooManyHolesError);
                }
                // The range being added covers a part of the hole but not of the data
                // in this contig, add a new contig containing the range.
                {
                  let inserted = self.add_contig_at(index)?;
                  *inserted = Contig::hole_and_data(offset, size);
                }
                // Previous contigs[index] got moved to contigs[index+1]
                self.contigs[index+1].shrink_hole_by(offset + size);
                index += 2;
            } else {
                unreachable!()
            }

            // Skip the portion of the range covered by this contig.
            if offset >= contig.total_size() {
                offset = offset.saturating_sub(contig.total_size());
            } else {
                size   = (offset + size).saturating_sub(contig.total_size());
                offset = 0;
            }
        }

        debug_assert!(size == 0);
        Ok(())
    }

    /// Remove a contiguous range from the front of the assembler and `Some(data_size)`,
    /// or return `None` if there is no such range.
    pub fn remove_front(&mut self) -> Option<usize> {
        let front = self.front();
        if front.has_hole() {
            None
        } else {
            let last_hole = self.remove_contig_at(0);
            last_hole.hole_size += front.data_size;

            debug_assert!(front.data_size > 0);
            Some(front.data_size)
        }
    }

    /// Iterate over all of the contiguous data ranges.
    ///
    /// This is used in calculating what data ranges have been received. The offset indicates the
    /// number of bytes of contiguous data received before the beginnings of this Assembler.
    ///
    ///    Data        Hole        Data
    /// |--- 100 ---|--- 200 ---|--- 100 ---|
    ///
    /// An offset of 1500 would return the ranges: ``(1500, 1600), (1800, 1900)``
    pub fn iter_data(&self, first_offset: usize) -> AssemblerIter {
        AssemblerIter::new(self, first_offset)
    }
}

pub struct AssemblerIter<'a> {
    assembler: &'a Assembler,
    offset: usize,
    index: usize,
    left: usize,
    right: usize
}

impl<'a> AssemblerIter<'a> {
    fn new(assembler: &'a Assembler, offset: usize) -> AssemblerIter<'a> {
        AssemblerIter {
            assembler: assembler,
            offset: offset,
            index: 0,
            left: 0,
            right: 0
        }
    }
}

impl<'a> Iterator for AssemblerIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        let mut data_range = None;
        while data_range.is_none() && self.index < self.assembler.contigs.len() {
            let contig = self.assembler.contigs[self.index];
            self.left += contig.hole_size;
            self.right = self.left + contig.data_size;
            data_range = if self.left < self.right {
                let data_range = (self.left + self.offset, self.right + self.offset);
                self.left = self.right;
                Some(data_range)
            } else {
                None
            };
            self.index += 1;
        }
        data_range
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use super::*;

    impl From<Vec<(usize, usize)>> for Assembler {
        fn from(vec: Vec<(usize, usize)>) -> Assembler {
            #[cfg(not(any(feature = "std", feature = "alloc")))]
            let mut contigs = [Contig::empty(); CONTIG_COUNT];
            #[cfg(any(feature = "std", feature = "alloc"))]
            let mut contigs = Box::new([Contig::empty(); CONTIG_COUNT]);
            for (i, &(hole_size, data_size)) in vec.iter().enumerate() {
                contigs[i] = Contig { hole_size, data_size };
            }
            Assembler { contigs }
        }
    }

    macro_rules! contigs {
        [$( $x:expr ),*] => ({
            Assembler::from(vec![$( $x ),*])
        })
    }

    #[test]
    fn test_new() {
        let assr = Assembler::new(16);
        assert_eq!(assr.total_size(), 16);
        assert_eq!(assr, contigs![(16, 0)]);
    }

    #[test]
    fn test_empty_add_full() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(0, 16), Ok(()));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_empty_add_front() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(0, 4), Ok(()));
        assert_eq!(assr, contigs![(0, 4), (12, 0)]);
    }

    #[test]
    fn test_empty_add_back() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(12, 4), Ok(()));
        assert_eq!(assr, contigs![(12, 4)]);
    }

    #[test]
    fn test_empty_add_mid() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(4, 8), Ok(()));
        assert_eq!(assr, contigs![(4, 8), (4, 0)]);
    }

    #[test]
    fn test_partial_add_front() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 4), Ok(()));
        assert_eq!(assr, contigs![(0, 12), (4, 0)]);
    }

    #[test]
    fn test_partial_add_back() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(12, 4), Ok(()));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_front_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 8), Ok(()));
        assert_eq!(assr, contigs![(0, 12), (4, 0)]);
    }

    #[test]
    fn test_partial_add_front_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(2, 6), Ok(()));
        assert_eq!(assr, contigs![(2, 10), (4, 0)]);
    }

    #[test]
    fn test_partial_add_back_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(8, 8), Ok(()));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_back_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(10, 4), Ok(()));
        assert_eq!(assr, contigs![(4, 10), (2, 0)]);
    }

    #[test]
    fn test_partial_add_both_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 16), Ok(()));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_partial_add_both_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(2, 12), Ok(()));
        assert_eq!(assr, contigs![(2, 12), (2, 0)]);
    }

    #[test]
    fn test_rejected_add_keeps_state() {
        let mut assr = Assembler::new(CONTIG_COUNT*20);
        for c in 1..=CONTIG_COUNT-1 {
          assert_eq!(assr.add(c*10, 3), Ok(()));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.add(1, 3), Err(TooManyHolesError));
        assert_eq!(assr_before, assr);
    }

    #[test]
    fn test_empty_remove_front() {
        let mut assr = contigs![(12, 0)];
        assert_eq!(assr.remove_front(), None);
    }

    #[test]
    fn test_trailing_hole_remove_front() {
        let mut assr = contigs![(0, 4), (8, 0)];
        assert_eq!(assr.remove_front(), Some(4));
        assert_eq!(assr, contigs![(12, 0)]);
    }

    #[test]
    fn test_trailing_data_remove_front() {
        let mut assr = contigs![(0, 4), (4, 4)];
        assert_eq!(assr.remove_front(), Some(4));
        assert_eq!(assr, contigs![(4, 4), (4, 0)]);

    }

    #[test]
    fn test_iter_empty() {
        let assr = Assembler::new(16);
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![]);
    }

    #[test]
    fn test_iter_full() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(0, 16), Ok(()));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(10, 26)]);
    }

    #[test]
    fn test_iter_offset() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(0, 16), Ok(()));
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(100, 116)]);
    }

    #[test]
    fn test_iter_one_front() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(0, 4), Ok(()));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(10, 14)]);
    }

    #[test]
    fn test_iter_one_back() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(12, 4), Ok(()));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(22, 26)]);
    }

    #[test]
    fn test_iter_one_mid() {
        let mut assr = Assembler::new(16);
        assert_eq!(assr.add(4, 8), Ok(()));
        let segments: Vec<_> = assr.iter_data(10).collect();
        assert_eq!(segments, vec![(14, 22)]);
    }

    #[test]
    fn test_iter_one_trailing_gap() {
        let assr = contigs![(4, 8), (4, 0)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(104, 112)]);
    }

    #[test]
    fn test_iter_two_split() {
        let assr = contigs![(2, 6), (4, 1), (1, 0)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(102, 108), (112, 113)]);
    }

    #[test]
    fn test_iter_three_split() {
        let assr = contigs![(2, 6), (2, 1), (2, 2), (1, 0)];
        let segments: Vec<_> = assr.iter_data(100).collect();
        assert_eq!(segments, vec![(102, 108), (110, 111), (113, 115)]);
    }
}
