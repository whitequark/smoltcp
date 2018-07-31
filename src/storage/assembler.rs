use core::fmt;

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

const CONTIG_COUNT: usize = 4;

/// A buffer (re)assembler.
///
/// Currently, up to a hardcoded limit of four holes can be tracked in the buffer.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Assembler {
    contigs: [Contig; CONTIG_COUNT]
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
        let mut contigs = [Contig::empty(); CONTIG_COUNT];
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
    fn add_contig_at(&mut self, at: usize) -> Result<&mut Contig, ()> {
        debug_assert!(!self.contigs[at].is_empty());

        if !self.back().is_empty() { return Err(()) }

        for i in (at + 1..self.contigs.len()).rev() {
            self.contigs[i] = self.contigs[i - 1];
        }

        self.contigs[at] = Contig::empty();
        Ok(&mut self.contigs[at])
    }

    /// Add a new contiguous range to the assembler, and return `Ok(())`,
    /// or return `Err(())` if too many discontiguities are already recorded.
    pub fn add(&mut self, mut offset: usize, mut size: usize) -> Result<(), ()> {
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
                // The range being added covers a part of the hole but not of the data
                // in this contig, add a new contig containing the range.
                self.contigs[index].shrink_hole_by(offset + size);
                let inserted = self.add_contig_at(index)?;
                *inserted = Contig::hole_and_data(offset, size);
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

    /// Return length of the front contiguous range without removing it from the assembler
    pub fn peek_front(&self) -> Option<usize> {
        let front = self.front();
        if front.has_hole() {
            None
        } else {
            Some(front.data_size)
        }
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use super::*;

    impl From<Vec<(usize, usize)>> for Assembler {
        fn from(vec: Vec<(usize, usize)>) -> Assembler {
            let mut contigs = [Contig::empty(); CONTIG_COUNT];
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
}
