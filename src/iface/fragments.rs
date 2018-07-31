#[cfg(not(feature = "fragmentation-ipv4"))]
use core::marker::PhantomData;
#[cfg(feature = "fragmentation-ipv4")]
use managed::ManagedSlice;
#[cfg(feature = "fragmentation-ipv4")]
use managed::ManagedMap;
#[cfg(feature = "fragmentation-ipv4")]
use storage::Assembler;
#[cfg(feature = "fragmentation-ipv4")]
use time::Instant;
#[cfg(feature = "fragmentation-ipv4")]
use wire::Ipv4Address;

/// Struct for reassembling fragmented packets,
/// it holds individual fragments and once all
/// fragments are present, the final packet can
/// be assembled
#[cfg(feature = "fragmentation-ipv4")]
pub struct Packet<'a> {
    rx_buffer: ManagedSlice<'a, u8>,
    state: PacketState,
}

#[cfg(feature = "fragmentation-ipv4")]
#[derive(Debug)]
enum PacketState {
    Empty,
    Assembling {
        assembler: Assembler,
        id: u16,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        last_used: Instant,
        has_header: bool,
        header_len: usize,
        total_len: usize,
    },
}

#[cfg(feature = "fragmentation-ipv4")]
impl<'a> Packet<'a> {
    /// Create a new empty packet
    pub fn new<S>(storage: S) -> Packet<'a>
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        let s = storage.into();
        Packet {
            rx_buffer: s,
            state: PacketState::Empty,
        }
    }

    /// Reset packet to the initial empty state
    pub fn reset(&mut self) {
        self.state = PacketState::Empty;
    }

    /// Add a fragment into the packet that is being reassembled
    pub fn add(
        &mut self,
        new_header_len: usize,
        offset: usize,
        payload_len: usize,
        data: &[u8],
        time: Instant,
    ) -> Result<(),()> {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot add a new fragment");
            }
            PacketState::Assembling {
                ref mut assembler,
                ref mut last_used,
                ref mut has_header,
                ref mut header_len,
                ..
            } => {
                debug_assert!(time >= *last_used);
                *last_used = time;

                if !(*has_header) {
                    assembler.add(0, new_header_len)?;
                    let range = 0..new_header_len;
                    self.rx_buffer[range].clone_from_slice(&data[0..new_header_len]);
                    *header_len = new_header_len;
                    *has_header = true;
                }

                assembler.add(offset + *header_len, payload_len)?;
                let range = (offset + *header_len)..(offset + payload_len + *header_len);
                self.rx_buffer[range].clone_from_slice(&data[*header_len..]);
            }
        }
        Ok(())
    }

    /// Return `true` if the packet has all fragments,
    /// and can be reassmbled, and `false` otherwise
    pub fn check_contig_range(&self) -> bool {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot check contig range");
            }
            PacketState::Assembling {
                ref assembler,
                ref total_len,
                ..
            } => {
                if *total_len != 0 {
                    if let Some(front) = assembler.peek_front() {
                        if front == *total_len {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Retrieve the first continuous segment from the assembler
    pub fn front(&mut self) -> Option<usize> {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot return front");
            }
            PacketState::Assembling {
                ref mut assembler, ..
            } => assembler.remove_front(),
        }
    }

    /// Is the packet empty?
    pub fn is_empty(&self) -> bool {
        match self.state {
            PacketState::Empty => true,
            PacketState::Assembling { .. } => false,
        }
    }

    /// Initiate reassembly of a frahgmented packet
    pub fn start(&mut self, id: u16, src_addr: Ipv4Address, dst_addr: Ipv4Address) {
        match self.state {
            PacketState::Empty => {
                self.state = PacketState::Assembling {
                    assembler: Assembler::new(self.rx_buffer.len()),
                    id: id,
                    src_addr: src_addr,
                    dst_addr: dst_addr,
                    last_used: Instant::from_millis(0),
                    has_header: false,
                    header_len: 0,
                    total_len: 0,
                }
            }
            PacketState::Assembling { .. } => {
                panic!("Attempting to start an assembling packet");
            }
        }
    }

    /// Set total length of the reassembled packet
    pub fn set_total_len(&mut self, len: usize) {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot set total length of the fragment");
            }
            PacketState::Assembling {
                ref mut total_len, ..
            } => {
                *total_len = len;
            }
        }
    }

    /// Get an immutable slice of the underlying packet data
    pub fn get_buffer_and_reset(&mut self, start: usize, end: usize) -> &[u8] {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot access its buffer");
            }
            PacketState::Assembling { .. } => {}
        }
        self.state = PacketState::Empty;
        &self.rx_buffer[start..end]
    }

    /// Get a mutable slice of the underlying packet data
    pub fn get_buffer_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        match self.state {
            PacketState::Empty => {
                panic!("Packet is empty, cannot access its buffer");
            }
            PacketState::Assembling { .. } => &mut self.rx_buffer[start..end],
        }
    }
}

#[cfg(feature = "fragmentation-ipv4")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Key {
    id: u16,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
}

#[cfg(feature = "fragmentation-ipv4")]
impl Key {
    pub fn new(id: u16, src_addr: Ipv4Address, dst_addr: Ipv4Address) -> Key {
        Key {
            id: id,
            src_addr: src_addr,
            dst_addr: dst_addr,
        }
    }
}

pub struct Set<'a> {
    #[cfg(feature = "fragmentation-ipv4")]
    packets: ManagedMap<'a, Key, Packet<'a>>,
    #[cfg(not(feature = "fragmentation-ipv4"))]
    _packets: PhantomData<&'a ()>,
}

#[cfg(feature = "fragmentation-ipv4")]
impl<'a> Set<'a> {
    /// Default timeout duration
    //pub(crate) const FRAGMENTATION_TIMEOUT_MS: i64 = 500;

    /// Create a new set of packets
    pub fn new<S>(storage: S) -> Set<'a>
    where
        S: Into<ManagedMap<'a, Key, Packet<'a>>>,
    {
        Set {
            packets: storage.into(),
        }
    }

    /// Add new packet into the set
    pub fn insert(&mut self, key: Key, packet: Packet<'a>) {
        match self.packets.insert(key, packet) {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    /// Contains given key? Equivalent of `contains_key` from `std::collections`
    pub fn contains_key(&self, key: &Key) -> bool {
        match self.packets.get(key) {
            Some(_) => true,
            None => false,
        }
    }

    /// Get a packet with given key (id+src_addr+dst_addr)
    /// If the map doesn't contain the key, create a new packet, insert it
    /// and return a reference to it.
    pub fn get_packet(&mut self, key: Key, _time: Instant) -> Option<&mut Packet<'a>> {
        // TODO: when should we clear the entry?
        //self.purge_old_packets(time);
        self.packets.get_mut(&key)
    }
}

/*
#[cfg(feature = "fragmentation-ipv4")]
impl<'a> Set<'a> {
    /// Default timeout duration
    pub(crate) const FRAGMENTATION_TIMEOUT_MS: i64 = 500;

    /// Create a new set of packets
    pub fn new<S>(storage: S) -> Set<'a>
        where S: Into<ManagedSlice<'a, Packet<'a>>>,
    {
        Set { packets: storage.into() }
    }

    /// Add new packet into the set
    pub fn add(&mut self, new_packet: Packet<'a>) {
        match self.packets {
            ManagedSlice::Borrowed(ref mut packets) => {
                for packet in packets.iter_mut() {
                    match packet.state {
                        PacketState::Empty => {
                            *packet = new_packet;
                            return;
                        },
                        PacketState::Assembling{..} => {}
                    }
                }
            },
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut packets) => {
                packets.push(new_packet);
            }
        }
    }

    /// Get a packet with given key
    fn get(&mut self, key_id: u16, key_src_addr: Ipv4Address, key_dst_addr: Ipv4Address) -> Option<&mut Packet<'a>> {
        for packet in self.packets.iter_mut() {
            match packet.state {
                PacketState::Empty => {},
                PacketState::Assembling{id, src_addr, dst_addr, ..} => {
                    if key_id == id &&
                       key_src_addr == src_addr &&
                       key_dst_addr == dst_addr {
                           return Some(packet);
                       }
                }
            }
        }
        None
    }

    /// Get an empty packet
    fn get_empty(&mut self) -> Option<&mut Packet<'a>> {
        for packet in self.packets.iter_mut() {
            match packet.state {
                PacketState::Empty => {return Some(packet);},
                PacketState::Assembling{..} => {}
            }
        }
        None
    }


    /// Remove stale packets
    fn purge_old_packets(&mut self, time: Instant) {
        for packet in self.packets.iter_mut() {
            match packet.state {
                PacketState::Empty => {},
                PacketState::Assembling{last_used, ..} => {
                    if (time.total_millis() - last_used.millis) > Self::FRAGMENTATION_TIMEOUT_MS {
                        packet.reset();
                    }
                }
            }
        }
    }

    /// Check if the set contains a packet with given `id`
    pub fn contains(&self, key_id: u16, key_src_addr: Ipv4Address, key_dst_addr: Ipv4Address) -> bool {
        for packet in self.packets.iter() {
            match packet.state {
                PacketState::Empty => {},
                PacketState::Assembling{id, src_addr, dst_addr, ..}=> {
                    if key_id == id &&
                       key_src_addr == src_addr &&
                       key_dst_addr == dst_addr {
                           return true;
                       }
                },
            }
        }
        false
    }

    /// Get a packet with given key
    pub fn get_packet(&mut self, id: u16, src_addr: Ipv4Address, dst_addr: Ipv4Address, time: Instant) -> Option<&mut Packet<'a>> {
        self.purge_old_packets(time);
        if self.contains(id, src_addr, dst_addr) {
            self.get(id, src_addr, dst_addr)
        } else {
            self.get_empty()
        }
    }
}
*/
