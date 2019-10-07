use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

// use {Error, Result};
use Result;

enum_with_unknown! {
    /// IEEE 802.15.4 protocol type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FrameType::Beacon => write!(f, "Beacon"),
            FrameType::Data => write!(f, "Data"),
            FrameType::Acknowledgement  => write!(f, "Ack"),
            FrameType::MacCommand  => write!(f, "MAC command"),
            FrameType::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}
enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and sourcerce addresses.
    pub enum AddressingMode(u8) {
        Absent    = 0b00,
        Short     = 0b10,
        Extended  = 0b11,
    }
}

impl fmt::Display for AddressingMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressingMode::Absent => write!(f, "Absent"),
            AddressingMode::Short => write!(f, "Short"),
            AddressingMode::Extended  => write!(f, "Extended"),
            AddressingMode::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}

/// A IEEE 802.15.4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    Absent,
    Short([u8; 2]),
    Extended([u8; 8]),
}

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address::Short([0xff; 2]);

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    fn short_from_bytes(a: [u8; 2]) -> Self {
        Self::Short(a)
    }

    fn extended_from_bytes(a: [u8; 8]) -> Self {
        Self::Extended(a)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "not-present"),
            Self::Short(bytes) => {
                write!(f, "{:02x}-{:02x}",
                   bytes[0], bytes[1])
            },
            Self::Extended(bytes) => {
                write!(f, "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                   bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7])
            }
        }
    }
}

/// A read/write wrapper around an IEEE 802.15.4 frame buffer.
#[derive(Debug, Clone)]
pub struct Frame<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    use wire::field::*;

    pub const FRAMECONTROL: Field =  0..2;
    pub const ADDRESSING:    Rest  =  3..;
    // pub const DESTINATION:  Field =  0..2;
}

macro_rules! fc_bit_field {
    ($field:ident, $bit:literal) => {
        #[allow(unused)]
        fn $field(&self) -> bool {
            true
        }
    }
}

impl<T: AsRef<[u8]>> Frame<T> {
    /// Imbue a raw octet buffer with Ethernet frame structure.
    pub fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        unimplemented!()
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the FrameType field.
    #[inline]
    pub fn frametype(&self) -> FrameType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FRAMECONTROL]);
        let raw = (raw & 0b111) as u8;
        FrameType::from(raw)
    }

    fc_bit_field!(security_enabled, 3);
    fc_bit_field!(frame_pending, 4);
    fc_bit_field!(ack_request, 5);
    fc_bit_field!(pan_id_compression, 6);

    /// Return the source addressing mode.
    #[inline]
    pub fn src_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FRAMECONTROL]);
        let raw = (raw >> 14 & 0b11) as u8;
        AddressingMode::from(raw)
    }

    /// Return the destination addressing mode.
    #[inline]
    pub fn dst_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FRAMECONTROL]);
        let raw = (raw >> 10 & 0b11) as u8;
        AddressingMode::from(raw)
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        match self.dst_addressing_mode() {
            AddressingMode::Absent => Address::Absent,
            AddressingMode::Short => {
                let data = &data[field::ADDRESSING];
                let mut raw = [0u8; 2];
                raw.clone_from_slice(&data);
                Address::short_from_bytes(raw)
            },
            AddressingMode::Extended => {
                let data = &data[field::ADDRESSING];
                let mut raw = [0u8; 8];
                raw.clone_from_slice(&data);
                Address::extended_from_bytes(raw)
            },
            _ => unreachable!(),
        }
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let _data = self.buffer.as_ref();
        unimplemented!()
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IEEE802.15.4 frame src={} dst={} type={}",
               self.src_addr(), self.dst_addr(), self.frametype())
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
    }
}
