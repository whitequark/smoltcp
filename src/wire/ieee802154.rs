use core::fmt;

use byteorder::{ByteOrder, LittleEndian};

// use {Error, Result};
use Result;

enum_with_unknown! {
    /// IEEE 802.15.4 protocol type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
        // Reserved = 0b100, // use the Unknown variant for this.
        Multipurpose = 0b101,
        FragmentOrFrak = 0b110,
        Extended = 0b111,
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FrameType::Beacon => write!(f, "Beacon"),
            FrameType::Data => write!(f, "Data"),
            FrameType::Acknowledgement  => write!(f, "Ack"),
            FrameType::MacCommand  => write!(f, "MAC command"),
            FrameType::Multipurpose =>  write!(f, "Multipurpose"),
            FrameType::FragmentOrFrak =>  write!(f, "FragmentOrFrak"),
            FrameType::Extended =>  write!(f, "Extended"),
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

/// A IEEE 802.15.4 PAN.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Pan(u16);


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
        pub fn $field(&self) -> bool {
            let data = self.buffer.as_ref();
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);

            ((raw >> $bit) & 0b1) == 0b1
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
    pub fn frame_type(&self) -> FrameType {
        let data = self.buffer.as_ref();
        let raw = &data[field::FRAMECONTROL];
        let raw = (raw[0] & 0b111) as u8;
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
        let raw = &data[field::FRAMECONTROL];
        let raw = (raw[1] >> 6 & 0b11) as u8;
        AddressingMode::from(raw)
    }

    /// Return the destination addressing mode.
    #[inline]
    pub fn dst_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = &data[field::FRAMECONTROL];
        let raw = (raw[1] >> 2 & 0b11) as u8;
        AddressingMode::from(raw)
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn dst_pan(&self) -> Option<Pan> {
        let data = self.addressing_fields();
        match self.dst_addressing_mode() {
            AddressingMode::Absent => None,
            AddressingMode::Short | AddressingMode::Extended => {
                Some(Pan(LittleEndian::read_u16(&data[0..2])))
            },
            _ => unreachable!(),
        }
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn src_pan(&self) -> Option<Pan> {
        let data = self.addressing_fields();
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        match self.src_addressing_mode() {
            AddressingMode::Absent => None,
            AddressingMode::Short => {
                Some(Pan(LittleEndian::read_u16(&data[offset..offset+2])))
            },
            _ => unreachable!(),
        }
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.addressing_fields();
        match self.dst_addressing_mode() {
            AddressingMode::Absent => Address::Absent,
            AddressingMode::Short => {
                let mut raw = [0u8; 2];
                raw.clone_from_slice(&data[2..4]);
                Address::short_from_bytes(raw)
            },
            AddressingMode::Extended => {
                let mut raw = [0u8; 8];
                raw.clone_from_slice(&data[2..10]);
                Address::extended_from_bytes(raw)
            },
            _ => unreachable!(),
        }
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.addressing_fields();
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2 + 2; // + both pan offsets

        match self.src_addressing_mode() {
            AddressingMode::Absent => Address::Absent,
            AddressingMode::Short => {
                let mut raw = [0u8; 2];
                raw.clone_from_slice(&data[offset..offset+2]);
                Address::short_from_bytes(raw)
            },
            AddressingMode::Extended => {
                let mut raw = [0u8; 8];
                raw.clone_from_slice(&data[offset..offset+8]);
                Address::extended_from_bytes(raw)
            },
            _ => unreachable!(),
        }
    }

    #[inline]
    fn addressing_fields(&self) -> &[u8] {
        &self.buffer.as_ref()[field::ADDRESSING]
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IEEE802.15.4 frame src={} dst={} type={}",
               self.src_addr(), self.dst_addr(), self.frame_type())
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;
    use Result;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
    }

    macro_rules! vector_test {
        ($name:ident $bytes:expr ; $($test_method:ident -> $expected:expr,)*) => {
            #[test]
            fn $name() -> Result<()> {
                let frame = &$bytes;
                // let _frame = Frame::new_checked(frame)?;
                let frame = Frame::new_unchecked(frame);

                $(
                    let v = frame.$test_method();
                    assert_eq!($expected, v, stringify!($test_method));
                );*

                Ok(())
            }
        }
    }

    vector_test! {
        extended_addr
        [
            0b0000_0001, 0b1100_1100, // frame control
            0b0, // seq
            0x03, 0x03, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // dst addr
            0x03, 0x04, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // src addr
        ];
        frame_type -> FrameType::Data,
        dst_addr -> Address::Extended([0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01]),
        src_addr -> Address::Extended([0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02]),
    }

    vector_test! {
        short_addr
        [
            0x01, 0x98,             // frame control
            0x00,                   // sequence number
            0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
            0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> false,
        dst_addr -> Address::Short([0x78, 0x56]),
        src_addr -> Address::Short([0xbc, 0x9a]),
        dst_pan -> Some(Pan(0x1234)),
        src_pan -> Some(Pan(0x1234)),
    }
}
