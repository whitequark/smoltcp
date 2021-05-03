use core::fmt;

use byteorder::{ByteOrder, LittleEndian};

use crate::Error;
use crate::Result;

enum_with_unknown! {
    /// IEEE 802.15.4 frame type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
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
            FrameType::Acknowledgement => write!(f, "Ack"),
            FrameType::MacCommand => write!(f, "MAC command"),
            FrameType::Multipurpose => write!(f, "Multipurpose"),
            FrameType::FragmentOrFrak => write!(f, "FragmentOrFrak"),
            FrameType::Extended => write!(f, "Extended"),
            FrameType::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}
enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum AddressingMode(u8) {
        Absent    = 0b00,
        Short     = 0b10,
        Extended  = 0b11,
    }
}

impl AddressingMode {
    /// Return the size in octets of the address.
    fn size(&self) -> usize {
        match self {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for AddressingMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressingMode::Absent => write!(f, "Absent"),
            AddressingMode::Short => write!(f, "Short"),
            AddressingMode::Extended => write!(f, "Extended"),
            AddressingMode::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}

/// A IEEE 802.15.4 PAN.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Pan(pub u16);

impl Pan {
    /// Return the PAN ID as bytes.
    pub fn as_bytes(&self) -> [u8; 2] {
        [(self.0 & 0xff) as u8, ((self.0 & 0xff00) >> 8) as u8] // XXX: check the order
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

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Address::Absent => &[],
            Address::Short(value) => value,
            Address::Extended(value) => value,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "not-present"),
            Self::Short(bytes) => {
                write!(f, "{:02x}-{:02x}", bytes[0], bytes[1])
            }
            Self::Extended(bytes) => {
                write!(
                    f,
                    "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
                )
            }
        }
    }
}

enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum FrameVersion(u8) {
        Ieee802154_2003    = 0b00,
        Ieee802154_2006    = 0b01,
        Ieee802154  = 0b10,
    }
}

/// A read/write wrapper around an IEEE 802.15.4 frame buffer.
#[derive(Debug, Clone)]
pub struct Frame<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub const FRAMECONTROL: Field = 0..2;
    pub const SEQUENCE_NUMBER: Field = 2..3;
    pub const ADDRESSING: Rest = 3..;
}

macro_rules! fc_bit_field {
    ($field:ident, $bit:literal) => {
        #[inline]
        pub fn $field(&self) -> bool {
            let data = self.buffer.as_ref();
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);

            ((raw >> $bit) & 0b1) == 0b1
        }
    };
}

macro_rules! set_fc_bit_field {
    ($field:ident, $bit:literal) => {
        #[inline]
        pub fn $field(&mut self) {
            let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);
            raw |= (0b1 << $bit);

            data.copy_from_slice(&raw.to_le_bytes());
        }
    };
}

impl<T: AsRef<[u8]>> Frame<T> {
    /// Input a raw octet buffer with Ethernet frame structure.
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
        if self.buffer.as_ref().is_empty() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the FrameType field.
    #[inline]
    pub fn frame_type(&self) -> FrameType {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let ft = (raw & 0b11) as u8;
        FrameType::from(ft)
    }

    fc_bit_field!(security_enabled, 3);
    fc_bit_field!(frame_pending, 4);
    fc_bit_field!(ack_request, 5);
    fc_bit_field!(pan_id_compression, 6);

    /// Return the destination addressing mode.
    #[inline]
    pub fn dst_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let am = ((raw >> 10) & 0b11) as u8;
        AddressingMode::from(am)
    }

    /// Return the frame version.
    #[inline]
    pub fn frame_version(&self) -> FrameVersion {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let fv = ((raw >> 12) & 0b11) as u8;
        FrameVersion::from(fv)
    }

    /// Return the source addressing mode.
    #[inline]
    pub fn src_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let am = ((raw >> 14) & 0b11) as u8;
        AddressingMode::from(am)
    }

    /// Return the sequence number of the frame.
    #[inline]
    pub fn sequence_number(&self) -> u8 {
        let data = self.buffer.as_ref();
        let raw = data[field::SEQUENCE_NUMBER][0];
        raw
    }

    /// Return the addressing fields.
    #[inline]
    fn addressing_fields(&self) -> Option<&[u8]> {
        match self.frame_type() {
            FrameType::Data => {
                let mut offset = 2;

                // Calculate the size of the addressing field.
                offset += self.dst_addressing_mode().size();
                offset += self.src_addressing_mode().size();

                // XXX: We assume DST_ADDR and SRC_ADDR are present when there is PAN ID compression
                if !self.pan_id_compression() {
                    offset += 2;
                }

                Some(&self.buffer.as_ref()[field::ADDRESSING][..offset])
            }
            _ => None,
        }
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn dst_pan_id(&self) -> Option<Pan> {
        match self.frame_type() {
            FrameType::Data => {
                let data = self.addressing_fields().unwrap();
                match self.dst_addressing_mode() {
                    AddressingMode::Absent => None,
                    AddressingMode::Short | AddressingMode::Extended => {
                        Some(Pan(LittleEndian::read_u16(&data[0..2])))
                    }
                    _ => unreachable!(),
                }
            }
            _ => None,
        }
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        match self.frame_type() {
            FrameType::Data => {
                let data = self.addressing_fields().unwrap();
                match self.dst_addressing_mode() {
                    AddressingMode::Absent => Address::Absent,
                    AddressingMode::Short => {
                        // XXX not sure if the endianness is correctly handled
                        let mut raw = [0u8; 2];
                        raw.clone_from_slice(&data[2..4]);
                        Address::short_from_bytes(raw)
                    }
                    AddressingMode::Extended => {
                        // XXX not sure if the endianness is correctly handled
                        let mut raw = [0u8; 8];
                        raw.clone_from_slice(&data[2..10]);
                        Address::extended_from_bytes(raw)
                    }
                    _ => unreachable!(),
                }
            }
            _ => Address::Absent,
        }
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn src_pan_id(&self) -> Option<Pan> {
        match self.frame_type() {
            FrameType::Data => {
                if self.pan_id_compression() {
                    return None;
                }

                let addressing_fields = self.addressing_fields().unwrap();
                let offset = self.dst_addressing_mode().size() + 2;

                match self.src_addressing_mode() {
                    AddressingMode::Absent => None,
                    AddressingMode::Short | AddressingMode::Extended => Some(Pan(
                        LittleEndian::read_u16(&addressing_fields[offset..offset + 2]),
                    )),
                    _ => unreachable!(),
                }
            }
            _ => None,
        }
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        match self.frame_type() {
            FrameType::Data => {
                let data = self.addressing_fields().unwrap();
                let mut offset = match self.dst_addressing_mode() {
                    AddressingMode::Absent => 0,
                    AddressingMode::Short => 2,
                    AddressingMode::Extended => 8,
                    _ => unreachable!(),
                } + 2;

                if !self.pan_id_compression() {
                    offset += 2;
                }

                match self.src_addressing_mode() {
                    AddressingMode::Absent => Address::Absent,
                    AddressingMode::Short => {
                        // XXX not sure if the endianness is correctly handled
                        let mut raw = [0u8; 2];
                        raw.clone_from_slice(&data[offset..offset + 2]);
                        Address::short_from_bytes(raw)
                    }
                    AddressingMode::Extended => {
                        // XXX not sure if the endianness is correctly handled
                        let mut raw = [0u8; 8];
                        raw.clone_from_slice(&data[offset..offset + 8]);
                        Address::extended_from_bytes(raw)
                    }
                    _ => unreachable!(),
                }
            }
            _ => Address::Absent,
        }
    }

    /// Return the Auxilliary Security Header Field
    #[inline]
    pub fn aux_security_header(&self) -> Option<&[u8]> {
        if self.security_enabled() {
            todo!();
        } else {
            None
        }
    }

    /// Return the FCS fields
    #[inline]
    pub fn fcs(&self) -> &[u8] {
        &self.buffer.as_ref()[self.buffer.as_ref().len() - 2..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> Option<&'a [u8]> {
        match self.frame_type() {
            FrameType::Data => {
                let data = &self.buffer.as_ref()[field::ADDRESSING];
                let offset = self.addressing_fields().unwrap().len();

                Some(&data[offset..data.len() - 2])
            }
            _ => None,
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// Set the frame type.
    #[inline]
    pub fn set_frame_type(&mut self, frame_type: FrameType) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b111)) | (u8::from(frame_type) as u16 & 0b111);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    set_fc_bit_field!(set_security_enabled, 3);
    set_fc_bit_field!(set_frame_pending, 4);
    set_fc_bit_field!(set_ack_request, 5);
    set_fc_bit_field!(set_pan_id_compression, 6);

    /// Set the frame version.
    #[inline]
    pub fn set_frame_version(&mut self, version: FrameVersion) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 12)) | ((u8::from(version) as u16 & 0b11) << 12);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Set the frame sequence number.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::SEQUENCE_NUMBER][0] = value;
    }

    /// Set the destination PAN ID.
    #[inline]
    pub fn set_dst_pan_id(&mut self, value: Pan) {
        // NOTE the destination addressing mode must be different than Absent.
        // This is the reason why we set it to Extended.
        self.set_dst_addressing_mode(AddressingMode::Extended);

        let data = self.buffer.as_mut();
        data[field::ADDRESSING][..2].copy_from_slice(&value.as_bytes());
    }

    /// Set the destination address.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        match value {
            Address::Absent => self.set_dst_addressing_mode(AddressingMode::Absent),
            Address::Short(ref value) => {
                self.set_dst_addressing_mode(AddressingMode::Short);
                let data = self.buffer.as_mut();
                data[field::ADDRESSING][2..2 + 2].copy_from_slice(value);
            }
            Address::Extended(ref value) => {
                self.set_dst_addressing_mode(AddressingMode::Extended);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[2..2 + 8].copy_from_slice(value);
            }
        }
    }

    /// Set the destination addressing mode.
    #[inline]
    fn set_dst_addressing_mode(&mut self, value: AddressingMode) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 10)) | ((u8::from(value) as u16 & 0b11) << 10);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Set the source PAN ID.
    #[inline]
    pub fn set_src_pan_id(&mut self, value: Pan) {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => todo!("{}", self.dst_addressing_mode()),
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let data = &mut self.buffer.as_mut()[field::ADDRESSING];
        data[offset..offset + 2].copy_from_slice(&value.as_bytes());
    }

    /// Set the source address.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => todo!("{}", self.dst_addressing_mode()),
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let offset = offset + if self.pan_id_compression() { 0 } else { 2 };

        match value {
            Address::Absent => self.set_src_addressing_mode(AddressingMode::Absent),
            Address::Short(ref value) => {
                self.set_src_addressing_mode(AddressingMode::Short);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[offset..offset + 2].copy_from_slice(value);
            }
            Address::Extended(ref value) => {
                self.set_src_addressing_mode(AddressingMode::Extended);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[offset..offset + 8].copy_from_slice(value);
            }
        }
    }

    /// Set the source addressing mode.
    #[inline]
    fn set_src_addressing_mode(&mut self, value: AddressingMode) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 14)) | ((u8::from(value) as u16 & 0b11) << 14);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> Option<&mut [u8]> {
        match self.frame_type() {
            FrameType::Data => {
                let mut start_offset = 3;
                start_offset += self.addressing_fields().unwrap().len();

                let data = self.buffer.as_mut();
                let end_offset = start_offset + data.len() - 2;
                Some(&mut data[start_offset..end_offset])
            }
            _ => None,
        }
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IEEE802.15.4 frame type={} seq={:2x} dst_pan={:x?} dest={} src_pan={:?} src={} fcs={:x?}",
            self.frame_type(),
            self.sequence_number(),
            self.dst_pan_id(),
            self.dst_addr(),
            self.src_pan_id(),
            self.src_addr(),
            self.fcs(),
        )
    }
}

/// A high-level representation of an IEEE802.15.4 frame.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a, T: AsRef<[u8]>> {
    pub frame_type: FrameType,
    pub security_enabled: bool,
    pub frame_pending: bool,
    pub ack_request: bool,
    pub sequence_number: u8,
    pub pan_id_compression: bool,
    pub frame_version: FrameVersion,
    pub dst_pan_id: Pan,
    pub dst_addr: Address,
    pub src_pan_id: Option<Pan>,
    pub src_addr: Address,
    pub payload: &'a T,
}

impl<'a, T: AsRef<[u8]>> Repr<'a, T> {
    /// Return the length of a buffer required to hold a packet with the payload of a given length.
    #[inline]
    pub fn buffer_len(&self) -> usize {
        3 + 2
            + match self.dst_addr {
                Address::Absent => 0,
                Address::Short(_) => 2,
                Address::Extended(_) => 8,
            }
            + if !self.pan_id_compression { 2 } else { 0 }
            + match self.src_addr {
                Address::Absent => 0,
                Address::Short(_) => 2,
                Address::Extended(_) => 8,
            }
            + self.payload.as_ref().len()
            + 2
    }
}

impl<'a, T: AsRef<[u8]>> Repr<'a, T> {
    /// Emit a high-level representation into an IEEE802.15.4 frame.
    pub fn emit<B: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<B>) {
        frame.set_frame_type(self.frame_type);
        if self.security_enabled {
            frame.set_security_enabled();
        }

        if self.frame_pending {
            frame.set_frame_pending();
        }

        if self.ack_request {
            frame.set_ack_request();
        }

        if self.pan_id_compression {
            frame.set_pan_id_compression();
        }

        frame.set_frame_version(self.frame_version);

        frame.set_sequence_number(self.sequence_number);

        frame.set_dst_pan_id(self.dst_pan_id);
        frame.set_dst_addr(self.dst_addr);

        if !self.pan_id_compression && self.src_pan_id.is_some() {
            frame.set_src_pan_id(self.src_pan_id.unwrap());
        }
        frame.set_src_addr(self.src_addr);

        let offset = 3 + frame.addressing_fields().unwrap().len();
        let payload_len = self.payload.as_ref().len();

        frame.buffer.as_mut()[offset..offset + payload_len].copy_from_slice(self.payload.as_ref());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
    }

    #[test]
    fn prepare_frame() {
        let mut buffer = [0u8; 128];

        let repr = Repr {
            frame_type: FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            pan_id_compression: true,
            frame_version: FrameVersion::Ieee802154,
            sequence_number: 0,
            dst_pan_id: Pan(0xabcd),
            dst_addr: Address::BROADCAST,
            src_pan_id: None,
            src_addr: Address::Extended([0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00]),
            payload: &1234u32.to_le_bytes(),
        };

        let buffer_len = repr.buffer_len();

        let mut frame = Frame::new_unchecked(&mut buffer[..buffer_len]);
        repr.emit(&mut frame);

        println!("{:2x?}", frame);

        assert_eq!(frame.frame_type(), FrameType::Data);
        assert_eq!(frame.security_enabled(), false);
        assert_eq!(frame.frame_pending(), false);
        assert_eq!(frame.ack_request(), true);
        assert_eq!(frame.pan_id_compression(), true);
        assert_eq!(frame.frame_version(), FrameVersion::Ieee802154);
        assert_eq!(frame.sequence_number(), 0);
        assert_eq!(frame.dst_pan_id(), Some(Pan(0xabcd)));
        assert_eq!(frame.dst_addr(), Address::BROADCAST);
        assert_eq!(frame.src_pan_id(), None);
        assert_eq!(
            frame.src_addr(),
            Address::Extended([0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00])
        );
    }

    macro_rules! vector_test {
        ($name:ident $bytes:expr ; $($test_method:ident -> $expected:expr,)*) => {
            #[test]
            fn $name() -> Result<()> {
                let frame = &$bytes;
                let frame = Frame::new_checked(frame)?;

                $(
                    let v = frame.$test_method();
                    assert_eq!($expected, v, stringify!($test_method));
                )*

                Ok(())
            }
        }
    }

    vector_test! {
        extended_addr
        [
            0b0000_0001, 0b1100_1100, // frame control
            0b0, // seq
            0xcd, 0xab, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // dst addr
            0x03, 0x04, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // src addr
        ];
        frame_type -> FrameType::Data,
        dst_addr -> Address::Extended([0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01]),
        src_addr -> Address::Extended([0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02]),
        dst_pan_id -> Some(Pan(0xabcd)),
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
        dst_addressing_mode -> AddressingMode::Short,
        frame_version -> FrameVersion::Ieee802154_2006,
        src_addressing_mode -> AddressingMode::Short,
        dst_pan_id -> Some(Pan(0x1234)),
        dst_addr -> Address::Short([0x78, 0x56]),
        src_pan_id -> Some(Pan(0x1234)),
        src_addr -> Address::Short([0xbc, 0x9a]),
    }

    vector_test! {
        zolertia_remote
        [
            0x41, 0xd8, // frame control
            0x01, // sequence number
            0xcd, 0xab, // Destination PAN id
            0xff, 0xff, // Short destination address
            0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // Extended source address
            0x2b, 0x00, 0x00, 0x00, // payload
            0xb3, 0x0d // FSM
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> true,
        dst_addressing_mode -> AddressingMode::Short,
        frame_version -> FrameVersion::Ieee802154_2006,
        src_addressing_mode -> AddressingMode::Extended,
        //payload -> Some(&[0x2b, 0x00, 0x00, 0x00]),
        fcs -> [0xb3, 0x0d],
    }
}
