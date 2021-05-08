use byteorder::{ByteOrder, NetworkEndian};

use crate::wire::field::*;
use crate::wire::ieee802154::Address as LlAddress;
use crate::wire::ipv6;
use crate::wire::IpProtocol;
use crate::Error;
use crate::Result;

/// A wrapper around the address provided in the 6LoWPAN_IPHC header.
/// This requires some context to convert it the an IPv6 address in some cases.
/// For 802.15.4 the context are the short/extended addresses.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Address<'a> {
    Complete(ipv6::Address),
    WithContext(&'a [u8]),
    Elided,
    Reserved,
}

impl<'a> Address<'a> {
    /// Resolve the address provided by the IPHC encoding.
    fn resolve(self, ll_addr: Option<LlAddress>) -> ipv6::Address {
        match self {
            Address::Complete(addr) => addr,
            Address::Elided => {
                let mut bytes = [0; 16];
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                match ll_addr {
                    Some(LlAddress::Short(ll)) => {
                        bytes[11] = 0xff;
                        bytes[12] = 0xfe;
                        bytes[14..].copy_from_slice(&ll);
                    }
                    Some(LlAddress::Extended(ll)) => {
                        bytes[8..].copy_from_slice(&LlAddress::Extended(ll).as_eui_64().unwrap());
                    }
                    _ => unreachable!(),
                }

                ipv6::Address::from_bytes(&bytes)
            }
            Address::Reserved => {
                unreachable!()
            }
            Address::WithContext(ctx) => {
                // XXX this is incorrect
                let mut bytes = [0; 16];
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                match ll_addr {
                    Some(LlAddress::Short(ll)) => {
                        bytes[11] = 0xff;
                        bytes[12] = 0xfe;

                        bytes[14..].copy_from_slice(&ll);
                    }
                    Some(LlAddress::Extended(ll)) => {
                        bytes[8..].copy_from_slice(&LlAddress::Extended(ll).as_eui_64().unwrap());
                    }
                    _ => unreachable!(),
                }

                ipv6::Address::from_bytes(&bytes)
            }
        }
    }
}

const DISPATCH: u8 = 0b011;

macro_rules! get_iphc_field {
    ($name:ident, $mask:expr, $shift:expr) => {
        fn $name(&self) -> u8 {
            let data = self.buffer.as_ref();
            let raw = NetworkEndian::read_u16(&data[self.iphc_fields()]);
            ((raw >> $shift) & $mask) as u8
        }
    };
}

macro_rules! set_iphc_field {
    ($name:ident, $mask:expr, $shift:expr) => {
        fn $name(&mut self, val: u8) {
            let iphc_field = self.iphc_fields();
            let data = &mut self.buffer.as_mut()[iphc_field];
            let mut raw = NetworkEndian::read_u16(data);

            raw = (raw & !($mask << $shift)) | ((val as u16) << $shift);
            data.copy_from_slice(&raw.to_le_bytes());
        }
    };
}

/// A read/write wrapper around a 6LoWPAN frame buffer.
#[derive(Debug, Clone)]
pub enum Packet<T: AsRef<[u8]>> {
    IphcPacket(IphcPacket<T>),
    NhcPacket(NhcPacket<T>),
}

/// A read/write wrapper around a 6LoWPAN_IPHC frame buffer.
#[derive(Debug, Clone)]
pub struct IphcPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> IphcPacket<T> {
    /// Input a raw octet buffer with a 6LoWPAN_IPHC frame structure.
    pub fn new_unchecked(buffer: T) -> IphcPacket<T> {
        IphcPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<IphcPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let buffer = self.buffer.as_ref();
        if buffer.is_empty() || buffer.len() < 2 {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Parse the next header field.
    /// This will return None when the NHC encoding is used.
    pub fn next_header(&self) -> Option<IpProtocol> {
        let nh = self.nh_field();

        if nh == 1 {
            // The next header field is compressed.
            // It is also encoded using LOWPAN_NHC.
            None
        } else {
            let mut start = (self.ip_fields_start() + self.traffic_class_size()) as usize;

            let data = self.buffer.as_ref();
            let nh = data[start..start + 1][0];
            Some(IpProtocol::from(nh))
        }
    }

    /// Parse the hop limit field.
    pub fn hop_limit(&self) -> u8 {
        match self.hlim_field() {
            0b00 => {
                let mut start = (self.ip_fields_start()
                    + self.traffic_class_size()
                    + self.next_header_size()) as usize;

                let data = self.buffer.as_ref();
                data[start..start + 1][0]
            }
            0b01 => 1,
            0b10 => 64,
            0b11 => 255,
            _ => unreachable!(),
        }
    }

    /// Return the source context identifier.
    pub fn src_context_id(&self) -> Option<u8> {
        if self.cid_field() == 1 {
            let data = self.buffer.as_ref();
            Some(data[1] >> 4)
        } else {
            None
        }
    }

    /// Return the destination context identifier.
    pub fn dst_context_id(&self) -> Option<u8> {
        if self.cid_field() == 1 {
            let data = self.buffer.as_ref();
            Some(data[1] & 0x0f)
        } else {
            None
        }
    }

    /// Parse the source address field.
    pub fn src_addr(&self) -> Address {
        let mut start = (self.ip_fields_start()
            + self.traffic_class_size()
            + self.next_header_size()
            + self.hop_limit_size()) as usize;

        match (self.sac_field(), self.sam_field()) {
            (0, 0b00) => {
                // The full address is carried in-line.
                let data = self.buffer.as_ref();
                Address::Complete(ipv6::Address::from_bytes(&data[start..start + 16]))
            }
            (0, 0b01) => {
                // The first 64-bits of the address is elided.
                // The value of those bits is the link-local prefix padded with zeros.
                // The remaining 64-bits are carried in-line.
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                // Link-local prefix
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                bytes[8..].copy_from_slice(&data[start..start + 8]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (0, 0b10) => {
                // The first 112 bits of the address are elided.
                // The value of the 64 bits is the link-local prefix padded with zeros.
                // The following 64 bits are 0000:00ff:fe00:XXXX,
                // where XXXX are the bits carried in-line.
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                // Link-local prefix
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                bytes[11] = 0xff;
                bytes[12] = 0xfe;

                bytes[14..].copy_from_slice(&data[start..start + 2]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (0, 0b11) => {
                // The address is fully elided.
                // The first 64 bits of the address are the link-local prefix padded with zeros.
                // The remaining 64 bits are computed from the encapsulating header.
                Address::Elided
            }
            (1, 0b00) => Address::Complete(ipv6::Address::UNSPECIFIED),
            (1, 0b01) => {
                // The address is derived using context information and the 64 bits carried in-line.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                let data = self.buffer.as_ref();
                let bytes = &data[start..start + 8];

                Address::WithContext(bytes)
            }
            (1, 0b10) => {
                // The address is derived using context information and the 16 bits carried in-line.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                let data = self.buffer.as_ref();
                let bytes = &data[start..start + 2];
                Address::Reserved
            }
            (1, 0b11) => {
                // The address is fully elided and is derived using context information and the encapsulating header.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                Address::WithContext(&[])
            }
            _ => unreachable!(),
        }
    }

    /// Parse the destination address field.
    pub fn dst_addr(&self) -> Address {
        let mut start = (self.ip_fields_start()
            + self.traffic_class_size()
            + self.next_header_size()
            + self.hop_limit_size()
            + self.src_address_size()) as usize;

        match (self.m_field(), self.dac_field(), self.dam_field()) {
            (0, 0, 0b00) => {
                // The full address is carried in-line.
                let data = self.buffer.as_ref();
                Address::Complete(ipv6::Address::from_bytes(&data[start..start + 16]))
            }
            (0, 0, 0b01) => {
                // The first 64-bits of the address is elided.
                // The value of those bits is the link-local prefix padded with zeros.
                // The remaining 64-bits are carried in-line.
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                // Link-local prefix
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                bytes[8..].copy_from_slice(&data[start..start + 8]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (0, 0, 0b10) => {
                // The first 112 bits of the address are elided.
                // The value of the 64 bits is the link-local prefix padded with zeros.
                // The following 64 bits are 0000:00ff:fe00:XXXX,
                // where XXXX are the bits carried in-line.
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                // Link-local prefix
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                bytes[11] = 0xff;
                bytes[12] = 0xfe;

                bytes[14..].copy_from_slice(&data[start..start + 2]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (0, 0, 0b11) => {
                // The address is fully elided.
                // The first 64 bits of the address are the link-local prefix padded with zeros.
                // The remaining 64 bits are computed from the encapsulating header.
                Address::Elided
            }
            (0, 1, 0b00) => Address::Reserved,
            (0, 1, 0b01) => {
                // The address is derived using context information and the 64 bits carried in-line.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                let data = self.buffer.as_ref();
                let bytes = &data[start..start + 8];

                Address::WithContext(bytes)
            }
            (0, 1, 0b10) => {
                // The address is derived using context information and the 16 bits carried in-line.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                let data = self.buffer.as_ref();
                let bytes = &data[start..start + 2];
                Address::Reserved
            }
            (0, 1, 0b11) => {
                // The address is fully elided and is derived using context information and the encapsulating header.
                // Bits covered by context information are always used.
                // Any IID bits not covered by context information are always used.
                // Any IID bits not covered by context information are directly from the corresponding bits carried in-line.
                // Any remaining bits are zero.
                Address::WithContext(&[])
            }
            (1, 0, 0b00) => {
                // The full address is carried in-line.
                let data = self.buffer.as_ref();
                Address::Complete(ipv6::Address::from_bytes(&data[start..start + 16]))
            }
            (1, 0, 0b01) => {
                // The address takes the form ffXX::00XX:XXXX:XXXX
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                bytes[0] = 0xff;
                bytes[1] = data[start];

                bytes[11..].copy_from_slice(&data[start + 1..start + 6]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (1, 0, 0b10) => {
                // The address takes the form ffXX::00XX:XXXX
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                bytes[0] = 0xff;
                bytes[1] = data[start];

                bytes[13..].copy_from_slice(&data[start + 1..start + 4]);

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (1, 0, 0b11) => {
                // The address takes the form ff02::00XX
                let data = self.buffer.as_ref();
                let mut bytes = [0u8; 16];

                bytes[0] = 0xff;
                bytes[1] = 0x02;

                bytes[15] = data[start];

                Address::Complete(ipv6::Address::from_bytes(&bytes))
            }
            (1, 1, 0b00) => {
                // This format is designed to match Unicast-Prefix-based IPv6 Multicast Addresses.
                // The multicast takes the form ffXX:XXLL:PPPP:PPPP:PPPP:PPPP:XXXX:XXXX.
                // X are octets that are carried in-line, in the order in which they appear.
                // P are octets used to encode the prefix itself.
                // L are octets used to encode the prefix length.
                // The prefix information P and L is taken from the specified context.
                todo!()
            }
            (1, 1, 0b01) => Address::Reserved,
            (1, 1, 0b10) => Address::Reserved,
            (1, 1, 0b11) => Address::Reserved,
            _ => unreachable!(),
        }
    }

    get_iphc_field!(dispatch_field, 0b111, 13);
    get_iphc_field!(tf_field, 0b11, 11);
    get_iphc_field!(nh_field, 0b1, 10);
    get_iphc_field!(hlim_field, 0b11, 8);
    get_iphc_field!(cid_field, 0b1, 7);
    get_iphc_field!(sac_field, 0b1, 6);
    get_iphc_field!(sam_field, 0b11, 4);
    get_iphc_field!(m_field, 0b1, 3);
    get_iphc_field!(dac_field, 0b1, 2);
    get_iphc_field!(dam_field, 0b11, 0);

    /// Return the range for the IPHC fields.
    fn iphc_fields(&self) -> Field {
        0..2
    }

    /// Return the start for the IP fields.
    fn ip_fields_start(&self) -> u8 {
        2 + self.cid_size()
    }

    /// Get the size in octets of the traffic class field.
    fn traffic_class_size(&self) -> u8 {
        match self.tf_field() {
            0b00 => 4,
            0b01 => 3,
            0b10 => 1,
            0b11 => 0,
            _ => unreachable!(),
        }
    }

    /// Get the size in octets of the next header field.
    fn next_header_size(&self) -> u8 {
        !(self.nh_field() == 1) as u8
    }

    /// Get the size in octets of the hop limit field.
    fn hop_limit_size(&self) -> u8 {
        (self.hlim_field() == 0b00) as u8
    }

    /// Get the size in octets of the CID field.
    fn cid_size(&self) -> u8 {
        (self.cid_field() == 1) as u8
    }

    /// Get the size in octets of the source address.
    fn src_address_size(&self) -> u8 {
        match (self.sac_field(), self.sam_field()) {
            (0, 0b00) => 16, // The full address is carried in-line.
            (0, 0b01) => 8,  // The first 64 bits are elided.
            (0, 0b10) => 2,  // The first 112 bits are elided.
            (0, 0b11) => 0,  // The address is fully elided.
            (1, 0b00) => 0,  // The UNSPECIFIED address.
            (1, 0b01) => 8,  // Address derived using context information.
            (1, 0b10) => 2,  // Address derived using context information.
            (1, 0b11) => 0,  // Address derived using context information.
            _ => unreachable!(),
        }
    }

    /// Get the size in octets of the address address.
    fn dst_address_size(&self) -> u8 {
        match (self.m_field(), self.dac_field(), self.dam_field()) {
            (0, 0, 0b00) => 16, // The full address is carried in-line.
            (0, 0, 0b01) => 8,  // The first 64 bits are elided.
            (0, 0, 0b10) => 2,  // The first 112 bits are elided.
            (0, 0, 0b11) => 0,  // The address is fully elided.
            (0, 1, 0b00) => 0,  // Reserved.
            (0, 1, 0b01) => 8,  // Address derived using context information.
            (0, 1, 0b10) => 2,  // Address derived using context information.
            (0, 1, 0b11) => 0,  // Address derived using context information.
            (1, 0, 0b00) => 16, // The full address is carried in-line.
            (1, 0, 0b01) => 6,  // The address takes the form ffXX::00XX:XXXX:XXXX.
            (1, 0, 0b10) => 4,  // The address takes the form ffXX::00XX:XXXX.
            (1, 0, 0b11) => 1,  // The address takes the form ff02::00XX.
            (1, 1, 0b00) => 6,  // Match Unicast-Prefix-based IPv6.
            (1, 1, 0b01) => 0,  // Reserved.
            (1, 1, 0b10) => 0,  // Reserved.
            (1, 1, 0b11) => 0,  // Reserved.
            _ => unreachable!(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IphcPacket<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let mut len = self.ip_fields_start();
        len += self.traffic_class_size();
        len += self.next_header_size();
        len += self.hop_limit_size();
        len += self.src_address_size();
        len += self.dst_address_size();

        let len = len as usize;

        let data = self.buffer.as_ref();
        &data[len..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> IphcPacket<T> {
    /// Set the dispatch field to `0b011`.
    fn set_dispatch_field(&mut self) {
        let iphc_field = self.iphc_fields();
        let data = &mut self.buffer.as_mut()[iphc_field];
        let mut raw = NetworkEndian::read_u16(data);

        raw = (raw & !(0b111 << 13)) | (0b11 << 13);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    set_iphc_field!(set_tf_field, 0b11, 11);
    set_iphc_field!(set_nh_field, 0b1, 10);
    set_iphc_field!(set_hlim_field, 0b11, 8);
    set_iphc_field!(set_cid_field, 0b1, 7);
    set_iphc_field!(set_sac_field, 0b1, 6);
    set_iphc_field!(set_sam_field, 0b11, 4);
    set_iphc_field!(set_m_field, 0b1, 3);
    set_iphc_field!(set_dac_field, 0b1, 2);
    set_iphc_field!(set_dam_field, 0b11, 0);

    fn set_field(&mut self, idx: usize, value: &[u8]) {
        let raw = self.buffer.as_mut();
        raw[idx..idx + value.len()].copy_from_slice(value);
    }

    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let mut len = self.ip_fields_start();

        len += self.traffic_class_size();
        len += self.next_header_size();
        len += self.hop_limit_size();
        len += self.src_address_size();
        len += self.dst_address_size();

        let len = len as usize;

        let data = self.buffer.as_mut();
        &mut data[len..]
    }
}

macro_rules! get_nhc_field {
    ($name:ident, $mask:expr, $shift:expr) => {
        fn $name(&self) -> u8 {
            let data = self.buffer.as_ref();
            let raw = &data[0];
            ((raw >> $shift) & $mask) as u8
        }
    };
}

/// A read/write wrapper around a 6LoWPAN_NHC frame buffer.
#[derive(Debug, Clone)]
pub enum NhcPacket<T: AsRef<[u8]>> {
    ExtHeader(ExtHeaderNhcPacket<T>),
    UdpHeader(UdpNhcPacket<T>),
}

impl<T: AsRef<[u8]>> NhcPacket<T> {
    pub fn dispatch_unchecked(buffer: T) -> Result<NhcPacket<T>> {
        let raw = buffer.as_ref();

        if raw[0] >> 4 == 0b1110 {
            // We have a compressed IPv6 Extension header.
            Ok(NhcPacket::ExtHeader(ExtHeaderNhcPacket::new_unchecked(
                buffer,
            )))
        } else if raw[0] >> 3 == 0b11110 {
            // We have a compressed UDP header.
            Ok(NhcPacket::UdpHeader(UdpNhcPacket::new_unchecked(buffer)))
        } else {
            Err(Error::Unrecognized)
        }
    }

    pub fn dispatch_checked(buffer: T) -> Result<NhcPacket<T>> {
        todo!();
    }
}

/// A read/write wrapper around a 6LoWPAN_NHC Next Header frame buffer.
#[derive(Debug, Clone)]
pub struct ExtHeaderNhcPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ExtHeaderNhcPacket<T> {
    /// Input a raw octet buffer with a 6LoWPAN_NHC frame structure.
    pub fn new_unchecked(buffer: T) -> ExtHeaderNhcPacket<T> {
        ExtHeaderNhcPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<ExtHeaderNhcPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let buffer = self.buffer.as_ref();
        if buffer.is_empty() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    get_nhc_field!(eid_field, 0b111, 1);
    get_nhc_field!(nh_field, 0b1, 0);

    /// Return the lenght of the Extension Header.
    pub fn header_len(&self) -> u8 {
        2
    }

    /// Return the length of the data of the Extension Header.
    pub fn header_data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[1]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ExtHeaderNhcPacket<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let start = self.header_len() as usize;
        &self.buffer.as_ref()[start..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> ExtHeaderNhcPacket<T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.header_len() as usize;
        &mut self.buffer.as_mut()[start..]
    }
}

/// A read/write wrapper around a 6LoWPAN_NHC_UDP frame buffer.
#[derive(Debug, Clone)]
pub struct UdpNhcPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UdpNhcPacket<T> {
    /// Input a raw octet buffer with a 6LoWPAN_NHC frame structure.
    pub fn new_unchecked(buffer: T) -> UdpNhcPacket<T> {
        UdpNhcPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<UdpNhcPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let buffer = self.buffer.as_ref();
        if buffer.is_empty() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    get_nhc_field!(checksum_field, 0b1, 2);
    get_nhc_field!(ports_field, 0b11, 0);

    /// Returns the index of the start of the next header compressed fields.
    fn nhc_fields_start(&self) -> usize {
        1
    }

    /// Return the source port number.
    fn src_port(&self) -> u16 {
        match self.ports_field() {
            0b00 | 0b01 => {
                // The full 16 bits are carried in-line.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                NetworkEndian::read_u16(&data[start..start + 2])
            }
            0b10 => {
                // The first 8 bits are elided.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                0xf000 + NetworkEndian::read_u16(&data[start..start + 1])
            }
            0b11 => {
                // The first 12 bits are elided.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                println!("Data: {:02x?}", data);
                println!("Start: {}", start);

                0xf0b0 + (NetworkEndian::read_u16(&data[start..start + 1]) >> 4)
            }
            _ => unreachable!(),
        }
    }

    /// Return the destination port number.
    fn dst_port(&self) -> u16 {
        match self.ports_field() {
            0b00 => {
                // The full 16 bits are carried in-line.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                NetworkEndian::read_u16(&data[start + 2..start + 4])
            }
            0b01 => {
                // The first 12 bits are elided.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                0xf000 + NetworkEndian::read_u16(&data[start + 2..start + 2 + 1])
            }
            0b10 => {
                // The full 16 bits are carried in-line.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                NetworkEndian::read_u16(&data[start + 1..start + 1 + 2])
            }
            0b11 => {
                // The first 12 bits are elided.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start();

                0xf0b0 + (NetworkEndian::read_u16(&data[start..start + 1]) & 0x000f)
            }
            _ => unreachable!(),
        }
    }

    /// Return the checksum.
    fn checksum(&self) -> Option<u16> {
        if self.checksum_field() == 0b0 {
            // The first 12 bits are elided.
            let data = self.buffer.as_ref();
            let start = self.nhc_fields_start() + self.ports_size();
            Some(NetworkEndian::read_u16(&data[start..start + 2]))
        } else {
            // The checksum is ellided and needs to be recomputed on the 6LoWPAN termination point.
            None
        }
    }

    // Return the size of the checksum field.
    fn checksum_size(&self) -> usize {
        match self.checksum_field() {
            0b0 => 2,
            0b1 => 0,
            _ => unreachable!(),
        }
    }

    /// Returns the total size of both port numbers.
    fn ports_size(&self) -> usize {
        match self.ports_field() {
            0b00 => 4, // 16 bits + 16 bits
            0b01 => 3, // 16 bits + 8 bits
            0b10 => 3, // 8 bits + 16 bits
            0b11 => 1, // 4 bits + 4 bits
            _ => unreachable!(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> UdpNhcPacket<&'a T> {
    /// Return a pointer to the payload.
    pub fn payload(&self) -> &'a [u8] {
        let start = 1 + self.ports_size() + self.checksum_size();
        &self.buffer.as_ref()[start..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> UdpNhcPacket<T> {
    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = 1 + self.ports_size() + self.checksum_size();
        &mut self.buffer.as_mut()[start..]
    }
}

/// A high-level representation of a 6LoWPAN_IPHC header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct IphcRepr<'a> {
    pub src_addr: ipv6::Address,
    pub ll_src_addr: Option<LlAddress>,
    pub dst_addr: ipv6::Address,
    pub ll_dst_addr: Option<LlAddress>,
    pub next_header: Option<IpProtocol>,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

impl<'a> IphcRepr<'a> {
    /// Parse a 6LoWPAN_IPHC packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(
        packet: &IphcPacket<&'a T>,
        ll_src_addr: Option<LlAddress>,
        ll_dst_addr: Option<LlAddress>,
    ) -> Result<IphcRepr<'a>> {
        // Ensure basic accessors will work.
        packet.check_len()?;

        if packet.dispatch_field() != DISPATCH {
            // This is not an 6LoWPAN_IPHC packet.
            return Err(Error::Unrecognized);
        }

        // // Unsupported modes currently treated as errors.
        // if packet.cid_field() == 1
        //     || (packet.sac_field() == 1 && packet.sam_field() != 0b00)
        //     || packet.dac_field() == 1
        // {
        //     return Err(Error::Unrecognized);
        // }

        let src_addr = packet.src_addr().resolve(ll_src_addr);
        let dst_addr = packet.src_addr().resolve(ll_dst_addr);

        Ok(IphcRepr {
            src_addr,
            ll_src_addr,
            dst_addr,
            ll_dst_addr,
            next_header: packet.next_header(),
            hop_limit: packet.hop_limit(),
            payload: packet.payload(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        todo!();
    }

    /// Emit a high-level representation into a 6LoWPAN packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut IphcPacket<T>) {
        let mut idx = 2;

        packet.set_dispatch_field();

        // SETTING THE TRAFIX FLOW
        // TODO: needs more work.
        packet.set_tf_field(0b11);

        // SETTING THE NEXT HEADER
        if let Some(nh) = self.next_header {
            packet.set_nh_field(0);
            packet.set_field(idx, &[nh.into()]);
            idx += 1;
        } else {
            // The next header is compressed using LOWPAN_NHC.
            packet.set_nh_field(1);
        }

        // SETTING THE HOP LIMIT
        match self.hop_limit {
            255 => packet.set_hlim_field(0b11),
            64 => packet.set_hlim_field(0b10),
            1 => packet.set_hlim_field(0b01),
            _ => {
                packet.set_hlim_field(0b00);
                packet.set_field(idx, &[self.hop_limit]);
                idx += 1;
            }
        }

        // SETTING THE SOURCE ADDRESS
        let src = self.src_addr.as_bytes();
        if self.src_addr == ipv6::Address::UNSPECIFIED {
            packet.set_sac_field(1);
            packet.set_sam_field(0b00);
        } else if self.src_addr.is_link_local() {
            // We have a link local address.
            // The remainder of the address can be elided when the context contains
            // a 802.15.4 short address or a 802.15.4 extended address which can be
            // converted to a eui64 address.

            if src[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                let ll = [src[14], src[15]];

                if self.ll_src_addr == Some(LlAddress::Short(ll)) {
                    // We have the context from the 802.15.4 frame.
                    // The context contains the short address.
                    // We can elide the source address.
                    packet.set_sam_field(0b11);
                } else {
                    // We don't have the context from the 802.15.4 frame.
                    // We cannot elide the source address, however we can elide 112 bits.
                    packet.set_sam_field(0b10);

                    packet.set_field(idx, &src[14..]);
                    idx += 2;
                }
            } else {
                if self
                    .ll_src_addr
                    .map(|addr| {
                        addr.as_eui_64()
                            .map(|addr| addr[..] == src[8..])
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
                {
                    // We have the context from the 802.15.4 frame.
                    // The context contains the extended address.
                    // We can elide the source address.
                    packet.set_sam_field(0b11);
                } else {
                    // We cannot elide the source address, however we can elide 64 bits.
                    packet.set_sam_field(0b01);

                    packet.set_field(idx, &src[8..]);
                    idx += 8;
                }
            }
        } else {
            // We cannot elide anything.
            packet.set_field(idx, src);
            idx += 16;
        }

        // SETTING THE DESTINATION ADDRESS
        let dst = self.dst_addr.as_bytes();
        if self.dst_addr.is_multicast() {
            packet.set_m_field(1);

            if dst[1] == 0x02 && dst[2..15] == [0; 13] {
                packet.set_dam_field(0b11);

                let raw = packet.buffer.as_mut();
                packet.set_field(idx, &[dst[15]]);
                idx += 1;
            } else if dst[2..13] == [0; 11] {
                packet.set_dam_field(0b10);

                let raw = packet.buffer.as_mut();
                packet.set_field(idx, &[dst[1]]);
                idx += 1;
                packet.set_field(idx, &dst[13..]);
                idx += 3;
            } else if dst[2..11] == [0; 9] {
                packet.set_dam_field(0b01);

                packet.set_field(idx, &[dst[1]]);
                idx += 1;
                packet.set_field(idx, &dst[11..]);
                idx += 5;
            } else {
                packet.set_dam_field(0b11);

                packet.set_field(idx, &dst);
                idx += 16;
            }
        } else {
            if self.dst_addr.is_link_local() {
                if dst[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    let ll = [dst[14], dst[15]];

                    if self.ll_dst_addr == Some(LlAddress::Short(ll)) {
                        packet.set_dam_field(0b11);
                    } else {
                        packet.set_dam_field(0b10);

                        packet.set_field(idx, &dst[14..]);
                        idx += 2;
                    }
                } else {
                    if self
                        .ll_dst_addr
                        .map(|addr| {
                            addr.as_eui_64()
                                .map(|addr| addr[..] == dst[8..])
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
                    {
                        packet.set_dam_field(0b11);
                    } else {
                        packet.set_dam_field(0b01);

                        packet.set_field(idx, &dst[8..]);
                        idx += 8;
                    }
                }
            } else {
                packet.set_dam_field(0b00);

                packet.set_field(idx, dst);
                idx += 16;
            }
        }
    }
}

/// A high-level representation of a 6LoWPAN_NHC.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NhcRepr<'a> {
    UdpNhc(UdpNhcRepr<'a>),
}

impl<'a> NhcRepr<'a> {
    /// Parse a 6LoWPAN_NHC packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &NhcPacket<&'a T>) -> Result<NhcRepr<'a>> {
        todo!();
    }
}

/// A high-level representation of a 6LoWPAN_NHC_UDP header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UdpNhcRepr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub checksum: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> UdpNhcRepr<'a> {
    /// Parse a 6LoWPAN_NHC_UDP packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &UdpNhcPacket<&'a T>) -> Result<UdpNhcRepr<'a>> {
        // TODO: Compute the checksum.

        Ok(UdpNhcRepr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            checksum: packet.checksum(),
            payload: packet.payload(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        todo!();
    }

    /// Emit a high-level representation into a 6LoWPAN_NHC_UDP packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut UdpNhcPacket<T>) {
        todo!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn iphc_fields() {
        let bytes = [
            0x7a, 0x33, // IPHC
            0x3a, // Next header
        ];

        let packet = IphcPacket::new_unchecked(bytes);

        assert_eq!(packet.dispatch_field(), 0b011);
        assert_eq!(packet.tf_field(), 0b11);
        assert_eq!(packet.nh_field(), 0b0);
        assert_eq!(packet.hlim_field(), 0b10);
        assert_eq!(packet.cid_field(), 0b0);
        assert_eq!(packet.sac_field(), 0b0);
        assert_eq!(packet.sam_field(), 0b11);
        assert_eq!(packet.m_field(), 0b0);
        assert_eq!(packet.dac_field(), 0b0);
        assert_eq!(packet.dam_field(), 0b11);

        assert_eq!(packet.next_header(), Some(IpProtocol::Icmpv6));

        assert_eq!(packet.src_address_size(), 0);
        assert_eq!(packet.dst_address_size(), 0);
        assert_eq!(packet.hop_limit(), 64);

        assert_eq!(packet.src_addr(), Address::Elided);
        assert_eq!(packet.dst_addr(), Address::Elided);

        let bytes = [
            0x7e, 0xf7, // IPHC,
            0x00, // CID
        ];

        let packet = IphcPacket::new_unchecked(bytes);

        assert_eq!(packet.dispatch_field(), 0b011);
        assert_eq!(packet.tf_field(), 0b11);
        assert_eq!(packet.nh_field(), 0b1);
        assert_eq!(packet.hlim_field(), 0b10);
        assert_eq!(packet.cid_field(), 0b1);
        assert_eq!(packet.sac_field(), 0b1);
        assert_eq!(packet.sam_field(), 0b11);
        assert_eq!(packet.m_field(), 0b0);
        assert_eq!(packet.dac_field(), 0b1);
        assert_eq!(packet.dam_field(), 0b11);

        assert_eq!(packet.next_header(), None);

        assert_eq!(packet.src_address_size(), 0);
        assert_eq!(packet.dst_address_size(), 0);
        assert_eq!(packet.hop_limit(), 64);

        assert_eq!(packet.src_addr(), Address::WithContext(&[]));
        assert_eq!(packet.dst_addr(), Address::WithContext(&[]));
    }

    #[test]
    fn udp_nhc_fields() {
        let bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];

        let packet = UdpNhcPacket::new_unchecked(bytes);
        assert_eq!(packet.checksum(), Some(0x28c4));
        assert_eq!(packet.src_port(), 5678);
        assert_eq!(packet.dst_port(), 8765);
    }

    #[test]
    fn ieee802154_udp() {
        use crate::wire::ieee802154::Frame as Ieee802154Frame;
        use crate::wire::ieee802154::Repr as Ieee802154Repr;

        // This data is captured using Wireshark from the communication between a RPL 6LoWPAN server
        // and a RPL 6LoWPAN client.
        // The frame is thus an IEEE802.15.4 frame, containing a 6LoWPAN packet,
        // containing a RPL extension header and an UDP header.
        let bytes: &[u8] = &[
            0x61, 0xdc, 0xdd, 0xcd, 0xab, 0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, 0xbf,
            0x9b, 0x15, 0x06, 0x00, 0x4b, 0x12, 0x00, 0x7e, 0xf7, 0x00, 0xe3, 0x06, 0x03, 0x00,
            0xff, 0x00, 0x00, 0x00, 0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4, 0x68, 0x65, 0x6c,
            0x6c, 0x6f, 0x20, 0x36, 0x35, 0x18, 0xb9,
        ];

        let ieee802154_frame = Ieee802154Frame::new_checked(bytes).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame).unwrap();

        let iphc_frame = IphcPacket::new_checked(ieee802154_repr.payload.unwrap()).unwrap();

        let iphc_repr = IphcRepr::parse(
            &iphc_frame,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
        )
        .unwrap();

        // The next header is compressed.
        assert_eq!(iphc_repr.next_header, None);

        // We dispatch the NHC packet.
        let nhc_packet = NhcPacket::dispatch_unchecked(iphc_repr.payload).unwrap();

        // We skip the parsing of the RPL header, since we do not support that yet.
        let udp_payload = match nhc_packet {
            NhcPacket::ExtHeader(ext_header) => {
                let start = ext_header.header_data_len() as usize;
                &ext_header.payload()[start..]
            }
            _ => unreachable!(),
        };

        let udp_nhc_frame = UdpNhcPacket::new_checked(udp_payload).unwrap();
        let udp_nhc_repr = UdpNhcRepr::parse(&udp_nhc_frame).unwrap();

        assert_eq!(udp_nhc_repr.src_port, 5678);
        assert_eq!(udp_nhc_repr.dst_port, 8765);
        assert_eq!(udp_nhc_repr.checksum, Some(0x28c4));
    }
}
