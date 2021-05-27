use crate::wire::ieee802154::Address as LlAddress;
use crate::wire::ipv6;
use crate::wire::IpProtocol;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NextHeader {
    Compressed,
    Uncompressed(IpProtocol),
}

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
    pub(crate) fn resolve(self, ll_addr: Option<LlAddress>) -> ipv6::Address {
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

pub mod iphc {
    use crate::wire::ieee802154::Address as LlAddress;
    use crate::wire::ipv6;
    use crate::wire::IpProtocol;
    use crate::Error;
    use crate::Result;
    use byteorder::{ByteOrder, NetworkEndian};

    use super::Address;
    use super::NextHeader;

    mod field {
        #![allow(non_snake_case)]

        use crate::wire::field::*;

        pub const IPHC_FIELD: Field = 0..2;
    }

    const DISPATCH: u8 = 0b011;

    macro_rules! get_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&self) -> u8 {
                let data = self.buffer.as_ref();
                let raw = NetworkEndian::read_u16(&data[field::IPHC_FIELD]);
                ((raw >> $shift) & $mask) as u8
            }
        };
    }

    macro_rules! set_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&mut self, val: u8) {
                let data = &mut self.buffer.as_mut()[field::IPHC_FIELD];
                let mut raw = NetworkEndian::read_u16(data);

                raw = (raw & !($mask << $shift)) | ((val as u16) << $shift);
                NetworkEndian::write_u16(data, raw);
            }
        };
    }

    /// A read/write wrapper around a LOWPAN_IPHC frame buffer.
    #[derive(Debug, Clone)]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        /// Input a raw octet buffer with a 6LoWPAN_IPHC frame structure.
        pub fn new_unchecked(buffer: T) -> Packet<T> {
            Packet { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<Packet<T>> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;
            Ok(packet)
        }

        /// Ensure that no accessor method will panic if called.
        /// Returns `Err(Error::Truncated)` if the buffer is too short.
        pub fn check_len(&self) -> Result<()> {
            let buffer = self.buffer.as_ref();
            if buffer.len() < 2 {
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
        pub fn next_header(&self) -> NextHeader {
            let nh = self.nh_field();

            if nh == 1 {
                // The next header field is compressed.
                // It is also encoded using LOWPAN_NHC.
                NextHeader::Compressed
            } else {
                // The full 8 bits for Next Header are carried in-line.
                let start = (self.ip_fields_start() + self.traffic_class_size()) as usize;

                let data = self.buffer.as_ref();
                let nh = data[start..start + 1][0];
                NextHeader::Uncompressed(IpProtocol::from(nh))
            }
        }

        /// Parse the hop limit field.
        pub fn hop_limit(&self) -> u8 {
            match self.hlim_field() {
                0b00 => {
                    let start = (self.ip_fields_start()
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
            let start = (self.ip_fields_start()
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
            let start = (self.ip_fields_start()
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

        get_field!(dispatch_field, 0b111, 13);
        get_field!(tf_field, 0b11, 11);
        get_field!(nh_field, 0b1, 10);
        get_field!(hlim_field, 0b11, 8);
        get_field!(cid_field, 0b1, 7);
        get_field!(sac_field, 0b1, 6);
        get_field!(sam_field, 0b11, 4);
        get_field!(m_field, 0b1, 3);
        get_field!(dac_field, 0b1, 2);
        get_field!(dam_field, 0b11, 0);

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

    impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
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

    impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Set the dispatch field to `0b011`.
        fn set_dispatch_field(&mut self) {
            let data = &mut self.buffer.as_mut()[field::IPHC_FIELD];
            let mut raw = NetworkEndian::read_u16(data);

            raw = (raw & !(0b111 << 13)) | (0b11 << 13);
            NetworkEndian::write_u16(data, raw);
        }

        set_field!(set_tf_field, 0b11, 11);
        set_field!(set_nh_field, 0b1, 10);
        set_field!(set_hlim_field, 0b11, 8);
        set_field!(set_cid_field, 0b1, 7);
        set_field!(set_sac_field, 0b1, 6);
        set_field!(set_sam_field, 0b11, 4);
        set_field!(set_m_field, 0b1, 3);
        set_field!(set_dac_field, 0b1, 2);
        set_field!(set_dam_field, 0b11, 0);

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

        fn set_next_header(&mut self, nh: NextHeader, mut idx: usize) -> usize {
            match nh {
                NextHeader::Uncompressed(nh) => {
                    self.set_nh_field(0);
                    self.set_field(idx, &[nh.into()]);
                    idx += 1;
                }
                NextHeader::Compressed => self.set_nh_field(1),
            }

            idx
        }

        fn set_hop_limit(&mut self, hl: u8, mut idx: usize) -> usize {
            match hl {
                255 => self.set_hlim_field(0b11),
                64 => self.set_hlim_field(0b10),
                1 => self.set_hlim_field(0b01),
                _ => {
                    self.set_hlim_field(0b00);
                    self.set_field(idx, &[hl]);
                    idx += 1;
                }
            }

            idx
        }

        /// Set the source address based on the IPv6 address and the Link-Local address.
        fn set_src_address(
            &mut self,
            src_addr: ipv6::Address,
            ll_src_addr: Option<LlAddress>,
            mut idx: usize,
        ) -> usize {
            let src = src_addr.as_bytes();
            if src_addr == ipv6::Address::UNSPECIFIED {
                self.set_sac_field(1);
                self.set_sam_field(0b00);
            } else if src_addr.is_link_local() {
                // We have a link local address.
                // The remainder of the address can be elided when the context contains
                // a 802.15.4 short address or a 802.15.4 extended address which can be
                // converted to a eui64 address.

                if src[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    let ll = [src[14], src[15]];

                    if ll_src_addr == Some(LlAddress::Short(ll)) {
                        // We have the context from the 802.15.4 frame.
                        // The context contains the short address.
                        // We can elide the source address.
                        self.set_sam_field(0b11);
                    } else {
                        // We don't have the context from the 802.15.4 frame.
                        // We cannot elide the source address, however we can elide 112 bits.
                        self.set_sam_field(0b10);

                        self.set_field(idx, &src[14..]);
                        idx += 2;
                    }
                } else {
                    if ll_src_addr
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
                        self.set_sam_field(0b11);
                    } else {
                        // We cannot elide the source address, however we can elide 64 bits.
                        self.set_sam_field(0b01);

                        self.set_field(idx, &src[8..]);
                        idx += 8;
                    }
                }
            } else {
                // We cannot elide anything.
                self.set_field(idx, src);
                idx += 16;
            }

            idx
        }

        fn set_dst_address(
            &mut self,
            dst_addr: ipv6::Address,
            ll_dst_addr: Option<LlAddress>,
            mut idx: usize,
        ) -> usize {
            let dst = dst_addr.as_bytes();
            if dst_addr.is_multicast() {
                self.set_m_field(1);

                if dst[1] == 0x02 && dst[2..15] == [0; 13] {
                    self.set_dam_field(0b11);

                    self.set_field(idx, &[dst[15]]);
                    idx += 1;
                } else if dst[2..13] == [0; 11] {
                    self.set_dam_field(0b10);

                    self.set_field(idx, &[dst[1]]);
                    idx += 1;
                    self.set_field(idx, &dst[13..]);
                    idx += 3;
                } else if dst[2..11] == [0; 9] {
                    self.set_dam_field(0b01);

                    self.set_field(idx, &[dst[1]]);
                    idx += 1;
                    self.set_field(idx, &dst[11..]);
                    idx += 5;
                } else {
                    self.set_dam_field(0b11);

                    self.set_field(idx, &dst);
                    idx += 16;
                }
            } else {
                if dst_addr.is_link_local() {
                    if dst[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                        let ll = [dst[14], dst[15]];

                        if ll_dst_addr == Some(LlAddress::Short(ll)) {
                            self.set_dam_field(0b11);
                        } else {
                            self.set_dam_field(0b10);

                            self.set_field(idx, &dst[14..]);
                            idx += 2;
                        }
                    } else {
                        if ll_dst_addr
                            .map(|addr| {
                                addr.as_eui_64()
                                    .map(|addr| addr[..] == dst[8..])
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false)
                        {
                            self.set_dam_field(0b11);
                        } else {
                            self.set_dam_field(0b01);

                            self.set_field(idx, &dst[8..]);
                            idx += 8;
                        }
                    }
                } else {
                    self.set_dam_field(0b00);

                    self.set_field(idx, dst);
                    idx += 16;
                }
            }

            idx
        }
    }

    /// A high-level representation of a LOWPAN_IPHC header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Repr {
        pub src_addr: ipv6::Address,
        pub ll_src_addr: Option<LlAddress>,
        pub dst_addr: ipv6::Address,
        pub ll_dst_addr: Option<LlAddress>,
        pub next_header: NextHeader,
        pub hop_limit: u8,
    }

    impl Repr {
        /// Parse a LOWPAN_IPHC packet and return a high-level representation.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(
            packet: &Packet<&T>,
            ll_src_addr: Option<LlAddress>,
            ll_dst_addr: Option<LlAddress>,
        ) -> Result<Repr> {
            // Ensure basic accessors will work.
            packet.check_len()?;

            if packet.dispatch_field() != DISPATCH {
                // This is not an LOWPAN_IPHC packet.
                return Err(Error::Malformed);
            }

            let src_addr = packet.src_addr().resolve(ll_src_addr);
            let dst_addr = packet.src_addr().resolve(ll_dst_addr);

            Ok(Repr {
                src_addr,
                ll_src_addr,
                dst_addr,
                ll_dst_addr,
                next_header: packet.next_header(),
                hop_limit: packet.hop_limit(),
            })
        }

        /// Return the length of a header that will be emitted from this high-level representation.
        pub fn buffer_len(&self) -> usize {
            2 + if self.src_addr == ipv6::Address::UNSPECIFIED {
                0
            } else if self.src_addr.is_link_local() {
                let src = self.src_addr.as_bytes();
                let ll = [src[14], src[15]];

                if src[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    if self.ll_src_addr == Some(LlAddress::Short(ll)) {
                        0
                    } else {
                        2
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
                        0
                    } else {
                        8
                    }
                }
            } else {
                16
            } + if self.dst_addr.is_multicast() {
                let dst = self.dst_addr.as_bytes();
                if dst[1] == 0x02 && dst[2..15] == [0; 13] {
                    1
                } else if dst[2..13] == [0; 11] {
                    4
                } else if dst[2..11] == [0; 9] {
                    6
                } else {
                    16
                }
            } else {
                let dst = self.dst_addr.as_bytes();
                if self.dst_addr.is_link_local() {
                    if dst[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                        let ll = [dst[14], dst[15]];

                        if self.ll_dst_addr == Some(LlAddress::Short(ll)) {
                            0
                        } else {
                            2
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
                            0
                        } else {
                            8
                        }
                    }
                } else {
                    16
                }
            }
        }

        /// Emit a high-level representation into a LOWPAN_IPHC packet.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
            let idx = 2;

            packet.set_dispatch_field();

            // SETTING THE TRAFIX FLOW
            // TODO: needs more work.
            packet.set_tf_field(0b11);

            let idx = packet.set_next_header(self.next_header, idx);
            let idx = packet.set_hop_limit(self.hop_limit, idx);
            let idx = packet.set_src_address(self.src_addr, self.ll_src_addr, idx);
            packet.set_dst_address(self.dst_addr, self.ll_dst_addr, idx);
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

            let packet = Packet::new_unchecked(bytes);

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

            assert_eq!(
                packet.next_header(),
                NextHeader::Uncompressed(IpProtocol::Icmpv6)
            );

            assert_eq!(packet.src_address_size(), 0);
            assert_eq!(packet.dst_address_size(), 0);
            assert_eq!(packet.hop_limit(), 64);

            assert_eq!(packet.src_addr(), Address::Elided);
            assert_eq!(packet.dst_addr(), Address::Elided);

            let bytes = [
                0x7e, 0xf7, // IPHC,
                0x00, // CID
            ];

            let packet = Packet::new_unchecked(bytes);

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

            assert_eq!(packet.next_header(), NextHeader::Compressed);

            assert_eq!(packet.src_address_size(), 0);
            assert_eq!(packet.dst_address_size(), 0);
            assert_eq!(packet.hop_limit(), 64);

            assert_eq!(packet.src_addr(), Address::WithContext(&[]));
            assert_eq!(packet.dst_addr(), Address::WithContext(&[]));
        }
    }
}

pub mod nhc {
    use crate::wire::ipv6;
    use crate::wire::udp::Repr as UdpRepr;
    use crate::wire::IpProtocol;
    use crate::Error;
    use crate::Result;
    use byteorder::{ByteOrder, NetworkEndian};
    use ipv6::Address;

    use super::NextHeader;

    mod field {
        #![allow(non_snake_case)]

        pub const NHC_FIELD: usize = 0;
        pub const UDP_FIELD: usize = 0;
    }

    macro_rules! get_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&self) -> u8 {
                let data = self.buffer.as_ref();
                let raw = &data[0];
                ((raw >> $shift) & $mask) as u8
            }
        };
    }

    macro_rules! set_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&mut self, val: u8) {
                let data = self.buffer.as_mut();
                let mut raw = data[0];
                raw = (raw & !($mask << $shift)) | (val << $shift);
                data[0] = raw;
            }
        };
    }

    /// A read/write wrapper around a LOWPAN_NHC frame buffer.
    #[derive(Debug, Clone)]
    pub enum Packet<T: AsRef<[u8]>> {
        ExtensionHeader(ExtensionHeaderPacket<T>),
        UdpHeader(UdpPacket<T>),
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        pub fn dispatch(buffer: T) -> Result<Packet<T>> {
            let raw = buffer.as_ref();

            #[cfg(feature = "std")]
            println!("{:02x?}", raw[0]);

            if raw[0] >> 4 == 0b1110 {
                // We have a compressed IPv6 Extension Header.
                Ok(Packet::ExtensionHeader(ExtensionHeaderPacket::new_checked(
                    buffer,
                )?))
            } else if raw[0] >> 3 == 0b11110 {
                // We have a compressed UDP header.
                Ok(Packet::UdpHeader(UdpPacket::new_checked(buffer)?))
            } else {
                Err(Error::Unrecognized)
            }
        }
    }

    // /// A high-level representation of a 6LoWPAN_NHC.
    // #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    // pub enum NhcRepr<'a> {
    //     UdpNhc(UdpNhcRepr<'a>),
    // }

    // impl<'a> NhcRepr<'a> {
    //     /// Parse a 6LoWPAN_NHC packet and return a high-level representation.
    //     pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Result<NhcRepr<'a>> {
    //         todo!();
    //     }
    // }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum ExtensionHeaderId {
        HopByHopHeader,
        RoutingHeader,
        FragmentHeader,
        DestinationOptionsHeader,
        MobilityHeader,
        Header,
        Reserved,
    }

    impl Into<IpProtocol> for ExtensionHeaderId {
        fn into(self) -> IpProtocol {
            match self {
                ExtensionHeaderId::HopByHopHeader => IpProtocol::HopByHop,
                ExtensionHeaderId::RoutingHeader => IpProtocol::Ipv6Route,
                ExtensionHeaderId::FragmentHeader => IpProtocol::Ipv6Frag,
                ExtensionHeaderId::DestinationOptionsHeader => IpProtocol::Ipv6Opts,
                ExtensionHeaderId::MobilityHeader => IpProtocol::Unknown(0),
                ExtensionHeaderId::Header => IpProtocol::Unknown(0),
                ExtensionHeaderId::Reserved => IpProtocol::Unknown(0),
            }
        }
    }

    pub(crate) const EXT_HEADER_DISPATCH: u8 = 0b1110;

    /// A read/write wrapper around a LOWPAN_NHC Next Header frame buffer.
    #[derive(Debug, Clone)]
    pub struct ExtensionHeaderPacket<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> ExtensionHeaderPacket<T> {
        /// Input a raw octet buffer with a LOWPAN_NHC Extension Header frame structure.
        pub fn new_unchecked(buffer: T) -> ExtensionHeaderPacket<T> {
            ExtensionHeaderPacket { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<ExtensionHeaderPacket<T>> {
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

        get_field!(dispatch_field, 0b1111, 4);
        get_field!(eid_field, 0b111, 1);
        get_field!(nh_field, 0b1, 0);

        /// Return the Extension Header ID.
        pub fn extension_header_id(&self) -> ExtensionHeaderId {
            match self.eid_field() {
                0 => ExtensionHeaderId::HopByHopHeader,
                1 => ExtensionHeaderId::RoutingHeader,
                2 => ExtensionHeaderId::FragmentHeader,
                3 => ExtensionHeaderId::DestinationOptionsHeader,
                4 => ExtensionHeaderId::MobilityHeader,
                5 | 6 => ExtensionHeaderId::Reserved,
                7 => ExtensionHeaderId::Header,
                _ => unreachable!(),
            }
        }

        /// Return the length field.
        pub fn length_field(&self) -> u8 {
            let start = 1 + self.next_header_size();

            let data = self.buffer.as_ref();
            data[start]
        }

        /// Parse the next header field.
        pub fn next_header(&self) -> NextHeader {
            if self.nh_field() == 1 {
                NextHeader::Compressed
            } else {
                // The full 8 bits for Next Header are carried in-line.
                let start = 1;

                let data = self.buffer.as_ref();
                let nh = data[start];
                NextHeader::Uncompressed(IpProtocol::from(nh))
            }
        }

        /// Return the size of the Next Header field.
        fn next_header_size(&self) -> usize {
            // If nh is set, then the Next Header is compressed using LOWPAN_NHC
            if self.nh_field() == 1 {
                0
            } else {
                1
            }
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> ExtensionHeaderPacket<&'a T> {
        /// Return a pointer to the payload.
        pub fn payload(&self) -> &'a [u8] {
            let start = 2 + self.next_header_size();
            &self.buffer.as_ref()[start..]
        }
    }

    impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> ExtensionHeaderPacket<T> {
        /// Return a mutable pointer to the payload.
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let start = 2 + self.next_header_size();
            &mut self.buffer.as_mut()[start..]
        }

        /// Set the dispatch field to `0b1110`.
        fn set_dispatch_field(&mut self) {
            let data = self.buffer.as_mut();
            data[0] = (data[0] & !(0b1111 << 4)) | (EXT_HEADER_DISPATCH << 4);
        }

        set_field!(set_eid_field, 0b111, 1);
        set_field!(set_nh_field, 0b1, 0);

        /// Set the Extension Header ID field.
        fn set_extension_header_id(&mut self, ext_header_id: ExtensionHeaderId) {
            let id = match ext_header_id {
                ExtensionHeaderId::HopByHopHeader => 0,
                ExtensionHeaderId::RoutingHeader => 1,
                ExtensionHeaderId::FragmentHeader => 2,
                ExtensionHeaderId::DestinationOptionsHeader => 3,
                ExtensionHeaderId::MobilityHeader => 4,
                ExtensionHeaderId::Header => 7,
                _ => unreachable!(),
            };

            self.set_eid_field(id);
        }

        /// Set the Next Header.
        fn set_next_header(&mut self, next_header: NextHeader) {
            match next_header {
                NextHeader::Compressed => self.set_nh_field(0b1),
                NextHeader::Uncompressed(nh) => {
                    self.set_nh_field(0b0);

                    let start = 1;
                    let data = self.buffer.as_mut();
                    data[start] = nh.into();
                }
            }
        }

        /// Set the length.
        fn set_length(&mut self, length: u8) {
            let start = 1 + self.next_header_size();

            let data = self.buffer.as_mut();
            data[start] = length;
        }
    }

    /// A high-level representation of an LOWPAN_NHC Extension Header header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct ExtensionHeaderRepr {
        ext_header_id: ExtensionHeaderId,
        next_header: NextHeader,
        length: u8,
    }

    impl ExtensionHeaderRepr {
        /// Parse a LOWPAN_NHC Extension Header packet and return a high-level representation.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(
            packet: &ExtensionHeaderPacket<&T>,
        ) -> Result<ExtensionHeaderRepr> {
            // Ensure basic accessors will work.
            packet.check_len()?;

            if packet.dispatch_field() != EXT_HEADER_DISPATCH {
                return Err(Error::Malformed);
            }

            Ok(ExtensionHeaderRepr {
                ext_header_id: packet.extension_header_id(),
                next_header: packet.next_header(),
                length: packet.payload().len() as u8,
            })
        }

        /// Return the length of a header that will be emitted from this high-level representation.
        pub fn buffer_len(&self) -> usize {
            let mut len = 1; // The minimal header size

            if self.next_header != NextHeader::Compressed {
                len += 1;
            }

            len += 1; // The length

            len
        }

        /// Emit a high-level representaiton into a LOWPAN_NHC Extension Header packet.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut ExtensionHeaderPacket<T>) {
            packet.set_dispatch_field();
            packet.set_extension_header_id(self.ext_header_id);
            packet.set_next_header(self.next_header);
            packet.set_length(self.length);
        }
    }

    pub(crate) const UDP_DISPATCH: u8 = 0b11110;

    /// A read/write wrapper around a 6LoWPAN_NHC_UDP frame buffer.
    #[derive(Debug, Clone)]
    pub struct UdpPacket<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> UdpPacket<T> {
        /// Input a raw octet buffer with a LOWPAN_NHC frame structure for UDP.
        pub fn new_unchecked(buffer: T) -> UdpPacket<T> {
            UdpPacket { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<UdpPacket<T>> {
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

        get_field!(dispatch_field, 0b11111, 3);
        get_field!(checksum_field, 0b1, 2);
        get_field!(ports_field, 0b11, 0);

        /// Returns the index of the start of the next header compressed fields.
        fn nhc_fields_start(&self) -> usize {
            1
        }

        /// Return the source port number.
        pub fn src_port(&self) -> u16 {
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

                    0xf000 + data[start] as u16
                }
                0b11 => {
                    // The first 12 bits are elided.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    0xf0b0 + (data[start] >> 4) as u16
                }
                _ => unreachable!(),
            }
        }

        /// Return the destination port number.
        pub fn dst_port(&self) -> u16 {
            match self.ports_field() {
                0b00 => {
                    // The full 16 bits are carried in-line.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    NetworkEndian::read_u16(&data[idx + 2..idx + 4])
                }
                0b01 => {
                    // The first 8 bits are elided.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    0xf000 + data[idx] as u16
                }
                0b10 => {
                    // The full 16 bits are carried in-line.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    NetworkEndian::read_u16(&data[idx + 1..idx + 1 + 2])
                }
                0b11 => {
                    // The first 12 bits are elided.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    0xf0b0 + (NetworkEndian::read_u16(&data[start..start + 1]) & 0xff)
                }
                _ => unreachable!(),
            }
        }

        /// Return the checksum.
        pub fn checksum(&self) -> Option<u16> {
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

    impl<'a, T: AsRef<[u8]> + ?Sized> UdpPacket<&'a T> {
        /// Return a pointer to the payload.
        pub fn payload(&self) -> &'a [u8] {
            let start = 1 + self.ports_size() + self.checksum_size();
            &self.buffer.as_ref()[start..]
        }
    }

    impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<T> {
        /// Return a mutable pointer to the payload.
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let start = 1 + self.ports_size() + self.checksum_size();
            &mut self.buffer.as_mut()[start..]
        }

        /// Set the dispatch field to `0b11110`.
        fn set_dispatch_field(&mut self) {
            let data = self.buffer.as_mut();
            data[0] = (data[0] & !(0b11111 << 3)) | (UDP_DISPATCH << 3);
        }

        set_field!(set_checksum_field, 0b1, 2);
        set_field!(set_ports_field, 0b11, 0);

        fn set_ports(&mut self, src_port: u16, dst_port: u16) {
            let mut idx = 1;

            match (src_port, dst_port) {
                (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => {
                    // We can compress both the source and destination ports.
                    self.set_ports_field(0b11);
                    let mut data = self.buffer.as_mut();
                    data[idx] = (((src_port - 0xf0b0) as u8) << 4) & ((dst_port - 0xf0b0) as u8);
                }
                (0xf000..=0xf0ff, _) => {
                    // We can compress the source port, but not the destination port.
                    self.set_ports_field(0b10);
                    let mut data = self.buffer.as_mut();
                    data[idx] = (src_port - 0xf000) as u8;
                    idx += 1;

                    NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
                }
                (_, 0xf000..=0xf0ff) => {
                    // We can compress the destination port, but not the source port.
                    self.set_ports_field(0b01);
                    let mut data = self.buffer.as_mut();
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                    idx += 2;
                    data[idx] = (dst_port - 0xf000) as u8;
                }
                (_, _) => {
                    // We cannot compress any port.
                    self.set_ports_field(0b00);
                    let mut data = self.buffer.as_mut();
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                    idx += 2;
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
                }
            };
        }

        fn set_checksum(&mut self, checksum: u16) {
            self.set_checksum_field(0b0);
            let idx = 1 + self.ports_size();
            let mut data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[idx..idx + 2], checksum);
        }
    }

    /// A high-level representation of a LOWPAN_NHC UDP header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct UdpNhcRepr<'a>(pub UdpRepr<'a>);

    impl<'a> UdpNhcRepr<'a> {
        /// Parse a LOWWPAN_NHC UDP packet and return a high-level representation.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(
            packet: &UdpPacket<&'a T>,
            src_addr: &ipv6::Address,
            dst_addr: &ipv6::Address,
            checksum: Option<u16>,
        ) -> Result<UdpNhcRepr<'a>> {
            // Ensure basic accessors will work.
            packet.check_len()?;

            if packet.dispatch_field() != UDP_DISPATCH {
                return Err(Error::Malformed);
            }

            // TODO: Compute the checksum.
            Ok(UdpNhcRepr(UdpRepr {
                src_port: packet.src_port(),
                dst_port: packet.dst_port(),
                payload: packet.payload(),
            }))
        }

        /// Return the length of a packet that will be emitted from this high-level representation.
        pub fn buffer_len(&self) -> usize {
            let mut len = 1; // The minimal header size

            len += 2; // XXX We assume we will add the checksum at the end

            // Check if we can compress the source and destination ports
            let len = match (self.src_port, self.dst_port) {
                (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => len + 1,
                (0xf000..=0xf0ff, _) | (_, 0xf000..=0xf0ff) => len + 3,
                (_, _) => len + 4,
            };

            len + self.payload.len()
        }

        /// Emit a high-level representation into a LOWPAN_NHC UDP header.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(
            &self,
            packet: &mut UdpPacket<T>,
            src_addr: &Address,
            dst_addr: &Address,
        ) {
            packet.set_dispatch_field();
            packet.set_ports(self.src_port, self.dst_port);

            packet.set_checksum(self.calculate_checksum(src_addr, dst_addr));
            packet.payload_mut()[..self.payload.len()].copy_from_slice(self.payload);
        }

        fn calculate_checksum(&self, src_addr: &Address, dst_addr: &Address) -> u16 {
            let mut checksum = 0u32;

            for c in src_addr
                .as_bytes()
                .chunks_exact(2)
                .chain(dst_addr.as_bytes().chunks_exact(2))
            {
                checksum += NetworkEndian::read_u16(c) as u32;
            }

            let udp_len: u32 = self.payload.len() as u32 + 8;
            checksum += udp_len >> 16;
            checksum += udp_len & 0xffff;

            checksum += 17; // next header

            checksum += self.src_port as u32;
            checksum += self.dst_port as u32;

            checksum += udp_len >> 16;
            checksum += udp_len & 0xffff;

            for c in self.payload.chunks(2) {
                if c.len() == 2 {
                    checksum += NetworkEndian::read_u16(c) as u32;
                } else {
                    checksum += (c[0] as u32) << 8;
                }
            }

            while checksum >> 16 != 0 {
                checksum = (checksum & 0xffff) + (checksum >> 16);
            }

            checksum as u16
        }
    }

    impl<'a> core::ops::Deref for UdpNhcRepr<'a> {
        type Target = UdpRepr<'a>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<'a> core::ops::DerefMut for UdpNhcRepr<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn ext_header_nhc_fields() {
            let bytes = [0xe3, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00];

            let packet = ExtensionHeaderPacket::new_checked(&bytes[..]).unwrap();
            assert_eq!(packet.dispatch_field(), EXT_HEADER_DISPATCH);
            assert_eq!(packet.length_field(), 6);
            assert_eq!(
                packet.extension_header_id(),
                ExtensionHeaderId::RoutingHeader
            );

            assert_eq!(packet.payload(), [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn ext_header_emit() {
            let ext_header = ExtensionHeaderRepr {
                ext_header_id: ExtensionHeaderId::RoutingHeader,
                next_header: NextHeader::Compressed,
                length: 6,
            };

            let len = ext_header.buffer_len();
            let mut buffer = [0u8; 127];
            let mut packet = ExtensionHeaderPacket::new_unchecked(&mut buffer[..len]);
            ext_header.emit(&mut packet);

            assert_eq!(packet.dispatch_field(), EXT_HEADER_DISPATCH);
            assert_eq!(packet.next_header(), NextHeader::Compressed);
            assert_eq!(packet.length_field(), 6);
            assert_eq!(
                packet.extension_header_id(),
                ExtensionHeaderId::RoutingHeader
            );
        }

        #[test]
        fn udp_nhc_fields() {
            let bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];

            let packet = UdpPacket::new_checked(&bytes[..]).unwrap();
            assert_eq!(packet.dispatch_field(), UDP_DISPATCH);
            assert_eq!(packet.checksum(), Some(0x28c4));
            assert_eq!(packet.src_port(), 5678);
            assert_eq!(packet.dst_port(), 8765);
        }

        #[test]
        fn udp_emit() {
            let udp = UdpNhcRepr(UdpRepr {
                src_port: 0xf0b1,
                dst_port: 0xf001,
                payload: b"Hello World",
            });

            let len = udp.buffer_len();
            let mut buffer = [0u8; 127];
            let mut packet = UdpPacket::new_unchecked(&mut buffer[..len]);
            udp.emit(&mut packet, None);

            assert_eq!(packet.dispatch_field(), UDP_DISPATCH);
            assert_eq!(packet.src_port(), 0xf0b1);
            assert_eq!(packet.dst_port(), 0xf001);
            assert_eq!(packet.payload_mut(), b"Hello World");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ieee802154_udp() {
        use crate::wire::ieee802154::Frame as Ieee802154Frame;
        use crate::wire::ieee802154::Repr as Ieee802154Repr;
        use crate::wire::ipv6routing;

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

        let iphc_frame = iphc::Packet::new_checked(ieee802154_repr.payload.unwrap()).unwrap();
        let iphc_repr = iphc::Repr::parse(
            &iphc_frame,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
        )
        .unwrap();

        // The next header is compressed.
        assert_eq!(iphc_repr.next_header, NextHeader::Compressed);

        // We dispatch the NHC packet.
        let nhc_packet = nhc::Packet::dispatch(iphc_frame.payload()).unwrap();

        let udp_payload = match nhc_packet {
            nhc::Packet::ExtensionHeader(ext_packet) => {
                // The next header is compressed (it is the UDP NHC compressed header).
                assert_eq!(ext_packet.next_header(), NextHeader::Compressed);
                assert_eq!(ext_packet.length_field(), 6);
                let payload = ext_packet.payload();

                let length = ext_packet.length_field() as usize;
                let ext_packet_payload = &payload[..length];

                match ext_packet.extension_header_id() {
                    nhc::ExtensionHeaderId::RoutingHeader => {
                        // We are not intersted in the Next Header protocol.
                        let proto = ipv6::Protocol::Unknown(0);
                        let mut new_payload = [0; 8];

                        new_payload[0] = proto.into();
                        new_payload[1] = (2 + length - 8) as u8;
                        new_payload[2..].copy_from_slice(ext_packet_payload);

                        let routing = ipv6routing::Header::new_checked(new_payload).unwrap();

                        assert_eq!(routing.routing_type(), ipv6routing::Type::Rpl);
                        assert_eq!(routing.segments_left(), 0);
                        assert_eq!(routing.cmpr_e(), 0xf);
                        assert_eq!(routing.cmpr_i(), 0xf);
                    }
                    _ => unreachable!(),
                }

                &payload[length..]
            }
            _ => unreachable!(),
        };

        let udp_nhc_frame = nhc::UdpPacket::new_checked(udp_payload).unwrap();
        let udp_repr = nhc::UdpNhcRepr::parse(
            &udp_nhc_frame,
            &iphc_repr.src_addr,
            &iphc_repr.dst_addr,
            None,
        )
        .unwrap();

        assert_eq!(udp_repr.src_port, 5678);
        assert_eq!(udp_repr.dst_port, 8765);
        assert_eq!(udp_nhc_frame.checksum(), Some(0x28c4));
    }
}
