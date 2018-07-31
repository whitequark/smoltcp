use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use phy::ChecksumCapabilities;
use super::ip::{checksum, pretty_print_ip_payload};

pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1].
///
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
// RFC 791 states the following:
//
// > Every internet module must be able to forward a datagram of 68
// > octets without further fragmentation... Every internet destination
// > must be able to receive a datagram of 576 octets either in one piece
// > or in fragments to be reassembled.
//
// As a result, we can assume that every host we send packets to can
// accept a packet of the following size.
pub const MIN_MTU: usize = 576;

/// A four-octet IPv4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 4]);

impl Address {
    /// An unspecified address.
    pub const UNSPECIFIED: Address = Address([0x00; 4]);

    /// The broadcast address.
    pub const BROADCAST:   Address = Address([0xff; 4]);

    /// Construct an IPv4 address from parts.
    pub fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address([a0, a1, a2, a3])
    }

    /// Construct an IPv4 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not four octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() ||
          self.is_multicast() ||
          self.is_unspecified())
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; 4]
    }

    /// Query whether the address is a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query whether the address falls into the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    /// Query whether the address falls into the "loopback" range.
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(x: ::std::net::Ipv4Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv4Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv4Addr {
        x.into()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// A specification of an IPv4 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Cidr {
    address:    Address,
    prefix_len: u8,
}

impl Cidr {
    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 32);
        Cidr { address, prefix_len }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Address, netmask: Address) -> Result<Cidr> {
        let netmask = NetworkEndian::read_u32(&netmask.0[..]);
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Ok(Cidr { address: addr, prefix_len: netmask.count_ones() as u8 })
        } else {
            Err(Error::Illegal)
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub fn netmask(&self) -> Address {
        if self.prefix_len == 0 {
            return Address([0, 0, 0, 0]);
        }

        let number = 0xffffffffu32 << (32 - self.prefix_len);
        let data = [
            ((number >> 24) & 0xff) as u8,
            ((number >> 16) & 0xff) as u8,
            ((number >>  8) & 0xff) as u8,
            ((number >>  0) & 0xff) as u8,
        ];

        Address(data)
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Address> {
        let network = self.network();

        if network.prefix_len == 31 || network.prefix_len == 32 {
            return None;
        }

        let network_number = NetworkEndian::read_u32(&network.address.0[..]);
        let number = network_number | 0xffffffffu32 >> network.prefix_len;
        let data = [
            ((number >> 24) & 0xff) as u8,
            ((number >> 16) & 0xff) as u8,
            ((number >>  8) & 0xff) as u8,
            ((number >>  0) & 0xff) as u8,
        ];

        Some(Address(data))
    }

    /// Return the network block of this IPv4 CIDR.
    pub fn network(&self) -> Cidr {
        let mask = self.netmask().0;
        let network = [
            self.address.0[0] & mask[0],
            self.address.0[1] & mask[1],
            self.address.0[2] & mask[2],
            self.address.0[3] & mask[3],
        ];
        Cidr { address: Address(network), prefix_len: self.prefix_len }
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        // right shift by 32 is not legal
        if self.prefix_len == 0 { return true }

        let shift = 32 - self.prefix_len;
        let self_prefix = NetworkEndian::read_u32(self.address.as_bytes()) >> shift;
        let addr_prefix = NetworkEndian::read_u32(addr.as_bytes()) >> shift;
        self_prefix == addr_prefix
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the subnetwork described by the given IPv4 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    use wire::field::*;

    pub const VER_IHL:  usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH:   Field = 2..4;
    pub const IDENT:    Field = 4..6;
    pub const FLG_OFF:  Field = 6..8;
    pub const TTL:      usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IPv4 packet structure.
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
    /// Returns `Err(Error::Malformed)` if the header length is greater
    /// than total length.
    ///
    /// The result of this check is invalidated by calling [set_header_len]
    /// and [set_total_len].
    ///
    /// [set_header_len]: #method.set_header_len
    /// [set_total_len]: #method.set_total_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end {
            Err(Error::Truncated)
        } else if len < self.header_len() as usize {
            Err(Error::Truncated)
        } else if self.header_len() as u16 > self.total_len() {
            Err(Error::Malformed)
        } else if len < self.total_len() as usize && self.dont_frag() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline]
    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline]
    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the protocol field.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SRC_ADDR])
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DST_ADDR])
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) { return true }

        let data = self.buffer.as_ref();
        checksum::data(&data[..self.header_len() as usize]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_addr:    Address,
    pub dst_addr:    Address,
    pub protocol:    Protocol,
    pub payload_len: usize,
    pub hop_limit:   u8
}

impl Repr {
    /// Parse an Internet Protocol version 4 packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>,
                                          checksum_caps: &ChecksumCapabilities) -> Result<Repr> {
        // Version 4 is expected.
        if packet.version() != 4 { return Err(Error::Malformed) }
        // Valid checksum is expected.
        if checksum_caps.ipv4.rx() && !packet.verify_checksum() { return Err(Error::Checksum) }
        #[cfg(not(feature = "fragmentation-ipv4"))]
        {
            // We do not support fragmentation.
            if packet.more_frags() || packet.frag_offset() != 0 { return Err(Error::Fragmented) }
        }

        // Since the packet is not fragmented, it must include the entire payload.
        let payload_len = packet.total_len() as usize - packet.header_len() as usize;
        if packet.payload().len() < payload_len  { return Err(Error::Truncated) }

        // All DSCP values are acceptable, since they are of no concern to receiving endpoint.
        // All ECN values are acceptable, since ECN requires opt-in from both endpoints.
        // All TTL values are acceptable, since we do not perform routing.
        Ok(Repr {
            src_addr:    packet.src_addr(),
            dst_addr:    packet.dst_addr(),
            protocol:    packet.protocol(),
            payload_len: payload_len,
            hop_limit:   packet.hop_limit()
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // We never emit any options.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>, checksum_caps: &ChecksumCapabilities) {
        packet.set_version(4);
        packet.set_header_len(field::DST_ADDR.end as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);
        let total_len = packet.header_len() as u16 + self.payload_len as u16;
        packet.set_total_len(total_len);
        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(self.hop_limit);
        packet.set_protocol(self.protocol);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);

        if checksum_caps.ipv4.tx() {
            packet.fill_checksum();
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self, &ChecksumCapabilities::ignored()) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv4 ({})", err)?;
                write!(f, " src={} dst={} proto={} hop_limit={}",
                       self.src_addr(), self.dst_addr(), self.protocol(), self.hop_limit())?;
                if self.version() != 4 {
                    write!(f, " ver={}", self.version())?;
                }
                if self.header_len() != 20 {
                    write!(f, " hlen={}", self.header_len())?;
                }
                if self.dscp() != 0 {
                    write!(f, " dscp={}", self.dscp())?;
                }
                if self.ecn() != 0 {
                    write!(f, " ecn={}", self.ecn())?;
                }
                write!(f, " tlen={}", self.total_len())?;
                if self.dont_frag() {
                    write!(f, " df")?;
                }
                if self.more_frags() {
                    write!(f, " mf")?;
                }
                if self.frag_offset() != 0 {
                    write!(f, " off={}", self.frag_offset())?;
                }
                if self.more_frags() || self.frag_offset() != 0 {
                    write!(f, " id={}", self.ident())?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv4 src={} dst={} proto={}",
               self.src_addr, self.dst_addr, self.protocol)
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        use wire::ip::checksum::format_checksum;

        let checksum_caps = ChecksumCapabilities::ignored();

        let (ip_repr, payload) = match Packet::new_checked(buffer) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ip_packet) => {
                match Repr::parse(&ip_packet, &checksum_caps) {
                    Err(_) => return Ok(()),
                    Ok(ip_repr) => {
                        write!(f, "{}{}", indent, ip_repr)?;
                        format_checksum(f, ip_packet.verify_checksum())?;
                        (ip_repr, ip_packet.payload())
                    }
                }
            }
        };

        pretty_print_ip_payload(f, indent, ip_repr, payload)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 30] =
        [0x45, 0x00, 0x00, 0x1e,
         0x01, 0x02, 0x62, 0x03,
         0x1a, 0x01, 0xd5, 0x6e,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 10] =
        [0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert_eq!(packet.more_frags(), true);
        assert_eq!(packet.dont_frag(), true);
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.protocol(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Address([0x11, 0x12, 0x13, 0x14]));
        assert_eq!(packet.dst_addr(), Address([0x21, 0x22, 0x23, 0x24]));
        assert_eq!(packet.verify_checksum(), true);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_hop_limit(0x1a);
        packet.set_protocol(Protocol::Icmp);
        packet.set_src_addr(Address([0x11, 0x12, 0x13, 0x14]));
        packet.set_dst_addr(Address([0x21, 0x22, 0x23, 0x24]));
        packet.fill_checksum();
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(Packet::new_unchecked(&bytes).payload().len(),
                   PAYLOAD_BYTES.len());
        assert_eq!(Packet::new_unchecked(&mut bytes).payload_mut().len(),
                   PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_total_len(128);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(),
                   Error::Truncated);
    }

    static REPR_PACKET_BYTES: [u8; 24] =
        [0x45, 0x00, 0x00, 0x18,
         0x00, 0x00, 0x40, 0x00,
         0x40, 0x01, 0xd2, 0x79,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0xff];

    static REPR_PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    fn packet_repr() -> Repr {
        Repr {
            src_addr:    Address([0x11, 0x12, 0x13, 0x14]),
            dst_addr:    Address([0x21, 0x22, 0x23, 0x24]),
            protocol:    Protocol::Icmp,
            payload_len: 4,
            hop_limit:   64
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_parse_bad_version() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(6);
        packet.fill_checksum();
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet, &ChecksumCapabilities::default()), Err(Error::Malformed));
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = vec![0; 40];
        bytes[0] = 0x09;
        assert_eq!(Packet::new_checked(&mut bytes), Err(Error::Malformed));
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet, &ChecksumCapabilities::default());
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&packet.into_inner()[..], &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_unspecified() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::UNSPECIFIED.is_broadcast());
        assert!(!Address::UNSPECIFIED.is_multicast());
        assert!(!Address::UNSPECIFIED.is_link_local());
        assert!(!Address::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Address::BROADCAST.is_unspecified());
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_link_local());
        assert!(!Address::BROADCAST.is_loopback());
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(Address::new(192, 168, 1, 10), 24);

        let inside_subnet = [
            [192, 168,   1,   0], [192, 168,   1,   1],
            [192, 168,   1,   2], [192, 168,   1,  10],
            [192, 168,   1, 127], [192, 168,   1, 255],
        ];

        let outside_subnet = [
            [192, 168,   0,   0], [127,   0,   0,   1],
            [192, 168,   2,   0], [192, 168,   0, 255],
            [  0,   0,   0,   0], [255, 255, 255, 255],
        ];

        let subnets = [
            ([192, 168,   1,   0], 32),
            ([192, 168,   1, 255], 24),
            ([192, 168,   1,  10], 30),
        ];

        let not_subnets = [
            ([192, 168,   1,  10], 23),
            ([127,   0,   0,   1],  8),
            ([192, 168,   1,   0],  0),
            ([192, 168,   0, 255], 32),
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets.iter().map(
            |&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p)) {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets.iter().map(
            |&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p)) {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(cidr.address(), 0);
        assert!(cidr_without_prefix.contains_addr(&Address::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_cidr_from_netmask() {
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 0]), Address([1, 0, 2, 0])).is_err(),
                   true);
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 0]), Address([0, 0, 0, 0])).is_err(),
                   true);
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 1]), Address([255, 255, 255, 0])).unwrap(),
                   Cidr::new(Address([0, 0, 0, 1]), 24));
        assert_eq!(Cidr::from_netmask(Address([192, 168, 0, 1]), Address([255, 255, 0, 0])).unwrap(),
                   Cidr::new(Address([192, 168, 0, 1]), 16));
        assert_eq!(Cidr::from_netmask(Address([172, 16, 0, 1]), Address([255, 240, 0, 0])).unwrap(),
                   Cidr::new(Address([172, 16, 0, 1]), 12));
        assert_eq!(Cidr::from_netmask(Address([255, 255, 255, 1]), Address([255, 255, 255, 0])).unwrap(),
                   Cidr::new(Address([255, 255, 255, 1]), 24));
        assert_eq!(Cidr::from_netmask(Address([255, 255, 255, 255]), Address([255, 255, 255, 255])).unwrap(),
                   Cidr::new(Address([255, 255, 255, 255]), 32));
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).netmask(),
                   Address([0, 0, 0, 0]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).netmask(),
                   Address([255, 255, 255, 0]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).netmask(),
                   Address([255, 255, 255, 255]));
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).netmask(),
                   Address([255, 0, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).netmask(),
                   Address([255, 255, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).netmask(),
                   Address([255, 255, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).netmask(),
                   Address([255, 255, 128, 0]));
        assert_eq!(Cidr::new(Address([172, 16, 0, 0]), 12).netmask(),
                   Address([255, 240, 0, 0]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).netmask(),
                   Address([255, 255, 255, 0]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).netmask(),
                   Address([255, 255, 255, 255]));
    }

    #[test]
    fn test_cidr_broadcast() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).broadcast().unwrap(),
                   Address([255, 255, 255, 255]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).broadcast().unwrap(),
                   Address([0, 0, 0, 255]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).broadcast(),
                   None);
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).broadcast().unwrap(),
                   Address([127, 255, 255, 255]));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).broadcast().unwrap(),
                   Address([192, 168, 255, 255]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).broadcast().unwrap(),
                   Address([192, 168, 255, 255]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).broadcast().unwrap(),
                   Address([192, 168, 127, 255]));
        assert_eq!(Cidr::new(Address([172, 16, 0, 1]), 12).broadcast().unwrap(),
                   Address([172, 31, 255, 255]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).broadcast().unwrap(),
                   Address([255, 255, 255, 255]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 254]), 31).broadcast(),
                   None);
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).broadcast(),
                   None);

    }

    #[test]
    fn test_cidr_network() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).network(),
                   Cidr::new(Address([0, 0, 0, 0]), 0));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).network(),
                   Cidr::new(Address([0, 0, 0, 0]), 24));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).network(),
                   Cidr::new(Address([0, 0, 0, 0]), 32));
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).network(),
                   Cidr::new(Address([127, 0, 0, 0]), 8));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).network(),
                   Cidr::new(Address([192, 168, 0, 0]), 16));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).network(),
                   Cidr::new(Address([192, 168, 0, 0]), 16));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).network(),
                   Cidr::new(Address([192, 168, 0, 0]), 17));
        assert_eq!(Cidr::new(Address([172,  16, 0, 1]), 12).network(),
                   Cidr::new(Address([172,  16, 0, 0]), 12));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).network(),
                   Cidr::new(Address([255, 255, 255, 0]), 24));
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).network(),
                   Cidr::new(Address([255, 255, 255, 255]), 32));
    }
}
