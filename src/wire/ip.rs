use core::fmt;
use core::convert::From;

use crate::{Error, Result};
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr, Ipv6Packet, Ipv6Repr};
#[cfg(feature = "sixlowpan")]
use crate::wire::{SixlowpanIphcRepr, SixlowpanIphcPacket};

/// Internet protocol version.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Version {
    Unspecified,
    #[cfg(feature = "proto-ipv4")]
    Ipv4,
    #[cfg(feature = "proto-ipv6")]
    Ipv6,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// This function never returns `Ok(IpVersion::Unspecified)`; instead,
    /// unknown versions result in `Err(Error::Unrecognized)`.
    pub fn of_packet(data: &[u8]) -> Result<Version> {
        match data[0] >> 4 {
            #[cfg(feature = "proto-ipv4")]
            4 => Ok(Version::Ipv4),
            #[cfg(feature = "proto-ipv6")]
            6 => Ok(Version::Ipv6),
            _ => Err(Error::Unrecognized)
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Version::Unspecified => write!(f, "IPv?"),
            #[cfg(feature = "proto-ipv4")]
            Version::Ipv4 => write!(f, "IPv4"),
            #[cfg(feature = "proto-ipv6")]
            Version::Ipv6 => write!(f, "IPv6"),
        }
    }
}

enum_with_unknown! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::HopByHop    => write!(f, "Hop-by-Hop"),
            Protocol::Icmp        => write!(f, "ICMP"),
            Protocol::Igmp        => write!(f, "IGMP"),
            Protocol::Tcp         => write!(f, "TCP"),
            Protocol::Udp         => write!(f, "UDP"),
            Protocol::Ipv6Route   => write!(f, "IPv6-Route"),
            Protocol::Ipv6Frag    => write!(f, "IPv6-Frag"),
            Protocol::Icmpv6      => write!(f, "ICMPv6"),
            Protocol::Ipv6NoNxt   => write!(f, "IPv6-NoNxt"),
            Protocol::Ipv6Opts    => write!(f, "IPv6-Opts"),
            Protocol::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// An internetworking address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[non_exhaustive]
pub enum Address {
    /// An unspecified address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Unspecified,
    /// An IPv4 address.
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Address),
    /// An IPv6 address.
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Address),
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    #[cfg(feature = "proto-ipv4")]
    pub fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Create an address wrapping an IPv6 address with the given octets.
    #[cfg(feature = "proto-ipv6")]
    #[allow(clippy::too_many_arguments)]
    pub fn v6(a0: u16, a1: u16, a2: u16, a3: u16,
              a4: u16, a5: u16, a6: u16, a7: u16) -> Address {
        Address::Ipv6(Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// Return an address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            Address::Unspecified     => &[],
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(ref addr)      => addr.as_bytes(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(ref addr)      => addr.as_bytes(),
        }
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match *self {
            Address::Unspecified     => false,
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr)      => addr.is_unicast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr)      => addr.is_unicast(),
        }
    }

    /// Query whether the address is a valid multicast address.
    pub fn is_multicast(&self) -> bool {
        match *self {
            Address::Unspecified     => false,
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr)      => addr.is_multicast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr)      => addr.is_multicast(),
        }
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match *self {
            Address::Unspecified     => false,
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr)      => addr.is_broadcast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(_)         => false,
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match *self {
            Address::Unspecified     => true,
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr)      => addr.is_unspecified(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr)      => addr.is_unspecified(),
        }
    }

    /// Return an unspecified address that has the same IP version as `self`.
    pub fn to_unspecified(&self) -> Address {
        match *self {
            Address::Unspecified     => Address::Unspecified,
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(_)         => Address::Ipv4(Ipv4Address::UNSPECIFIED),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(_)         => Address::Ipv6(Ipv6Address::UNSPECIFIED),
        }
    }

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    pub fn to_prefix_len(&self) -> Option<u8> {
        let mut ones = true;
        let mut prefix_len = 0;
        for byte in self.as_bytes() {
            let mut mask = 0x80;
            for _ in 0..8 {
                let one = *byte & mask != 0;
                if ones {
                    // Expect 1s until first 0
                    if one {
                        prefix_len += 1;
                    } else {
                        ones = false;
                    }
                } else if one {
                    // 1 where 0 was expected
                    return None
                }
                mask >>= 1;
            }
        }
        Some(prefix_len)
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<::std::net::IpAddr> for Address {
    fn from(x: ::std::net::IpAddr) -> Address {
        match x {
            ::std::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4.into()),
            ::std::net::IpAddr::V6(ipv6) => Address::Ipv6(ipv6.into()),
        }
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv4"))]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(ipv4: ::std::net::Ipv4Addr) -> Address {
        Address::Ipv4(ipv4.into())
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv6"))]
impl From<::std::net::Ipv6Addr> for Address {
    fn from(ipv6: ::std::net::Ipv6Addr) -> Address {
        Address::Ipv6(ipv6.into())
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Unspecified
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Address::Unspecified     => write!(f, "*"),
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr)      => write!(f, "{}", addr),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr)      => write!(f, "{}", addr),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        match self {
            &Address::Unspecified     => defmt::write!(f, "{:?}", "*"),
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr)      => defmt::write!(f, "{:?}", addr),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(addr)      => defmt::write!(f, "{:?}", addr),
        }
    }
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[non_exhaustive]
pub enum Cidr {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Cidr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Cidr),
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given address is unspecified, or
    /// the given prefix length is invalid for the given address.
    pub fn new(addr: Address, prefix_len: u8) -> Cidr {
        match addr {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => Cidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => Cidr::Ipv6(Ipv6Cidr::new(addr, prefix_len)),
            Address::Unspecified =>
                panic!("a CIDR block cannot be based on an unspecified address"),
        }
    }

    /// Return the IP address of this CIDR block.
    pub fn address(&self) -> Address {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr)      => Address::Ipv4(cidr.address()),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr)      => Address::Ipv6(cidr.address()),
        }
    }

    /// Return the prefix length of this CIDR block.
    pub fn prefix_len(&self) -> u8 {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr)      => cidr.prefix_len(),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr)      => cidr.prefix_len(),
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        match (self, addr) {
            #[cfg(feature = "proto-ipv4")]
            (&Cidr::Ipv4(ref cidr), &Address::Ipv4(ref addr)) =>
                cidr.contains_addr(addr),
            #[cfg(feature = "proto-ipv6")]
            (&Cidr::Ipv6(ref cidr), &Address::Ipv6(ref addr)) =>
                cidr.contains_addr(addr),
            #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv4"))]
            (&Cidr::Ipv4(_), &Address::Ipv6(_)) | (&Cidr::Ipv6(_), &Address::Ipv4(_)) =>
                false,
            (_, &Address::Unspecified) =>
                // a fully unspecified address covers both IPv4 and IPv6,
                // and no CIDR block can do that.
                false,
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            #[cfg(feature = "proto-ipv4")]
            (&Cidr::Ipv4(ref cidr), &Cidr::Ipv4(ref other)) =>
                cidr.contains_subnet(other),
            #[cfg(feature = "proto-ipv6")]
            (&Cidr::Ipv6(ref cidr), &Cidr::Ipv6(ref other)) =>
                cidr.contains_subnet(other),
            #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv4"))]
            (&Cidr::Ipv4(_), &Cidr::Ipv6(_)) | (&Cidr::Ipv6(_), &Cidr::Ipv4(_)) =>
                false,
        }
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Cidr> for Cidr {
    fn from(addr: Ipv4Cidr) -> Self {
        Cidr::Ipv4(addr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Cidr> for Cidr {
    fn from(addr: Ipv6Cidr) -> Self {
        Cidr::Ipv6(addr)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr)      => write!(f, "{}", cidr),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr)      => write!(f, "{}", cidr),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cidr {
    fn format(&self, f: defmt::Formatter) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Cidr::Ipv4(cidr)      => defmt::write!(f, "{:?}", cidr),
            #[cfg(feature = "proto-ipv6")]
            &Cidr::Ipv6(cidr)      => defmt::write!(f, "{:?}", cidr),
        }
    }
}

/// An internet endpoint address.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16
}

impl Endpoint {
    /// An endpoint with unspecified address and port.
    pub const UNSPECIFIED: Endpoint = Endpoint { addr: Address::Unspecified, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }

    /// Query whether the endpoint has a specified address and port.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<::std::net::SocketAddr> for Endpoint {
    fn from(x: ::std::net::SocketAddr) -> Endpoint {
        Endpoint {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv4"))]
impl From<::std::net::SocketAddrV4> for Endpoint {
    fn from(x: ::std::net::SocketAddrV4) -> Endpoint {
        Endpoint {
            addr: x.ip().clone().into(),
            port: x.port(),
        }
    }
}

#[cfg(all(feature = "std", feature = "proto-ipv6"))]
impl From<::std::net::SocketAddrV6> for Endpoint {
    fn from(x: ::std::net::SocketAddrV6) -> Endpoint {
        Endpoint {
            addr: x.ip().clone().into(),
            port: x.port(),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Endpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

impl From<u16> for Endpoint {
    fn from(port: u16) -> Endpoint {
        Endpoint { addr: Address::Unspecified, port }
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint { addr: addr.into(), port }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains a concrete
/// high-level representation for some IP protocol version, or an unspecified representation,
/// which permits the `IpAddress::Unspecified` addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr {
    Unspecified {
        src_addr:    Address,
        dst_addr:    Address,
        protocol:    Protocol,
        payload_len: usize,
        hop_limit:   u8
    },
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Repr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Repr),
    #[cfg(feature = "proto-sixlowpan")]
    Sixlowpan(SixlowpanIphcRepr),
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Repr> for Repr {
    fn from(repr: Ipv4Repr) -> Repr {
        Repr::Ipv4(repr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Repr> for Repr {
    fn from(repr: Ipv6Repr) -> Repr {
        Repr::Ipv6(repr)
    }
}

impl Repr {
    /// Return the protocol version.
    pub fn version(&self) -> Version {
        match *self {
            Repr::Unspecified { .. } => Version::Unspecified,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(_) => Version::Ipv4,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(_) => Version::Ipv6,
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(_) => Version::Ipv6,
        }
    }

    /// Return the source address.
    pub fn src_addr(&self) -> Address {
        match *self {
            Repr::Unspecified { src_addr, .. } => src_addr,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => Address::Ipv6(repr.src_addr),
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => Address::Ipv6(repr.src_addr),
        }
    }

    /// Return the destination address.
    pub fn dst_addr(&self) -> Address {
        match *self {
            Repr::Unspecified { dst_addr, .. } => dst_addr,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => Address::Ipv6(repr.dst_addr),
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => Address::Ipv6(repr.dst_addr),
        }
    }

    /// Return the protocol.
    pub fn protocol(&self) -> Protocol {
        match *self {
            Repr::Unspecified { protocol, .. } => protocol,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.protocol,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.next_header,
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => todo!(),
        }
    }

    /// Return the payload length.
    pub fn payload_len(&self) -> usize {
        match *self {
            Repr::Unspecified { payload_len, .. } => payload_len,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.payload_len,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.payload_len,
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => todo!(),
        }
    }

    /// Set the payload length.
    pub fn set_payload_len(&mut self, length: usize) {
        match *self {
            Repr::Unspecified { ref mut payload_len, .. } =>
                *payload_len = length,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(Ipv4Repr { ref mut payload_len, .. }) =>
                *payload_len = length,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(Ipv6Repr { ref mut payload_len, .. }) =>
                *payload_len = length,
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(_) => todo!(),
        }
    }

    /// Return the TTL value.
    pub fn hop_limit(&self) -> u8 {
        match *self {
            Repr::Unspecified { hop_limit, .. }    => hop_limit,
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(Ipv4Repr { hop_limit, .. }) => hop_limit,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(Ipv6Repr { hop_limit, ..})  => hop_limit,
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(SixlowpanIphcRepr { hop_limit, ..}) => hop_limit,
        }
    }

    /// Convert an unspecified representation into a concrete one, or return
    /// `Err(Error::Unaddressable)` if not possible.
    ///
    /// # Panics
    /// This function panics if source and destination addresses belong to different families,
    /// or the destination address is unspecified, since this indicates a logic error.
    pub fn lower(&self, fallback_src_addrs: &[Cidr]) -> Result<Repr> {
        macro_rules! resolve_unspecified {
            ($reprty:path, $ipty:path, $iprepr:expr, $fallbacks:expr) => {
                if $iprepr.src_addr.is_unspecified() {
                    for cidr in $fallbacks {
                        match cidr.address() {
                            $ipty(addr) => {
                                $iprepr.src_addr = addr;
                                return Ok($reprty($iprepr));
                            },
                            _ => ()
                        }
                    }
                    Err(Error::Unaddressable)
                } else {
                    Ok($reprty($iprepr))
                }
            }
        }

        match self {
            #[cfg(feature = "proto-ipv4")]
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv4(_),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv4(src_ipv4_addr) = src_addr {
                    Some(src_ipv4_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv4(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Ok(Repr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr.ok_or(Error::Unaddressable)?,
                    dst_addr, protocol, payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv6")]
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv6(_),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv6(src_ipv6_addr) = src_addr {
                    Some(src_ipv6_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv6(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Ok(Repr::Ipv6(Ipv6Repr {
                    src_addr:    src_addr.ok_or(Error::Unaddressable)?,
                    next_header: protocol,
                    dst_addr, payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv4")]
            &Repr::Unspecified {
                src_addr: Address::Ipv4(src_addr),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Ok(Repr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    protocol:    protocol,
                    payload_len: payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv6")]
            &Repr::Unspecified {
                src_addr: Address::Ipv6(src_addr),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Ok(Repr::Ipv6(Ipv6Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    next_header: protocol,
                    payload_len: payload_len,
                    hop_limit:   hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(mut repr) =>
                resolve_unspecified!(Repr::Ipv4, Address::Ipv4, repr, fallback_src_addrs),

            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(mut repr) =>
                resolve_unspecified!(Repr::Ipv6, Address::Ipv6, repr, fallback_src_addrs),

            #[cfg(feature = "proto-sixlowpan")]
            &Repr::Sixlowpan(_) => todo!(),

            &Repr::Unspecified { .. } =>
                panic!("source and destination IP address families do not match"),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn buffer_len(&self) -> usize {
        match *self {
            Repr::Unspecified { .. } =>
                panic!("unspecified IP representation"),
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) =>
                repr.buffer_len(),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) =>
                repr.buffer_len(),
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => repr.buffer_len(),
        }
    }

    /// Emit this high-level representation into a buffer.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T, _checksum_caps: &ChecksumCapabilities) {
        match *self {
            Repr::Unspecified { .. } =>
                panic!("unspecified IP representation"),
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) =>
                repr.emit(&mut Ipv4Packet::new_unchecked(buffer), &_checksum_caps),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) =>
                repr.emit(&mut Ipv6Packet::new_unchecked(buffer)),
            #[cfg(feature = "proto-sixlowpan")]
            Repr::Sixlowpan(repr) => repr.emit(&mut SixlowpanIphcPacket::new_unchecked(buffer)),
        }
    }

    /// Return the total length of a packet that will be emitted from this
    /// high-level representation.
    ///
    /// This is the same as `repr.buffer_len() + repr.payload_len()`.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn total_len(&self) -> usize {
        self.buffer_len() + self.payload_len()
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }

        // Add the last remaining odd byte, if any.
        if let Some(&value) = data.first() {
            accum += (value as u32) << 8;
        }

        propagate_carries(accum)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    /// Compute an IP pseudo header checksum.
    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address,
                         protocol: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&Address::Ipv4(src_addr), &Address::Ipv4(dst_addr)) => {
                let mut proto_len = [0u8; 4];
                proto_len[1] = protocol.into();
                NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            },

            #[cfg(feature = "proto-ipv6")]
            (&Address::Ipv6(src_addr), &Address::Ipv6(dst_addr)) => {
                let mut proto_len = [0u8; 8];
                proto_len[7] = protocol.into();
                NetworkEndian::write_u32(&mut proto_len[0..4], length);
                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            }

            _ => panic!("Unexpected pseudo header addresses: {}, {}",
                        src_addr, dst_addr)
        }
    }

    // We use this in pretty printer implementations.
    pub(crate) fn format_checksum(f: &mut fmt::Formatter, correct: bool) -> fmt::Result {
        if !correct {
            write!(f, " (checksum incorrect)")
        } else {
            Ok(())
        }
    }
}

use crate::wire::pretty_print::PrettyIndent;

pub fn pretty_print_ip_payload<T: Into<Repr>>(f: &mut fmt::Formatter, indent: &mut PrettyIndent,
                                              ip_repr: T, payload: &[u8]) -> fmt::Result {
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::Icmpv4Packet;
    #[cfg(feature = "proto-ipv4")]
    use super::pretty_print::PrettyPrint;
    use crate::wire::{TcpPacket, TcpRepr, UdpPacket, UdpRepr};
    use crate::wire::ip::checksum::format_checksum;

    let checksum_caps = ChecksumCapabilities::ignored();
    let repr = ip_repr.into();
    match repr.protocol() {
        #[cfg(feature = "proto-ipv4")]
        Protocol::Icmp => {
            indent.increase(f)?;
            Icmpv4Packet::<&[u8]>::pretty_print(&payload, f, indent)
        }
        Protocol::Udp => {
            indent.increase(f)?;
            match UdpPacket::<&[u8]>::new_checked(payload) {
                Err(err) => write!(f, "{}({})", indent, err),
                Ok(udp_packet) => {
                    match UdpRepr::parse(&udp_packet, &repr.src_addr(),
                                         &repr.dst_addr(), &checksum_caps) {
                        Err(err) => write!(f, "{}{} ({})", indent, udp_packet, err),
                        Ok(udp_repr) => {
                            write!(f, "{}{}", indent, udp_repr)?;
                            let valid = udp_packet.verify_checksum(&repr.src_addr(),
                                                                   &repr.dst_addr());
                            format_checksum(f, valid)
                        }
                    }
                }
            }
        }
        Protocol::Tcp => {
            indent.increase(f)?;
            match TcpPacket::<&[u8]>::new_checked(payload) {
                Err(err) => write!(f, "{}({})", indent, err),
                Ok(tcp_packet) => {
                    match TcpRepr::parse(&tcp_packet, &repr.src_addr(),
                                         &repr.dst_addr(), &checksum_caps) {
                        Err(err) => write!(f, "{}{} ({})", indent, tcp_packet, err),
                        Ok(tcp_repr) => {
                            write!(f, "{}{}", indent, tcp_repr)?;
                            let valid = tcp_packet.verify_checksum(&repr.src_addr(),
                                                                   &repr.dst_addr());
                            format_checksum(f, valid)
                        }
                    }
                }
            }
        }
        _ => Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(unused)]

    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_1: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 1]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_2: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 2]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_3: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 3]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_4: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 4]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_UNSPECIFIED: IpAddress = IpAddress::Ipv6(Ipv6Address::UNSPECIFIED);

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_1: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_2: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 2]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_3: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 3]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_4: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 4]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_UNSPECIFIED: IpAddress = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);


    use super::*;
    use crate::wire::{IpAddress, IpProtocol,IpCidr};
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::{Ipv4Address, Ipv4Repr};

    macro_rules! generate_common_tests {
        ($name:ident, $repr:ident, $ip_repr:path, $ip_addr:path,
         $addr_from:path, $nxthdr:ident, $bytes_a:expr, $bytes_b:expr,
         $unspecified:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn test_ip_repr_lower() {
                    let ip_addr_a = $addr_from(&$bytes_a);
                    let ip_addr_b = $addr_from(&$bytes_b);
                    let proto = IpProtocol::Icmp;
                    let payload_len = 10;

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr(ip_addr_a),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 0x2a,
                            payload_len,
                        }.lower(&[]),
                        Ok($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 0x2a,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  IpAddress::Unspecified,
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[]),
                        Err(Error::Unaddressable)
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  IpAddress::Unspecified,
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Ok($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr($unspecified),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Ok($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr($unspecified),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[]),
                        Ok($ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }).lower(&[]),
                        Ok($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }).lower(&[]),
                        Err(Error::Unaddressable)
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }).lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Ok($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );
                }
            }
        };
        (ipv4 $addr_bytes_a:expr, $addr_bytes_b:expr) => {
            generate_common_tests!(ipv4, Ipv4Repr, Repr::Ipv4, IpAddress::Ipv4,
                                   Ipv4Address::from_bytes, protocol, $addr_bytes_a,
                                   $addr_bytes_b, Ipv4Address::UNSPECIFIED);
        };
        (ipv6 $addr_bytes_a:expr, $addr_bytes_b:expr) => {
            generate_common_tests!(ipv6, Ipv6Repr, Repr::Ipv6, IpAddress::Ipv6,
                                   Ipv6Address::from_bytes, next_header, $addr_bytes_a,
                                   $addr_bytes_b, Ipv6Address::UNSPECIFIED);
        }
    }

    #[cfg(feature = "proto-ipv4")]
    generate_common_tests!(ipv4
                           [1, 2, 3, 4],
                           [5, 6, 7, 8]);

    #[cfg(feature = "proto-ipv6")]
    generate_common_tests!(ipv6
                           [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                           [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    #[should_panic(expected = "source and destination IP address families do not match")]
    fn test_lower_between_families() {
        Repr::Unspecified {
            src_addr:  Address::Ipv6(Ipv6Address::UNSPECIFIED),
            dst_addr:  Address::Ipv4(Ipv4Address::UNSPECIFIED),
            protocol:  IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: 0
        }.lower(&[]);
    }

    #[test]
    fn endpoint_unspecified() {
        assert!(!Endpoint::UNSPECIFIED.is_specified());
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn to_prefix_len_ipv4() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(
                Some(prefix_len),
                mask.into().to_prefix_len()
            );
        }

        test_eq(0, Ipv4Address::new(0, 0, 0, 0));
        test_eq(1, Ipv4Address::new(128, 0, 0, 0));
        test_eq(2, Ipv4Address::new(192, 0, 0, 0));
        test_eq(3, Ipv4Address::new(224, 0, 0, 0));
        test_eq(4, Ipv4Address::new(240, 0, 0, 0));
        test_eq(5, Ipv4Address::new(248, 0, 0, 0));
        test_eq(6, Ipv4Address::new(252, 0, 0, 0));
        test_eq(7, Ipv4Address::new(254, 0, 0, 0));
        test_eq(8, Ipv4Address::new(255, 0, 0, 0));
        test_eq(9, Ipv4Address::new(255, 128, 0, 0));
        test_eq(10, Ipv4Address::new(255, 192, 0, 0));
        test_eq(11, Ipv4Address::new(255, 224, 0, 0));
        test_eq(12, Ipv4Address::new(255, 240, 0, 0));
        test_eq(13, Ipv4Address::new(255, 248, 0, 0));
        test_eq(14, Ipv4Address::new(255, 252, 0, 0));
        test_eq(15, Ipv4Address::new(255, 254, 0, 0));
        test_eq(16, Ipv4Address::new(255, 255, 0, 0));
        test_eq(17, Ipv4Address::new(255, 255, 128, 0));
        test_eq(18, Ipv4Address::new(255, 255, 192, 0));
        test_eq(19, Ipv4Address::new(255, 255, 224, 0));
        test_eq(20, Ipv4Address::new(255, 255, 240, 0));
        test_eq(21, Ipv4Address::new(255, 255, 248, 0));
        test_eq(22, Ipv4Address::new(255, 255, 252, 0));
        test_eq(23, Ipv4Address::new(255, 255, 254, 0));
        test_eq(24, Ipv4Address::new(255, 255, 255, 0));
        test_eq(25, Ipv4Address::new(255, 255, 255, 128));
        test_eq(26, Ipv4Address::new(255, 255, 255, 192));
        test_eq(27, Ipv4Address::new(255, 255, 255, 224));
        test_eq(28, Ipv4Address::new(255, 255, 255, 240));
        test_eq(29, Ipv4Address::new(255, 255, 255, 248));
        test_eq(30, Ipv4Address::new(255, 255, 255, 252));
        test_eq(31, Ipv4Address::new(255, 255, 255, 254));
        test_eq(32, Ipv4Address::new(255, 255, 255, 255));
    }

    #[cfg(feature = "proto-ipv4")]
    fn to_prefix_len_ipv4_error() {
        assert_eq!(None, IpAddress::from(Ipv4Address::new(255,255,255,1)).to_prefix_len());
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn to_prefix_len_ipv6() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(
                Some(prefix_len),
                mask.into().to_prefix_len()
            );
        }

        test_eq(0, Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0));
        test_eq(128, Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff));
    }

    #[cfg(feature = "proto-ipv6")]
    fn to_prefix_len_ipv6_error() {
        assert_eq!(None, IpAddress::from(Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 1)).to_prefix_len());
    }
}
