/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides two levels
of functionality.

 * First, it provides functions to extract fields from sequences of octets,
   and to insert fields into sequences of octets. This happens `Packet` family of
   structures, e.g. [EthernetFrame] or [Ipv4Packet].
 * Second, in cases where the space of valid field values is much smaller than the space
   of possible field values, it provides a compact, high-level representation
   of packet data that can be parsed from and emitted into a sequence of octets.
   This happens through the `Repr` family of structs and enums, e.g. [ArpRepr] or [Ipv4Repr].

[EthernetFrame]: struct.EthernetFrame.html
[Ipv4Packet]: struct.Ipv4Packet.html
[ArpRepr]: enum.ArpRepr.html
[Ipv4Repr]: struct.Ipv4Repr.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.

In the `Repr` family of data structures, the `Repr::parse()` method never panics
as long as `Packet::new_checked()` (or `Packet::check_len()`) has succeeded, and
the `Repr::emit()` method never panics as long as the underlying buffer is exactly
`Repr::buffer_len()` octets long.

# Examples

To emit an IP packet header into an octet buffer, and then parse it back:

```rust
# #[cfg(feature = "proto-ipv4")]
# {
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    protocol:    IpProtocol::Tcp,
    payload_len: 10,
    hop_limit:   64
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
}
{ // parsing
    let packet = Ipv4Packet::new_checked(&buffer)
                            .expect("truncated packet");
    let parsed = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())
                          .expect("malformed packet");
    assert_eq!(repr, parsed);
}
# }
```
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest  = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(all(feature = "proto-ipv4", feature = "medium-ethernet"))]
mod arp;
#[cfg(feature = "ieee802154")]
pub mod ieee802154;
#[cfg(feature = "sixlowpan")]
mod sixlowpan;
pub(crate) mod ip;
#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-ipv6")]
mod ipv6option;
#[cfg(feature = "proto-ipv6")]
mod ipv6hopbyhop;
#[cfg(feature = "proto-ipv6")]
mod ipv6fragment;
#[cfg(feature = "proto-ipv6")]
mod ipv6routing;
#[cfg(feature = "proto-ipv4")]
mod icmpv4;
#[cfg(feature = "proto-ipv6")]
mod icmpv6;
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
mod icmp;
#[cfg(feature = "proto-igmp")]
mod igmp;
#[cfg(all(feature = "proto-ipv6", any(feature = "medium-ethernet", feature = "medium-sixlowpan")))]
mod ndisc;
#[cfg(all(feature = "proto-ipv6", any(feature = "medium-ethernet", feature = "medium-sixlowpan")))]
mod ndiscoption;
#[cfg(feature = "proto-ipv6")]
mod mld;
mod udp;
mod tcp;
#[cfg(feature = "proto-dhcpv4")]
pub(crate) mod dhcpv4;

pub use self::pretty_print::PrettyPrinter;

#[cfg(feature = "medium-ethernet")]
pub use self::ethernet::{EtherType as EthernetProtocol,
                         Address as EthernetAddress,
                         Frame as EthernetFrame,
                         HEADER_LEN as ETHERNET_HEADER_LEN,
                         Repr as EthernetRepr};

#[cfg(all(feature = "proto-ipv4", feature = "medium-ethernet"))]
pub use self::arp::{Hardware as ArpHardware,
                    Operation as ArpOperation,
                    Packet as ArpPacket,
                    Repr as ArpRepr};

#[cfg(feature = "sixlowpan")]
pub use self::sixlowpan::{iphc::{Packet as SixlowpanIphcPacket,
                                 Repr as SixlowpanIphcRepr},
                          nhc::{Packet as SixlowpanNhcPacket,
                                ExtensionHeaderPacket as SixlowpanExtHeaderPacket,
                                ExtensionHeaderRepr as SixlowpanExtHeaderRepr,
                                UdpPacket as SixlowpanUdpPacket,
                                UdpNhcRepr as SixlowpanUdpRepr},
                          NextHeader as SixlowpanNextHeader,};
                    

#[cfg(feature = "ieee802154")]
pub use self::ieee802154::{Address as Ieee802154Address,
                           Pan as Ieee802154Pan,
                           Frame as Ieee802154Frame,
                           FrameType as Ieee802154FrameType,
                           FrameVersion as Ieee802154FrameVersion,
                           AddressingMode as Ieee802154AddressingMode,
                           Repr as Ieee802154Repr};

pub use self::ip::{Version as IpVersion,
                   Protocol as IpProtocol,
                   Address as IpAddress,
                   Endpoint as IpEndpoint,
                   Repr as IpRepr,
                   Cidr as IpCidr};

#[cfg(feature = "proto-ipv4")]
pub use self::ipv4::{Address as Ipv4Address,
                     Packet as Ipv4Packet,
                     Repr as Ipv4Repr,
                     Cidr as Ipv4Cidr,
                     MIN_MTU as IPV4_MIN_MTU};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6::{Address as Ipv6Address,
                     Packet as Ipv6Packet,
                     Repr as Ipv6Repr,
                     Cidr as Ipv6Cidr,
                     MIN_MTU as IPV6_MIN_MTU};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6option::{Ipv6Option,
                           Repr as Ipv6OptionRepr,
                           Type as Ipv6OptionType,
                           FailureType as Ipv6OptionFailureType};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6hopbyhop::{Header as Ipv6HopByHopHeader,
                             Repr as Ipv6HopByHopRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6fragment::{Header as Ipv6FragmentHeader,
                             Repr as Ipv6FragmentRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6routing::{Header as Ipv6RoutingHeader,
                            Repr as Ipv6RoutingRepr};

#[cfg(feature = "proto-ipv4")]
pub use self::icmpv4::{Message as Icmpv4Message,
                       DstUnreachable as Icmpv4DstUnreachable,
                       Redirect as Icmpv4Redirect,
                       TimeExceeded as Icmpv4TimeExceeded,
                       ParamProblem as Icmpv4ParamProblem,
                       Packet as Icmpv4Packet,
                       Repr as Icmpv4Repr};

#[cfg(feature = "proto-igmp")]
pub use self::igmp::{Packet as IgmpPacket,
                     Repr as IgmpRepr,
                     IgmpVersion};

#[cfg(feature = "proto-ipv6")]
pub use self::icmpv6::{Message as Icmpv6Message,
                       DstUnreachable as Icmpv6DstUnreachable,
                       TimeExceeded as Icmpv6TimeExceeded,
                       ParamProblem as Icmpv6ParamProblem,
                       Packet as Icmpv6Packet,
                       Repr as Icmpv6Repr};

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
pub use self::icmp::Repr as IcmpRepr;


#[cfg(all(feature = "proto-ipv6", any(feature = "medium-ethernet", feature = "medium-sixlowpan")))]
pub use self::ndisc::{Repr as NdiscRepr,
                      RouterFlags as NdiscRouterFlags,
                      NeighborFlags as NdiscNeighborFlags};

#[cfg(all(feature = "proto-ipv6", any(feature = "medium-ethernet", feature = "medium-sixlowpan")))]
pub use self::ndiscoption::{NdiscOption,
                            Repr as NdiscOptionRepr,
                            Type as NdiscOptionType,
                            PrefixInformation as NdiscPrefixInformation,
                            RedirectedHeader as NdiscRedirectedHeader,
                            PrefixInfoFlags as NdiscPrefixInfoFlags};

#[cfg(feature = "proto-ipv6")]
pub use self::mld::{AddressRecord as MldAddressRecord,
                    Repr as MldRepr};

pub use self::udp::{Packet as UdpPacket,
                    Repr as UdpRepr};

pub use self::tcp::{SeqNumber as TcpSeqNumber,
                    Packet as TcpPacket,
                    TcpOption,
                    Repr as TcpRepr,
                    Control as TcpControl};

#[cfg(feature = "proto-dhcpv4")]
pub use self::dhcpv4::{Packet as DhcpPacket,
                       Repr as DhcpRepr,
                       MessageType as DhcpMessageType};

/// Representation of an hardware address, such as an Ethernet address or an IEEE802.15.4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareAddress {
    BROADCAST,
    #[cfg(feature = "medium-ethernet")]
    Ethernet(EthernetAddress),
    #[cfg(feature = "medium-sixlowpan")]
    Ieee802154(Ieee802154Address),
}

impl HardwareAddress {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
            #[cfg(feature = "medium-sixlowpan")]
            HardwareAddress::Ieee802154(addr) => addr.as_bytes(),
            _ => todo!(),
        }
    }

    /// Query wether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
            #[cfg(feature = "medium-sixlowpan")]
            HardwareAddress::Ieee802154(addr) => addr.is_unicast(),
            _ => todo!(),
        }
    }

    /// Query wether the address is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
            #[cfg(feature = "medium-sixlowpan")]
            HardwareAddress::Ieee802154(addr) => addr.is_broadcast(),
            _ => todo!(),
        }
    }
}

impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

#[cfg(feature = "medium-sixlowpan")]
impl From<Ieee802154Address> for HardwareAddress {
    fn from(addr: Ieee802154Address) -> Self {
        HardwareAddress::Ieee802154(addr)
    }
}
