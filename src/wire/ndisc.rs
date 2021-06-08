use byteorder::{ByteOrder, NetworkEndian};
use bitflags::bitflags;

use crate::{Error, Result};
use crate::wire::icmpv6::{field, Message, Packet};
use crate::wire::{Ipv6Repr, Ipv6Packet};
use crate::wire::{NdiscOption, NdiscOptionRepr, NdiscOptionType};
use crate::wire::{NdiscPrefixInformation, NdiscRedirectedHeader};
use crate::time::Duration;
use crate::wire::Ipv6Address;

use crate::wire::HardwareAddress;

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct RouterFlags: u8 {
        const MANAGED = 0b10000000;
        const OTHER   = 0b01000000;
    }
}

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct NeighborFlags: u8 {
        const ROUTER    = 0b10000000;
        const SOLICITED = 0b01000000;
        const OVERRIDE  = 0b00100000;
    }
}

/// Getters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the current hop limit field.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CUR_HOP_LIMIT]
    }

    /// Return the Router Advertisement flags.
    #[inline]
    pub fn router_flags(&self) -> RouterFlags {
        let data = self.buffer.as_ref();
        RouterFlags::from_bits_truncate(data[field::ROUTER_FLAGS])
    }

    /// Return the router lifetime field.
    #[inline]
    pub fn router_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_secs(NetworkEndian::read_u16(&data[field::ROUTER_LT]) as u64)
    }

    /// Return the reachable time field.
    #[inline]
    pub fn reachable_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::REACHABLE_TM]) as u64)
    }

    /// Return the retransmit time field.
    #[inline]
    pub fn retrans_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::RETRANS_TM]) as u64)
    }
}

/// Common getters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the target address field.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::TARGET_ADDR])
    }
}


/// Getters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Neighbor Solicitation flags.
    #[inline]
    pub fn neighbor_flags(&self) -> NeighborFlags {
        let data = self.buffer.as_ref();
        NeighborFlags::from_bits_truncate(data[field::NEIGH_FLAGS])
    }
}

/// Getters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the destination address field.
    #[inline]
    pub fn dest_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::DEST_ADDR])
    }
}

/// Setters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the current hop limit field.
    #[inline]
    pub fn set_current_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CUR_HOP_LIMIT] = value;
    }

    /// Set the Router Advertisement flags.
    #[inline]
    pub fn set_router_flags(&mut self, flags: RouterFlags) {
        self.buffer.as_mut()[field::ROUTER_FLAGS] = flags.bits();
    }

    /// Set the router lifetime field.
    #[inline]
    pub fn set_router_lifetime(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ROUTER_LT], value.secs() as u16);
    }

    /// Set the reachable time field.
    #[inline]
    pub fn set_reachable_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::REACHABLE_TM], value.total_millis() as u32);
    }

    /// Set the retransmit time field.
    #[inline]
    pub fn set_retrans_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RETRANS_TM], value.total_millis() as u32);
    }
}

/// Common setters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the target address field.
    #[inline]
    pub fn set_target_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::TARGET_ADDR].copy_from_slice(value.as_bytes());
    }
}

/// Setters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Neighbor Solicitation flags.
    #[inline]
    pub fn set_neighbor_flags(&mut self, flags: NeighborFlags) {
        self.buffer.as_mut()[field::NEIGH_FLAGS] = flags.bits();
    }
}

/// Setters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the destination address field.
    #[inline]
    pub fn set_dest_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::DEST_ADDR].copy_from_slice(value.as_bytes());
    }
}

/// A high-level representation of an Neighbor Discovery packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'a> {
    RouterSolicit {
        lladdr: Option<HardwareAddress>
    },
    RouterAdvert {
        hop_limit: u8,
        flags: RouterFlags,
        router_lifetime: Duration,
        reachable_time: Duration,
        retrans_time: Duration,
        lladdr: Option<HardwareAddress>,
        mtu: Option<u32>,
        prefix_info: Option<NdiscPrefixInformation>
    },
    NeighborSolicit {
        target_addr: Ipv6Address,
        lladdr: Option<HardwareAddress>
    },
    NeighborAdvert {
        flags: NeighborFlags,
        target_addr: Ipv6Address,
        lladdr: Option<HardwareAddress>
    },
    Redirect {
        target_addr: Ipv6Address,
        dest_addr: Ipv6Address,
        lladdr: Option<HardwareAddress>,
        redirected_hdr: Option<NdiscRedirectedHeader<'a>>
    }
}

impl<'a> Repr<'a> {
    /// Parse an NDISC packet and return a high-level representation of the
    /// packet.
    pub fn parse<T>(packet: &Packet<&'a T>)
                   -> Result<Repr<'a>>
                where T: AsRef<[u8]> + ?Sized {
        match packet.msg_type() {
            Message::RouterSolicit => {
                let lladdr = if !packet.payload().is_empty() {
                    let opt = NdiscOption::new_checked(packet.payload())?;
                    match opt.option_type() {
                        NdiscOptionType::SourceLinkLayerAddr => Some(opt.link_layer_addr().into()),
                        _ => { return Err(Error::Unrecognized); }
                    }
                } else {
                    None
                };
                Ok(Repr::RouterSolicit { lladdr })
            },
            Message::RouterAdvert => {
                let mut offset = 0;
                let (mut lladdr, mut mtu, mut prefix_info) = (None, None, None);
                while packet.payload().len() - offset > 0 {
                    let pkt = NdiscOption::new_checked(&packet.payload()[offset..])?;
                    let opt = NdiscOptionRepr::parse(&pkt)?;
                    match opt {
                        NdiscOptionRepr::SourceLinkLayerAddr(addr) => lladdr = Some(addr.into()),
                        NdiscOptionRepr::Mtu(val) => mtu = Some(val),
                        NdiscOptionRepr::PrefixInformation(info) => prefix_info = Some(info),
                        _ => { return Err(Error::Unrecognized); }
                    }
                    offset += opt.buffer_len();
                }
                Ok(Repr::RouterAdvert {
                    hop_limit: packet.current_hop_limit(),
                    flags: packet.router_flags(),
                    router_lifetime: packet.router_lifetime(),
                    reachable_time: packet.reachable_time(),
                    retrans_time: packet.retrans_time(),
                    lladdr, mtu, prefix_info
                })
            },
            Message::NeighborSolicit => {
                let lladdr = if !packet.payload().is_empty() {
                    let opt = NdiscOption::new_checked(packet.payload())?;
                    match opt.option_type() {
                        NdiscOptionType::SourceLinkLayerAddr => Some(opt.link_layer_addr().into()),
                        _ => { return Err(Error::Unrecognized); }
                    }
                } else {
                    None
                };
                Ok(Repr::NeighborSolicit {
                    target_addr: packet.target_addr(), lladdr
                })
            },
            Message::NeighborAdvert => {
                let lladdr = if !packet.payload().is_empty() {
                    let opt = NdiscOption::new_checked(packet.payload())?;
                    match opt.option_type() {
                        NdiscOptionType::TargetLinkLayerAddr => Some(opt.link_layer_addr().into()),
                        _ => { return Err(Error::Unrecognized); }
                    }
                } else {
                    None
                };
                Ok(Repr::NeighborAdvert {
                    flags: packet.neighbor_flags(),
                    target_addr: packet.target_addr(),
                    lladdr
                })
            },
            Message::Redirect => {
                let mut offset = 0;
                let (mut lladdr, mut redirected_hdr) = (None, None);
                while packet.payload().len() - offset > 0 {
                    let opt = NdiscOption::new_checked(&packet.payload()[offset..])?;
                    match opt.option_type() {
                        NdiscOptionType::SourceLinkLayerAddr => {
                            lladdr = Some(opt.link_layer_addr().into());
                            offset += 8;
                        },
                        NdiscOptionType::RedirectedHeader => {
                            if opt.data_len() < 6 {
                                return Err(Error::Truncated)
                            } else {
                                let ip_packet =
                                    Ipv6Packet::new_unchecked(&opt.data()[offset + 8..]);
                                let ip_repr = Ipv6Repr::parse(&ip_packet)?;
                                let data = &opt.data()[offset + 8 + ip_repr.buffer_len()..];
                                redirected_hdr = Some(NdiscRedirectedHeader {
                                    header: ip_repr, data
                                });
                                offset += 8 + ip_repr.buffer_len() + data.len();
                            }
                        }
                        _ => { return Err(Error::Unrecognized); }
                    }
                }
                Ok(Repr::Redirect {
                    target_addr: packet.target_addr(),
                    dest_addr: packet.dest_addr(),
                    lladdr, redirected_hdr
                })
            },
            _ => Err(Error::Unrecognized)
        }
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::RouterSolicit { lladdr } => {
                match lladdr {
                    Some(_) => field::UNUSED.end + 8,
                    None => field::UNUSED.end,
                }
            },
            &Repr::RouterAdvert { lladdr, mtu, prefix_info, .. } => {
                let mut offset = 0;
                if lladdr.is_some() {
                    offset += 8;
                }
                if mtu.is_some() {
                    offset += 8;
                }
                if prefix_info.is_some() {
                    offset += 32;
                }
                field::RETRANS_TM.end + offset
            },
            &Repr::NeighborSolicit { lladdr, .. } | &Repr::NeighborAdvert { lladdr, .. } => {
                match lladdr {
                    Some(addr) => {
                        let mut len = field::TARGET_ADDR.end;
                        len += 2;
                        len += addr.as_bytes().len();

                        // A packet of len == 30 is a packet with an Ethernet address
                        if len > 30 {
                            // TODO: find out why this padding is +4 and not +6
                            // WireShark wants a padding of +6, however, then the packet is not accepted when using ping
                            // When a padding of +4 is used, then WireShark complains and says that the packet is malformed,
                            // however, ping accepts this packet.
                            len += 4; // Padding
                        }
                        len
                    }
                    None => field::TARGET_ADDR.end,
                }
            },
            &Repr::Redirect { lladdr, redirected_hdr, .. } => {
                let mut offset = 0;
                if lladdr.is_some() {
                    offset += 8;
                }
                if let Some(NdiscRedirectedHeader { header, data }) = redirected_hdr {
                    offset += 8 + header.buffer_len() + data.len();
                }
                field::DEST_ADDR.end + offset
            }
        }
    }

    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        match *self {
            Repr::RouterSolicit { lladdr } => {
                packet.set_msg_type(Message::RouterSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            },

            Repr::RouterAdvert { hop_limit, flags, router_lifetime, reachable_time,
                                  retrans_time, lladdr, mtu, prefix_info } => {
                packet.set_msg_type(Message::RouterAdvert);
                packet.set_msg_code(0);
                packet.set_current_hop_limit(hop_limit);
                packet.set_router_flags(flags);
                packet.set_router_lifetime(router_lifetime);
                packet.set_reachable_time(reachable_time);
                packet.set_retrans_time(retrans_time);
                let mut offset = 0;
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                    offset += 8;
                }
                if let Some(mtu) = mtu {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::Mtu(mtu).emit(&mut opt_pkt);
                    offset += 8;
                }
                if let Some(prefix_info) = prefix_info {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::PrefixInformation(prefix_info).emit(&mut opt_pkt)
                }
            },

            Repr::NeighborSolicit { target_addr, lladdr } => {
                packet.set_msg_type(Message::NeighborSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            },

            Repr::NeighborAdvert { flags, target_addr, lladdr } => {
                packet.set_msg_type(Message::NeighborAdvert);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_neighbor_flags(flags);
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            },

            Repr::Redirect { target_addr, dest_addr, lladdr, redirected_hdr } => {
                packet.set_msg_type(Message::Redirect);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.set_dest_addr(dest_addr);
                let offset = match lladdr {
                    Some(lladdr) => {
                        let mut opt_pkt =
                            NdiscOption::new_unchecked(packet.payload_mut());
                        NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                        8
                    },
                    None => 0,
                };
                if let Some(redirected_hdr) = redirected_hdr {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::RedirectedHeader(redirected_hdr).emit(&mut opt_pkt);
                }
            },
        }
    }
}

#[cfg(test)]
mod test {
    use crate::phy::ChecksumCapabilities;
    use super::*;
    use crate::wire::Icmpv6Repr;
    use crate::wire::ip::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2};

    static ROUTER_ADVERT_BYTES: [u8; 24] =
        [0x86, 0x00, 0xa9, 0xde,
         0x40, 0x80, 0x03, 0x84,
         0x00, 0x00, 0x03, 0x84,
         0x00, 0x00, 0x03, 0x84,
         0x01, 0x01, 0x52, 0x54,
         0x00, 0x12, 0x34, 0x56];
    static SOURCE_LINK_LAYER_OPT: [u8; 8] =
        [0x01, 0x01, 0x52, 0x54,
         0x00, 0x12, 0x34, 0x56];

    fn create_repr<'a>() -> Icmpv6Repr<'a> {
        Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::from_millis(900),
            retrans_time: Duration::from_millis(900),
            lladdr: Some(HardwareAddres::Ethernet(EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]))),
            mtu: None,
            prefix_info: None
        })
    }

    #[test]
    fn test_router_advert_deconstruct() {
        let packet = Packet::new_unchecked(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::RouterAdvert);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.current_hop_limit(), 64);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        assert_eq!(packet.router_lifetime(), Duration::from_secs(900));
        assert_eq!(packet.reachable_time(), Duration::from_millis(900));
        assert_eq!(packet.retrans_time(), Duration::from_millis(900));
        assert_eq!(packet.payload(), &SOURCE_LINK_LAYER_OPT[..]);
    }

    #[test]
    fn test_router_advert_construct() {
        let mut bytes = vec![0x0; 24];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        packet.payload_mut().copy_from_slice(&SOURCE_LINK_LAYER_OPT[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&packet.into_inner()[..], &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    fn test_router_advert_repr_parse() {
        let packet = Packet::new_unchecked(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(Icmpv6Repr::parse(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                                     &packet, &ChecksumCapabilities::default()).unwrap(),
                   create_repr());
    }

    #[test]
    fn test_router_advert_repr_emit() {
        let mut bytes = vec![0x2a; 24];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        create_repr().emit(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                           &mut packet, &ChecksumCapabilities::default());
        assert_eq!(&packet.into_inner()[..], &ROUTER_ADVERT_BYTES[..]);
    }
}
