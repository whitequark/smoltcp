use core::fmt;
use byteorder::{NetworkEndian, ByteOrder};
use bitflags::bitflags;

use crate::{Error, Result};
use crate::time::Duration;
use crate::wire::{Ipv6Address, Ipv6Packet, Ipv6Repr};

#[cfg(feature = "medium-ethernet")]
use crate::wire::EthernetAddress;
#[cfg(feature = "medium-sixlowpan")]
use crate::wire::Ieee802154Address;

use crate::wire::HardwareAddress;

enum_with_unknown! {
    /// NDISC Option Type
    pub enum Type(u8) {
        /// Source Link-layer Address
        SourceLinkLayerAddr = 0x1,
        /// Target Link-layer Address
        TargetLinkLayerAddr = 0x2,
        /// Prefix Information
        PrefixInformation   = 0x3,
        /// Redirected Header
        RedirectedHeader    = 0x4,
        /// MTU
        Mtu                 = 0x5
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Type::SourceLinkLayerAddr => write!(f, "source link-layer address"),
            Type::TargetLinkLayerAddr => write!(f, "target link-layer address"),
            Type::PrefixInformation   => write!(f, "prefix information"),
            Type::RedirectedHeader    => write!(f, "redirected header"),
            Type::Mtu                 => write!(f, "mtu"),
            Type::Unknown(id) => write!(f, "{}", id)
        }
    }
}

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct PrefixInfoFlags: u8 {
        const ON_LINK  = 0b10000000;
        const ADDRCONF = 0b01000000;
    }
}

/// A read/write wrapper around an [NDISC Option].
///
/// [NDISC Option]: https://tools.ietf.org/html/rfc4861#section-4.6
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NdiscOption<T: AsRef<[u8]>> {
    buffer: T
}

// Format of an NDISC Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~                              ...                              ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc4861#section-4.6 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE:          usize = 0;
    // 8-bit unsigned integer. Length of the option, in units of 8 octests.
    pub const LENGTH:        usize = 1;
    // Minimum length of an option.
    pub const MIN_OPT_LEN:   usize = 8;
    // Variable-length field. Option-Type-specific data.
    pub fn DATA(length: u8) -> Field {
        2..length as usize * 8
    }

    // Source/Target Link-layer Option fields.
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Link-Layer Address
    #[cfg(feature = "medium-ethernet")]
    pub const LL_ADDR:       Field = 2..8;
    #[cfg(feature = "medium-sixlowpan")]
    pub const LL_ADDR:       Field = 2..10;

    // Prefix Information Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Valid Lifetime                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Preferred Lifetime                      |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved2                           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +                            Prefix                             +
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix length.
    pub const PREFIX_LEN:    usize = 2;
    // Flags field of prefix header.
    pub const FLAGS:         usize = 3;
    // Valid lifetime.
    pub const VALID_LT:      Field = 4..8;
    // Preferred lifetime.
    pub const PREF_LT:       Field = 8..12;
    // Reserved bits
    pub const PREF_RESERVED: Field = 12..16;
    // Prefix
    pub const PREFIX:        Field = 16..32;

    // Redirected Header Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |            Reserved           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  ~                       IP header + data                        ~
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Reserved bits.
    pub const IP_RESERVED:   Field = 4..8;
    // Redirected header IP header + data.
    pub const IP_DATA:       usize = 8;
    pub const REDIR_MIN_SZ:  usize = 48;

    // MTU Option fields
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |           Reserved            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              MTU                              |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  MTU
    pub const MTU:           Field = 4..8;
}

/// Core getter methods relevant to any type of NDISC option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Create a raw octet buffer with an NDISC Option structure.
    pub fn new_unchecked(buffer: T) -> NdiscOption<T> {
        NdiscOption { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<NdiscOption<T>> {
        let opt = Self::new_unchecked(buffer);
        opt.check_len()?;
        Ok(opt)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_data_len].
    ///
    /// [set_data_len]: #method.set_data_len
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::MIN_OPT_LEN {
            Err(Error::Truncated)
        } else {
            let data_range = field::DATA(data[field::LENGTH]);
            if len < data_range.end {
                Err(Error::Truncated)
            } else {
                match self.option_type() {
                    Type::SourceLinkLayerAddr | Type::TargetLinkLayerAddr | Type::Mtu =>
                        Ok(()),
                    Type::PrefixInformation if data_range.end >= field::PREFIX.end =>
                        Ok(()),
                    Type::RedirectedHeader if data_range.end >= field::REDIR_MIN_SZ =>
                        Ok(()),
                    Type::Unknown(_) =>
                        Ok(()),
                    _ =>
                        Err(Error::Truncated),
                }
            }
        }
    }

    /// Consume the NDISC option, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the option type.
    #[inline]
    pub fn option_type(&self) -> Type {
        let data = self.buffer.as_ref();
        Type::from(data[field::TYPE])
    }

    /// Return the length of the data.
    #[inline]
    pub fn data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }
}

/// Getter methods only relevant for Source/Target Link-layer Address options.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the Source/Target Link-layer Address.
    #[inline]
    pub fn link_layer_addr(&self) -> HardwareAddress {
        let data = self.buffer.as_ref();
        let addr = &data[field::LL_ADDR];

        #[cfg(feature = "medium-ethernet")]
        {
            HardwareAddress::Ethernet(EthernetAddress::from_bytes(addr))
        }

        #[cfg(feature = "medium-sixlowpan")]
        {
            HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(addr))
        }
    }
}

/// Getter methods only relevant for the MTU option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the MTU value.
    #[inline]
    pub fn mtu(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::MTU])
    }
}

/// Getter methods only relevant for the Prefix Information option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the prefix length.
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.buffer.as_ref()[field::PREFIX_LEN]
    }

    /// Return the prefix information flags.
    #[inline]
    pub fn prefix_flags(&self) -> PrefixInfoFlags {
        PrefixInfoFlags::from_bits_truncate(self.buffer.as_ref()[field::FLAGS])
    }

    /// Return the valid lifetime of the prefix.
    #[inline]
    pub fn valid_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_secs(NetworkEndian::read_u32(&data[field::VALID_LT]) as u64)
    }

    /// Return the preferred lifetime of the prefix.
    #[inline]
    pub fn preferred_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_secs(NetworkEndian::read_u32(&data[field::PREF_LT]) as u64)
    }

    /// Return the prefix.
    #[inline]
    pub fn prefix(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::PREFIX])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NdiscOption<&'a T> {
    /// Return the option data.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let len = self.data_len();
        let data = self.buffer.as_ref();
        &data[field::DATA(len)]
    }
}

/// Core setter methods relevant to any type of NDISC option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the option type.
    #[inline]
    pub fn set_option_type(&mut self, value: Type) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into();
    }

    /// Set the option data length.
    #[inline]
    pub fn set_data_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
    }
}

/// Setter methods only relevant for Source/Target Link-layer Address options.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the Source/Target Link-layer Address.
    #[inline]
    pub fn set_link_layer_addr(&mut self, addr: HardwareAddress) {
        let data = self.buffer.as_mut();
        let data = &mut data[field::LL_ADDR];
        data.copy_from_slice(&addr.as_bytes());
    }
}

/// Setter methods only relevant for the MTU option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the MTU value.
    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::MTU], value);
    }
}

/// Setter methods only relevant for the Prefix Information option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the prefix length.
    #[inline]
    pub fn set_prefix_len(&mut self, value: u8) {
        self.buffer.as_mut()[field::PREFIX_LEN] = value;
    }

    /// Set the prefix information flags.
    #[inline]
    pub fn set_prefix_flags(&mut self, flags: PrefixInfoFlags) {
        self.buffer.as_mut()[field::FLAGS] = flags.bits();
    }

    /// Set the valid lifetime of the prefix.
    #[inline]
    pub fn set_valid_lifetime(&mut self, time: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::VALID_LT], time.secs() as u32);
    }

    /// Set the preferred lifetime of the prefix.
    #[inline]
    pub fn set_preferred_lifetime(&mut self, time: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::PREF_LT], time.secs() as u32);
    }

    /// Clear the reserved bits.
    #[inline]
    pub fn clear_prefix_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::PREF_RESERVED], 0);
    }

    /// Set the prefix.
    #[inline]
    pub fn set_prefix(&mut self, addr: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::PREFIX].copy_from_slice(addr.as_bytes());
    }
}

/// Setter methods only relevant for the Redirected Header option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Clear the reserved bits.
    #[inline]
    pub fn clear_redirected_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::IP_RESERVED], 0);
    }
}


impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> NdiscOption<&'a mut T> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        let data = self.buffer.as_mut();
        &mut data[field::DATA(len)]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for NdiscOption<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "NDISC Option ({})", err)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrefixInformation {
    pub prefix_len: u8,
    pub flags: PrefixInfoFlags,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
    pub prefix: Ipv6Address
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RedirectedHeader<'a> {
    pub header: Ipv6Repr,
    pub data: &'a [u8]
}

/// A high-level representation of an NDISC Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'a> {
    SourceLinkLayerAddr(HardwareAddress),
    TargetLinkLayerAddr(HardwareAddress),
    PrefixInformation(PrefixInformation),
    RedirectedHeader(RedirectedHeader<'a>),
    Mtu(u32),
    Unknown {
        type_:  u8,
        length: u8,
        data:   &'a [u8]
    },
}

impl<'a> Repr<'a> {
    /// Parse an NDISC Option and return a high-level representation.
    pub fn parse<T>(opt: &'a NdiscOption<&'a T>) -> Result<Repr<'a>>
            where T: AsRef<[u8]> + ?Sized {
        match opt.option_type() {
            Type::SourceLinkLayerAddr => {
                if opt.data_len() == 1 {
                    Ok(Repr::SourceLinkLayerAddr(opt.link_layer_addr()))
                } else {
                    Err(Error::Malformed)
                }
            },
            Type::TargetLinkLayerAddr => {
                if opt.data_len() == 1 {
                    Ok(Repr::TargetLinkLayerAddr(opt.link_layer_addr()))
                } else {
                    Err(Error::Malformed)
                }
            },
            Type::PrefixInformation => {
                if opt.data_len() == 4 {
                    Ok(Repr::PrefixInformation(PrefixInformation {
                        prefix_len: opt.prefix_len(),
                        flags: opt.prefix_flags(),
                        valid_lifetime: opt.valid_lifetime(),
                        preferred_lifetime: opt.preferred_lifetime(),
                        prefix: opt.prefix()
                    }))
                } else {
                    Err(Error::Malformed)
                }
            },
            Type::RedirectedHeader => {
                // If the options data length is less than 6, the option
                // does not have enough data to fill out the IP header
                // and common option fields.
                if opt.data_len() < 6 {
                    Err(Error::Truncated)
                } else {
                    let ip_packet = Ipv6Packet::new_unchecked(&opt.data()[field::IP_DATA..]);
                    let ip_repr = Ipv6Repr::parse(&ip_packet)?;
                    Ok(Repr::RedirectedHeader(RedirectedHeader {
                        header: ip_repr,
                        data: &opt.data()[field::IP_DATA + ip_repr.buffer_len()..]
                    }))
                }
            },
            Type::Mtu => {
                if opt.data_len() == 1 {
                    Ok(Repr::Mtu(opt.mtu()))
                } else {
                    Err(Error::Malformed)
                }
            },
            Type::Unknown(id) => {
                Ok(Repr::Unknown {
                    type_: id,
                    length: opt.data_len(),
                    data: opt.data()
                })
            }
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::SourceLinkLayerAddr(_) | &Repr::TargetLinkLayerAddr(_) =>
                field::LL_ADDR.end,
            &Repr::PrefixInformation(_) =>
                field::PREFIX.end,
            &Repr::RedirectedHeader(RedirectedHeader { header, data }) =>
                field::IP_DATA + header.buffer_len() + data.len(),
            &Repr::Mtu(_) =>
                field::MTU.end,
            &Repr::Unknown { length, .. } =>
                field::DATA(length).end
        }
    }

    /// Emit a high-level representation into an NDISC Option.
    pub fn emit<T>(&self, opt: &mut NdiscOption<&'a mut T>)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        match *self {
            Repr::SourceLinkLayerAddr(addr) => {
                opt.set_option_type(Type::SourceLinkLayerAddr);
                #[cfg(feature = "medium-ethernet")]
                {
                    opt.set_data_len(1);
                }
                #[cfg(feature = "medium-sixlowpan")]
                {
                    opt.set_data_len(2);
                }
                opt.set_link_layer_addr(addr);
            },
            Repr::TargetLinkLayerAddr(addr) => {
                opt.set_option_type(Type::TargetLinkLayerAddr);
                #[cfg(feature = "medium-ethernet")]
                {
                    opt.set_data_len(1);
                }
                #[cfg(feature = "medium-sixlowpan")]
                {
                    opt.set_data_len(2);
                }
                opt.set_link_layer_addr(addr);
            },
            Repr::PrefixInformation(PrefixInformation {
                prefix_len, flags, valid_lifetime,
                preferred_lifetime, prefix
            }) => {
                opt.clear_prefix_reserved();
                opt.set_option_type(Type::PrefixInformation);
                opt.set_data_len(4);
                opt.set_prefix_len(prefix_len);
                opt.set_prefix_flags(flags);
                opt.set_valid_lifetime(valid_lifetime);
                opt.set_preferred_lifetime(preferred_lifetime);
                opt.set_prefix(prefix);
            },
            Repr::RedirectedHeader(RedirectedHeader {
                header, data
            }) => {
                let data_len = data.len() / 8;
                opt.clear_redirected_reserved();
                opt.set_option_type(Type::RedirectedHeader);
                opt.set_data_len((header.buffer_len() + 1 + data_len) as u8);
                let mut ip_packet =
                    Ipv6Packet::new_unchecked(&mut opt.data_mut()[field::IP_DATA..]);
                header.emit(&mut ip_packet);
                let payload = &mut ip_packet.into_inner()[header.buffer_len()..];
                payload.copy_from_slice(&data[..data_len]);
            }
            Repr::Mtu(mtu) => {
                opt.set_option_type(Type::Mtu);
                opt.set_data_len(1);
                opt.set_mtu(mtu);
            }
            Repr::Unknown { type_: id, length, data } => {
                opt.set_option_type(Type::Unknown(id));
                opt.set_data_len(length);
                opt.data_mut().copy_from_slice(data);
            }
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NDISC Option: ")?;
        match *self {
            Repr::SourceLinkLayerAddr(addr) => {
                write!(f, "SourceLinkLayer addr={}", addr)
            },
            Repr::TargetLinkLayerAddr(addr) => {
                write!(f, "TargetLinkLayer addr={}", addr)
            },
            Repr::PrefixInformation(PrefixInformation {
                prefix, prefix_len,
                ..
            }) => {
                write!(f, "PrefixInformation prefix={}/{}", prefix, prefix_len)
            },
            Repr::RedirectedHeader(RedirectedHeader {
                header,
                ..
            }) => {
                write!(f, "RedirectedHeader header={}", header)
            },
            Repr::Mtu(mtu) => {
                write!(f, "MTU mtu={}", mtu)
            },
            Repr::Unknown { type_: id, length, .. } => {
                write!(f, "Unknown({}) length={}", id, length)
            }
        }
    }
}

use crate::wire::pretty_print::{PrettyPrint, PrettyIndent};

impl<T: AsRef<[u8]>> PrettyPrint for NdiscOption<T> {
    fn pretty_print(buffer: &dyn AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        match NdiscOption::new_checked(buffer) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ndisc) => {
                match Repr::parse(&ndisc) {
                    Err(_) => Ok(()),
                    Ok(repr) => {
                        write!(f, "{}{}", indent, repr)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Error;
    use crate::time::Duration;
    use crate::wire::{EthernetAddress, Ipv6Address};
    use super::{NdiscOption, Type, PrefixInfoFlags, PrefixInformation, Repr};

    static PREFIX_OPT_BYTES: [u8; 32] = [
        0x03, 0x04, 0x40, 0xc0,
        0x00, 0x00, 0x03, 0x84,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    ];

    #[test]
    fn test_deconstruct() {
        let opt = NdiscOption::new_unchecked(&PREFIX_OPT_BYTES[..]);
        assert_eq!(opt.option_type(), Type::PrefixInformation);
        assert_eq!(opt.data_len(), 4);
        assert_eq!(opt.prefix_len(), 64);
        assert_eq!(opt.prefix_flags(), PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        assert_eq!(opt.valid_lifetime(), Duration::from_secs(900));
        assert_eq!(opt.preferred_lifetime(), Duration::from_secs(1000));
        assert_eq!(opt.prefix(), Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0x00; 32];
        let mut opt = NdiscOption::new_unchecked(&mut bytes[..]);
        opt.set_option_type(Type::PrefixInformation);
        opt.set_data_len(4);
        opt.set_prefix_len(64);
        opt.set_prefix_flags(PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        opt.set_valid_lifetime(Duration::from_secs(900));
        opt.set_preferred_lifetime(Duration::from_secs(1000));
        opt.set_prefix(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(&PREFIX_OPT_BYTES[..], &opt.into_inner()[..]);
    }

    #[test]
    fn test_short_packet() {
        assert_eq!(NdiscOption::new_checked(&[0x00, 0x00]), Err(Error::Truncated));
        let bytes = [
            0x03, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];
        assert_eq!(NdiscOption::new_checked(&bytes), Err(Error::Truncated));
    }

    #[test]
    fn test_repr_parse_link_layer_opt() {
        let mut bytes = [0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34];
        let addr = EthernetAddress([0x54, 0x52, 0x00, 0x12, 0x23, 0x34]);
        {
            assert_eq!(Repr::parse(&NdiscOption::new_unchecked(&bytes)),
                       Ok(Repr::SourceLinkLayerAddr(addr)));
        }
        bytes[0] = 0x02;
        {
            assert_eq!(Repr::parse(&NdiscOption::new_unchecked(&bytes)),
                       Ok(Repr::TargetLinkLayerAddr(addr)));
        }
    }

    #[test]
    fn test_repr_parse_prefix_info() {
        let repr = Repr::PrefixInformation(PrefixInformation {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        });
        assert_eq!(Repr::parse(&NdiscOption::new_unchecked(&PREFIX_OPT_BYTES)), Ok(repr));
    }

    #[test]
    fn test_repr_emit_prefix_info() {
        let mut bytes = [0x2a; 32];
        let repr = Repr::PrefixInformation(PrefixInformation {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        });
        let mut opt = NdiscOption::new_unchecked(&mut bytes);
        repr.emit(&mut opt);
        assert_eq!(&opt.into_inner()[..], &PREFIX_OPT_BYTES[..]);
    }

    #[test]
    fn test_repr_parse_mtu() {
        let bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc];
        assert_eq!(Repr::parse(&NdiscOption::new_unchecked(&bytes)), Ok(Repr::Mtu(1500)));
    }
}
