use core::{cmp, fmt};
use byteorder::{ByteOrder, NetworkEndian};

use crate::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::checksum;
use crate::wire::{IpAddress, IpProtocol, Ipv6Packet, Ipv6Repr};
use crate::wire::MldRepr;
#[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
use crate::wire::NdiscRepr;

enum_with_unknown! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Destination Unreachable.
        DstUnreachable  = 0x01,
        /// Packet Too Big.
        PktTooBig       = 0x02,
        /// Time Exceeded.
        TimeExceeded    = 0x03,
        /// Parameter Problem.
        ParamProblem    = 0x04,
        /// Echo Request
        EchoRequest     = 0x80,
        /// Echo Reply
        EchoReply       = 0x81,
        /// Multicast Listener Query
        MldQuery        = 0x82,
        /// Router Solicitation
        RouterSolicit   = 0x85,
        /// Router Advertisement
        RouterAdvert    = 0x86,
        /// Neighbor Solicitation
        NeighborSolicit = 0x87,
        /// Neighbor Advertisement
        NeighborAdvert  = 0x88,
        /// Redirect
        Redirect        = 0x89,
        /// Multicast Listener Report
        MldReport       = 0x8f
    }
}

impl Message {
    /// Per [RFC 4443 § 2.1] ICMPv6 message types with the highest order
    /// bit set are informational messages while message types without
    /// the highest order bit set are error messages.
    ///
    /// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
    pub fn is_error(&self) -> bool {
        (u8::from(*self) & 0x80) != 0x80
    }

    /// Return a boolean value indicating if the given message type
    /// is an [NDISC] message type.
    ///
    /// [NDISC]: https://tools.ietf.org/html/rfc4861
    pub fn is_ndisc(&self) -> bool {
        match *self {
            Message::RouterSolicit | Message::RouterAdvert | Message::NeighborSolicit |
            Message::NeighborAdvert | Message::Redirect => true,
            _ => false,
        }
    }

    /// Return a boolean value indicating if the given message type
    /// is an [MLD] message type.
    ///
    /// [MLD]: https://tools.ietf.org/html/rfc3810
    pub fn is_mld(&self) -> bool {
        match *self {
            Message::MldQuery | Message::MldReport => true,
            _ => false,
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::DstUnreachable  => write!(f, "destination unreachable"),
            Message::PktTooBig       => write!(f, "packet too big"),
            Message::TimeExceeded    => write!(f, "time exceeded"),
            Message::ParamProblem    => write!(f, "parameter problem"),
            Message::EchoReply       => write!(f, "echo reply"),
            Message::EchoRequest     => write!(f, "echo request"),
            Message::RouterSolicit   => write!(f, "router solicitation"),
            Message::RouterAdvert    => write!(f, "router advertisement"),
            Message::NeighborSolicit => write!(f, "neighbor solicitation"),
            Message::NeighborAdvert  => write!(f, "neighbor advert"),
            Message::Redirect        => write!(f, "redirect"),
            Message::MldQuery        => write!(f, "multicast listener query"),
            Message::MldReport       => write!(f, "multicast listener report"),
            Message::Unknown(id)     => write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// No Route to destination.
        NoRoute         = 0,
        /// Communication with destination administratively prohibited.
        AdminProhibit   = 1,
        /// Beyond scope of source address.
        BeyondScope     = 2,
        /// Address unreachable.
        AddrUnreachable = 3,
        /// Port unreachable.
        PortUnreachable = 4,
        /// Source address failed ingress/egress policy.
        FailedPolicy    = 5,
        /// Reject route to destination.
        RejectRoute     = 6
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DstUnreachable::NoRoute =>
               write!(f, "no route to destination"),
            DstUnreachable::AdminProhibit =>
               write!(f, "communication with destination administratively prohibited"),
            DstUnreachable::BeyondScope =>
               write!(f, "beyond scope of source address"),
            DstUnreachable::AddrUnreachable =>
               write!(f, "address unreachable"),
            DstUnreachable::PortUnreachable =>
               write!(f, "port unreachable"),
            DstUnreachable::FailedPolicy =>
               write!(f, "source address failed ingress/egress policy"),
            DstUnreachable::RejectRoute =>
               write!(f, "reject route to destination"),
            DstUnreachable::Unknown(id) =>
                write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Erroneous header field encountered.
        ErroneousHdrField  = 0,
        /// Unrecognized Next Header type encountered.
        UnrecognizedNxtHdr = 1,
        /// Unrecognized IPv6 option encountered.
        UnrecognizedOption = 2
    }
}

impl fmt::Display for ParamProblem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParamProblem::ErroneousHdrField  =>
               write!(f, "erroneous header field."),
            ParamProblem::UnrecognizedNxtHdr =>
               write!(f, "unrecognized next header type."),
            ParamProblem::UnrecognizedOption =>
               write!(f, "unrecognized IPv6 option."),
            ParamProblem::Unknown(id) =>
                write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// Hop limit exceeded in transit.
        HopLimitExceeded    = 0,
        /// Fragment reassembly time exceeded.
        FragReassemExceeded = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TimeExceeded::HopLimitExceeded =>
               write!(f, "hop limit exceeded in transit"),
            TimeExceeded::FragReassemExceeded =>
               write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) =>
                write!(f, "{}", id)
        }
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 6 packet buffer.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    pub(super) buffer: T
}

// Ranges and constants describing key boundaries in the ICMPv6 header.
pub(super) mod field {
    use crate::wire::field::*;

    // ICMPv6: See https://tools.ietf.org/html/rfc4443
    pub const TYPE:              usize = 0;
    pub const CODE:              usize = 1;
    pub const CHECKSUM:          Field = 2..4;

    pub const UNUSED:            Field = 4..8;
    pub const MTU:               Field = 4..8;
    pub const POINTER:           Field = 4..8;
    pub const ECHO_IDENT:        Field = 4..6;
    pub const ECHO_SEQNO:        Field = 6..8;

    pub const HEADER_END:        usize = 8;

    // NDISC: See https://tools.ietf.org/html/rfc4861
    // Router Advertisement message offsets
    pub const CUR_HOP_LIMIT:     usize = 4;
    pub const ROUTER_FLAGS:      usize = 5;
    pub const ROUTER_LT:         Field = 6..8;
    pub const REACHABLE_TM:      Field = 8..12;
    pub const RETRANS_TM:        Field = 12..16;

    // Neighbor Solicitation message offsets
    pub const TARGET_ADDR:       Field = 8..24;

    // Neighbor Advertisement message offsets
    pub const NEIGH_FLAGS:       usize = 4;

    // Redirected Header message offsets
    pub const DEST_ADDR:         Field = 24..40;

    // MLD:
    //   - https://tools.ietf.org/html/rfc3810
    //   - https://tools.ietf.org/html/rfc3810
    // Multicast Listener Query message
    pub const MAX_RESP_CODE:     Field = 4..6;
    pub const QUERY_RESV:        Field = 6..8;
    pub const QUERY_MCAST_ADDR:  Field = 8..24;
    pub const SQRV:              usize = 24;
    pub const QQIC:              usize = 25;
    pub const QUERY_NUM_SRCS:    Field = 26..28;

    // Multicast Listener Report Message
    pub const RECORD_RESV:       Field = 4..6;
    pub const NR_MCAST_RCRDS:    Field = 6..8;

    // Multicast Address Record Offsets
    pub const RECORD_TYPE:       usize = 0;
    pub const AUX_DATA_LEN:      usize = 1;
    pub const RECORD_NUM_SRCS:   Field = 2..4;
    pub const RECORD_MCAST_ADDR: Field = 4..20;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ICMPv6 packet structure.
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
        let len = self.buffer.as_ref().len();
        if len < field::HEADER_END || len < self.header_len() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        Message::from(data[field::TYPE])
    }

    /// Return the message code field.
    #[inline]
    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_SEQNO])
    }

    /// Return the MTU field (for packet too big messages).
    #[inline]
    pub fn pkt_too_big_mtu(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::MTU])
    }

    /// Return the pointer field (for parameter problem messages).
    #[inline]
    pub fn param_problem_ptr(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::POINTER])
    }


    /// Return the header length. The result depends on the value of
    /// the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::DstUnreachable  => field::UNUSED.end,
            Message::PktTooBig       => field::MTU.end,
            Message::TimeExceeded    => field::UNUSED.end,
            Message::ParamProblem    => field::POINTER.end,
            Message::EchoRequest     => field::ECHO_SEQNO.end,
            Message::EchoReply       => field::ECHO_SEQNO.end,
            Message::RouterSolicit   => field::UNUSED.end,
            Message::RouterAdvert    => field::RETRANS_TM.end,
            Message::NeighborSolicit => field::TARGET_ADDR.end,
            Message::NeighborAdvert  => field::TARGET_ADDR.end,
            Message::Redirect        => field::DEST_ADDR.end,
            Message::MldQuery        => field::QUERY_NUM_SRCS.end,
            Message::MldReport       => field::NR_MCAST_RCRDS.end,
            // For packets that are not included in RFC 4443, do not
            // include the last 32 bits of the ICMPv6 header in
            // `header_bytes`. This must be done so that these bytes
            // can be accessed in the `payload`.
            _ => field::CHECKSUM.end
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) { return true }

        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Icmpv6,
                                    data.len() as u32),
            checksum::data(data)
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CODE] = value
    }

    /// Clear any reserved fields in the message header.
    ///
    /// # Panics
    /// This function panics if the message type has not been set.
    /// See [set_msg_type].
    ///
    /// [set_msg_type]: #method.set_msg_type
    #[inline]
    pub fn clear_reserved(&mut self) {
        match self.msg_type() {
            Message::RouterSolicit | Message::NeighborSolicit |
            Message::NeighborAdvert | Message::Redirect => {
                let data = self.buffer.as_mut();
                NetworkEndian::write_u32(&mut data[field::UNUSED], 0);
            },
            Message::MldQuery => {
                let data = self.buffer.as_mut();
                NetworkEndian::write_u16(&mut data[field::QUERY_RESV], 0);
                data[field::SQRV] &= 0xf;
            },
            Message::MldReport => {
                let data = self.buffer.as_mut();
                NetworkEndian::write_u16(&mut data[field::RECORD_RESV], 0);
            }
            ty => panic!("Message type `{}` does not have any reserved fields.", ty),
        }
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_SEQNO], value)
    }

    /// Set the MTU field (for packet too big messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not an packet too big packet.
    #[inline]
    pub fn set_pkt_too_big_mtu(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::MTU], value)
    }

    /// Set the pointer field (for parameter problem messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not a parameter problem message.
    #[inline]
    pub fn set_param_problem_ptr(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::POINTER], value)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Icmpv6,
                                        data.len() as u32),
                checksum::data(data)
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Control Message Protocol version 6 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr<'a> {
    DstUnreachable {
        reason: DstUnreachable,
        header: Ipv6Repr,
        data:   &'a [u8]
    },
    PktTooBig {
        mtu: u32,
        header: Ipv6Repr,
        data:   &'a [u8]
    },
    TimeExceeded {
        reason: TimeExceeded,
        header: Ipv6Repr,
        data:   &'a [u8]
    },
    ParamProblem {
        reason:  ParamProblem,
        pointer: u32,
        header:  Ipv6Repr,
        data:    &'a [u8]
    },
    EchoRequest {
        ident:  u16,
        seq_no: u16,
        data:   &'a [u8]
    },
    EchoReply {
        ident:  u16,
        seq_no: u16,
        data:   &'a [u8]
    },
    #[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
    Ndisc(NdiscRepr<'a>),
    Mld(MldRepr<'a>),
}

impl<'a> Repr<'a> {
    /// Parse an Internet Control Message Protocol version 6 packet and return
    /// a high-level representation.
    pub fn parse<T>(src_addr: &IpAddress, dst_addr: &IpAddress,
                    packet: &Packet<&'a T>, checksum_caps: &ChecksumCapabilities)
                   -> Result<Repr<'a>>
                where T: AsRef<[u8]> + ?Sized {
        fn create_packet_from_payload<'a, T>(packet: &Packet<&'a T>)
                                            -> Result<(&'a [u8], Ipv6Repr)>
                where T: AsRef<[u8]> + ?Sized {
            let ip_packet = Ipv6Packet::new_checked(packet.payload())?;

            let payload = &packet.payload()[ip_packet.header_len() as usize..];
            if payload.len() < 8 { return Err(Error::Truncated) }
            let repr = Ipv6Repr {
                src_addr: ip_packet.src_addr(),
                dst_addr: ip_packet.dst_addr(),
                next_header: ip_packet.next_header(),
                payload_len: payload.len(),
                hop_limit: ip_packet.hop_limit()
            };
            Ok((payload, repr))
        }
        // Valid checksum is expected.
        if checksum_caps.icmpv6.rx() && !packet.verify_checksum(src_addr, dst_addr) {
            return Err(Error::Checksum)
        }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::DstUnreachable, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header: repr,
                    data: payload
                })
            },
            (Message::PktTooBig, 0) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::PktTooBig {
                    mtu: packet.pkt_too_big_mtu(),
                    header: repr,
                    data: payload
                })
            },
            (Message::TimeExceeded, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::TimeExceeded {
                    reason: TimeExceeded::from(code),
                    header: repr,
                    data: payload
                })
            },
            (Message::ParamProblem, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::ParamProblem {
                    reason: ParamProblem::from(code),
                    pointer: packet.param_problem_ptr(),
                    header: repr,
                    data: payload
                })
            },
            (Message::EchoRequest, 0) => {
                Ok(Repr::EchoRequest {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    data:   packet.payload()
                })
            },
            (Message::EchoReply, 0) => {
                Ok(Repr::EchoReply {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    data:   packet.payload()
                })
            },
            #[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
            (msg_type, 0) if msg_type.is_ndisc() => {
                NdiscRepr::parse(packet).map(Repr::Ndisc)
            },
            (msg_type, 0) if msg_type.is_mld() => {
                MldRepr::parse(packet).map(Repr::Mld)
            },
            _ => Err(Error::Unrecognized)
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::DstUnreachable { header, data, .. } | &Repr::PktTooBig { header, data, .. } |
            &Repr::TimeExceeded { header, data, .. } | &Repr::ParamProblem { header, data, .. } => {
                field::UNUSED.end + header.buffer_len() + data.len()
            }
            &Repr::EchoRequest { data, .. } |
            &Repr::EchoReply { data, .. } => {
                field::ECHO_SEQNO.end + data.len()
            },
            #[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
            &Repr::Ndisc(ndisc) => {
                ndisc.buffer_len()
            },
            &Repr::Mld(mld) => {
                mld.buffer_len()
            },
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 6
    /// packet.
    pub fn emit<T>(&self, src_addr: &IpAddress, dst_addr: &IpAddress,
                   packet: &mut Packet<&mut T>, checksum_caps: &ChecksumCapabilities)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        fn emit_contained_packet(buffer: &mut [u8], header: Ipv6Repr, data: &[u8]) {
            let mut ip_packet = Ipv6Packet::new_unchecked(buffer);
            header.emit(&mut ip_packet);
            let payload = &mut ip_packet.into_inner()[header.buffer_len()..];
            payload.copy_from_slice(&data[..]);
        }

        match *self {
            Repr::DstUnreachable { reason, header, data } => {
                packet.set_msg_type(Message::DstUnreachable);
                packet.set_msg_code(reason.into());

                emit_contained_packet(packet.payload_mut(), header, &data);
            },

            Repr::PktTooBig { mtu, header, data } => {
                packet.set_msg_type(Message::PktTooBig);
                packet.set_msg_code(0);
                packet.set_pkt_too_big_mtu(mtu);

                emit_contained_packet(packet.payload_mut(), header, &data);
            },

            Repr::TimeExceeded { reason, header, data } => {
                packet.set_msg_type(Message::TimeExceeded);
                packet.set_msg_code(reason.into());

                emit_contained_packet(packet.payload_mut(), header, &data);
            },

            Repr::ParamProblem { reason, pointer, header, data } => {
                packet.set_msg_type(Message::ParamProblem);
                packet.set_msg_code(reason.into());
                packet.set_param_problem_ptr(pointer);

                emit_contained_packet(packet.payload_mut(), header, &data);
            },

            Repr::EchoRequest { ident, seq_no, data } => {
                packet.set_msg_type(Message::EchoRequest);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let data_len = cmp::min(packet.payload_mut().len(), data.len());
                packet.payload_mut()[..data_len].copy_from_slice(&data[..data_len])
            },

            Repr::EchoReply { ident, seq_no, data } => {
                packet.set_msg_type(Message::EchoReply);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let data_len = cmp::min(packet.payload_mut().len(), data.len());
                packet.payload_mut()[..data_len].copy_from_slice(&data[..data_len])
            },

            #[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
            Repr::Ndisc(ndisc) => {
                ndisc.emit(packet)
            },

            Repr::Mld(mld) => {
                mld.emit(packet)
            },
        }

        if checksum_caps.icmpv6.tx() {
            packet.fill_checksum(src_addr, dst_addr);
        } else {
            // make sure we get a consistently zeroed checksum, since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::wire::{Ipv6Address, Ipv6Repr, IpProtocol};
    use crate::wire::ip::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2};
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] =
        [0x80, 0x00, 0x19, 0xb3,
         0x12, 0x34, 0xab, 0xcd,
         0xaa, 0x00, 0x00, 0xff];

    static ECHO_PACKET_PAYLOAD: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_BYTES: [u8; 60] =
        [0x02, 0x00, 0x0f, 0xc9,
         0x00, 0x00, 0x05, 0xdc,
         0x60, 0x00, 0x00, 0x00,
         0x00, 0x0c, 0x11, 0x40,
         0xfe, 0x80, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01,
         0xfe, 0x80, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x02,
         0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x12, 0x4d,
         0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_IP_PAYLOAD: [u8; 52] =
        [0x60, 0x00, 0x00, 0x00,
         0x00, 0x0c, 0x11, 0x40,
         0xfe, 0x80, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01,
         0xfe, 0x80, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x02,
         0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x12, 0x4d,
         0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_UDP_PAYLOAD: [u8; 12] =
        [0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x12, 0x4d,
         0xaa, 0x00, 0x00, 0xff];

    fn echo_packet_repr() -> Repr<'static> {
        Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &ECHO_PACKET_PAYLOAD
        }
    }

    fn too_big_packet_repr() -> Repr<'static> {
        Repr::PktTooBig {
            mtu: 1500,
            header: Ipv6Repr {
                src_addr: Ipv6Address([0xfe, 0x80, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x01]),
                dst_addr: Ipv6Address([0xfe, 0x80, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x02]),
                next_header: IpProtocol::Udp,
                payload_len: 12,
                hop_limit: 0x40
            },
            data: &PKT_TOO_BIG_UDP_PAYLOAD,
        }
    }

    #[test]
    fn test_echo_deconstruct() {
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x19b3);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.payload(), &ECHO_PACKET_PAYLOAD[..]);
        assert_eq!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2), true);
        assert!(!packet.msg_type().is_error());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.payload_mut().copy_from_slice(&ECHO_PACKET_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_echo_repr_parse() {
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
        let repr = Repr::parse(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                               &packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(repr, echo_packet_repr());
    }

    #[test]
    fn test_echo_emit() {
        let repr = echo_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                  &mut packet, &ChecksumCapabilities::default());
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_too_big_deconstruct() {
        let packet = Packet::new_unchecked(&PKT_TOO_BIG_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::PktTooBig);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x0fc9);
        assert_eq!(packet.pkt_too_big_mtu(), 1500);
        assert_eq!(packet.payload(), &PKT_TOO_BIG_IP_PAYLOAD[..]);
        assert_eq!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2), true);
        assert!(packet.msg_type().is_error());
    }

    #[test]
    fn test_too_big_construct() {
        let mut bytes = vec![0xa5; 60];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::PktTooBig);
        packet.set_msg_code(0);
        packet.set_pkt_too_big_mtu(1500);
        packet.payload_mut().copy_from_slice(&PKT_TOO_BIG_IP_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&packet.into_inner()[..], &PKT_TOO_BIG_BYTES[..]);
    }

    #[test]
    fn test_too_big_repr_parse() {
        let packet = Packet::new_unchecked(&PKT_TOO_BIG_BYTES[..]);
        let repr = Repr::parse(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                               &packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(repr, too_big_packet_repr());
    }

    #[test]
    fn test_too_big_emit() {
        let repr = too_big_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2,
                  &mut packet, &ChecksumCapabilities::default());
        assert_eq!(&packet.into_inner()[..], &PKT_TOO_BIG_BYTES[..]);
    }
}
