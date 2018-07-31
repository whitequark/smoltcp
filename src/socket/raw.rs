use core::cmp::min;

use {Error, Result};
use phy::ChecksumCapabilities;
use socket::{Socket, SocketMeta, SocketHandle, PollAt};
use storage::{PacketBuffer, PacketMetadata};
use wire::{IpVersion, IpRepr, IpProtocol};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Repr, Ipv4Packet};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Repr, Ipv6Packet};

/// A UDP packet metadata.
pub type RawPacketMetadata = PacketMetadata<()>;

/// A UDP packet ring buffer.
pub type RawSocketBuffer<'a, 'b> = PacketBuffer<'a, 'b, ()>;

/// A raw IP socket.
///
/// A raw socket is bound to a specific IP protocol, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct RawSocket<'a, 'b: 'a> {
    pub(crate) meta: SocketMeta,
    ip_version:  IpVersion,
    ip_protocol: IpProtocol,
    rx_buffer:   RawSocketBuffer<'a, 'b>,
    tx_buffer:   RawSocketBuffer<'a, 'b>,
}

impl<'a, 'b> RawSocket<'a, 'b> {
    /// Create a raw IP socket bound to the given IP version and datagram protocol,
    /// with the given buffers.
    pub fn new(ip_version: IpVersion, ip_protocol: IpProtocol,
               rx_buffer: RawSocketBuffer<'a, 'b>,
               tx_buffer: RawSocketBuffer<'a, 'b>) -> RawSocket<'a, 'b> {
        RawSocket {
            meta: SocketMeta::default(),
            ip_version,
            ip_protocol,
            rx_buffer,
            tx_buffer,
        }
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Return the IP version the socket is bound to.
    #[inline]
    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    /// Return the IP protocol the socket is bound to.
    #[inline]
    pub fn ip_protocol(&self) -> IpProtocol {
        self.ip_protocol
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    ///
    /// If the buffer is filled in a way that does not match the socket's
    /// IP version or protocol, the packet will be silently dropped.
    ///
    /// **Note:** The IP header is parsed and reserialized, and may not match
    /// the header actually transmitted bit for bit.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8]> {
        let packet_buf = self.tx_buffer.enqueue(size, ())?;

        net_trace!("{}:{}:{}: buffer to send {} octets",
                   self.meta.handle, self.ip_version, self.ip_protocol,
                   packet_buf.len());
        Ok(packet_buf.as_mut())
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<()> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    ///
    /// **Note:** The IP header is parsed and reserialized, and may not match
    /// the header actually received bit for bit.
    pub fn recv(&mut self) -> Result<&[u8]> {
        let ((), packet_buf) = self.rx_buffer.dequeue()?;

        net_trace!("{}:{}:{}: receive {} buffered octets",
                   self.meta.handle, self.ip_version, self.ip_protocol,
                   packet_buf.len());
        Ok(packet_buf)
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr) -> bool {
        if ip_repr.version() != self.ip_version { return false }
        if ip_repr.protocol() != self.ip_protocol { return false }

        true
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, payload: &[u8],
                          checksum_caps: &ChecksumCapabilities) -> Result<()> {
        debug_assert!(self.accepts(ip_repr));

        let header_len = ip_repr.buffer_len();
        let total_len  = header_len + payload.len();
        let packet_buf = self.rx_buffer.enqueue(total_len, ())?;
        ip_repr.emit(&mut packet_buf.as_mut()[..header_len], &checksum_caps);
        packet_buf.as_mut()[header_len..].copy_from_slice(payload);

        net_trace!("{}:{}:{}: receiving {} octets",
                   self.meta.handle, self.ip_version, self.ip_protocol,
                   packet_buf.len());
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, checksum_caps: &ChecksumCapabilities, emit: F) ->
                             Result<()>
            where F: FnOnce((IpRepr, &[u8])) -> Result<()> {
        fn prepare<'a>(protocol: IpProtocol, buffer: &'a mut [u8],
                   _checksum_caps: &ChecksumCapabilities) -> Result<(IpRepr, &'a [u8])> {
            match IpVersion::of_packet(buffer.as_ref())? {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => {
                    let mut packet = Ipv4Packet::new_checked(buffer.as_mut())?;
                    if packet.protocol() != protocol { return Err(Error::Unaddressable) }
                    if _checksum_caps.ipv4.tx() {
                        packet.fill_checksum();
                    } else {
                        // make sure we get a consistently zeroed checksum,
                        // since implementations might rely on it
                        packet.set_checksum(0);
                    }

                    let packet = Ipv4Packet::new_unchecked(&*packet.into_inner());
                    let ipv4_repr = Ipv4Repr::parse(&packet, _checksum_caps)?;
                    Ok((IpRepr::Ipv4(ipv4_repr), packet.payload()))
                }
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => {
                    let mut packet = Ipv6Packet::new_checked(buffer.as_mut())?;
                    if packet.next_header() != protocol { return Err(Error::Unaddressable) }
                    let packet = Ipv6Packet::new_unchecked(&*packet.into_inner());
                    let ipv6_repr = Ipv6Repr::parse(&packet)?;
                    Ok((IpRepr::Ipv6(ipv6_repr), packet.payload()))
                }
                IpVersion::Unspecified => unreachable!(),
                IpVersion::__Nonexhaustive => unreachable!()
            }
        }

        let handle      = self.meta.handle;
        let ip_protocol = self.ip_protocol;
        let ip_version  = self.ip_version;
        self.tx_buffer.dequeue_with(|&mut (), packet_buf| {
            match prepare(ip_protocol, packet_buf.as_mut(), &checksum_caps) {
                Ok((ip_repr, raw_packet)) => {
                    net_trace!("{}:{}:{}: sending {} octets",
                               handle, ip_version, ip_protocol,
                               ip_repr.buffer_len() + raw_packet.len());
                    emit((ip_repr, raw_packet))
                }
                Err(error) => {
                    net_debug!("{}:{}:{}: dropping outgoing packet ({})",
                               handle, ip_version, ip_protocol,
                               error);
                    // Return Ok(()) so the packet is dequeued.
                    Ok(())
                }
            }
        })
    }

    pub(crate) fn poll_at(&self) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

impl<'a, 'b> Into<Socket<'a, 'b>> for RawSocket<'a, 'b> {
    fn into(self) -> Socket<'a, 'b> {
        Socket::Raw(self)
    }
}

#[cfg(test)]
mod test {
    use wire::IpRepr;
    #[cfg(feature = "proto-ipv4")]
    use wire::{Ipv4Address, Ipv4Repr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Ipv6Address, Ipv6Repr};
    use super::*;

    fn buffer(packets: usize) -> RawSocketBuffer<'static, 'static> {
        RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets])
    }

    #[cfg(feature = "proto-ipv4")]
    mod ipv4_locals {
        use super::*;

        pub fn socket(rx_buffer: RawSocketBuffer<'static, 'static>,
                      tx_buffer: RawSocketBuffer<'static, 'static>)
                     -> RawSocket<'static, 'static> {
            RawSocket::new(IpVersion::Ipv4, IpProtocol::Unknown(IP_PROTO),
                           rx_buffer, tx_buffer)
        }

        pub const IP_PROTO: u8 = 63;
        pub const HEADER_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([10, 0, 0, 1]),
            dst_addr: Ipv4Address([10, 0, 0, 2]),
            protocol: IpProtocol::Unknown(IP_PROTO),
            payload_len: 4,
            hop_limit: 64
        });
        pub const PACKET_BYTES: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x3f, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x01,
            0x0a, 0x00, 0x00, 0x02,
            0xaa, 0x00, 0x00, 0xff
        ];
        pub const PACKET_PAYLOAD: [u8; 4] = [
            0xaa, 0x00, 0x00, 0xff
        ];
    }

    #[cfg(feature = "proto-ipv6")]
    mod ipv6_locals {
        use super::*;

        pub fn socket(rx_buffer: RawSocketBuffer<'static, 'static>,
                      tx_buffer: RawSocketBuffer<'static, 'static>)
                     -> RawSocket<'static, 'static> {
            RawSocket::new(IpVersion::Ipv6, IpProtocol::Unknown(IP_PROTO),
                           rx_buffer, tx_buffer)
        }

        pub const IP_PROTO: u8 = 63;
        pub const HEADER_REPR: IpRepr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: Ipv6Address([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            dst_addr: Ipv6Address([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]),
            next_header: IpProtocol::Unknown(IP_PROTO),
            payload_len: 4,
            hop_limit: 64
        });

        pub const PACKET_BYTES: [u8; 44] = [
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x3f, 0x40,
            0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
            0xaa, 0x00, 0x00, 0xff
        ];

        pub const PACKET_PAYLOAD: [u8; 4] = [
            0xaa, 0x00, 0x00, 0xff
        ];
    }

    macro_rules! reusable_ip_specific_tests {
        ($module:ident, $socket:path, $hdr:path, $packet:path, $payload:path) => {
            mod $module {
                use super::*;

                #[test]
                fn test_send_truncated() {
                    let mut socket = $socket(buffer(0), buffer(1));
                    assert_eq!(socket.send_slice(&[0; 56][..]), Err(Error::Truncated));
                }

                #[test]
                fn test_send_dispatch() {
                    let checksum_caps = &ChecksumCapabilities::default();
                    let mut socket = $socket(buffer(0), buffer(1));

                    assert!(socket.can_send());
                    assert_eq!(socket.dispatch(&checksum_caps, |_| unreachable!()),
                               Err(Error::Exhausted));

                    assert_eq!(socket.send_slice(&$packet[..]), Ok(()));
                    assert_eq!(socket.send_slice(b""), Err(Error::Exhausted));
                    assert!(!socket.can_send());

                    assert_eq!(socket.dispatch(&checksum_caps, |(ip_repr, ip_payload)| {
                        assert_eq!(ip_repr, $hdr);
                        assert_eq!(ip_payload, &$payload);
                        Err(Error::Unaddressable)
                    }), Err(Error::Unaddressable));
                    assert!(!socket.can_send());

                    assert_eq!(socket.dispatch(&checksum_caps, |(ip_repr, ip_payload)| {
                        assert_eq!(ip_repr, $hdr);
                        assert_eq!(ip_payload, &$payload);
                        Ok(())
                    }), Ok(()));
                    assert!(socket.can_send());
                }

                #[test]
                fn test_recv_truncated_slice() {
                    let mut socket = $socket(buffer(1), buffer(0));

                    assert!(socket.accepts(&$hdr));
                    assert_eq!(socket.process(&$hdr, &$payload,
                                              &ChecksumCapabilities::default()), Ok(()));

                    let mut slice = [0; 4];
                    assert_eq!(socket.recv_slice(&mut slice[..]), Ok(4));
                    assert_eq!(&slice, &$packet[..slice.len()]);
                }

                #[test]
                fn test_recv_truncated_packet() {
                    let mut socket = $socket(buffer(1), buffer(0));

                    let mut buffer = vec![0; 128];
                    buffer[..$packet.len()].copy_from_slice(&$packet[..]);

                    assert!(socket.accepts(&$hdr));
                    assert_eq!(socket.process(&$hdr, &buffer, &ChecksumCapabilities::default()),
                               Err(Error::Truncated));
                }
            }
        }
    }

    #[cfg(feature = "proto-ipv4")]
    reusable_ip_specific_tests!(ipv4, ipv4_locals::socket, ipv4_locals::HEADER_REPR,
                                ipv4_locals::PACKET_BYTES, ipv4_locals::PACKET_PAYLOAD);

    #[cfg(feature = "proto-ipv6")]
    reusable_ip_specific_tests!(ipv6, ipv6_locals::socket, ipv6_locals::HEADER_REPR,
                                ipv6_locals::PACKET_BYTES, ipv6_locals::PACKET_PAYLOAD);


    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_send_illegal() {
        let checksum_caps = &ChecksumCapabilities::default();
        #[cfg(feature = "proto-ipv4")]
        {
            let mut socket = ipv4_locals::socket(buffer(0), buffer(2));

            let mut wrong_version = ipv4_locals::PACKET_BYTES.clone();
            Ipv4Packet::new_unchecked(&mut wrong_version).set_version(6);

            assert_eq!(socket.send_slice(&wrong_version[..]), Ok(()));
            assert_eq!(socket.dispatch(&checksum_caps, |_| unreachable!()),
                       Ok(()));

            let mut wrong_protocol = ipv4_locals::PACKET_BYTES.clone();
            Ipv4Packet::new_unchecked(&mut wrong_protocol).set_protocol(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&wrong_protocol[..]), Ok(()));
            assert_eq!(socket.dispatch(&checksum_caps, |_| unreachable!()),
                       Ok(()));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let mut socket = ipv6_locals::socket(buffer(0), buffer(2));

            let mut wrong_version = ipv6_locals::PACKET_BYTES.clone();
            Ipv6Packet::new_unchecked(&mut wrong_version[..]).set_version(4);

            assert_eq!(socket.send_slice(&wrong_version[..]), Ok(()));
            assert_eq!(socket.dispatch(&checksum_caps, |_| unreachable!()),
                       Ok(()));

            let mut wrong_protocol = ipv6_locals::PACKET_BYTES.clone();
            Ipv6Packet::new_unchecked(&mut wrong_protocol[..]).set_next_header(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&wrong_protocol[..]), Ok(()));
            assert_eq!(socket.dispatch(&checksum_caps, |_| unreachable!()),
                       Ok(()));
        }
    }

    #[test]
    fn test_recv_process() {
        #[cfg(feature = "proto-ipv4")]
        {
            let mut socket = ipv4_locals::socket(buffer(1), buffer(0));
            assert!(!socket.can_recv());

            let mut cksumd_packet = ipv4_locals::PACKET_BYTES.clone();
            Ipv4Packet::new_unchecked(&mut cksumd_packet).fill_checksum();

            assert_eq!(socket.recv(), Err(Error::Exhausted));
            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            assert_eq!(socket.process(&ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD,
                                      &ChecksumCapabilities::default()),
                       Ok(()));
            assert!(socket.can_recv());

            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            assert_eq!(socket.process(&ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD,
                                      &ChecksumCapabilities::default()),
                       Err(Error::Exhausted));
            assert_eq!(socket.recv(), Ok(&cksumd_packet[..]));
            assert!(!socket.can_recv());
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let mut socket = ipv6_locals::socket(buffer(1), buffer(0));
            assert!(!socket.can_recv());

            assert_eq!(socket.recv(), Err(Error::Exhausted));
            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            assert_eq!(socket.process(&ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD,
                                      &ChecksumCapabilities::default()),
                       Ok(()));
            assert!(socket.can_recv());

            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            assert_eq!(socket.process(&ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD,
                                      &ChecksumCapabilities::default()),
                       Err(Error::Exhausted));
            assert_eq!(socket.recv(), Ok(&ipv6_locals::PACKET_BYTES[..]));
            assert!(!socket.can_recv());
        }
    }

    #[test]
    fn test_doesnt_accept_wrong_proto() {
        #[cfg(feature = "proto-ipv4")]
        {
            let socket = RawSocket::new(IpVersion::Ipv4,
                IpProtocol::Unknown(ipv4_locals::IP_PROTO+1), buffer(1), buffer(1));
            assert!(!socket.accepts(&ipv4_locals::HEADER_REPR));
            #[cfg(feature = "proto-ipv6")]
            assert!(!socket.accepts(&ipv6_locals::HEADER_REPR));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let socket = RawSocket::new(IpVersion::Ipv6,
                IpProtocol::Unknown(ipv6_locals::IP_PROTO+1), buffer(1), buffer(1));
            assert!(!socket.accepts(&ipv6_locals::HEADER_REPR));
            #[cfg(feature = "proto-ipv4")]
            assert!(!socket.accepts(&ipv4_locals::HEADER_REPR));
        }
    }
}
