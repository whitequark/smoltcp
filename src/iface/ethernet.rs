// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP.

use managed::{Managed, ManagedSlice};

use {Error, Result};
use phy::{Device, DeviceCapabilities};
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{Ipv4Address};
use wire::{IpAddress, IpProtocol, IpRepr, IpCidr};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
#[cfg(feature = "socket-udp")] use wire::{UdpPacket, UdpRepr};
#[cfg(feature = "socket-tcp")] use wire::{TcpPacket, TcpRepr, TcpControl};
use socket::{Socket, SocketSet, AsSocket};
#[cfg(feature = "socket-raw")] use socket::RawSocket;
#[cfg(feature = "socket-udp")] use socket::UdpSocket;
#[cfg(feature = "socket-tcp")] use socket::TcpSocket;
use super::ArpCache;

/// An Ethernet network device. Wraps an [`EthernetInterface`](struct.EthernetInterface.html) and
/// a [`phy::Device`](../phy/trait.Device.html). It provides a `poll` method, which handles
/// complete socket I/O.
pub struct EthernetDevice<'a, 'b, 'c, DeviceT: Device + 'a> {
    device:         Managed<'a, DeviceT>,
    interface:      Interface<'b, 'c>,
}

/// A device independent Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'b, 'c> {
    arp_cache:      Managed<'b, ArpCache>,
    ethernet_addr:  EthernetAddress,
    ip_addrs:       ManagedSlice<'c, IpCidr>,
    ipv4_gateway:   Option<Ipv4Address>,
    device_capabilities: DeviceCapabilities,
}

/// An optional Ethernet network packet.
pub enum Packet<'a> {
    None,
    Arp(ArpRepr),
    Icmpv4(Ipv4Repr, Icmpv4Repr<'a>),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> Packet<'a> {
    /// Returns the buffer length required to store the packet. The
    /// [`write_into_buffer`](#method.write_into_buffer) method requires a buffer of at least
    /// this size.
    pub fn required_buffer_len(&self) -> usize {
        EthernetFrame::<&[u8]>::buffer_len(match self {
            &Packet::Arp(arp_repr) => arp_repr.buffer_len(),
            &Packet::Icmpv4(ipv4_repr, _) => IpRepr::Ipv4(ipv4_repr).total_len(),
            &Packet::Raw((ref ip_repr, _)) => ip_repr.total_len(),
            &Packet::Udp((ref ip_repr, _)) => ip_repr.total_len(),
            &Packet::Tcp((ref ip_repr, _)) => ip_repr.total_len(),
            &Packet::None => 0,
        })
    }
}

impl<'a, 'b, 'c, DeviceT: Device + 'a> EthernetDevice<'a, 'b, 'c, DeviceT> {
    /// Create an ethernet device using the provided ethernet interface and
    /// underlying network device.
    pub fn new<DeviceMT, I>(device: DeviceMT, mut interface: Interface<'b, 'c>) -> Self
            where DeviceMT: Into<Managed<'a, DeviceT>>
    {
        let device = device.into();
        interface.device_capabilities = device.capabilities();
        Self { device, interface }
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing
    /// since an arbitrary moment in time, such as system startup.
    ///
    /// This function returns a _soft deadline_ for calling it the next time.
    /// That is, if `iface.poll(&mut sockets, 1000)` returns `Ok(Some(2000))`,
    /// it harmless (but wastes energy) to call it 500 ms later, and potentially
    /// harmful (impacting quality of service) to call it 1500 ms later.
    ///
    /// # Errors
    /// This method will routinely return errors in response to normal network
    /// activity as well as certain boundary conditions such as buffer exhaustion.
    /// These errors are provided as an aid for troubleshooting, and are meant
    /// to be logged and ignored.

    /// As a special case, `Err(Error::Unrecognized)` is returned in response to
    /// packets containing any unsupported protocol, option, or form, which is
    /// a very common occurrence and on a production system it should not even
    /// be logged.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<Option<u64>> {
        self.socket_egress(sockets, timestamp)?;

        if self.socket_ingress(sockets, timestamp)? {
            Ok(Some(0))
        } else {
            Ok(sockets.iter().filter_map(|socket| socket.poll_at()).min())
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let frame =
                match self.device.receive(timestamp) {
                    Ok(frame) => frame,
                    Err(Error::Exhausted) => break, // nothing to receive
                    Err(err) => return Err(err)
                };

            let response =
                match self.interface.process_frame(sockets, timestamp, &frame) {
                    Ok(response) => response,
                    Err(err) => {
                        net_debug!("cannot process ingress packet: {}", err);
                        return Err(err)
                    }
                };
            processed_any = true;

            match self.dispatch(timestamp, response) {
                Ok(()) => (),
                Err(err) => {
                    net_debug!("cannot dispatch response packet: {}", err);
                    return Err(err)
                }
            }
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<()> {
        let mut caps = self.device.capabilities();
        caps.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len();

        for socket in sockets.iter_mut() {
            let mut device_result = Ok(());
            let socket_result =
                match socket {
                    #[cfg(feature = "socket-raw")]
                    &mut Socket::Raw(ref mut socket) =>
                        socket.dispatch(|response| {
                            device_result = self.dispatch(timestamp, Packet::Raw(response));
                            device_result
                        }, &caps.checksum),
                    #[cfg(feature = "socket-udp")]
                    &mut Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response| {
                            device_result = self.dispatch(timestamp, Packet::Udp(response));
                            device_result
                        }),
                    #[cfg(feature = "socket-tcp")]
                    &mut Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &caps, |response| {
                            device_result = self.dispatch(timestamp, Packet::Tcp(response));
                            device_result
                        }),
                    &mut Socket::__Nonexhaustive(_) => unreachable!()
                };
            match (device_result, socket_result) {
                (Err(Error::Unaddressable), _) => break, // no one to transmit to
                (Err(Error::Exhausted), _) => break,     // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (),   // nothing to transmit
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!("cannot dispatch egress packet: {}", err);
                    return Err(err)
                }
                (Ok(()), Ok(())) => ()
            }
        }

        Ok(())
    }

    fn dispatch(&mut self, timestamp: u64, packet: Packet) -> Result<()> {
        let tx_len = packet.required_buffer_len();
        let mut tx_buffer = self.device.transmit(timestamp, tx_len)?;
        debug_assert!(tx_buffer.as_ref().len() == tx_len);

        let result = self.interface.write_into_buffer(packet, tx_buffer.as_mut());
        match result {
            Err(Error::UnknownEthernetAddress(dst_ip)) => {
                let arp_packet = self.interface.arp_request_packet(&dst_ip);
                self.dispatch(timestamp, arp_packet)
            }
            other => other
        }
    }
}

impl<'b, 'c> Interface<'b, 'c> {
    /// Create an ethernet interface.
    ///
    /// # Panics
    /// See the restrictions on [set_hardware_addr](#method.set_hardware_addr)
    /// and [set_protocol_addrs](#method.set_protocol_addrs) functions.
    pub fn new<ArpCacheMT, ProtocolAddrsMT, Ipv4GatewayAddrT>
              (arp_cache: ArpCacheMT,
               ethernet_addr: EthernetAddress,
               ip_addrs: ProtocolAddrsMT,
               ipv4_gateway: Ipv4GatewayAddrT) ->
              Interface<'b, 'c>
            where ArpCacheMT: Into<Managed<'b, ArpCache>>,
                  ProtocolAddrsMT: Into<ManagedSlice<'c, IpCidr>>,
                  Ipv4GatewayAddrT: Into<Option<Ipv4Address>>, {
        let arp_cache = arp_cache.into();
        let ip_addrs = ip_addrs.into();
        let ipv4_gateway = ipv4_gateway.into();

        Self::check_ethernet_addr(&ethernet_addr);
        Self::check_ip_addrs(&ip_addrs);
        Interface {
            arp_cache, ethernet_addr, ip_addrs, ipv4_gateway,
            device_capabilities: Default::default()
        }
    }

    fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    /// Get the Ethernet address of the interface.
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.ethernet_addr
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        self.ethernet_addr = addr;
        Self::check_ethernet_addr(&self.ethernet_addr);
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.ip_addrs.as_ref()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'c, IpCidr>)>(&mut self, f: F) {
        f(&mut self.ip_addrs);
        Self::check_ip_addrs(&self.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the IPv4 gateway of the interface.
    pub fn ipv4_gateway(&self) -> Option<Ipv4Address> {
        self.ipv4_gateway
    }

    /// Set the IPv4 gateway of the interface.
    pub fn set_ipv4_gateway<GatewayAddrT>(&mut self, gateway: GatewayAddrT)
            where GatewayAddrT: Into<Option<Ipv4Address>> {
        self.ipv4_gateway = gateway.into();
    }

    /// Processes the passed ethernet frame.
    pub fn process_frame<'frame, T: AsRef<[u8]>>(&mut self, sockets: &mut SocketSet,
        timestamp: u64, frame: &'frame T)
        -> Result<Packet<'frame>>
    {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address.
        if !eth_frame.dst_addr().is_broadcast() &&
                eth_frame.dst_addr() != self.ethernet_addr {
            return Ok(Packet::None)
        }

        match eth_frame.ethertype() {
            EthernetProtocol::Arp =>
                self.process_arp(&eth_frame),
            EthernetProtocol::Ipv4 =>
                self.process_ipv4(sockets, timestamp, &eth_frame),
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    /// Processes an ethernet frame containing an ARP packet.
    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Packet<'frame>> {
        let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
        let arp_repr = ArpRepr::parse(&arp_packet)?;

        match arp_repr {
            // Respond to ARP requests aimed at us, and fill the ARP cache from all ARP
            // requests and replies, to minimize the chance that we have to perform
            // an explicit ARP request.
            ArpRepr::EthernetIpv4 {
                operation, source_hardware_addr, source_protocol_addr, target_protocol_addr, ..
            } => {
                if source_protocol_addr.is_unicast() && source_hardware_addr.is_unicast() {
                    self.arp_cache.fill(&source_protocol_addr.into(),
                                        &source_hardware_addr);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source in {}", arp_repr);
                    return Err(Error::Malformed)
                }

                if operation == ArpOperation::Request && self.has_ip_addr(target_protocol_addr) {
                    Ok(Packet::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.ethernet_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr
                    }))
                } else {
                    Ok(Packet::None)
                }
            }

            _ => Err(Error::Unrecognized)
        }
    }

    /// Processes an ethernet frame containing an IPv4 packet.
    fn process_ipv4<'frame, T: AsRef<[u8]>>
                   (&mut self, sockets: &mut SocketSet, _timestamp: u64,
                    eth_frame: &EthernetFrame<&'frame T>) ->
                   Result<Packet<'frame>> {
        let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
        let checksum_caps = self.device_capabilities.checksum;
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source in {}", ipv4_repr);
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the ARP cache from IP header of unicast frames.
            self.arp_cache.fill(&IpAddress::Ipv4(ipv4_repr.src_addr),
                                &eth_frame.src_addr());
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        #[cfg(feature = "socket-raw")]
        for raw_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<RawSocket>>::try_as_socket) {
            if !raw_socket.accepts(&ip_repr) { continue }

            match raw_socket.process(&ip_repr, ip_payload, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_raw_socket = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }

        if !self.has_ip_addr(ipv4_repr.dst_addr) {
            // Ignore IP packets not directed at us.
            return Ok(Packet::None)
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                self.process_icmpv4(ipv4_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ip_repr, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, _timestamp, ip_repr, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(Packet::None),

            _ => {
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..8]
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmp_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmp_reply_repr))
            }
        }
    }

    /// Processes an IPv4 payload containing an ICMPv4 packet.
    fn process_icmpv4<'frame>(&self, ipv4_repr: Ipv4Repr, ip_payload: &'frame [u8]) ->
                             Result<Packet<'frame>> {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum;
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &checksum_caps)?;

        match icmp_repr {
            // Respond to echo requests.
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident:  ident,
                    seq_no: seq_no,
                    data:   data
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmp_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmp_reply_repr))
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(Packet::None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "socket-udp")]
    /// Processes an IPv4 payload containing an UDP packet.
    fn process_udp<'frame>(&self, sockets: &mut SocketSet,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum;
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for udp_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<UdpSocket>>::try_as_socket) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) { continue }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(Packet::None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => {
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..8]
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmpv4_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmpv4_reply_repr))
            },
            IpRepr::Unspecified { .. } |
            IpRepr::__Nonexhaustive =>
                unreachable!()
        }
    }

    #[cfg(feature = "socket-tcp")]
    /// Processes an IPv4 payload containing a TCP packet.
    fn process_tcp<'frame>(&self, sockets: &mut SocketSet, timestamp: u64,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum;
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for tcp_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<TcpSocket>>::try_as_socket) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) { continue }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map_or(Packet::None, Packet::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(Packet::None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Packet::Tcp(TcpSocket::rst_reply(&ip_repr, &tcp_repr)))
        }
    }

    /// Writes the packet into the buffer, which must have at least size
    /// [`packet.required_buffer_len`](enum.EthernetPacket.html#method.required_buffer_len).
    pub fn write_into_buffer(&mut self, packet: Packet, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < packet.required_buffer_len() {
            return Err(Error::Truncated);
        }
        let checksum_caps = self.device_capabilities.checksum;
        match packet {
            Packet::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    };

                self.write_ethernet(buffer, |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            Packet::Icmpv4(ipv4_repr, icmpv4_repr) => {
                self.write_ip(buffer, IpRepr::Ipv4(ipv4_repr), |_ip_repr, payload| {
                    icmpv4_repr.emit(&mut Icmpv4Packet::new(payload), &checksum_caps);
                })
            }
            #[cfg(feature = "socket-raw")]
            Packet::Raw((ip_repr, raw_packet)) => {
                self.write_ip(buffer, ip_repr, |_ip_repr, payload| {
                    payload.copy_from_slice(raw_packet);
                })
            }
            #[cfg(feature = "socket-udp")]
            Packet::Udp((ip_repr, udp_repr)) => {
                self.write_ip(buffer, ip_repr, |ip_repr, payload| {
                    udp_repr.emit(&mut UdpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            #[cfg(feature = "socket-tcp")]
            Packet::Tcp((ip_repr, mut tcp_repr)) => {
                let caps = self.device_capabilities.clone();
                self.write_ip(buffer, ip_repr, |ip_repr, payload| {
                    // This is a terrible hack to make TCP performance more acceptable on systems
                    // where the TCP buffers are significantly larger than network buffers,
                    // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                    // together with four 1500 B Ethernet receive buffers. If left untreated,
                    // this would result in our peer pushing our window and sever packet loss.
                    //
                    // I'm really not happy about this "solution" but I don't know what else to do.
                    if let Some(max_burst_size) = caps.max_burst_size {
                        let mut max_segment_size = caps.max_transmission_unit;
                        max_segment_size -= EthernetFrame::<&[u8]>::header_len();
                        max_segment_size -= ip_repr.buffer_len();
                        max_segment_size -= tcp_repr.header_len();

                        let max_window_size = max_burst_size * max_segment_size;
                        if tcp_repr.window_len as usize > max_window_size {
                            tcp_repr.window_len = max_window_size as u16;
                        }
                    }

                    tcp_repr.emit(&mut TcpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            Packet::None => Ok(())
        }
    }

    fn write_ethernet<F>(&self, buffer: &mut [u8], f: F) -> Result<()>
            where F: FnOnce(EthernetFrame<&mut [u8]>) {

        let mut frame = EthernetFrame::new(buffer);
        frame.set_src_addr(self.ethernet_addr);

        f(frame);

        Ok(())
    }

    fn route(&self, addr: &IpAddress) -> Result<IpAddress> {
        self.ip_addrs
            .iter()
            .find(|cidr| cidr.contains_addr(&addr))
            .map(|_cidr| Ok(addr.clone())) // route directly
            .unwrap_or_else(|| {
                match (addr, self.ipv4_gateway) {
                    // route via a gateway
                    (&IpAddress::Ipv4(_), Some(gateway)) =>
                        Ok(gateway.into()),
                    // unroutable
                    _ => Err(Error::Unaddressable)
                }
            })
    }

    fn lookup_hardware_addr(&mut self, dst_addr: &IpAddress) ->
                           Result<EthernetAddress> {
        let dst_addr = self.route(dst_addr)?;

        if let Some(hardware_addr) = self.arp_cache.lookup(&dst_addr) {
            return Ok(hardware_addr)
        }

        if dst_addr.is_broadcast() {
            return Ok(EthernetAddress::BROADCAST)
        }

        net_debug!("address {} not in ARP cache", dst_addr);
        Err(Error::UnknownEthernetAddress(dst_addr))
    }

    fn arp_request_packet(&self, dst_addr: &IpAddress) -> Packet<'static> {
        let src = match self.ip_addrs.first() {
            Some(addr) => addr,
            // if we have no IP, we can't get an ARP response, so we don't send
            // a request
            None => return Packet::None,
        };
        match (src, dst_addr) {
            (&IpCidr::Ipv4(src), &IpAddress::Ipv4(dst_addr)) => {
                net_debug!("address {} not in ARP cache, sending request",
                           dst_addr);

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.ethernet_addr,
                    source_protocol_addr: src.address(),
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };
                Packet::Arp(arp_repr)
            }
            _ => unreachable!()
        }
    }

    fn write_ip<F>(&mut self, buffer: &mut [u8], ip_repr: IpRepr, f: F) -> Result<()>
            where F: FnOnce(IpRepr, &mut [u8]) {
        let ip_repr = ip_repr.lower(&self.ip_addrs)?;
        let checksum_caps = self.device_capabilities.checksum;

        let dst_hardware_addr = self.lookup_hardware_addr(&ip_repr.dst_addr())?;

        self.write_ethernet(buffer, |mut frame| {
            frame.set_dst_addr(dst_hardware_addr);
            match ip_repr {
                IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                _ => unreachable!()
            }

            ip_repr.emit(frame.payload_mut(), &checksum_caps);

            let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
            f(ip_repr, payload)
        })
    }
}
