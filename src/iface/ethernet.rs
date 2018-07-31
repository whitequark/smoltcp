// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

use core::cmp;
use managed::{ManagedSlice, ManagedMap};

use {Error, Result};
use phy::{Device, DeviceCapabilities, RxToken, TxToken};
use time::{Duration, Instant};
use wire::pretty_print::PrettyPrinter;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{IpAddress, IpProtocol, IpRepr, IpCidr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Address, Ipv6Packet, Ipv6Repr, IPV6_MIN_MTU};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Packet, Ipv4Repr, IPV4_MIN_MTU};
#[cfg(feature = "proto-ipv4")]
use wire::{ArpPacket, ArpRepr, ArpOperation};
#[cfg(feature = "proto-ipv4")]
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
#[cfg(feature = "proto-ipv6")]
use wire::{Icmpv6Packet, Icmpv6Repr, Icmpv6ParamProblem};
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use wire::IcmpRepr;
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6HopByHopHeader, Ipv6HopByHopRepr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6OptionRepr, Ipv6OptionFailureType};
#[cfg(feature = "proto-ipv6")]
use wire::{NdiscNeighborFlags, NdiscRepr};
#[cfg(all(feature = "proto-ipv6", feature = "socket-udp"))]
use wire::Icmpv6DstUnreachable;
#[cfg(feature = "socket-udp")]
use wire::{UdpPacket, UdpRepr};
#[cfg(feature = "socket-tcp")]
use wire::{TcpPacket, TcpRepr, TcpControl};

use socket::{Socket, SocketSet, AnySocket, PollAt};
#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use socket::IcmpSocket;
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use socket::TcpSocket;
#[cfg(feature = "fragmentation-ipv4")]
use super::{FragmentKey,FragmentedPacket};
use super::{NeighborCache, NeighborAnswer};
use super::Routes;
use super::FragmentSet;

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'b, 'c, 'e, 'f, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    inner:  InterfaceInner<'b, 'c, 'e, 'f>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for prorcessing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
struct InterfaceInner<'b, 'c, 'e, 'f> {
    neighbor_cache:         NeighborCache<'b>,
    ethernet_addr:          EthernetAddress,
    ip_addrs:               ManagedSlice<'c, IpCidr>,
    routes:                 Routes<'e>,
    device_capabilities:    DeviceCapabilities,
    fragments:              Option<FragmentSet<'f>>,
}

/// A builder structure used for creating a Ethernet network
/// interface.
pub struct InterfaceBuilder <'b, 'c, 'e, 'f, DeviceT: for<'d> Device<'d>> {
    device:              DeviceT,
    ethernet_addr:       Option<EthernetAddress>,
    neighbor_cache:      Option<NeighborCache<'b>>,
    ip_addrs:            ManagedSlice<'c, IpCidr>,
    routes:              Routes<'e>,
    fragments:           Option<FragmentSet<'f>>,
}

impl<'b, 'c, 'e, 'f, DeviceT> InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache};
    /// # use smoltcp::phy::Loopback;
    /// use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};
    ///
    /// let device = // ...
    /// # Loopback::new();
    /// let hw_addr = // ...
    /// # EthernetAddress::default();
    /// let neighbor_cache = // ...
    /// # NeighborCache::new(BTreeMap::new());
    /// let ip_addrs = // ...
    /// # [];
    /// let iface = EthernetInterfaceBuilder::new(device)
    ///         .ethernet_addr(hw_addr)
    ///         .neighbor_cache(neighbor_cache)
    ///         .ip_addrs(ip_addrs)
    ///         .finalize();
    /// ```
    pub fn new(device: DeviceT) -> InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT> {
        InterfaceBuilder {
            device:              device,
            ethernet_addr:       None,
            neighbor_cache:      None,
            ip_addrs:            ManagedSlice::Borrowed(&mut []),
            routes:              Routes::new(ManagedMap::Borrowed(&mut [])),
            fragments:           None,
        }
    }

    /// Set the Ethernet address the interface will use. See also
    /// [ethernet_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [ethernet_addr]: struct.EthernetInterface.html#method.ethernet_addr
    pub fn ethernet_addr(mut self, addr: EthernetAddress) -> InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT> {
        InterfaceInner::check_ethernet_addr(&addr);
        self.ethernet_addr = Some(addr);
        self
    }

    /// Set the IP addresses the interface will use. See also
    /// [ip_addrs].
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    ///
    /// [ip_addrs]: struct.EthernetInterface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT>
        where T: Into<ManagedSlice<'c, IpCidr>>
    {
        let ip_addrs = ip_addrs.into();
        InterfaceInner::check_ip_addrs(&ip_addrs);
        self.ip_addrs = ip_addrs;
        self
    }

    /// Set the IP routes the interface will use. See also
    /// [routes].
    ///
    /// [routes]: struct.EthernetInterface.html#method.routes
    pub fn routes<T>(mut self, routes: T) -> InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT>
        where T: Into<Routes<'e>>
    {
        self.routes = routes.into();
        self
    }

    /// Set the Neighbor Cache the interface will use.
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'b>) ->
                         InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT> {
        self.neighbor_cache = Some(neighbor_cache);
        self
    }

    /// Set the fragment set
    #[cfg(feature = "fragmentation-ipv4")]
    pub fn fragments_set(mut self, fragments: FragmentSet<'f>) ->
                        InterfaceBuilder<'b, 'c, 'e, 'f, DeviceT> {
        self.fragments = Some(fragments);
        self
    }


    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// If a required option is not provided, this function will panic. Required
    /// options are:
    ///
    /// - [ethernet_addr]
    /// - [neighbor_cache]
    ///
    /// [ethernet_addr]: #method.ethernet_addr
    /// [neighbor_cache]: #method.neighbor_cache
    pub fn finalize(self) -> Interface<'b, 'c, 'e, 'f, DeviceT> {
        match (self.ethernet_addr, self.neighbor_cache) {
            (Some(ethernet_addr), Some(neighbor_cache)) => {
                let device_capabilities = self.device.capabilities();
                Interface {
                    device: self.device,
                    inner: InterfaceInner {
                        ethernet_addr, device_capabilities, neighbor_cache,
                        ip_addrs: self.ip_addrs,
                        routes: self.routes,
                        fragments: self.fragments,
                    }
                }
            },
            _ => panic!("a required option was not set"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Packet<'a> {
    None,
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    #[cfg(feature = "proto-ipv4")]
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6((Ipv6Repr, Icmpv6Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> Packet<'a> {
    fn neighbor_addr(&self) -> Option<IpAddress> {
        match self {
            &Packet::None => None,
            #[cfg(feature = "proto-ipv4")]
            &Packet::Arp(_) => None,
            #[cfg(feature = "proto-ipv4")]
            &Packet::Icmpv4((ref ipv4_repr, _)) => Some(ipv4_repr.dst_addr.into()),
            #[cfg(feature = "proto-ipv6")]
            &Packet::Icmpv6((ref ipv6_repr, _)) => Some(ipv6_repr.dst_addr.into()),
            #[cfg(feature = "socket-raw")]
            &Packet::Raw((ref ip_repr, _)) => Some(ip_repr.dst_addr()),
            #[cfg(feature = "socket-udp")]
            &Packet::Udp((ref ip_repr, _)) => Some(ip_repr.dst_addr()),
            #[cfg(feature = "socket-tcp")]
            &Packet::Tcp((ref ip_repr, _)) => Some(ip_repr.dst_addr())
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minumum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    cmp::min(len, mtu - header_len * 2 - 8)
}

impl<'b, 'c, 'e, 'f, DeviceT> Interface<'b, 'c, 'e, 'f, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Get the Ethernet address of the interface.
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.inner.ethernet_addr
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        self.inner.ethernet_addr = addr;
        InterfaceInner::check_ethernet_addr(&self.inner.ethernet_addr);
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'c, IpCidr>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes<'e> {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes<'e> {
        &mut self.inner.routes
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    ///
    /// # Errors
    /// This method will routinely return errors in response to normal network
    /// activity as well as certain boundary conditions such as buffer exhaustion.
    /// These errors are provided as an aid for troubleshooting, and are meant
    /// to be logged and ignored.
    ///
    /// As a special case, `Err(Error::Unrecognized)` is returned in response to
    /// packets containing any unsupported protocol, option, or form, which is
    /// a very common occurrence and on a production system it should not even
    /// be logged.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut readiness_may_have_changed = false;
        loop {
            let processed_any = self.socket_ingress(sockets, timestamp)?;
            let emitted_any   = self.socket_egress(sockets, timestamp)?;
            if processed_any || emitted_any {
                readiness_may_have_changed = true;
            } else {
                break
            }
        }
        Ok(readiness_may_have_changed)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Instant> {
        sockets.iter().filter_map(|socket| {
            let socket_poll_at = socket.poll_at();
            match socket.meta().poll_at(socket_poll_at, |ip_addr|
                self.inner.has_neighbor(&ip_addr, timestamp)) {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
            }
        }).min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Duration> {
        match self.poll_at(sockets, timestamp) {
            Some(poll_at) if timestamp < poll_at => {
                Some(poll_at - timestamp)
            }
            Some(_) => {
                Some(Duration::from_millis(0))
            }
            _ => None
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let &mut Self { ref mut device, ref mut inner } = self;
            let (rx_token, tx_token) = match device.receive() {
                None => break,
                Some(tokens) => tokens,
            };
            rx_token.consume(timestamp, |frame| {
                let mut fragments = ::core::mem::replace(&mut inner.fragments, None);
                // this corresponds to `let mut fragments = inner.fragments; && inner.fragments = None;`
                let r = inner.process_ethernet(sockets, timestamp, &frame, &mut fragments).map_err(|err| {
                    net_debug!("cannot process ingress packet: {}", err);
                    net_debug!("packet dump follows:\n{}",
                               PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame));
                    err
                }).and_then(|response| {
                    processed_any = true;
                    inner.dispatch(tx_token, timestamp, response).map_err(|err| {
                        net_debug!("cannot dispatch response packet: {}", err);
                        err
                    })
                });
                // Restore inner.fragments
                inner.fragments = fragments;
                r
            })?;
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut caps = self.device.capabilities();
        caps.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len();

        let mut emitted_any = false;
        for mut socket in sockets.iter_mut() {
            if !socket.meta_mut().egress_permitted(|ip_addr|
                    self.inner.has_neighbor(&ip_addr, timestamp)) {
                continue
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());
            let &mut Self { ref mut device, ref mut inner } = self;

            macro_rules! respond {
                ($response:expr) => ({
                    let response = $response;
                    neighbor_addr = response.neighbor_addr();
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    device_result = inner.dispatch(tx_token, timestamp, response);
                    device_result
                })
            }

            let socket_result =
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(ref mut socket) =>
                        socket.dispatch(&caps.checksum, |response|
                            respond!(Packet::Raw(response))),
                    #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
                    Socket::Icmp(ref mut socket) =>
                        socket.dispatch(&caps, |response| {
                            match response {
                                #[cfg(feature = "proto-ipv4")]
                                (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) =>
                                    respond!(Packet::Icmpv4((ipv4_repr, icmpv4_repr))),
                                #[cfg(feature = "proto-ipv6")]
                                (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) =>
                                    respond!(Packet::Icmpv6((ipv6_repr, icmpv6_repr))),
                                _ => Err(Error::Unaddressable)
                            }
                        }),
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response|
                            respond!(Packet::Udp(response))),
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &caps, |response|
                            respond!(Packet::Tcp(response))),
                    Socket::__Nonexhaustive(_) => unreachable!()
                };

            match (device_result, socket_result) {
                (Err(Error::Exhausted), _) => break,     // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (),   // nothing to transmit
                (Err(Error::Unaddressable), _) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighboor.
                    socket.meta_mut().neighbor_missing(timestamp,
                        neighbor_addr.expect("non-IP response packet"));
                    break
                }
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!("{}: cannot dispatch egress packet: {}",
                               socket.meta().handle, err);
                    return Err(err)
                }
                (Ok(()), Ok(())) => emitted_any = true
            }
        }
        Ok(emitted_any)
    }
}

impl<'b, 'c, 'e, 'f> InterfaceInner<'b, 'c, 'e, 'f> {
    fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "proto-ipv6")]
    pub fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().find(|cidr| {
            match *cidr {
                &IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK=> {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        }).is_some()
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    fn process_ethernet<'frame, 'r : 'frame, T: AsRef<[u8]>>
                       (&mut self, sockets: &mut SocketSet, timestamp: Instant, frame: &'frame T,
                       _fragments: &'r mut Option<FragmentSet<'f>>) ->
                       Result<Packet<'frame>>
    {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address.
        if !eth_frame.dst_addr().is_broadcast() &&
           !eth_frame.dst_addr().is_multicast() &&
                eth_frame.dst_addr() != self.ethernet_addr {
            return Ok(Packet::None)
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp =>
                self.process_arp(timestamp, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 =>
                self.process_ipv4(sockets, timestamp, &eth_frame, _fragments),
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 =>
                self.process_ipv6(sockets, timestamp, &eth_frame),
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, timestamp: Instant, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Packet<'frame>>
    {
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
                    self.neighbor_cache.fill(source_protocol_addr.into(),
                                             source_hardware_addr,
                                             timestamp);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
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

    #[cfg(all(any(feature = "proto-ipv4", feature = "proto-ipv6"), feature = "socket-raw"))]
    fn raw_socket_filter<'frame>(&mut self, sockets: &mut SocketSet, ip_repr: &IpRepr,
                                 ip_payload: &'frame [u8]) -> bool {
        let checksum_caps = self.device_capabilities.checksum.clone();
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for mut raw_socket in sockets.iter_mut().filter_map(RawSocket::downcast) {
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
        handled_by_raw_socket
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ipv6<'frame, T: AsRef<[u8]>>
                   (&mut self, sockets: &mut SocketSet, timestamp: Instant,
                    eth_frame: &EthernetFrame<&'frame T>) ->
                   Result<Packet<'frame>>
    {
        let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the neighbor cache from IP header of unicast frames.
            let ip_addr = IpAddress::Ipv6(ipv6_repr.src_addr);
            if self.in_same_network(&ip_addr) &&
                    self.neighbor_cache.lookup_pure(&ip_addr, timestamp).is_none() {
                self.neighbor_cache.fill(ip_addr, eth_frame.src_addr(), timestamp);
            }
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(sockets, timestamp, ipv6_repr, ipv6_repr.next_header,
                             handled_by_raw_socket, ip_payload)
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    #[cfg(feature = "proto-ipv6")]
    fn process_nxt_hdr<'frame>
                   (&mut self, sockets: &mut SocketSet, timestamp: Instant, ipv6_repr: Ipv6Repr,
                    nxt_hdr: IpProtocol, handled_by_raw_socket: bool, ip_payload: &'frame [u8])
                   -> Result<Packet<'frame>>
    {
        match nxt_hdr {
            IpProtocol::Icmpv6 =>
                self.process_icmpv6(sockets, timestamp, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop =>
                self.process_hopbyhop(sockets, timestamp, ipv6_repr, handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(Packet::None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU,
                                                         ipv6_repr.buffer_len());
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
            },
        }
    }

    /// Process an IPv4 fragment
    /// Returns etiher an assembled packet, or nothing (if no packet is available),
    /// or an error caused by processing a packet.
    #[cfg(feature = "fragmentation-ipv4")]
    fn process_ipv4_fragment<'frame, 'r>
            (&mut self, ipv4_packet: Ipv4Packet<&'frame [u8]>, timestamp: Instant,
             fragments: &'r mut Option<FragmentSet<'f>>) -> Result<Option<Ipv4Packet<&'r [u8]>>>
    {
        match *fragments {
            Some(ref mut fragments) => {
                let key = FragmentKey::new(ipv4_packet.ident(),
                                           ipv4_packet.src_addr(),
                                           ipv4_packet.dst_addr());
                // get an existing fragment or attempt to get a new one
                if !fragments.contains_key(&key) {
                    // attempt to insert an empty fragment
                    let fragment = FragmentedPacket::new(vec![0; 65535]);
                    fragments.insert(key.clone(), fragment);
                }

                let fragment = match fragments.get_packet(key, timestamp) {
                    Some(frag) => frag,
                    None => return Err(Error::FragmentSetFull),
                };

                if fragment.is_empty() {
                    // this is a new packet
                    fragment.start(ipv4_packet.ident(),
                                   ipv4_packet.src_addr(),
                                   ipv4_packet.dst_addr());
                }

                if !ipv4_packet.more_frags() {
                    // last fragment, remember data length
                    fragment.set_total_len(ipv4_packet.frag_offset() as usize +
                                           ipv4_packet.total_len() as usize);
                }

                match fragment.add(ipv4_packet.header_len() as usize,
                             ipv4_packet.frag_offset() as usize,
                             ipv4_packet.payload().len(),
                             ipv4_packet.into_inner(),
                             timestamp) {
                    Ok(_) => {},
                    Err(_) => {
                        fragment.reset();
                        return Err(Error::TooManyFragments);
                    }
                }

                if fragment.check_contig_range() {
                    // this is the last packet, attempt reassembly
                    let front = fragment.front().unwrap();
                    {
                        // because the different mutability of the underlying buffers, we have to do this exercise
                        let mut ipv4_packet = Ipv4Packet::new_checked(fragment.get_buffer_mut(0,front))?;
                        ipv4_packet.set_total_len(front as u16);
                        ipv4_packet.fill_checksum();
                    }
                    // TODO: handle removing elements, this way the map just grows indefinitely...
                    return Ok(Some(Ipv4Packet::new_checked(fragment.get_buffer_and_reset(0,front))?));
                }

                // not the last fragment
                return Ok(None);
            },
            None => {
                return Err(Error::NoFragmentSet);
            }
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4<'frame, 'r : 'frame, T: AsRef<[u8]>>
                   (&mut self, sockets: &mut SocketSet, timestamp: Instant,
                    eth_frame: &EthernetFrame<&'frame T>,
                    _fragments: &'r mut Option<FragmentSet<'f>>) ->
                   Result<Packet<'frame>>
    {
        let ipv4_packet_in = Ipv4Packet::new_checked(eth_frame.payload())?;
        let checksum_caps = self.device_capabilities.checksum.clone();

        let ipv4_packet;
        if ipv4_packet_in.more_frags() || ipv4_packet_in.frag_offset() > 0{
            #[cfg(feature = "fragmentation-ipv4")]
            match self.process_ipv4_fragment(ipv4_packet_in, timestamp, _fragments)? {
                Some(assembled_packet) => {
                    ipv4_packet = assembled_packet;
                },
                None => return Ok(Packet::None),
            }
            #[cfg(not(feature = "fragmentation-ipv4"))]
            return Err(Error::Fragmented)
        } else {
            // non-fragmented packet
            ipv4_packet = ipv4_packet_in;
        }

        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the neighbor cache from IP header of unicast frames.
            let ip_addr = IpAddress::Ipv4(ipv4_repr.src_addr);
            if self.in_same_network(&ip_addr) {
                self.neighbor_cache.fill(ip_addr, eth_frame.src_addr(), timestamp);
            }
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);

        if !ipv4_repr.dst_addr.is_broadcast() &&
           !ipv4_repr.dst_addr.is_multicast() &&
           !self.has_ip_addr(ipv4_repr.dst_addr) {
            // Ignore IP packets not directed at us.
            return Ok(Packet::None)
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ip_repr, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ip_repr, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(Packet::None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU,
                                                         ipv4_repr.buffer_len());
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr))
            }
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_icmpv6<'frame>(&mut self, _sockets: &mut SocketSet, timestamp: Instant,
                              ip_repr: IpRepr, ip_payload: &'frame [u8]) -> Result<Packet<'frame>>
    {
        let icmp_packet = Icmpv6Packet::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let icmp_repr = Icmpv6Repr::parse(&ip_repr.src_addr(), &ip_repr.dst_addr(),
                                          &icmp_packet, &checksum_caps)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv6"))]
        for mut icmp_socket in _sockets.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr.into(), &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr.into(), &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_icmp_socket = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // ICMP sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            Icmpv6Repr::EchoRequest { ident, seq_no, data } => {
                match ip_repr {
                    IpRepr::Ipv6(ipv6_repr) => {
                        let icmp_reply_repr = Icmpv6Repr::EchoReply {
                            ident:  ident,
                            seq_no: seq_no,
                            data:   data
                        };
                        Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
                    },
                    _ => Err(Error::Unrecognized),
                }
            }

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => Ok(Packet::None),

            // Forward any NDISC packets to the ndisc packet handler
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => self.process_ndisc(timestamp, ipv6_repr, repr),
                _ => Ok(Packet::None)
            },

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(Packet::None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ndisc<'frame>(&mut self, timestamp: Instant, ip_repr: Ipv6Repr,
                             repr: NdiscRepr<'frame>) -> Result<Packet<'frame>> {
        let packet = match repr {
            NdiscRepr::NeighborAdvert { lladdr, target_addr, flags } => {
                let ip_addr = ip_repr.src_addr.into();
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        if flags.contains(NdiscNeighborFlags::OVERRIDE) {
                            self.neighbor_cache.fill(ip_addr, lladdr, timestamp)
                        } else {
                            if self.neighbor_cache.lookup_pure(&ip_addr, timestamp).is_none() {
                                    self.neighbor_cache.fill(ip_addr, lladdr, timestamp)
                            }
                        }
                    },
                    _ => (),
                }
                Ok(Packet::None)
            }
            NdiscRepr::NeighborSolicit { target_addr, lladdr, .. } => {
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        self.neighbor_cache.fill(ip_repr.src_addr.into(), lladdr, timestamp)
                    },
                    _ => (),
                }
                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: target_addr,
                        lladdr: Some(self.ethernet_addr)
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len()
                    };
                    Ok(Packet::Icmpv6((ip_repr, advert)))
                } else {
                    Ok(Packet::None)
                }
            }
            _ => Ok(Packet::None)
        };
        packet
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_hopbyhop<'frame>(&mut self, sockets: &mut SocketSet, timestamp: Instant,
                                ipv6_repr: Ipv6Repr, handled_by_raw_socket: bool,
                                ip_payload: &'frame [u8]) -> Result<Packet<'frame>>
    {
        let hbh_pkt = Ipv6HopByHopHeader::new_checked(ip_payload)?;
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_pkt)?;
        for result in hbh_repr.options() {
            let opt_repr = result?;
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return Ok(Packet::None);
                        },
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return Err(Error::Unrecognized);
                        }
                    }
                }
                _ => return Err(Error::Unrecognized),
            }
        }
        self.process_nxt_hdr(sockets, timestamp, ipv6_repr, hbh_repr.next_header,
                             handled_by_raw_socket, &ip_payload[hbh_repr.buffer_len()..])
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_icmpv4<'frame>(&self, _sockets: &mut SocketSet, ip_repr: IpRepr,
                              ip_payload: &'frame [u8]) -> Result<Packet<'frame>>
    {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &checksum_caps)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
        for mut icmp_socket in _sockets.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr.into(), &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr.into(), &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_icmp_socket = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // ICMP sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            #[cfg(feature = "proto-ipv4")]
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident:  ident,
                    seq_no: seq_no,
                    data:   data
                };
                match ip_repr {
                    IpRepr::Ipv4(ipv4_repr) => Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr)),
                    _ => Err(Error::Unrecognized),
                }
            },

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(Packet::None),

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(Packet::None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn icmpv4_reply<'frame, 'icmp: 'frame>
                   (&self, ipv4_repr: Ipv4Repr, icmp_repr: Icmpv4Repr<'icmp>) ->
                   Packet<'frame>
    {
        if ipv4_repr.dst_addr.is_unicast() {
            let ipv4_reply_repr = Ipv4Repr {
                src_addr:    ipv4_repr.dst_addr,
                dst_addr:    ipv4_repr.src_addr,
                protocol:    IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Packet::Icmpv4((ipv4_reply_repr, icmp_repr))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            Packet::None
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn icmpv6_reply<'frame, 'icmp: 'frame>
                   (&self, ipv6_repr: Ipv6Repr, icmp_repr: Icmpv6Repr<'icmp>) ->
                   Packet<'frame>
    {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr:    ipv6_repr.dst_addr,
                dst_addr:    ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Packet::Icmpv6((ipv6_reply_repr, icmp_repr))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            Packet::None
        }
    }

    #[cfg(feature = "socket-udp")]
    fn process_udp<'frame>(&self, sockets: &mut SocketSet,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
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
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU,
                                                         ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr))
            },
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => {
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU,
                                                         ipv6_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
            },
            IpRepr::Unspecified { .. } |
            IpRepr::__Nonexhaustive => Err(Error::Unaddressable),
        }
    }

    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(&self, sockets: &mut SocketSet, timestamp: Instant,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut tcp_socket in sockets.iter_mut().filter_map(TcpSocket::downcast) {
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

    fn dispatch<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                    packet: Packet) -> Result<()>
        where Tx: TxToken
    {
        let checksum_caps = self.device_capabilities.checksum.clone();
        match packet {
            #[cfg(feature = "proto-ipv4")]
            Packet::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            #[cfg(feature = "proto-ipv4")]
            Packet::Icmpv4((ipv4_repr, icmpv4_repr)) => {
                self.dispatch_ip(tx_token, timestamp, IpRepr::Ipv4(ipv4_repr),
                                 |_ip_repr, payload| {
                    icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &checksum_caps);
                })
            }
            #[cfg(feature = "proto-ipv6")]
            Packet::Icmpv6((ipv6_repr, icmpv6_repr)) => {
                self.dispatch_ip(tx_token, timestamp, IpRepr::Ipv6(ipv6_repr),
                                 |ip_repr, payload| {
                    icmpv6_repr.emit(&ip_repr.src_addr(), &ip_repr.dst_addr(),
                                     &mut Icmpv6Packet::new_unchecked(payload), &checksum_caps);
                })
            }
            #[cfg(feature = "socket-raw")]
            Packet::Raw((ip_repr, raw_packet)) => {
                self.dispatch_ip(tx_token, timestamp, ip_repr, |_ip_repr, payload| {
                    payload.copy_from_slice(raw_packet);
                })
            }
            #[cfg(feature = "socket-udp")]
            Packet::Udp((ip_repr, udp_repr)) => {
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    udp_repr.emit(&mut UdpPacket::new_unchecked(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            #[cfg(feature = "socket-tcp")]
            Packet::Tcp((ip_repr, mut tcp_repr)) => {
                let caps = self.device_capabilities.clone();
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
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

                    tcp_repr.emit(&mut TcpPacket::new_unchecked(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            Packet::None => Ok(())
        }
    }

    fn dispatch_ethernet<Tx, F>(&mut self, tx_token: Tx, timestamp: Instant,
                                buffer_len: usize, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(EthernetFrame<&mut [u8]>)
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(timestamp, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer.as_mut());
            frame.set_src_addr(self.ethernet_addr);

            f(frame);

            Ok(())
        })
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs
            .iter()
            .find(|cidr| cidr.contains_addr(addr))
            .is_some()
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Ok(addr.clone())
        }

        // Route via a router.
        match self.routes.lookup(addr, timestamp) {
            Some(router_addr) => Ok(router_addr),
            None => Err(Error::Unaddressable),
        }
    }

    fn has_neighbor<'a>(&self, addr: &'a IpAddress, timestamp: Instant) -> bool {
        match self.route(addr, timestamp) {
            Ok(routed_addr) => {
                self.neighbor_cache
                    .lookup_pure(&routed_addr, timestamp)
                    .is_some()
            }
            Err(_) => false
        }
    }

    fn lookup_hardware_addr<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                                src_addr: &IpAddress, dst_addr: &IpAddress) ->
                               Result<(EthernetAddress, Tx)>
        where Tx: TxToken
    {
        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr =
                match dst_addr {
                    &IpAddress::Unspecified =>
                        None,
                    #[cfg(feature = "proto-ipv4")]
                    &IpAddress::Ipv4(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x01, 0x00,
                            0x5e, b[1] & 0x7F,
                            b[2], b[3],
                        ])),
                    #[cfg(feature = "proto-ipv6")]
                    &IpAddress::Ipv6(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x33, 0x33,
                            b[12], b[13],
                            b[14], b[15],
                        ])),
                    &IpAddress::__Nonexhaustive =>
                        unreachable!()
                };
            match hardware_addr {
                Some(hardware_addr) =>
                    // Destination is multicast
                    return Ok((hardware_addr, tx_token)),
                None =>
                    // Continue
                    (),
            }
        }

        let dst_addr = self.route(dst_addr, timestamp)?;

        match self.neighbor_cache.lookup(&dst_addr, timestamp) {
            NeighborAnswer::Found(hardware_addr) =>
                return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited =>
                return Err(Error::Unaddressable),
            NeighborAnswer::NotFound => (),
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending ARP request",
                           dst_addr);

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.ethernet_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;

                Err(Error::Unaddressable)
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending Neighbor Solicitation",
                           dst_addr);

                let checksum_caps = self.device_capabilities.checksum.clone();

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: src_addr,
                    lladdr: Some(self.ethernet_addr),
                });

                let ip_repr = IpRepr::Ipv6(Ipv6Repr {
                    src_addr: src_addr,
                    dst_addr: dst_addr.solicited_node(),
                    next_header: IpProtocol::Icmpv6,
                    payload_len: solicit.buffer_len(),
                    hop_limit: 0xff
                });

                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    solicit.emit(&ip_repr.src_addr(), &ip_repr.dst_addr(),
                                 &mut Icmpv6Packet::new_unchecked(payload), &checksum_caps);
                })?;

                Err(Error::Unaddressable)
            }

            _ => Err(Error::Unaddressable)
        }
    }

    fn dispatch_ip<Tx, F>(&mut self, tx_token: Tx, timestamp: Instant,
                          ip_repr: IpRepr, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(IpRepr, &mut [u8])
    {
        let ip_repr = ip_repr.lower(&self.ip_addrs)?;
        let checksum_caps = self.device_capabilities.checksum.clone();

        let (dst_hardware_addr, tx_token) =
            self.lookup_hardware_addr(tx_token, timestamp,
                                      &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        self.dispatch_ethernet(tx_token, timestamp, ip_repr.total_len(), |mut frame| {
            frame.set_dst_addr(dst_hardware_addr);
            match ip_repr {
                #[cfg(feature = "proto-ipv4")]
                IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpRepr::Ipv6(_) => frame.set_ethertype(EthernetProtocol::Ipv6),
                _ => return
            }

            ip_repr.emit(frame.payload_mut(), &checksum_caps);

            let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
            f(ip_repr, payload)
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use {Result, Error};

    use super::InterfaceBuilder;
    use iface::{NeighborCache, EthernetInterface};
    use phy::{self, Loopback, ChecksumCapabilities};
    use time::Instant;
    use socket::SocketSet;
    #[cfg(feature = "proto-ipv4")]
    use wire::{ArpOperation, ArpPacket, ArpRepr};
    use wire::{EthernetAddress, EthernetFrame, EthernetProtocol};
    use wire::{IpAddress, IpCidr, IpProtocol, IpRepr};
    #[cfg(feature = "proto-ipv4")]
    use wire::{Ipv4Address, Ipv4Repr};
    #[cfg(feature = "proto-ipv4")]
    use wire::{Icmpv4Repr, Icmpv4DstUnreachable};
    #[cfg(all(feature = "socket-udp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
    use wire::{UdpPacket, UdpRepr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Ipv6Address, Ipv6Repr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Icmpv6Packet, Icmpv6Repr, Icmpv6ParamProblem};
    #[cfg(feature = "proto-ipv6")]
    use wire::{NdiscNeighborFlags, NdiscRepr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Ipv6HopByHopHeader, Ipv6Option, Ipv6OptionRepr};
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    use iface::{FragmentSet};
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    use wire::{Ipv4Packet};

    use super::Packet;

    fn create_loopback<'a, 'b, 'c, 'd>() -> (EthernetInterface<'static, 'b, 'c, 'd, Loopback>,
                                         SocketSet<'static, 'a, 'b>) {
        // Create a basic device
        let device = Loopback::new();
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface = InterfaceBuilder::new(device)
                .ethernet_addr(EthernetAddress::default())
                .neighbor_cache(NeighborCache::new(BTreeMap::new()))
                .ip_addrs(ip_addrs)
                .finalize();

        (iface, SocketSet::new(vec![]))
    }

    #[derive(Debug, PartialEq)]
    struct MockTxToken;

    impl phy::TxToken for MockTxToken {
        fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
                where F: FnOnce(&mut [u8]) -> Result<R> {
            Err(Error::__Nonexhaustive)
        }
    }

    #[test]
    #[should_panic(expected = "a required option was not set")]
    fn test_builder_initialization_panic() {
        InterfaceBuilder::new(Loopback::new()).finalize();
    }

    #[test]
    fn test_no_icmp_no_unicast() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 54];

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });
        #[cfg(feature = "proto-ipv6")]
        let repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr:    Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr:    Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame, &mut None),
                   Ok(Packet::None));
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(iface.inner.process_ipv6(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Packet::None));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_icmp_error_no_payload() {
        static NO_BYTES: [u8; 0] = [];
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 34];

        // Unknown Ipv4 Protocol with no payload
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        // emit the above repr to a frame
        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        // The expected Destination Unreachable response due to the
        // unknown protocol
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::ProtoUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Unknown(12),
                payload_len: 0,
                hop_limit: 64
            },
            data: &NO_BYTES
        };

        let expected_repr = Packet::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64
            },
            icmp_repr
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame, &mut None),
                   Ok(expected_repr));
    }

    #[test]
    #[cfg(all(feature = "socket-udp", feature = "proto-ipv4"))]
    fn test_icmp_error_port_unreachable() {
        static UDP_PAYLOAD: [u8; 12] = [
            0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x2c, 0x20, 0x57,
            0x6f, 0x6c, 0x64, 0x21
        ];
        let (iface, mut socket_set) = create_loopback();

        let mut udp_bytes_unicast = vec![0u8; 20];
        let mut udp_bytes_broadcast = vec![0u8; 20];
        let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
        let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload:  &UDP_PAYLOAD
        };

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   64
        });

        // Emit the representations to a packet
        udp_repr.emit(&mut packet_unicast, &ip_repr.src_addr(),
                      &ip_repr.dst_addr(), &ChecksumCapabilities::default());

        let data = packet_unicast.into_inner();

        // The expected Destination Unreachable ICMPv4 error response due
        // to no sockets listening on the destination port.
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.buffer_len(),
                hop_limit: 64
            },
            data: &data
        };
        let expected_repr = Packet::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64
            },
            icmp_repr
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, data),
                   Ok(expected_repr));

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   64
        });

        // Emit the representations to a packet
        udp_repr.emit(&mut packet_broadcast, &ip_repr.src_addr(),
                      &IpAddress::Ipv4(Ipv4Address::BROADCAST),
                      &ChecksumCapabilities::default());

        // Ensure that the port unreachable error does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address and no socket is bound to the port.
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr,
                   packet_broadcast.into_inner()), Ok(Packet::None));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata};
        use wire::IpEndpoint;

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (iface, mut socket_set) = create_loopback();

        let rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);

        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        let mut udp_bytes = vec![0u8; 13];
        let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

        let socket_handle = socket_set.add(udp_socket);

        #[cfg(feature = "proto-ipv6")]
        let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload:  &UDP_PAYLOAD
        };

        #[cfg(feature = "proto-ipv6")]
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr:    src_ip,
            dst_addr:    Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   0x40
        });
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    src_ip,
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   0x40
        });

        {
            // Bind the socket to port 68
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert_eq!(socket.bind(68), Ok(()));
            assert!(!socket.can_recv());
            assert!(socket.can_send());
        }

        udp_repr.emit(&mut packet, &ip_repr.src_addr(), &ip_repr.dst_addr(),
                      &ChecksumCapabilities::default());

        // Packet should be handled by bound UDP socket
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, packet.into_inner()),
                   Ok(Packet::None));

        {
            // Make sure the payload to the UDP packet processed by process_udp is
            // appended to the bound sockets rx_buffer
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67))));
        }
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_icmp_reply_size() {
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        use wire::IPV4_MIN_MTU as MIN_MTU;
        #[cfg(feature = "proto-ipv6")]
        use wire::Icmpv6DstUnreachable;
        #[cfg(feature = "proto-ipv6")]
        use wire::IPV6_MIN_MTU as MIN_MTU;

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        const MAX_PAYLOAD_LEN: usize = 528;
        #[cfg(feature = "proto-ipv6")]
        const MAX_PAYLOAD_LEN: usize = 1192;

        let (iface, mut socket_set) = create_loopback();

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let src_addr = Ipv4Address([192, 168, 1, 1]);
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let dst_addr = Ipv4Address([192, 168, 1, 2]);
        #[cfg(feature = "proto-ipv6")]
        let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(feature = "proto-ipv6")]
        let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        // UDP packet that if not tructated will cause a icmp port unreachable reply
        // to exeed the minimum mtu bytes in length.
        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; MAX_PAYLOAD_LEN]
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };
        #[cfg(feature = "proto-ipv6")]
        let ip_repr = Ipv6Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };
        let payload = packet.into_inner();

        // Expected packets
        #[cfg(feature = "proto-ipv6")]
        let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: ip_repr,
            data:   &payload[..MAX_PAYLOAD_LEN]
        };
        #[cfg(feature = "proto-ipv6")]
        let expected_ip_repr = Ipv6Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len()
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: ip_repr,
            data:   &payload[..MAX_PAYLOAD_LEN]
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_ip_repr = Ipv4Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmpv4_repr.buffer_len()
        };

        // The expected packet does not exceed the IPV4_MIN_MTU
        assert_eq!(expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(), MIN_MTU);
        // The expected packet and the generated packet are equal
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr.into(), payload),
                   Ok(Packet::Icmpv4((expected_ip_repr, expected_icmp_repr))));
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr.into(), payload),
                   Ok(Packet::Icmpv6((expected_ip_repr, expected_icmp_repr))));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_valid_arp_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 42];

        let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: local_ip_addr,
        };

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for us triggers an ARP Reply
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner(), &mut None),
                   Ok(Packet::Arp(ArpRepr::EthernetIpv4 {
                       operation: ArpOperation::Reply,
                       source_hardware_addr: local_hw_addr,
                       source_protocol_addr: local_ip_addr,
                       target_hardware_addr: remote_hw_addr,
                       target_protocol_addr: remote_ip_addr
                   })));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(local_ip_addr), &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_handle_valid_ndisc_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 86];

        let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
        let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: local_ip_addr,
            lladdr: Some(remote_hw_addr),
        });
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: local_ip_addr.solicited_node(),
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: solicit.buffer_len()
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        {
            ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            solicit.emit(&remote_ip_addr.into(), &local_ip_addr.solicited_node().into(),
                         &mut Icmpv6Packet::new_unchecked(
                            &mut frame.payload_mut()[ip_repr.buffer_len()..]),
                         &ChecksumCapabilities::default());
        }

        let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
            flags: NdiscNeighborFlags::SOLICITED,
            target_addr: local_ip_addr,
            lladdr: Some(local_hw_addr)
        });

        let ipv6_expected = Ipv6Repr {
            src_addr: local_ip_addr,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: icmpv6_expected.buffer_len()
        };

        // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner(), &mut None),
                   Ok(Packet::Icmpv6((ipv6_expected, icmpv6_expected))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv6(local_ip_addr), &IpAddress::Ipv6(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_other_arp_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 42];

        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x03]),
        };

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for someone else does not trigger an ARP Reply
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner(), &mut None),
                   Ok(Packet::None));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
    fn test_icmpv4_socket() {
        use socket::{IcmpSocket, IcmpEndpoint, IcmpSocketBuffer, IcmpPacketMetadata};
        use wire::Icmpv4Packet;

        let (iface, mut socket_set) = create_loopback();

        let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);
        let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);

        let icmpv4_socket = IcmpSocket::new(rx_buffer, tx_buffer);

        let socket_handle = socket_set.add(icmpv4_socket);

        let ident = 0x1234;
        let seq_no = 0x5432;
        let echo_data = &[0xff; 16];

        {
            let mut socket = socket_set.get::<IcmpSocket>(socket_handle);
            // Bind to the ID 0x1234
            assert_eq!(socket.bind(IcmpEndpoint::Ident(ident)), Ok(()));
        }

        // Ensure the ident we bound to and the ident of the packet are the same.
        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        let echo_repr = Icmpv4Repr::EchoRequest{ ident, seq_no, data: echo_data };
        echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
        let icmp_data = &packet.into_inner()[..];

        let ipv4_repr = Ipv4Repr {
            src_addr:    Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr:    Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            protocol:    IpProtocol::Icmp,
            payload_len: 24,
            hop_limit:   64
        };
        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        // Open a socket and ensure the packet is handled due to the listening
        // socket.
        {
            assert!(!socket_set.get::<IcmpSocket>(socket_handle).can_recv());
        }

        // Confirm we still get EchoReply from `smoltcp` even with the ICMP socket listening
        let echo_reply = Icmpv4Repr::EchoReply{ ident, seq_no, data: echo_data };
        let ipv4_reply = Ipv4Repr {
            src_addr: ipv4_repr.dst_addr,
            dst_addr: ipv4_repr.src_addr,
            ..ipv4_repr
        };
        assert_eq!(iface.inner.process_icmpv4(&mut socket_set, ip_repr, icmp_data),
                   Ok(Packet::Icmpv4((ipv4_reply, echo_reply))));

        {
            let mut socket = socket_set.get::<IcmpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(),
                       Ok((&icmp_data[..],
                           IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02)))));
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_solicited_node_addrs() {
        let (mut iface, _) = create_loopback();
        let mut new_addrs = vec![IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
                                 IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64)];
        iface.update_ip_addrs(|addrs| {
            new_addrs.extend(addrs.to_vec());
            *addrs = From::from(new_addrs);
        });
        assert!(iface.inner.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
        assert!(iface.inner.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
        assert!(!iface.inner.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_icmpv6_nxthdr_unknown() {
        let (mut iface, mut socket_set) = create_loopback();

        let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);

        let mut eth_bytes = vec![0; 66];
        let payload = [0x12, 0x34, 0x56, 0x78];

        let ipv6_repr = Ipv6Repr {
            src_addr:    remote_ip_addr,
            dst_addr:    Ipv6Address::LOOPBACK,
            next_header: IpProtocol::HopByHop,
            payload_len: 12,
            hop_limit:   0x40,
        };

        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            let ip_repr = IpRepr::Ipv6(ipv6_repr);
            frame.set_dst_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_src_addr(remote_hw_addr);
            frame.set_ethertype(EthernetProtocol::Ipv6);
            ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            let mut offset = ipv6_repr.buffer_len();
            {
                let mut hbh_pkt =
                    Ipv6HopByHopHeader::new_unchecked(&mut frame.payload_mut()[offset..]);
                hbh_pkt.set_next_header(IpProtocol::Unknown(0x0c));
                hbh_pkt.set_header_len(0);
                offset += 8;
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[..]);
                    Ipv6OptionRepr::PadN(3).emit(&mut pad_pkt);
                }
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[5..]);
                    Ipv6OptionRepr::Pad1.emit(&mut pad_pkt);
                }
            }
            frame.payload_mut()[offset..].copy_from_slice(&payload);
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let reply_icmp_repr = Icmpv6Repr::ParamProblem {
            reason:  Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header:  ipv6_repr,
            data:    &payload[..]
        };

        let reply_ipv6_repr = Ipv6Repr {
            src_addr:    Ipv6Address::LOOPBACK,
            dst_addr:    remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: reply_icmp_repr.buffer_len(),
            hop_limit:   0x40,
        };

        // Ensure the unknown next header causes a ICMPv6 Parameter Problem
        // error message to be sent to the sender.
        assert_eq!(iface.inner.process_ipv6(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Packet::Icmpv6((reply_ipv6_repr, reply_icmp_repr))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv6(Ipv6Address::LOOPBACK),
            &IpAddress::Ipv6(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    use std::vec::Vec;
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn create_loopback_with_fragments<'a, 'b>() -> (EthernetInterface<'static, 'b, 'static, 'static, Loopback>,
                                     Vec<u8>, Vec<u8>, Vec<u8>) {
        // Create a basic device
        let device = Loopback::new();
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128)
        ];

        // A simple fragments set
        /*
        let mut fragments = FragmentSet::new(vec![]);
        let fragment = FragmentedPacket::new(vec![0; 65535]);
        fragments.add(fragment);
        */
        let fragments = FragmentSet::new(BTreeMap::new());

        let iface = InterfaceBuilder::new(device)
                .ethernet_addr(EthernetAddress::default())
                .neighbor_cache(NeighborCache::new(BTreeMap::new()))
                .ip_addrs(ip_addrs)
                .fragments_set(fragments)
                .finalize();

        // create 3 packets representing a large UDP packet
        let mut packet1 = vec![
                              0x45, 0x0, 0x5, 0xdc, 0xd4, 0xba, 0x20, 0x0, 0x40, 0x11, 0x75, 0x2,
                              0xc0, 0xa8, 0x45, 0x2, 0xc0, 0xa8, 0x45, 0x1, 0x15, 0xb3, 0x1b, 0x39,
                              0x10, 0x8, 0x43, 0x3d
                              ];

        packet1.extend_from_slice(&vec![0xc; 1472]);

        let mut packet2 = vec![
                              0x45, 0x00, 0x05, 0xdc, 0xd4, 0xba, 0x20, 0xb9, 0x40, 0x11, 0x74, 0x49,
                              0xc0, 0xa8, 0x45, 0x02, 0xc0, 0xa8, 0x45, 0x01
                              ];

        packet2.extend_from_slice(&vec![0xc; 1480]);

        let mut packet3 = vec![
                              0x45, 0x00, 0x04, 0x8c, 0xd4, 0xba, 0x01, 0x72, 0x40, 0x11, 0x94, 0xe0,
                              0xc0, 0xa8, 0x45, 0x02, 0xc0, 0xa8, 0x45, 0x01
                              ];

        packet3.extend_from_slice(&vec![0xc; 1144]);

        (iface, packet1, packet2, packet3)
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_123() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_ne!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(3), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_321() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_ne!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(3), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_231() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_ne!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(3), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_213() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_ne!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(3), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_duplicate() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_ne!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(3), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

    #[test]
    #[cfg(all(feature = "fragmentation-ipv4", feature = "std"))]
    fn test_fragmentation_ipv4_udp_timeout() {
        let (mut iface, packet1, packet2, packet3) = create_loopback_with_fragments();

        let packet = Ipv4Packet::new_checked(packet1.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet2.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(2), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;

        let packet = Ipv4Packet::new_checked(packet3.as_slice()).unwrap();
        let mut fragments = ::std::mem::replace(&mut iface.inner.fragments, None);
        assert_eq!(iface.inner.process_ipv4_fragment(packet, Instant::from_millis(1000), &mut fragments),
                   Ok(None));
        iface.inner.fragments = fragments;
    }

}
