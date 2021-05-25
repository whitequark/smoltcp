// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

use core::cmp;
use managed::{ManagedSlice, ManagedMap};

use crate::{Error, Result};
use crate::phy::{Device, DeviceCapabilities, RxToken, TxToken, Medium};
use crate::time::{Duration, Instant};
use crate::wire::*;
use crate::socket::*;
#[cfg(feature = "medium-ethernet")]
use crate::iface::{NeighborCache, NeighborAnswer};
use crate::iface::Routes;

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    inner:  InterfaceInner<'a>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for prorcessing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
struct InterfaceInner<'a> {
    #[cfg(feature = "medium-ethernet")]
    neighbor_cache:         Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-ethernet")]
    ethernet_addr:          Option<EthernetAddress>,
    #[cfg(feature = "medium-sixlowpan")]
    ieee802154_addr:        Option<Ieee802154Address>,
    ip_addrs:               ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip:                 bool,
    routes:                 Routes<'a>,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups:  ManagedMap<'a, Ipv4Address, ()>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state:      IgmpReportState,
    device_capabilities:    DeviceCapabilities,
}

/// A builder structure used for creating a network interface.
pub struct InterfaceBuilder <'a, DeviceT: for<'d> Device<'d>> {
    device:                 DeviceT,
    #[cfg(feature = "medium-ethernet")]
    ethernet_addr:          Option<EthernetAddress>,
    #[cfg(feature = "medium-ethernet")]
    neighbor_cache:         Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-sixlowpan")]
    ieee802154_addr:        Option<Ieee802154Address>,
    ip_addrs:               ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip:                 bool,
    routes:                 Routes<'a>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups:  ManagedMap<'a, Ipv4Address, ()>,
}

impl<'a, DeviceT> InterfaceBuilder<'a, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    #[cfg_attr(feature = "medium-ethernet", doc = r##"
# Examples

```
# use std::collections::BTreeMap;
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
# use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};

let device = // ...
# Loopback::new(Medium::Ethernet);
let hw_addr = // ...
# EthernetAddress::default();
let neighbor_cache = // ...
# NeighborCache::new(BTreeMap::new());
let ip_addrs = // ...
# [];
let iface = InterfaceBuilder::new(device)
        .ethernet_addr(hw_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();
```
    "##)]
    pub fn new(device: DeviceT) -> Self {
        InterfaceBuilder {
            device:              device,
            #[cfg(feature = "medium-ethernet")]
            ethernet_addr:       None,
            #[cfg(feature = "medium-ethernet")]
            neighbor_cache:      None,
            #[cfg(feature = "medium-sixlowpan")]
            ieee802154_addr:     None,
            ip_addrs:            ManagedSlice::Borrowed(&mut []),
            #[cfg(feature = "proto-ipv4")]
            any_ip:              false,
            routes:              Routes::new(ManagedMap::Borrowed(&mut [])),
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups:   ManagedMap::Borrowed(&mut []),
        }
    }

    /// Set the Ethernet address the interface will use. See also
    /// [ethernet_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [ethernet_addr]: struct.Interface.html#method.ethernet_addr
    #[cfg(feature = "medium-ethernet")]
    pub fn ethernet_addr(mut self, addr: EthernetAddress) -> Self {
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
    /// [ip_addrs]: struct.Interface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> Self
        where T: Into<ManagedSlice<'a, IpCidr>>
    {
        let ip_addrs = ip_addrs.into();
        InterfaceInner::check_ip_addrs(&ip_addrs);
        self.ip_addrs = ip_addrs;
        self
    }

    /// Enable or disable the AnyIP capability, allowing packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [routes] specifies one of
    /// the interface's [ip_addrs] as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    ///
    /// [routes]: struct.Interface.html#method.routes
    /// [ip_addrs]: struct.Interface.html#method.ip_addrs
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(mut self, enabled: bool) -> Self {
        self.any_ip = enabled;
        self
    }

    /// Set the IP routes the interface will use. See also
    /// [routes].
    ///
    /// [routes]: struct.Interface.html#method.routes
    pub fn routes<T>(mut self, routes: T) -> InterfaceBuilder<'a, DeviceT>
        where T: Into<Routes<'a>>
    {
        self.routes = routes.into();
        self
    }

    /// Provide storage for multicast groups.
    ///
    /// Join multicast groups by calling [`join_multicast_group()`] on an `Interface`.
    /// Using [`join_multicast_group()`] will send initial membership reports.
    ///
    /// A previously destroyed interface can be recreated by reusing the multicast group
    /// storage, i.e. providing a non-empty storage to `ipv4_multicast_groups()`.
    /// Note that this way initial membership reports are **not** sent.
    ///
    /// [`join_multicast_group()`]: struct.Interface.html#method.join_multicast_group
    #[cfg(feature = "proto-igmp")]
    pub fn ipv4_multicast_groups<T>(mut self, ipv4_multicast_groups: T) -> Self
        where T: Into<ManagedMap<'a, Ipv4Address, ()>>
    {
        self.ipv4_multicast_groups = ipv4_multicast_groups.into();
        self
    }

    /// Set the Neighbor Cache the interface will use.
    #[cfg(feature = "medium-ethernet")]
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'a>) -> Self {
        self.neighbor_cache = Some(neighbor_cache);
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
    pub fn finalize(self) -> Interface<'a, DeviceT> {
        let device_capabilities = self.device.capabilities();

        #[cfg(feature = "medium-ethernet")]
        let (ethernet_addr, neighbor_cache) = match device_capabilities.medium {
            Medium::Ethernet => (
                Some(self.ethernet_addr.expect("ethernet_addr required option was not set")),
                Some(self.neighbor_cache.expect("neighbor_cache required option was not set"))
            ),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                assert!(self.ethernet_addr.is_none(), "ethernet_addr is set, but device medium is IP");
                assert!(self.neighbor_cache.is_none(), "neighbor_cache is set, but device medium is IP");
                (None, None)
            }
            #[cfg(feature = "medium-sixlowpan")]
            Medium::Sixlowpan => {
                assert!(self.ieee802154_addr.is_some(), "ieee802154_addr required option was not set");
                (None, None)
            }
        };

        Interface {
            device: self.device,
            inner: InterfaceInner {
                #[cfg(feature = "medium-ethernet")]
                ethernet_addr,
                #[cfg(feature = "medium-sixlowpan")]
                ieee802154_addr: self.ieee802154_addr,
                ip_addrs: self.ip_addrs,
                #[cfg(feature = "proto-ipv4")]
                any_ip: self.any_ip,
                routes: self.routes,
                device_capabilities,
                #[cfg(feature = "medium-ethernet")]
                neighbor_cache,
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: self.ipv4_multicast_groups,
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
            }
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
enum EthernetPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(IpPacket<'a>),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum IpPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "proto-igmp")]
    Igmp((Ipv4Repr, IgmpRepr)),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6((Ipv6Repr, Icmpv6Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> IpPacket<'a> {
    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            IpPacket::Icmpv4((ipv4_repr, _)) => IpRepr::Ipv4(*ipv4_repr),
            #[cfg(feature = "proto-igmp")]
            IpPacket::Igmp((ipv4_repr, _)) => IpRepr::Ipv4(*ipv4_repr),
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((ipv6_repr, _)) => IpRepr::Ipv6(*ipv6_repr),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((ip_repr, _)) => ip_repr.clone(),
        }
    }

    pub(crate) fn emit_payload(&self, _ip_repr: IpRepr, payload: &mut [u8], caps: &DeviceCapabilities) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            IpPacket::Icmpv4((_, icmpv4_repr)) => 
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "proto-igmp")]
            IpPacket::Igmp((_, igmp_repr)) =>
                igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload)),
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((_, icmpv6_repr)) =>
                icmpv6_repr.emit(&_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                         &mut Icmpv6Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw((_, raw_packet)) =>
                payload.copy_from_slice(raw_packet),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udp_repr)) =>
                udp_repr.emit(&mut UdpPacket::new_unchecked(payload),
                              &_ip_repr.src_addr(), &_ip_repr.dst_addr(), &caps.checksum),
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((_, mut tcp_repr)) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= _ip_repr.buffer_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(&mut TcpPacket::new_unchecked(payload),
                                &_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                                &caps.checksum);
            }
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

#[cfg(feature = "proto-igmp")]
enum IgmpReportState {
    Inactive,
    ToGeneralQuery {
        version:    IgmpVersion,
        timeout:    Instant,
        interval:   Duration,
        next_index: usize
    },
    ToSpecificQuery {
        version:    IgmpVersion,
        timeout:    Instant,
        group:      Ipv4Address
    },
}

impl<'a, DeviceT> Interface<'a, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Get the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if if the interface's medium is not Ethernet.

    #[cfg(feature = "medium-ethernet")]
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.inner.ethernet_addr.unwrap()
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, or if the
    /// interface's medium is not Ethernet.
    #[cfg(feature = "medium-ethernet")]
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        assert!(self.device.capabilities().medium == Medium::Ethernet);
        InterfaceInner::check_ethernet_addr(&addr);
        self.inner.ethernet_addr = Some(addr);
    }

    /// Get a reference to the inner device.
    pub fn device(&self) -> &DeviceT {
        &self.device
    }

    /// Get a mutable reference to the inner device.
    ///
    /// There are no invariants imposed on the device by the interface itself. Furthermore the
    /// trait implementations, required for references of all lifetimes, guarantees that the
    /// mutable reference can not invalidate the device as such. For some devices, such access may
    /// still allow modifications with adverse effects on the usability as a `phy` device. You
    /// should not use them this way.
    pub fn device_mut(&mut self) -> &mut DeviceT {
        &mut self.device
    }

    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<T: Into<IpAddress>>(&mut self, addr: T, _timestamp: Instant) -> Result<bool> {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let is_not_new = self.inner.ipv4_multicast_groups.insert(addr, ())
                    .map_err(|_| Error::Exhausted)?
                    .is_some();
                if is_not_new {
                    Ok(false)
                } else if let Some(pkt) =
                        self.inner.igmp_report_packet(IgmpVersion::Version2, addr) {
                    // Send initial membership report
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, _timestamp, pkt)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable)
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<T: Into<IpAddress>>(&mut self, addr: T, _timestamp: Instant) -> Result<bool> {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.inner.ipv4_multicast_groups.remove(&addr)
                    .is_none();
                if was_not_present {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_leave_packet(addr) {
                    // Send group leave packet
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, _timestamp, pkt)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable)
        }
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_multicast_group(addr)
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs().iter()
            .filter_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                _ => None,
            }).next()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'a, IpCidr>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_address()
    }

    pub fn routes(&self) -> &Routes<'a> {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes<'a> {
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

            #[cfg(feature = "proto-igmp")]
            self.igmp_egress(timestamp)?;

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
                match inner.device_capabilities.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        inner.process_ethernet(sockets, timestamp, &frame).map_err(|err| {
                            net_debug!("cannot process ingress packet: {}", err);
                            #[cfg(not(feature = "defmt"))]
                            net_debug!("packet dump follows:\n{}",
                                    PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame));
                            err
                        }).and_then(|response| {
                            processed_any = true;
                            match response {
                                Some(packet) => {
                                    inner.dispatch(tx_token, timestamp, packet).map_err(|err| {
                                        net_debug!("cannot dispatch response packet: {}", err);
                                        err
                                    })
                                }
                                None => Ok(())
                            }
                        })
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => {
                        inner.process_ip(sockets, timestamp, &frame).map_err(|err| {
                            net_debug!("cannot process ingress packet: {}", err);
                            //net_debug!("packet dump follows:\n{}",
                            //        PrettyPrinter::<IpFrame<&[u8]>>::new("", &frame));
                            err
                        }).and_then(|response| {
                            processed_any = true;
                            match response {
                                Some(packet) => {
                                    inner.dispatch_ip(tx_token, timestamp, packet).map_err(|err| {
                                        net_debug!("cannot dispatch response packet: {}", err);
                                        err
                                    })
                                }
                                None => Ok(())
                            }
                        })
                    }
                    #[cfg(feature = "medium-sixlowpan")]
                    Medium::Sixlowpan => {
                        inner.process_sixlowpan(sockets, timestamp, &frame).map_err(|err| {
                            net_debug!("cannot process ingress packet: {}", err);
                            err
                        }).and_then(|response| {
                            processed_any = true;
                            match response {
                                Some(packet) => {
                                    inner.dispatch_ip(tx_token, timestamp, packet).map_err(|err| {
                                        net_debug!("cannot dispatch response packet: {}", err);
                                        err
                                    })
                                }
                                None => Ok(())
                            }
                        })
                    }
                }
            })?;
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let _caps = self.device.capabilities();

        let mut emitted_any = false;
        for mut socket in sockets.iter_mut() {
            if !socket.meta_mut().egress_permitted(timestamp, |ip_addr|
                    self.inner.has_neighbor(&ip_addr, timestamp)) {
                continue
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());
            let &mut Self { ref mut device, ref mut inner } = self;

            macro_rules! respond {
                ($response:expr) => ({
                    let response = $response;
                    neighbor_addr = Some(response.ip_repr().dst_addr());
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    device_result = inner.dispatch_ip(tx_token, timestamp, response);
                    device_result
                })
            }

            let socket_result =
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(ref mut socket) =>
                        socket.dispatch(&_caps.checksum, |response|
                            respond!(IpPacket::Raw(response))),
                    #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
                    Socket::Icmp(ref mut socket) =>
                        socket.dispatch(|response| {
                            match response {
                                #[cfg(feature = "proto-ipv4")]
                                (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) =>
                                    respond!(IpPacket::Icmpv4((ipv4_repr, icmpv4_repr))),
                                #[cfg(feature = "proto-ipv6")]
                                (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) =>
                                    respond!(IpPacket::Icmpv6((ipv6_repr, icmpv6_repr))),
                                _ => Err(Error::Unaddressable)
                            }
                        }),
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response|
                            respond!(IpPacket::Udp(response))),
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) => {
                        let ip_mtu = match _caps.medium {
                            #[cfg(feature = "medium-ethernet")]
                            Medium::Ethernet => _caps.max_transmission_unit - EthernetFrame::<&[u8]>::header_len(),
                            #[cfg(feature = "medium-ip")]
                            Medium::Ip => _caps.max_transmission_unit,
                            #[cfg(feature = "medium-sixlowpan")]
                            Medium::Sixlowpan => todo!(),
                        };
                        socket.dispatch(timestamp, ip_mtu, |response|
                            respond!(IpPacket::Tcp(response)))
                    }
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

    /// Depending on `igmp_report_state` and the therein contained
    /// timeouts, send IGMP membership reports.
    #[cfg(feature = "proto-igmp")]
    fn igmp_egress(&mut self, timestamp: Instant) -> Result<bool> {
        match self.inner.igmp_report_state {
            IgmpReportState::ToSpecificQuery { version, timeout, group }
                    if timestamp >= timeout => {
                if let Some(pkt) = self.inner.igmp_report_packet(version, group) {
                    // Send initial membership report
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, timestamp, pkt)?;
                }

                self.inner.igmp_report_state = IgmpReportState::Inactive;
                Ok(true)
            }
            IgmpReportState::ToGeneralQuery { version, timeout, interval, next_index }
                    if timestamp >= timeout => {
                let addr = self.inner.ipv4_multicast_groups
                    .iter()
                    .nth(next_index)
                    .map(|(addr, ())| *addr);

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.inner.igmp_report_packet(version, addr) {
                            // Send initial membership report
                            let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                            self.inner.dispatch_ip(tx_token, timestamp, pkt)?;
                        }

                        let next_timeout = (timeout + interval).max(timestamp);
                        self.inner.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version, timeout: next_timeout, interval, next_index: next_index + 1
                        };
                        Ok(true)
                    }

                    None => {
                        self.inner.igmp_report_state = IgmpReportState::Inactive;
                        Ok(false)
                    }
                }
            }
            _ => Ok(false)
        }
    }
}

impl<'a> InterfaceInner<'a> {
    #[cfg(feature = "medium-ethernet")]
    fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
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
        self.ip_addrs.iter().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK=> {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        })
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter()
            .filter_map(
                |addr| match *addr {
                    IpCidr::Ipv4(cidr) => Some(cidr.address()),
                    #[cfg(feature = "proto-ipv6")]
                    IpCidr::Ipv6(_) => None
                })
            .next()
    }

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false`.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) =>
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS ||
                self.ipv4_multicast_groups.get(&key).is_some(),
            _ =>
                false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet<'frame, T: AsRef<[u8]>>
                       (&mut self, sockets: &mut SocketSet, timestamp: Instant, frame: &'frame T) ->
                       Result<Option<EthernetPacket<'frame>>>
    {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast() &&
           !eth_frame.dst_addr().is_multicast() &&
           eth_frame.dst_addr() != self.ethernet_addr.unwrap()
        {
            return Ok(None)
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp =>
                self.process_arp(timestamp, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
                if eth_frame.src_addr().is_unicast() && ipv4_packet.src_addr().is_unicast() {
                    // Fill the neighbor cache from IP header of unicast frames.
                    let ip_addr = IpAddress::Ipv4(ipv4_packet.src_addr());
                    if self.in_same_network(&ip_addr) {
                        self.neighbor_cache.as_mut().unwrap().fill(ip_addr, eth_frame.src_addr(), timestamp);
                    }
                }

                self.process_ipv4(sockets, timestamp, &ipv4_packet).map(|o| o.map(EthernetPacket::Ip))
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
                if eth_frame.src_addr().is_unicast() && ipv6_packet.src_addr().is_unicast()  {
                    // Fill the neighbor cache from IP header of unicast frames.
                    let ip_addr = IpAddress::Ipv6(ipv6_packet.src_addr());
                    if self.in_same_network(&ip_addr) &&
                            self.neighbor_cache.as_mut().unwrap().lookup(&ip_addr, timestamp).found() {
                        self.neighbor_cache.as_mut().unwrap().fill(ip_addr, eth_frame.src_addr(), timestamp);
                    }
                }
        
                self.process_ipv6(sockets, timestamp, &ipv6_packet).map(|o| o.map(EthernetPacket::Ip))
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame, T: AsRef<[u8]>>
                  (&mut self, sockets: &mut SocketSet, timestamp: Instant, ip_payload: &'frame T) ->
                  Result<Option<IpPacket<'frame>>>
    {
        match IpVersion::of_packet(ip_payload.as_ref()) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = Ipv4Packet::new_checked(ip_payload)?;
                self.process_ipv4(sockets, timestamp, &ipv4_packet)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = Ipv6Packet::new_checked(ip_payload)?;
                self.process_ipv6(sockets, timestamp, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    
    #[cfg(feature = "medium-sixlowpan")]
    fn process_sixlowpan<'frame, T: AsRef<[u8]> + ?Sized>
                  (&mut self, sockets: &mut SocketSet, timestamp: Instant, sixlowpan_payload: &'frame T) ->
                  Result<Option<IpPacket<'frame>>>
    {
        let ieee802154_frame = Ieee802154Frame::new_checked(sixlowpan_payload)?;
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame)?;

        match ieee802154_repr.payload {
            Some(payload) => {
                // The first header needs to be an IPHC header.
                let iphc_packet = SixlowpanIphcPacket::new_checked(payload)?;
                let iphc_repr = SixlowpanIphcRepr::parse(&iphc_packet, ieee802154_repr.src_addr, ieee802154_repr.dst_addr)?;

                if !iphc_repr.src_addr.is_unicast() {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
                    return Err(Error::Malformed)
                }

                let payload = iphc_packet.payload();
                let ip_repr = IpRepr::Sixlowpan(iphc_repr);

                // Currently we assume the next header is a UDP, so we mark all the rest with todo.
                match iphc_repr.next_header {
                    SixlowpanNextHeader::Compressed => {
                        match SixlowpanNhcPacket::dispatch(payload)? {
                            SixlowpanNhcPacket::ExtensionHeader(ext_header) => todo!(),
                            SixlowpanNhcPacket::UdpHeader(udp_packet) => {
                                // Handle the UDP
                                let udp_repr = SixlowpanUdpRepr::parse(&udp_packet, &iphc_repr.src_addr, &iphc_repr.dst_addr, udp_packet.checksum())?;

                                // Look for UDP sockets that will accept the UDP packet.
                                // If it does not accept the packet, then send an ICMP message.
                                for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
                                    if !udp_socket.accepts(&ip_repr, &udp_repr) { continue; }

                                    match udp_socket.process(&ip_repr, &udp_repr) {
                                        Ok(()) => return Ok(None),
                                        Err(e) => return Err(e),
                                    }
                                }

                                // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
                                match ip_repr {
                                    #[cfg(feature = "proto-ipv6")]
                                    IpRepr::Ipv6(ipv6_repr) => {
                                        let payload_len = icmp_reply_payload_len(payload.len(), IPV6_MIN_MTU,
                                                                                 ipv6_repr.buffer_len());
                                        let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                                            reason: Icmpv6DstUnreachable::PortUnreachable,
                                            header: ipv6_repr,
                                            data:   &payload[0..payload_len]
                                        };
                                        Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
                                    },
                                    IpRepr::Unspecified { .. } => Err(Error::Unaddressable),
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                    SixlowpanNextHeader::Uncompressed(nxt_hdr) => {
                        match nxt_hdr {
                            IpProtocol::Icmpv6 => self.process_icmpv6(sockets, timestamp, ip_repr, iphc_packet.payload()),
                            hdr => todo!("{:?}", hdr),
                        }
                    }
                }
            }
            None => Ok(None)
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, timestamp: Instant, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Option<EthernetPacket<'frame>>>
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
                    self.neighbor_cache.as_mut().unwrap().fill(source_protocol_addr.into(),
                                             source_hardware_addr,
                                             timestamp);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
                    return Err(Error::Malformed)
                }

                if operation == ArpOperation::Request && self.has_ip_addr(target_protocol_addr) {
                    Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.ethernet_addr.unwrap(),
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr
                    })))
                } else {
                    Ok(None)
                }
            }
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
                // The socket buffer is full or the packet was truncated
                Err(Error::Exhausted) | Err(Error::Truncated) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }
        handled_by_raw_socket
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ipv6<'frame, T: AsRef<[u8]> + ?Sized>
                   (&mut self, sockets: &mut SocketSet, timestamp: Instant,
                    ipv6_packet: &Ipv6Packet<&'frame T>) ->
                   Result<Option<IpPacket<'frame>>> {
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
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
                   -> Result<Option<IpPacket<'frame>>>
    {
        match nxt_hdr {
            IpProtocol::Icmpv6 =>
                self.process_icmpv6(sockets, timestamp, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ipv6_repr.into(), handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop =>
                self.process_hopbyhop(sockets, timestamp, ipv6_repr, handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(None),

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

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4<'frame, T: AsRef<[u8]> + ?Sized>
                   (&mut self, sockets: &mut SocketSet, timestamp: Instant,
                    ipv4_packet: &Ipv4Packet<&'frame T>) ->
                   Result<Option<IpPacket<'frame>>>
    {
        let checksum_caps = self.device_capabilities.checksum.clone();
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        if !self.has_ip_addr(ipv4_repr.dst_addr) &&
           !self.has_multicast_group(ipv4_repr.dst_addr) &&
           !self.is_broadcast_v4(ipv4_repr.dst_addr) {

            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.any_ip ||
                    self.routes.lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), timestamp)
                        .map_or(true, |router_addr| !self.has_ip_addr(router_addr)) {
                return Ok(None);
            }
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "proto-igmp")]
            IpProtocol::Igmp =>
                self.process_igmp(timestamp, ipv4_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ip_repr, handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ip_repr, ip_payload),

            _ if handled_by_raw_socket =>
                Ok(None),

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

    /// Checks if an incoming packet has a broadcast address for the interfaces
    /// associated ipv4 addresses.
    #[cfg(feature = "proto-ipv4")]
    fn is_subnet_broadcast(&self, address: Ipv4Address) -> bool {
        self.ip_addrs.iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None
            })
            .any(|broadcast_address| address == broadcast_address)
    } 
    
    /// Checks if an ipv4 address is broadcast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        address.is_broadcast() || self.is_subnet_broadcast(address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.is_unicast() && !self.is_subnet_broadcast(address)
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    #[cfg(feature = "proto-igmp")]
    fn process_igmp<'frame>(&mut self, timestamp: Instant, ipv4_repr: Ipv4Repr,
                            ip_payload: &'frame [u8]) -> Result<Option<IpPacket<'frame>>> {
        let igmp_packet = IgmpPacket::new_checked(ip_payload)?;
        let igmp_repr = IgmpRepr::parse(&igmp_packet)?;

        // FIXME: report membership after a delay
        match igmp_repr {
            IgmpRepr::MembershipQuery { group_addr, version, max_resp_time } => {
                // General query
                if group_addr.is_unspecified() &&
                        ipv4_repr.dst_addr == Ipv4Address::MULTICAST_ALL_SYSTEMS {
                    // Are we member in any groups?
                    if self.ipv4_multicast_groups.iter().next().is_some() {
                        let interval = match version {
                            IgmpVersion::Version1 =>
                                Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = self.ipv4_multicast_groups.len() as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version, timeout: timestamp + interval, interval, next_index: 0
                        };
                    }
                } else {
                    // Group-specific query
                    if self.has_multicast_group(group_addr) && ipv4_repr.dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version, timeout: timestamp + timeout, group: group_addr
                        };
                    }
                }
            },
            // Ignore membership reports
            IgmpRepr::MembershipReport { .. } => (),
            // Ignore hosts leaving groups
            IgmpRepr::LeaveGroup{ .. } => (),
        }

        Ok(None)
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_icmpv6<'frame>(&mut self, _sockets: &mut SocketSet, _timestamp: Instant,
                              ip_repr: IpRepr, ip_payload: &'frame [u8]) -> Result<Option<IpPacket<'frame>>>
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
                        let icmp_reply_repr = Icmpv6Repr::EchoReply { ident, seq_no, data };
                        Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
                    },
                    _ => Err(Error::Unrecognized),
                }
            }

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => Ok(None),

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(feature = "medium-ethernet")]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => self.process_ndisc(_timestamp, ipv6_repr, repr),
                _ => Ok(None)
            },

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn process_ndisc<'frame>(&mut self, timestamp: Instant, ip_repr: Ipv6Repr,
                             repr: NdiscRepr<'frame>) -> Result<Option<IpPacket<'frame>>> {
        match repr {
            NdiscRepr::NeighborAdvert { lladdr, target_addr, flags } => {
                let ip_addr = ip_repr.src_addr.into();
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        if flags.contains(NdiscNeighborFlags::OVERRIDE) ||
                                !self.neighbor_cache.as_mut().unwrap().lookup(&ip_addr, timestamp).found() {
                            self.neighbor_cache.as_mut().unwrap().fill(ip_addr, lladdr, timestamp)
                        }
                    },
                    _ => (),
                }
                Ok(None)
            }
            NdiscRepr::NeighborSolicit { target_addr, lladdr, .. } => {
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        self.neighbor_cache.as_mut().unwrap().fill(ip_repr.src_addr.into(), lladdr, timestamp)
                    },
                    _ => (),
                }
                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: target_addr,
                        lladdr: Some(self.ethernet_addr.unwrap())
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len()
                    };
                    Ok(Some(IpPacket::Icmpv6((ip_repr, advert))))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None)
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_hopbyhop<'frame>(&mut self, sockets: &mut SocketSet, timestamp: Instant,
                                ipv6_repr: Ipv6Repr, handled_by_raw_socket: bool,
                                ip_payload: &'frame [u8]) -> Result<Option<IpPacket<'frame>>>
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
                            return Ok(None);
                        },
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return Err(Error::Unrecognized);
                        }
                    }
                }
            }
        }
        self.process_nxt_hdr(sockets, timestamp, ipv6_repr, hbh_repr.next_header,
                             handled_by_raw_socket, &ip_payload[hbh_repr.buffer_len()..])
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_icmpv4<'frame>(&self, _sockets: &mut SocketSet, ip_repr: IpRepr,
                              ip_payload: &'frame [u8]) -> Result<Option<IpPacket<'frame>>>
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
                let icmp_reply_repr = Icmpv4Repr::EchoReply { ident, seq_no, data };
                match ip_repr {
                    IpRepr::Ipv4(ipv4_repr) => Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr)),
                    _ => Err(Error::Unrecognized),
                }
            },

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(None),

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn icmpv4_reply<'frame, 'icmp: 'frame>
                   (&self, ipv4_repr: Ipv4Repr, icmp_repr: Icmpv4Repr<'icmp>) ->
                   Option<IpPacket<'frame>>
    {
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if self.is_unicast_v4(ipv4_repr.dst_addr) {
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr:    ipv4_repr.dst_addr,
                dst_addr:    ipv4_repr.src_addr,
                protocol:    IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
        } else if self.is_broadcast_v4(ipv4_repr.dst_addr) {
            // Only reply to broadcasts for echo replies and not other ICMP messages
            match icmp_repr {
                Icmpv4Repr::EchoReply {..} => match self.ipv4_address() {
                    Some(src_addr) => {
                        let ipv4_reply_repr = Ipv4Repr {
                            src_addr:    src_addr,
                            dst_addr:    ipv4_repr.src_addr,
                            protocol:    IpProtocol::Icmp,
                            payload_len: icmp_repr.buffer_len(),
                            hop_limit:   64
                        };
                        Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
                    },
                    None => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn icmpv6_reply<'frame, 'icmp: 'frame>
                   (&self, ipv6_repr: Ipv6Repr, icmp_repr: Icmpv6Repr<'icmp>) ->
                   Option<IpPacket<'frame>>
    {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr:    ipv6_repr.dst_addr,
                dst_addr:    ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Some(IpPacket::Icmpv6((ipv6_reply_repr, icmp_repr)))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }

    #[cfg(feature = "socket-udp")]
    fn process_udp<'frame>(&self, sockets: &mut SocketSet,
                           ip_repr: IpRepr, handled_by_raw_socket: bool, ip_payload: &'frame [u8]) ->
                          Result<Option<IpPacket<'frame>>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) { continue }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket =>
                Ok(None),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket =>
                Ok(None),
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
            #[cfg(feature = "sixlowpan")]
            IpRepr::Sixlowpan(sixlowpan_repr) => {
                let ipv6_repr = Ipv6Repr {
                    src_addr: sixlowpan_repr.src_addr,
                    dst_addr: sixlowpan_repr.dst_addr,
                    next_header: IpProtocol::Udp, // XXX
                    payload_len: ip_payload.len(),
                    hop_limit: sixlowpan_repr.hop_limit,
                };

                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU,
                                                         sixlowpan_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
            }
            IpRepr::Unspecified { .. } => Err(Error::Unaddressable),
        }
    }

    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(&self, sockets: &mut SocketSet, timestamp: Instant,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Option<IpPacket<'frame>>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut tcp_socket in sockets.iter_mut().filter_map(TcpSocket::downcast) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) { continue }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map(IpPacket::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Some(IpPacket::Tcp(TcpSocket::rst_reply(&ip_repr, &tcp_repr))))
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                    packet: EthernetPacket) -> Result<()>
        where Tx: TxToken
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                    };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            EthernetPacket::Ip(packet) => {
                self.dispatch_ip(tx_token, timestamp, packet)
            },
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch_ethernet<Tx, F>(&mut self, tx_token: Tx, timestamp: Instant,
                                buffer_len: usize, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(EthernetFrame<&mut [u8]>)
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(timestamp, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);
            frame.set_src_addr(self.ethernet_addr.unwrap());

            f(frame);

            Ok(())
        })
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs
            .iter()
            .any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Ok(*addr)
        }

        // Route via a router.
        match self.routes.lookup(addr, timestamp) {
            Some(router_addr) => Ok(router_addr),
            None => Err(Error::Unaddressable),
        }
    }

    fn has_neighbor(&self, addr: &IpAddress, timestamp: Instant) -> bool {
        match self.route(addr, timestamp) {
            Ok(_routed_addr) => {
                match self.device_capabilities.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => self.neighbor_cache.as_ref().unwrap()
                        .lookup(&_routed_addr, timestamp)
                        .found(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => true,
                    #[cfg(feature = "medium-sixlowpan")]
                    Medium::Sixlowpan => todo!(),
                }
            }
            Err(_) => false
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn lookup_hardware_addr<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                                src_addr: &IpAddress, dst_addr: &IpAddress) ->
                               Result<(EthernetAddress, Tx)>
        where Tx: TxToken
    {
        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr =
                match *dst_addr {
                    IpAddress::Unspecified =>
                        None,
                    #[cfg(feature = "proto-ipv4")]
                    IpAddress::Ipv4(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x01, 0x00,
                            0x5e, b[1] & 0x7F,
                            b[2], b[3],
                        ])),
                    #[cfg(feature = "proto-ipv6")]
                    IpAddress::Ipv6(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x33, 0x33,
                            b[12], b[13],
                            b[14], b[15],
                        ])),
                };
            if let Some(hardware_addr) = hardware_addr {
                return Ok((hardware_addr, tx_token))
            }
        }

        let dst_addr = self.route(dst_addr, timestamp)?;

        match self.neighbor_cache.as_mut().unwrap().lookup(&dst_addr, timestamp) {
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
                    source_hardware_addr: self.ethernet_addr.unwrap(),
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending Neighbor Solicitation",
                           dst_addr);

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.ethernet_addr.unwrap()),
                });

                let packet = IpPacket::Icmpv6((
                    Ipv6Repr {
                        src_addr: src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff
                    },
                    solicit,
                ));

                self.dispatch_ip(tx_token, timestamp, packet)?;
            }

            _ => ()
        }
        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.as_mut().unwrap().limit_rate(timestamp);
        Err(Error::Unaddressable)
    }

    fn dispatch_ip<Tx: TxToken>(&mut self, tx_token: Tx, timestamp: Instant,
                          packet: IpPacket) -> Result<()> {
        let ip_repr = packet.ip_repr().lower(&self.ip_addrs)?;
        let caps = self.device_capabilities.clone();

        match self.device_capabilities.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
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

                    ip_repr.emit(frame.payload_mut(), &caps.checksum);

                    let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &caps);
                })
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                let tx_len = ip_repr.total_len();
                tx_token.consume(timestamp, tx_len, |mut tx_buffer| {
                    debug_assert!(tx_buffer.as_ref().len() == tx_len);

                    ip_repr.emit(&mut tx_buffer, &caps.checksum);

                    let payload = &mut tx_buffer[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &caps);

                    Ok(())
                })
            }
            #[cfg(feature = "medium-sixlowpan")]
            Medium::Sixlowpan => {
                // Conver the packet to a LOWPAN compatible packet.
                todo!();
            }
        }
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_report_packet<'any>(&self, version: IgmpVersion, group_addr: Ipv4Address) -> Option<IpPacket<'any>> {
        let iface_addr = self.ipv4_address()?;
        let igmp_repr = IgmpRepr::MembershipReport {
            group_addr,
            version,
        };
        let pkt = IpPacket::Igmp((Ipv4Repr {
            src_addr:    iface_addr,
            // Send to the group being reported
            dst_addr:    group_addr,
            protocol:    IpProtocol::Igmp,
            payload_len: igmp_repr.buffer_len(),
            hop_limit:   1,
            // TODO: add Router Alert IPv4 header option. See
            // [#183](https://github.com/m-labs/smoltcp/issues/183).
        }, igmp_repr));
        Some(pkt)
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_leave_packet<'any>(&self, group_addr: Ipv4Address) -> Option<IpPacket<'any>> {
        self.ipv4_address().map(|iface_addr| {
            let igmp_repr = IgmpRepr::LeaveGroup { group_addr };
            IpPacket::Igmp((Ipv4Repr {
                src_addr:    iface_addr,
                dst_addr:    Ipv4Address::MULTICAST_ALL_ROUTERS,
                protocol:    IpProtocol::Igmp,
                payload_len: igmp_repr.buffer_len(),
                hop_limit:   1,
            }, igmp_repr))
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "proto-igmp")]
    use std::vec::Vec;
    use std::collections::BTreeMap;

    use super::*;

    use crate::{Result, Error};
    #[cfg(feature = "medium-ethernet")]
    use crate::iface::NeighborCache;
    use crate::iface::Interface;
    #[cfg(feature = "proto-igmp")]
    use crate::time::Instant;
    use crate::socket::SocketSet;
    use crate::phy::{Loopback, ChecksumCapabilities};

    fn create_loopback<'a>() -> (Interface<'a, Loopback>, SocketSet<'a>) {
        #[cfg(feature = "medium-ethernet")]
        return create_loopback_ethernet();
        #[cfg(not(feature = "medium-ethernet"))]
        return create_loopback_ip();
    }

    #[cfg(all(feature = "medium-ip"))]
    #[allow(unused)]
    fn create_loopback_ip<'a>() -> (Interface<'a, Loopback>, SocketSet<'a>) {
        // Create a basic device
        let device = Loopback::new(Medium::Ip);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder
            .ipv4_multicast_groups(BTreeMap::new());
        let iface = iface_builder
            .finalize();

        (iface, SocketSet::new(vec![]))
    }

    #[cfg(all(feature = "medium-ethernet"))]
    fn create_loopback_ethernet<'a>() -> (Interface<'a, Loopback>, SocketSet<'a>) {
        // Create a basic device
        let device = Loopback::new(Medium::Ethernet);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = InterfaceBuilder::new(device)
            .ethernet_addr(EthernetAddress::default())
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder
            .ipv4_multicast_groups(BTreeMap::new());
        let iface = iface_builder
            .finalize();

        (iface, SocketSet::new(vec![]))
    }

    #[cfg(feature = "proto-igmp")]
    fn recv_all(iface: &mut Interface<'_, Loopback>, timestamp: Instant) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        while let Some((rx, _tx)) = iface.device.receive() {
            rx.consume(timestamp, |pkt| {
                pkts.push(pkt.to_vec());
                Ok(())
            }).unwrap();
        }
        pkts
    }

    #[derive(Debug, PartialEq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct MockTxToken;

    impl TxToken for MockTxToken {
        fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
                where F: FnOnce(&mut [u8]) -> Result<R> {
            Err(Error::Unaddressable)
        }
    }

    #[test]
    #[should_panic(expected = "ethernet_addr required option was not set")]
    #[cfg(all(feature = "medium-ethernet"))]
    fn test_builder_initialization_panic() {
        InterfaceBuilder::new(Loopback::new(Medium::Ethernet)).finalize();
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_no_icmp_no_unicast_ipv4() {
        let (mut iface, mut socket_set) = create_loopback();

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_no_icmp_no_unicast_ipv6() {
        let (mut iface, mut socket_set) = create_loopback();

        // Unknown Ipv6 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr:    Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr:    Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv6Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(iface.inner.process_ipv6(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_icmp_error_no_payload() {
        static NO_BYTES: [u8; 0] = [];
        let (mut iface, mut socket_set) = create_loopback();

        // Unknown Ipv4 Protocol with no payload
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let mut bytes = vec![0u8; 34];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

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

        let expected_repr = IpPacket::Icmpv4((
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
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Some(expected_repr)));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_local_subnet_broadcasts() {
        let (mut iface, _) = create_loopback();
        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 1, 23]), 24));
            });
        });

        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 1, 255])), true);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 1, 254])), false);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 16));
            });
        });
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 23, 255])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 23, 254])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 255, 254])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 168, 255, 255])), true);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 8));
            });
        });
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 23, 1, 255])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 23, 1, 254])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 255, 255, 254])), false);
        assert_eq!(iface.inner.is_subnet_broadcast(Ipv4Address([192, 255, 255, 255])), true);
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
        let expected_repr = IpPacket::Icmpv4((
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
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, false, data),
                   Ok(Some(expected_repr)));

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
                   false, packet_broadcast.into_inner()), Ok(None));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use crate::socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata};
        use crate::wire::IpEndpoint;

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
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, false, packet.into_inner()),
                   Ok(None));

        {
            // Make sure the payload to the UDP packet processed by process_udp is
            // appended to the bound sockets rx_buffer
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67))));
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_ipv4_broadcast() {
        use crate::wire::{Ipv4Packet, Icmpv4Repr, Icmpv4Packet};

        let (mut iface, mut socket_set) = create_loopback();

        let our_ipv4_addr = iface.ipv4_address().unwrap();
        let src_ipv4_addr = Ipv4Address([127, 0, 0, 2]);

        // ICMPv4 echo request
        let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
        let icmpv4_repr = Icmpv4Repr::EchoRequest {
            ident: 0x1234, seq_no: 0xabcd, data: &icmpv4_data
        };

        // Send to IPv4 broadcast address
        let ipv4_repr = Ipv4Repr {
            src_addr:    src_ipv4_addr,
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Icmp,
            hop_limit:   64,
            payload_len: icmpv4_repr.buffer_len(),
        };

        // Emit to ip frame
        let mut bytes = vec![0u8;
            ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()
        ];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default());
            icmpv4_repr.emit(
                &mut Icmpv4Packet::new_unchecked(
                    &mut bytes[ipv4_repr.buffer_len()..]),
                &ChecksumCapabilities::default());
            Ipv4Packet::new_unchecked(&bytes)
        };

        // Expected ICMPv4 echo reply
        let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
            ident: 0x1234, seq_no: 0xabcd, data: &icmpv4_data };
        let expected_ipv4_repr = Ipv4Repr {
            src_addr: our_ipv4_addr,
            dst_addr: src_ipv4_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmpv4_repr.buffer_len(),
        };
        let expected_packet = IpPacket::Icmpv4((expected_ipv4_repr, expected_icmpv4_repr));

        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Some(expected_packet)));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_icmp_reply_size() {
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        use crate::wire::IPV4_MIN_MTU as MIN_MTU;
        #[cfg(feature = "proto-ipv6")]
        use crate::wire::Icmpv6DstUnreachable;
        #[cfg(feature = "proto-ipv6")]
        use crate::wire::IPV6_MIN_MTU as MIN_MTU;

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
            payload_len: expected_icmp_repr.buffer_len()
        };

        // The expected packet does not exceed the IPV4_MIN_MTU
        assert_eq!(expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(), MIN_MTU);
        // The expected packet and the generated packet are equal
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr.into(), false, payload),
                   Ok(Some(IpPacket::Icmpv4((expected_ip_repr, expected_icmp_repr)))));
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr.into(), false, payload),
                   Ok(Some(IpPacket::Icmpv6((expected_ip_repr, expected_icmp_repr)))));
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_valid_arp_request() {
        let (mut iface, mut socket_set) = create_loopback_ethernet();

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
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                       operation: ArpOperation::Reply,
                       source_hardware_addr: local_hw_addr,
                       source_protocol_addr: local_ip_addr,
                       target_hardware_addr: remote_hw_addr,
                       target_protocol_addr: remote_ip_addr
                   }))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(local_ip_addr), &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn test_handle_valid_ndisc_request() {
        let (mut iface, mut socket_set) = create_loopback_ethernet();

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
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(Some(EthernetPacket::Ip(IpPacket::Icmpv6((ipv6_expected, icmpv6_expected))))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv6(local_ip_addr), &IpAddress::Ipv6(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_other_arp_request() {
        let (mut iface, mut socket_set) = create_loopback_ethernet();

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
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(None));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
    fn test_icmpv4_socket() {
        use crate::socket::{IcmpSocket, IcmpEndpoint, IcmpSocketBuffer, IcmpPacketMetadata};
        use crate::wire::Icmpv4Packet;

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
                   Ok(Some(IpPacket::Icmpv4((ipv4_reply, echo_reply)))));

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

        let payload = [0x12, 0x34, 0x56, 0x78];

        let ipv6_repr = Ipv6Repr {
            src_addr:    remote_ip_addr,
            dst_addr:    Ipv6Address::LOOPBACK,
            next_header: IpProtocol::HopByHop,
            payload_len: 12,
            hop_limit:   0x40,
        };

        let mut bytes = vec![0; 52];
        let frame = {
            let ip_repr = IpRepr::Ipv6(ipv6_repr);
            ip_repr.emit(&mut bytes, &ChecksumCapabilities::default());
            let mut offset = ipv6_repr.buffer_len();
            {
                let mut hbh_pkt =
                    Ipv6HopByHopHeader::new_unchecked(&mut bytes[offset..]);
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
            bytes[offset..].copy_from_slice(&payload);
            Ipv6Packet::new_unchecked(&bytes)
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
                   Ok(Some(IpPacket::Icmpv6((reply_ipv6_repr, reply_icmp_repr)))));
    }

    #[test]
    #[cfg(feature = "proto-igmp")]
    fn test_handle_igmp() {
        fn recv_igmp(mut iface: &mut Interface<'_, Loopback>, timestamp: Instant) -> Vec<(Ipv4Repr, IgmpRepr)> {
            let caps = iface.device.capabilities();
            let checksum_caps = &caps.checksum;
            recv_all(&mut iface, timestamp)
                .iter()
                .filter_map(|frame| {
                    
                    let ipv4_packet = match caps.medium {
                        #[cfg(feature = "medium-ethernet")]
                        Medium::Ethernet => {
                            let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                            Ipv4Packet::new_checked(eth_frame.payload()).ok()?
                        }
                        #[cfg(feature = "medium-ip")]
                        Medium::Ip => Ipv4Packet::new_checked(&frame[..]).ok()?,
                        #[cfg(feature = "medium-sixlowpan")]
                        Medium::Sixlowpan => todo!(),
                    };
                    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps).ok()?;
                    let ip_payload = ipv4_packet.payload();
                    let igmp_packet = IgmpPacket::new_checked(ip_payload).ok()?;
                    let igmp_repr = IgmpRepr::parse(&igmp_packet).ok()?;
                    Some((ipv4_repr, igmp_repr))
                })
                .collect::<Vec<_>>()
        }

        let groups = [
            Ipv4Address::new(224, 0, 0, 22),
            Ipv4Address::new(224, 0, 0, 56),
        ];

        let (mut iface, mut socket_set) = create_loopback();

        // Join multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.join_multicast_group(*group, timestamp)
                .unwrap();
        }

        let reports = recv_igmp(&mut iface, timestamp);
        assert_eq!(reports.len(), 2);
        for (i, group_addr) in groups.iter().enumerate() {
            assert_eq!(reports[i].0.protocol, IpProtocol::Igmp);
            assert_eq!(reports[i].0.dst_addr, *group_addr);
            assert_eq!(reports[i].1, IgmpRepr::MembershipReport {
                group_addr: *group_addr,
                version: IgmpVersion::Version2,
            });
        }

        // General query
        let timestamp = Instant::now();
        const GENERAL_QUERY_BYTES: &[u8] = &[
            0x46, 0xc0, 0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 
            0x01, 0x02, 0x47, 0x43, 0xac, 0x16, 0x63, 0x04, 
            0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 
            0x11, 0x64, 0xec, 0x8f, 0x00, 0x00, 0x00, 0x00, 
            0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        {
            // Transmit GENERAL_QUERY_BYTES into loopback
            let tx_token = iface.device.transmit().unwrap();
            tx_token.consume(
                timestamp, GENERAL_QUERY_BYTES.len(),
                |buffer| {
                    buffer.copy_from_slice(GENERAL_QUERY_BYTES);
                    Ok(())
                }).unwrap();
        }
        // Trigger processing until all packets received through the
        // loopback have been processed, including responses to
        // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
        // pkts that could be checked.
        iface.socket_ingress(&mut socket_set, timestamp).unwrap();

        // Leave multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.leave_multicast_group(*group, timestamp)
                .unwrap();
        }

        let leaves = recv_igmp(&mut iface, timestamp);
        assert_eq!(leaves.len(), 2);
        for (i, group_addr) in groups.iter().cloned().enumerate() {
            assert_eq!(leaves[i].0.protocol, IpProtocol::Igmp);
            assert_eq!(leaves[i].0.dst_addr, Ipv4Address::MULTICAST_ALL_ROUTERS);
            assert_eq!(leaves[i].1, IgmpRepr::LeaveGroup { group_addr });
        }
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_no_reply() {
        use crate::socket::{RawSocket, RawSocketBuffer, RawPacketMetadata};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let (mut iface, mut socket_set) = create_loopback();

        let packets = 1;
        let rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; 10]
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to frame
        let mut bytes = vec![0u8;
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            Ipv4Packet::new_unchecked(&bytes)
        };

        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_truncated_packet() {
        use crate::socket::{RawSocket, RawSocketBuffer, RawPacketMetadata};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let (mut iface, mut socket_set) = create_loopback();

        let packets = 1;
        let rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; 49] // 49 > 48, hence packet will be truncated
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to frame
        let mut bytes = vec![0u8;
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            Ipv4Packet::new_unchecked(&bytes)
        };

        let frame = iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame);

        // because the packet could not be handled we should send an Icmp message
        assert!(match frame {  
            Ok(Some(IpPacket::Icmpv4(_))) => true,
            _ => false,
        });
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
    fn test_raw_socket_with_udp_socket() {
        use crate::socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata,
                     RawSocket, RawSocketBuffer, RawPacketMetadata};
        use crate::wire::{IpVersion, IpEndpoint, Ipv4Packet, UdpPacket, UdpRepr};

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (mut iface, mut socket_set) = create_loopback();

        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_socket_handle = socket_set.add(udp_socket);
        {
            // Bind the socket to port 68
            let mut socket = socket_set.get::<UdpSocket>(udp_socket_handle);
            assert_eq!(socket.bind(68), Ok(()));
            assert!(!socket.can_recv());
            assert!(socket.can_send());
        }

        let packets = 1;
        let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, raw_rx_buffer, raw_tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &UDP_PAYLOAD
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to frame
        let mut bytes = vec![0u8;
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            Ipv4Packet::new_unchecked(&bytes)
        };

        assert_eq!(iface.inner.process_ipv4(&mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));

        {
            // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
            let mut socket = socket_set.get::<UdpSocket>(udp_socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67))));
        }
    }
}
