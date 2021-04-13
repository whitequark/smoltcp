#[macro_use]
extern crate log;
extern crate byteorder;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use byteorder::{ByteOrder, NetworkEndian};
use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache, Routes};
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::Device;
use smoltcp::socket::{DnsQuery, DnsSocket, SocketSet};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    EthernetAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr,
    Ipv4Address, Ipv6Address,
};
use std::cmp;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;

fn main() {
    utils::setup_logging("warn");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let device_caps = device.capabilities();

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let servers = vec![
        Ipv4Address::new(8, 8, 4, 4).into(),
        Ipv4Address::new(8, 8, 8, 8).into(),
    ];
    let dns_socket = DnsSocket::new(servers, vec![]);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let src_ipv6 = IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
        IpCidr::new(src_ipv6, 64),
        IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
    ];
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let default_v6_gw = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100);
    let mut routes_storage = [None; 2];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    routes.add_default_ipv6_route(default_v6_gw).unwrap();
    let mut iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .neighbor_cache(neighbor_cache)
        .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let dns_handle = sockets.add(dns_socket);


    let name = &[
        0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00,
    ];
    let name = &[
        0x03, 0x77, 0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03,
        0x63, 0x6f, 0x6d, 0x00
    ];

    sockets.get::<DnsSocket>(dns_handle).query(name).unwrap();

    loop {
        let timestamp = Instant::now();
        debug!("timestamp {:?}", timestamp);

        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
