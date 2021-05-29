/*

# Setup

    modprobe mac802154_hwsim

    ip link set wpan0 down
    iwpan dev wpan0 set pan_id 0xbeef
    ip link add link wpan0 name lowpan0 type lowpan
    ip link set wpan0 up
    ip link set lowpan0 up

    iwpan dev wpan1 del
    iwpan phy phy1 interface add monitor%d type monitor

# Running

    sudo ./target/debug/examples/sixlowpan

# Teardown

    rmmod mac802154_hwsim
    
 */

mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::os::unix::io::AsRawFd;
use std::str;

use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::{wait as phy_wait, Device, Medium, RawSocket};
use smoltcp::socket::SocketSet;
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{IpAddress, IpCidr};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);

    let device = RawSocket::new("monitor0", Medium::Sixlowpan).unwrap();

    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

    let ethernet_addr = smoltcp::wire::Ieee802154Address::Extended([
        0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ]);
    let ip_addrs = [IpCidr::new(
        IpAddress::v6(0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242),
        64,
    )];

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(device).ip_addrs(ip_addrs);
    builder = builder
        .ieee802154_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache);
    let mut iface = builder.finalize();

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // udp:6969: respond "hello"
        {
            let mut socket = sockets.get::<UdpSocket>(udp_handle);
            if !socket.is_open() {
                socket.bind(6969).unwrap()
            }

            let client = match socket.recv() {
                Ok((data, endpoint)) => {
                    debug!(
                        "udp:6969 recv data: {:?} from {}",
                        str::from_utf8(data).unwrap(),
                        endpoint
                    );
                    Some(endpoint)
                }
                Err(_) => None,
            };
            if let Some(endpoint) = client {
                let data = b"hello\n";
                debug!(
                    "udp:6969 send data: {:?}",
                    str::from_utf8(data.as_ref()).unwrap()
                );
                socket.send_slice(data, endpoint).unwrap();
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
