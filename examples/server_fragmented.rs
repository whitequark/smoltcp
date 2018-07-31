#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use std::str;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::SocketSet;
use smoltcp::socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::{Duration, Instant};
use smoltcp::iface::FragmentSet;

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 9000]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 9000]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp2_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp2_socket = TcpSocket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let tcp3_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp3_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp3_socket = TcpSocket::new(tcp3_rx_buffer, tcp3_tx_buffer);

    let tcp4_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp4_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp4_socket = TcpSocket::new(tcp4_rx_buffer, tcp4_tx_buffer);

    let fragments = FragmentSet::new(BTreeMap::new());
    /*
    let mut fragments = FragmentSet::new(vec![]);
    let fragment = FragmentedPacket::new(vec![0; 65535]);
    fragments.add(fragment);
    */

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];

    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .fragments_set(fragments)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle  = sockets.add(udp_socket);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);
    let tcp3_handle = sockets.add(tcp3_socket);
    let tcp4_handle = sockets.add(tcp4_socket);

    let mut tcp_6970_active = false;
    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}",e);
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
                    debug!("udp:6969 recv data: {:?} from {}",
                           str::from_utf8(data.as_ref()).unwrap(), endpoint);
                    Some(endpoint)
                }
                Err(_) => None
            };
            if let Some(endpoint) = client {
                let data = b"hello\n";
                debug!("udp:6969 send data: {:?}",
                       str::from_utf8(data.as_ref()).unwrap());
                socket.send_slice(data, endpoint).unwrap();
            }
        }

        // tcp:6969: respond "hello"
        {
            let mut socket = sockets.get::<TcpSocket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(6969).unwrap();
            }

            if socket.can_send() {
                debug!("tcp:6969 send greeting");
                write!(socket, "hello\n").unwrap();
                debug!("tcp:6969 close");
                socket.close();
            }
        }

        // tcp:6970: echo with reverse
        {
            let mut socket = sockets.get::<TcpSocket>(tcp2_handle);
            if !socket.is_open() {
                socket.listen(6970).unwrap()
            }

            if socket.is_active() && !tcp_6970_active {
                debug!("tcp:6970 connected");
            } else if !socket.is_active() && tcp_6970_active {
                debug!("tcp:6970 disconnected");
            }
            tcp_6970_active = socket.is_active();

            if socket.may_recv() {
                let data = socket.recv(|buffer| {
                    let mut data = buffer.to_owned();
                    if data.len() > 0 {
                        debug!("tcp:6970 recv data: {:?}",
                               str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (data.len(), data)
                }).unwrap();
                if socket.can_send() && data.len() > 0 {
                    debug!("tcp:6970 send data: {:?}",
                           str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                debug!("tcp:6970 close");
                socket.close();
            }
        }

        // tcp:6971: sinkhole
        {
            let mut socket = sockets.get::<TcpSocket>(tcp3_handle);
            if !socket.is_open() {
                socket.listen(6971).unwrap();
                socket.set_keep_alive(Some(Duration::from_millis(1000)));
                socket.set_timeout(Some(Duration::from_millis(2000)));
            }

            if socket.may_recv() {
                socket.recv(|buffer| {
                    if buffer.len() > 0 {
                        debug!("tcp:6971 recv {:?} octets", buffer.len());
                    }
                    (buffer.len(), ())
                }).unwrap();
            } else if socket.may_send() {
                socket.close();
            }
        }

        // tcp:6972: fountain
        {
            let mut socket = sockets.get::<TcpSocket>(tcp4_handle);
            if !socket.is_open() {
                socket.listen(6972).unwrap()
            }

            if socket.may_send() {
                socket.send(|data| {
                    if data.len() > 0 {
                        debug!("tcp:6972 send {:?} octets", data.len());
                        for (i, b) in data.iter_mut().enumerate() {
                            *b = (i % 256) as u8;
                        }
                    }
                    (data.len(), ())
                }).unwrap();
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
