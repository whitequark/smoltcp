#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate smoltcp;

use std as core;
extern crate getopts;

use core::cmp;
use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol};
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Packet, Ipv6Packet, TcpPacket};
use smoltcp::iface::{NeighborCache, InterfaceBuilder};
use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::{Duration, Instant};

mod utils {
    include!("../utils.rs");
}

mod mock {
    use std::sync::Arc;
    use std::sync::atomic::{Ordering, AtomicUsize};
    use smoltcp::time::{Duration, Instant};

    // should be AtomicU64 but that's unstable
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Clock(Arc<AtomicUsize>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Arc::new(AtomicUsize::new(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0.fetch_add(duration.total_millis() as usize, Ordering::SeqCst);
        }

        pub fn elapsed(&self) -> Instant {
            Instant::from_millis(self.0.load(Ordering::SeqCst) as i64)
        }
    }
}

struct TcpHeaderFuzzer([u8; 56], usize);

impl TcpHeaderFuzzer {
    // The fuzzer won't fuzz any packets with the SYN flag set in order to make sure the connection
    // is established before the fuzzed headers arrive.
    //
    // It will also not fuzz the source and dest port so it reaches the open socket.
    //
    // Otherwise, it replaces the entire rest of the TCP header with the fuzzer's output.
    pub fn new(data: &[u8]) -> TcpHeaderFuzzer {
        let copy_len = cmp::min(data.len(), 56 /* max TCP header length without port numbers*/);

        let mut fuzzer = TcpHeaderFuzzer([0; 56], copy_len);
        fuzzer.0[..copy_len].copy_from_slice(&data[..copy_len]);
        fuzzer
    }
}

impl smoltcp::phy::Fuzzer for TcpHeaderFuzzer {
    fn fuzz_packet(&self, frame_data: &mut [u8]) {
        if self.1 == 0 {
            return;
        }

        let tcp_packet_offset = {
            let eth_frame = EthernetFrame::new_unchecked(&frame_data);
            EthernetFrame::<&mut [u8]>::header_len() + match eth_frame.ethertype() {
                EthernetProtocol::Ipv4 =>
                    Ipv4Packet::new_unchecked(eth_frame.payload()).header_len() as usize,
                EthernetProtocol::Ipv6 =>
                    Ipv6Packet::new_unchecked(eth_frame.payload()).header_len() as usize,
                _ => return
            }
        };

        let tcp_is_syn = {
            let tcp_packet = TcpPacket::new_checked(&frame_data[tcp_packet_offset..]).unwrap();
            tcp_packet.syn()
        };

        if tcp_is_syn {
            return;
        }

        if !frame_data.ends_with(b"abcdef") {
            return;
        }

        let tcp_header_len = {
            let tcp_packet = &frame_data[tcp_packet_offset..];
            (tcp_packet[12] as usize >> 4) * 4
        };

        let tcp_packet = &mut frame_data[tcp_packet_offset+4..];

        let replacement_data = &self.0[..self.1];
        let copy_len = cmp::min(replacement_data.len(), tcp_header_len);
        assert!(copy_len < tcp_packet.len());
        tcp_packet[..copy_len].copy_from_slice(&replacement_data[..copy_len]);
    }
}

struct EmptyFuzzer();

impl smoltcp::phy::Fuzzer for EmptyFuzzer {
    fn fuzz_packet(&self, _: &mut [u8]) {}
}

fuzz_target!(|data: &[u8]| {
    let clock = mock::Clock::new();

    let device = {

        let (mut opts, mut free) = utils::create_options();
        utils::add_middleware_options(&mut opts, &mut free);

        let mut matches = utils::parse_options(&opts, free);
        let loopback = Loopback::new(Medium::Ethernet);
        let device = utils::parse_middleware_options(&mut matches, loopback, /*loopback=*/ true);

        smoltcp::phy::FuzzInjector::new(device,
                                        EmptyFuzzer(),
                                        TcpHeaderFuzzer::new(data))
    };

    let mut neighbor_cache_entries = [None; 8];
    let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);

    let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
    let mut iface = InterfaceBuilder::new(device)
            .ethernet_addr(EthernetAddress::default())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

    let server_socket = {
        // It is not strictly necessary to use a `static mut` and unsafe code here, but
        // on embedded systems that smoltcp targets it is far better to allocate the data
        // statically to verify that it fits into RAM rather than get undefined behavior
        // when stack overflows.
        static mut TCP_SERVER_RX_DATA: [u8; 1024] = [0; 1024];
        static mut TCP_SERVER_TX_DATA: [u8; 1024] = [0; 1024];
        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
        TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let client_socket = {
        static mut TCP_CLIENT_RX_DATA: [u8; 1024] = [0; 1024];
        static mut TCP_CLIENT_TX_DATA: [u8; 1024] = [0; 1024];
        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_RX_DATA[..] });
        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_TX_DATA[..] });
        TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let mut socket_set_entries: [_; 2] = Default::default();
    let mut socket_set = SocketSet::new(&mut socket_set_entries[..]);
    let server_handle = socket_set.add(server_socket);
    let client_handle = socket_set.add(client_socket);

    let mut did_listen  = false;
    let mut did_connect = false;
    let mut done = false;

    iface.up().expect("Failed to set device up");

    while !done && clock.elapsed() < Instant::from_millis(4_000) {
        let _ = iface.poll(&mut socket_set, clock.elapsed());

        {
            let mut socket = socket_set.get::<TcpSocket>(server_handle);
            if !socket.is_active() && !socket.is_listening() {
                if !did_listen {
                    socket.listen(1234).unwrap();
                    did_listen = true;
                }
            }

            if socket.can_recv() {
                socket.close();
                done = true;
            }
        }

        {
            let mut socket = socket_set.get::<TcpSocket>(client_handle);
            if !socket.is_open() {
                if !did_connect {
                    socket.connect((IpAddress::v4(127, 0, 0, 1), 1234),
                                   (IpAddress::Unspecified, 65000)).unwrap();
                    did_connect = true;
                }
            }

            if socket.can_send() {
                socket.send_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
                socket.close();
            }
        }

        match iface.poll_delay(&socket_set, clock.elapsed()) {
            Some(Duration { millis: 0 }) => {},
            Some(delay) => {
                clock.advance(delay)
            },
            None => clock.advance(Duration::from_millis(1))
        }
    }
});
