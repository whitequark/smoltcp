#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_mut)]
#![allow(clippy::collapsible_if)]

#[cfg(feature = "std")]
#[allow(dead_code)]
mod utils;

use core::str;
use log::{debug, error, info};

use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

#[cfg(not(feature = "std"))]
mod mock {
    use core::cell::Cell;
    use smoltcp::time::{Duration, Instant};

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Clock(Cell<Instant>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Cell::new(Instant::from_millis(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration)
        }

        pub fn elapsed(&self) -> Instant {
            self.0.get()
        }
    }
}

#[cfg(feature = "std")]
mod mock {
    use smoltcp::time::{Duration, Instant};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // should be AtomicU64 but that's unstable
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Clock(Arc<AtomicUsize>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Arc::new(AtomicUsize::new(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0
                .fetch_add(duration.total_millis() as usize, Ordering::SeqCst);
        }

        pub fn elapsed(&self) -> Instant {
            Instant::from_millis(self.0.load(Ordering::SeqCst) as i64)
        }
    }
}

fn main() {
    let clock = mock::Clock::new();
    let device = Loopback::new(Medium::Ethernet);

    #[cfg(feature = "std")]
    let device = {
        let clock = clock.clone();
        utils::setup_logging_with_clock("", move || clock.elapsed());

        let (mut opts, mut free) = utils::create_options();
        utils::add_middleware_options(&mut opts, &mut free);

        let mut matches = utils::parse_options(&opts, free);
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ true)
    };

    let mut neighbor_cache_entries = [None; 8];
    let mut neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);

    let mut ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
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

    let mut did_listen = false;
    let mut did_connect = false;
    let mut done = false;
    while !done && clock.elapsed() < Instant::from_millis(10_000) {
        match iface.poll(&mut socket_set, clock.elapsed()) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        {
            let mut socket = socket_set.get::<TcpSocket>(server_handle);
            if !socket.is_active() && !socket.is_listening() {
                if !did_listen {
                    debug!("listening");
                    socket.listen(1234).unwrap();
                    did_listen = true;
                }
            }

            if socket.can_recv() {
                debug!(
                    "got {:?}",
                    socket.recv(|buffer| { (buffer.len(), str::from_utf8(buffer).unwrap()) })
                );
                socket.close();
                done = true;
            }
        }

        {
            let mut socket = socket_set.get::<TcpSocket>(client_handle);
            if !socket.is_open() {
                if !did_connect {
                    debug!("connecting");
                    socket
                        .connect(
                            (IpAddress::v4(127, 0, 0, 1), 1234),
                            (IpAddress::Unspecified, 65000),
                        )
                        .unwrap();
                    did_connect = true;
                }
            }

            if socket.can_send() {
                debug!("sending");
                socket.send_slice(b"0123456789abcdef").unwrap();
                socket.close();
            }
        }

        match iface.poll_delay(&socket_set, clock.elapsed()) {
            Some(Duration::ZERO) => debug!("resuming"),
            Some(delay) => {
                debug!("sleeping for {} ms", delay);
                clock.advance(delay)
            }
            None => clock.advance(Duration::from_millis(1)),
        }
    }

    if done {
        info!("done")
    } else {
        error!("this is taking too long, bailing out")
    }
}
