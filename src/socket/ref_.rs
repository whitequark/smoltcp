use core::ops::{Deref, DerefMut};

#[cfg(feature = "socket-raw")]
use crate::socket::RawSocket;
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use crate::socket::IcmpSocket;
#[cfg(feature = "socket-udp")]
use crate::socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use crate::socket::TcpSocket;
#[cfg(feature = "socket-dns")]
use crate::socket::DnsSocket;

/// A trait for tracking a socket usage session.
///
/// Allows implementation of custom drop logic that runs only if the socket was changed
/// in specific ways. For example, drop logic for UDP would check if the local endpoint
/// has changed, and if yes, notify the socket set.
#[doc(hidden)]
pub trait Session {
    fn finish(&mut self) {}
}

#[cfg(feature = "socket-raw")]
impl<'a> Session for RawSocket<'a> {}
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
impl<'a> Session for IcmpSocket<'a> {}
#[cfg(feature = "socket-udp")]
impl<'a> Session for UdpSocket<'a> {}
#[cfg(feature = "socket-tcp")]
impl<'a> Session for TcpSocket<'a> {}
#[cfg(feature = "socket-dns")]
impl<'a> Session for DnsSocket<'a> {}

/// A smart pointer to a socket.
///
/// Allows the network stack to efficiently determine if the socket state was changed in any way.
pub struct Ref<'a, T: Session + 'a> {
    /// Reference to the socket.
    ///
    /// This is almost always `Some` except when dropped in `into_inner` which removes the socket
    /// reference. This properly tracks the initialization state without any additional bytes as
    /// the `None` variant occupies the `0` pattern which is invalid for the reference.
    socket: Option<&'a mut T>,
}

impl<'a, T: Session + 'a> Ref<'a, T> {
    /// Wrap a pointer to a socket to make a smart pointer.
    ///
    /// Calling this function is only necessary if your code is using [into_inner].
    ///
    /// [into_inner]: #method.into_inner
    pub fn new(socket: &'a mut T) -> Self {
        Ref { socket: Some(socket) }
    }

    /// Unwrap a smart pointer to a socket.
    ///
    /// The finalization code is not run. Prompt operation of the network stack depends
    /// on wrapping the returned pointer back and dropping it.
    ///
    /// Calling this function is only necessary to achieve composability if you *must*
    /// map a `&mut SocketRef<'a, XSocket>` to a `&'a mut XSocket` (note the lifetimes);
    /// be sure to call [new] afterwards.
    ///
    /// [new]: #method.new
    pub fn into_inner(mut ref_: Self) -> &'a mut T {
        ref_.socket.take().unwrap()
    }
}

impl<'a, T: Session> Deref for Ref<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // Deref is only used while the socket is still in place (into inner has not been called).
        self.socket.as_ref().unwrap()
    }
}

impl<'a, T: Session> DerefMut for Ref<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.socket.as_mut().unwrap()
    }
}

impl<'a, T: Session> Drop for Ref<'a, T> {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            Session::finish(socket);
        }
    }
}
