use core::{fmt, slice};
use managed::ManagedSlice;

use crate::socket::{Socket, SocketRef, AnySocket};
#[cfg(feature = "socket-tcp")]
use crate::socket::TcpState;

/// An item of a socket set.
///
/// The only reason this struct is public is to allow the socket set storage
/// to be allocated externally.
#[derive(Debug)]
pub struct Item<'a> {
    socket: Socket<'a>,
    refs:   usize
}

/// A handle, identifying a socket in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Handle(usize);

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.
#[derive(Debug)]
pub struct Set<'a> {
    sockets: ManagedSlice<'a, Option<Item<'a>>>
}

impl<'a> Set<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> Set<'a>
            where SocketsT: Into<ManagedSlice<'a, Option<Item<'a>>>> {
        let sockets = sockets.into();
        Set { sockets }
    }

    /// Add a socket to the set with the reference count 1, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T>(&mut self, socket: T) -> Handle
        where T: Into<Socket<'a>>
    {
        fn put<'a>(index: usize, slot: &mut Option<Item<'a>>,
                       mut socket: Socket<'a>) -> Handle {
            net_trace!("[{}]: adding", index);
            let handle = Handle(index);
            socket.meta_mut().handle = handle;
            *slot = Some(Item { socket, refs: 1 });
            handle
        }

        let socket = socket.into();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                return put(index, slot, socket)
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => {
                panic!("adding a socket to a full SocketSet")
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(None);
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&mut self, handle: Handle) -> SocketRef<T> {
        match self.sockets[handle.0].as_mut() {
            Some(item) => {
                T::downcast(SocketRef::new(&mut item.socket))
                  .expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket")
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: Handle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket")
        }
    }

    /// Increase reference count by 1.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn retain(&mut self, handle: Handle) {
        self.sockets[handle.0]
            .as_mut()
            .expect("handle does not refer to a valid socket")
            .refs += 1
    }

    /// Decrease reference count by 1.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set,
    /// or if the reference count is already zero.
    pub fn release(&mut self, handle: Handle) {
        let refs = &mut self.sockets[handle.0]
                            .as_mut()
                            .expect("handle does not refer to a valid socket")
                            .refs;
        if *refs == 0 { panic!("decreasing reference count past zero") }
        *refs -= 1
    }

    /// Prune the sockets in this set.
    ///
    /// Pruning affects sockets with reference count 0. Open sockets are closed.
    /// Closed sockets are removed and dropped.
    pub fn prune(&mut self) {
        for (index, item) in self.sockets.iter_mut().enumerate() {
            let mut may_remove = false;
            if let Some(Item { refs: 0, ref mut socket }) = *item {
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(_) =>
                        may_remove = true,
                    #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
                    Socket::Icmp(_) =>
                        may_remove = true,
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(_) =>
                        may_remove = true,
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) =>
                        if socket.state() == TcpState::Closed {
                            may_remove = true
                        } else {
                            socket.close()
                        },
                    #[cfg(feature = "socket-dns")]
                    Socket::Dns(_) =>
                        may_remove = true,
                }
            }
            if may_remove {
                net_trace!("[{}]: pruning", index);
                *item = None
            }
        }
    }

    /// Iterate every socket in this set.
    pub fn iter<'d>(&'d self) -> Iter<'d, 'a> {
        Iter { lower: self.sockets.iter() }
    }

    /// Iterate every socket in this set, as SocketRef.
    pub fn iter_mut<'d>(&'d mut self) -> IterMut<'d, 'a> {
        IterMut { lower: self.sockets.iter_mut() }
    }
}

/// Immutable socket set iterator.
///
/// This struct is created by the [iter](struct.SocketSet.html#method.iter)
/// on [socket sets](struct.SocketSet.html).
pub struct Iter<'a, 'b: 'a> {
    lower: slice::Iter<'a, Option<Item<'b>>>
}

impl<'a, 'b: 'a> Iterator for Iter<'a, 'b> {
    type Item = &'a Socket<'b>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item_opt) = self.lower.next() {
            if let Some(item) = item_opt.as_ref() {
                return Some(&item.socket)
            }
        }
        None
    }
}

/// Mutable socket set iterator.
///
/// This struct is created by the [iter_mut](struct.SocketSet.html#method.iter_mut)
/// on [socket sets](struct.SocketSet.html).
pub struct IterMut<'a, 'b: 'a> {
    lower: slice::IterMut<'a, Option<Item<'b>>>,
}

impl<'a, 'b: 'a> Iterator for IterMut<'a, 'b> {
    type Item = SocketRef<'a, Socket<'b>>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item_opt) = self.lower.next() {
            if let Some(item) = item_opt.as_mut() {
                return Some(SocketRef::new(&mut item.socket))
            }
        }
        None
    }
}
