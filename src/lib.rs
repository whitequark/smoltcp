#![cfg_attr(feature = "alloc", feature(alloc))]
#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(any(feature = "proto-ipv4", feature = "proto-ipv6"), deny(unused))]

//! The _smoltcp_ library is built in a layered structure, with the layers corresponding
//! to the levels of API abstraction. Only the highest layers would be used by a typical
//! application; however, the goal of _smoltcp_ is not just to provide a simple interface
//! for writing applications but also to be a toolbox of networking primitives, so
//! every layer is fully exposed and documented.
//!
//! When discussing networking stacks and layering, often the [OSI model][osi] is invoked.
//! _smoltcp_ makes no effort to conform to the OSI model as it is not applicable to TCP/IP.
//!
//! # The socket layer
//! The socket layer APIs are provided in the module [socket](socket/index.html); currently,
//! raw, ICMP, TCP, and UDP sockets are provided. The socket API provides the usual primitives,
//! but necessarily differs in many from the [Berkeley socket API][berk], as the latter was
//! not designed to be used without heap allocation.
//!
//! The socket layer provides the buffering, packet construction and validation, and (for
//! stateful sockets) the state machines, but it is interface-agnostic. An application must
//! use sockets together with a network interface.
//!
//! # The interface layer
//! The interface layer APIs are provided in the module [iface](iface/index.html); currently,
//! Ethernet interface is provided.
//!
//! The interface layer handles the control messages, physical addressing and neighbor discovery.
//! It routes packets to and from sockets.
//!
//! # The physical layer
//! The physical layer APIs are provided in the module [phy](phy/index.html); currently,
//! raw socket and TAP interface are provided. In addition, two _middleware_ interfaces
//! are provided: the _tracer device_, which prints a human-readable representation of packets,
//! and the _fault injector device_, which randomly introduces errors into the transmitted
//! and received packet sequences.
//!
//! The physical layer handles interaction with a platform-specific network device.
//!
//! # The wire layers
//! Unlike the higher layers, the wire layer APIs will not be used by a typical application.
//! They however are the bedrock of _smoltcp_, and everything else is built on top of them.
//!
//! The wire layer APIs are designed by the principle "make illegal states irrepresentable".
//! If a wire layer object can be constructed, then it can also be parsed from or emitted to
//! a lower level.
//!
//! The wire layer APIs also provide _tcpdump_-like pretty printing.
//!
//! ## The representation layer
//! The representation layer APIs are provided in the module [wire].
//!
//! The representation layer exists to reduce the state space of raw packets. Raw packets
//! may be nonsensical in a multitude of ways: invalid checksums, impossible combinations of flags,
//! pointers to fields out of bounds, meaningless options... Representations shed all that,
//! as well as any features not supported by _smoltcp_.
//!
//! ## The packet layer
//! The packet layer APIs are also provided in the module [wire].
//!
//! The packet layer exists to provide a more structured way to work with packets than
//! treating them as sequences of octets. It makes no judgement as to content of the packets,
//! except where necessary to provide safe access to fields, and strives to implement every
//! feature ever defined, to ensure that, when the representation layer is unable to make sense
//! of a packet, it is still logged correctly and in full.
//!
//! ## Packet and representation layer support
//!  | Protocol | Packet | Representation |
//!  |----------|--------|----------------|
//!  | Ethernet | Yes    | Yes            |
//!  | ARP      | Yes    | Yes            |
//!  | IPv4     | Yes    | Yes            |
//!  | ICMPv4   | Yes    | Yes            |
//!  | IGMPv1/2 | Yes    | Yes            |
//!  | IPv6     | Yes    | Yes            |
//!  | ICMPv6   | Yes    | Yes            |
//!  | TCP      | Yes    | Yes            |
//!  | UDP      | Yes    | Yes            |
//!
//! [wire]: wire/index.html
//! [osi]: https://en.wikipedia.org/wiki/OSI_model
//! [berk]: https://en.wikipedia.org/wiki/Berkeley_sockets

/* XXX compiler bug
#![cfg(not(any(feature = "socket-raw",
               feature = "socket-udp",
               feature = "socket-tcp")))]
compile_error!("at least one socket needs to be enabled"); */

// FIXME(dlrobertson): clippy fails with this lint
#![cfg_attr(feature = "cargo-clippy", allow(if_same_then_else))]

#[cfg(feature = "proto-ipv6")]
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate managed;
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(any(feature = "phy-raw_socket", feature = "phy-tap_interface"))]
extern crate libc;
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "log")]
#[macro_use(log, trace, debug)]
extern crate log;

use core::fmt;

#[macro_use]
mod macros;
mod parsers;

pub mod storage;
pub mod phy;
pub mod wire;
pub mod iface;
pub mod socket;
pub mod time;

/// The error type for the networking stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An operation is not permitted in the current state.
    Illegal,
    /// An endpoint or address of a remote host could not be translated to a lower level address.
    /// E.g. there was no an Ethernet address corresponding to an IPv4 address in the ARP cache,
    /// or a TCP connection attempt was made to an unspecified endpoint.
    Unaddressable,

    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
    /// An incoming packet had an incorrect checksum and was dropped.
    Checksum,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming IP packet has been split into several IP fragments and was dropped,
    /// since IP reassembly is not supported.
    Fragmented,
    /// An incoming packet was recognized but was self-contradictory.
    /// E.g. a TCP packet with both SYN and FIN flags set.
    Malformed,
    /// An incoming packet was recognized but contradicted internal state.
    /// E.g. a TCP packet addressed to a socket that doesn't exist.
    Dropped,

    /// Fragmentation was enabled, but no FragmentSet was provided
    NoFragmentSet,
    /// FragmentSet full
    FragmentSetFull,
    /// Fragment reassembly error, typically too many fragments
    TooManyFragments,

    #[doc(hidden)]
    __Nonexhaustive
}

/// The result type for the networking stack.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Exhausted     => write!(f, "buffer space exhausted"),
            &Error::Illegal       => write!(f, "illegal operation"),
            &Error::Unaddressable => write!(f, "unaddressable destination"),
            &Error::Truncated     => write!(f, "truncated packet"),
            &Error::Checksum      => write!(f, "checksum error"),
            &Error::Unrecognized  => write!(f, "unrecognized packet"),
            &Error::Fragmented    => write!(f, "fragmented packet"),
            &Error::Malformed     => write!(f, "malformed packet"),
            &Error::Dropped       => write!(f, "dropped by socket"),
            &Error::NoFragmentSet => write!(f, "no fragment set provided"),
            &Error::FragmentSetFull => write!(f, "fragment set full"),
            &Error::TooManyFragments => write!(f, "too many fragments"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
