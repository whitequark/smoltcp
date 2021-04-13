#![allow(dead_code, unused)]
use managed::ManagedSlice;

use crate::socket::{PollAt, Socket, SocketHandle, SocketMeta};
use crate::time::{Duration, Instant};
use crate::wire::dns::{Flags, Opcode, Packet, Question, Record, RecordData, Repr, Type};
use crate::wire::{IpAddress, IpEndpoint, IpProtocol, IpRepr, Ipv4Address, UdpRepr};
use crate::{Error, Result};

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 255;
const MAX_ADDRESS_COUNT: usize = 4;
const RETRANSMIT_DELAY: Duration = Duration { millis: 3000 };

// TEMPORARY rand implementation.
// TODO: a real rand.
#[derive(Debug)]
struct Rand {
    val: u16,
}

impl Rand {
    fn new() -> Self {
        Self { val: 0x3874 }
    }

    fn rand(&mut self) -> u16 {
        self.val += 1;
        self.val
    }

    fn rand_port(&mut self) -> u16 {
        loop {
            let port = self.rand();
            if port > 1024 {
                return port;
            }
        }
    }
}

/// State for an in-progress DNS query.
///
/// The only reason this struct is public is to allow the socket state
/// to be allocated externally.
#[derive(Debug)]
pub struct DnsQuery {
    state: State,
    
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    type_: Type,

    port: u16, // UDP port (src for request, dst for response)
    txid: u16, // transaction ID

    retransmit_at: Option<Instant>, // if None, it has never been sent.
    delay: Duration,
}

#[derive(Debug)]
enum State {
    Running,
    Done,
    Failed,
}

/// A handle to an in-progress DNS query.
pub struct QueryHandle(usize);

/// A Domain Name System socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct DnsSocket<'a> {
    pub(crate) meta: SocketMeta,

    servers: ManagedSlice<'a, IpAddress>,
    queries: ManagedSlice<'a, Option<DnsQuery>>,

    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,

    // TEMPORARY rand implementation. TODO
    rand: Rand,
}

impl<'a> DnsSocket<'a> {
    /// Create a DNS socket with the given buffers.
    pub fn new<Q, S>(servers: S, queries: Q) -> DnsSocket<'a>
    where
        S: Into<ManagedSlice<'a, IpAddress>>,
        Q: Into<ManagedSlice<'a, Option<DnsQuery>>>,
    {
        DnsSocket {
            meta: SocketMeta::default(),
            servers: servers.into(),
            queries: queries.into(),
            hop_limit: None,
            rand: Rand::new(),
        }
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    fn find_free_query(&mut self) -> Result<QueryHandle> {
        for (i, q) in self.queries.iter().enumerate() {
            if q.is_none() {
                return Ok(QueryHandle(i));
            }
        }

        match self.queries {
            ManagedSlice::Borrowed(_) => Err(Error::Exhausted),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Ok(QueryHandle(index))
            }
        }
    }

    pub fn query(&mut self, name: &[u8]) -> Result<QueryHandle> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::Truncated);
        }

        let handle = self.find_free_query()?;

        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);

        self.queries[handle.0] = Some(DnsQuery {
            state: State::Running,
            name: name_buf,
            name_len: name.len(),
            type_: Type::A,

            txid: self.rand.rand(),
            port: self.rand.rand_port(),

            delay: RETRANSMIT_DELAY,
            retransmit_at: None,
        });
        Ok(handle)
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        udp_repr.src_port == DNS_PORT
            && self
                .servers
                .iter()
                .any(|server| *server == ip_repr.src_addr())
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> Result<()> {
        debug_assert!(self.accepts(ip_repr, udp_repr));

        let size = udp_repr.payload.len();

        net_trace!(
            "{}: receiving {} octets from {:?}:{}",
            self.meta.handle,
            size,
            ip_repr.src_addr(),
            udp_repr.dst_port
        );

        let p = Packet::new_checked(udp_repr.payload)?;
        if p.opcode() != Opcode::Query {
            net_trace!("{}: unwanted opcode {:?}", self.meta.handle, p.opcode());
        }

        if p.question_count() != 1 {
            net_trace!(
                "{}: bad question count {:?}",
                self.meta.handle,
                p.question_count()
            );
        }

        let q = match self
            .queries
            .iter_mut()
            .flatten()
            .find(|q| udp_repr.dst_port == q.port && p.transaction_id() == q.txid)
        {
            None => {
                net_trace!("{}: no query matched", self.meta.handle);
                return Ok(());
            }
            Some(q) => q,
        };

        let payload = p.payload();
        let (mut payload, question) = Question::parse(payload)?;

        if question.type_ != q.type_ {
            net_trace!("{}: type mismatch", self.meta.handle);
        }
        if !eq_names(
            p.parse_name(question.name),
            p.parse_name(&q.name[..q.name_len]),
        )? {
            net_trace!("{}: question name mismatch", self.meta.handle);
        }

        let mut got_ips = false;

        for _ in 0..p.answer_record_count() {
            let (payload2, r) = Record::parse(payload)?;
            payload = payload2;

            if !eq_names(p.parse_name(r.name), p.parse_name(&q.name[..q.name_len]))? {
                net_trace!("answer name mismatch: {:?}", r);
                continue;
            }

            match r.data {
                RecordData::A(addr) => {
                    net_trace!("A: {:?}", addr);
                    got_ips = true;
                }
                RecordData::AAAA(addr) => {
                    net_trace!("AAAA: {:?}", addr);
                    got_ips = true;
                }
                RecordData::CNAME(name) => {
                    net_trace!("CNAME: {:?}", name);
                    q.name_len = copy_name(&mut q.name, p.parse_name(name))?;

                    // Relaunch query with the new name.
                    // If the server has bundled A records for the CNAME in the same packet,
                    // we'll process them in next iterations, and cancel the query relaunch.
                    q.retransmit_at = None;
                    q.delay = RETRANSMIT_DELAY;
                    q.txid = self.rand.rand();
                    q.port = self.rand.rand_port();
                }
                RecordData::Other(type_, data) => net_trace!("unknown: {:?} {:?}", type_, data),
            }
        }

        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, timestamp: Instant, emit: F) -> Result<()>
    where
        F: FnOnce((IpRepr, UdpRepr)) -> Result<()>,
    {
        net_trace!("poll {:?}", timestamp);
        let handle = self.handle();
        let hop_limit = self.hop_limit.unwrap_or(64);

        for q in self.queries.iter_mut().flatten() {
            if let Some(t) = q.retransmit_at {
                if t > timestamp {
                    // query is waiting for retransmit
                    continue;
                }
            }

            let name = &q.name[..q.name_len];

            let repr = Repr {
                transaction_id: q.txid,
                flags: Flags::RECURSION_DESIRED,
                opcode: Opcode::Query,
                question: Question {
                    name,
                    type_: Type::A,
                },
            };

            let mut buf = [0u8; 512];
            let buf = &mut buf[..repr.buffer_len()];
            repr.emit(&mut Packet::new_unchecked(buf));

            let udp_repr = UdpRepr {
                src_port: q.port,
                dst_port: 53,
                payload: buf,
            };
            let ip_repr = IpRepr::Unspecified {
                src_addr: Ipv4Address::new(192, 168, 69, 1).into(),
                dst_addr: Ipv4Address::new(8, 8, 8, 8).into(),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.buffer_len(),
                hop_limit: hop_limit,
            };

            net_trace!(
                "{}: sending {} octets to {:?}:{}",
                self.meta.handle,
                buf.len(),
                ip_repr.dst_addr(),
                udp_repr.src_port
            );

            if let Err(e) = emit((ip_repr, udp_repr)) {
                net_trace!("DNS emit error {:?}", e);
                return Ok(());
            }

            q.retransmit_at = Some(timestamp + q.delay);
            q.delay *= 2;

            return Ok(());
        }

        // Nothing to dispatch
        Err(Error::Exhausted)
    }

    pub(crate) fn poll_at(&self) -> PollAt {
        self.queries
            .iter()
            .flatten()
            .map(|q| match q.retransmit_at {
                Some(t) => PollAt::Time(t),
                None => PollAt::Now,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

impl<'a> Into<Socket<'a>> for DnsSocket<'a> {
    fn into(self) -> Socket<'a> {
        Socket::Dns(self)
    }
}

fn eq_names<'a>(
    mut a: impl Iterator<Item = Result<&'a [u8]>>,
    mut b: impl Iterator<Item = Result<&'a [u8]>>,
) -> Result<bool> {
    loop {
        match (a.next(), b.next()) {
            // Handle errors
            (Some(Err(e)), _) => return Err(e),
            (_, Some(Err(e))) => return Err(e),

            // Both finished -> equal
            (None, None) => return Ok(true),

            // One finished before the other -> not equal
            (None, _) => return Ok(false),
            (_, None) => return Ok(false),

            // Got two labels, check if they're equal
            (Some(Ok(la)), Some(Ok(lb))) => {
                if la != lb {
                    return Ok(false);
                }
            }
        }
    }
}

fn copy_name<'a>(
    dest: &'a mut [u8],
    name: impl Iterator<Item = Result<&'a [u8]>>,
) -> Result<usize> {
    let mut pos: usize = 0;
    for label in name {
        let label = label?;
        if pos + 1 + label.len() > dest.len() {
            return Err(Error::Truncated);
        }
        dest[pos] = label.len() as u8;
        dest[pos + 1..pos + 1 + label.len()].copy_from_slice(label);
        pos += 1 + label.len();
    }

    // Write terminator 0x00
    if pos + 1 > dest.len() {
        return Err(Error::Truncated);
    }
    dest[pos] = 0;
    pos += 1;

    Ok(pos)
}
