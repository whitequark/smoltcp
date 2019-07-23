// See https://tools.ietf.org/html/rfc2131 for the DHCP specification.

use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use super::{EthernetAddress, Ipv4Address};
use super::arp::Hardware;

const DHCP_MAGIC_NUMBER: u32 = 0x63825363;

enum_with_unknown! {
    /// The possible opcodes of a DHCP packet.
    pub enum OpCode(u8) {
        Request = 1,
        Reply = 2,
    }
}

enum_with_unknown! {
    /// The possible message types of a DHCP packet.
    pub enum MessageType(u8) {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8,
    }
}

impl MessageType {
    fn opcode(&self) -> OpCode {
        match *self {
            MessageType::Discover | MessageType::Inform | MessageType::Request |
                MessageType::Decline | MessageType::Release => OpCode::Request,
            MessageType::Offer | MessageType::Ack | MessageType::Nak => OpCode::Reply,
            MessageType::Unknown(_) => OpCode::Unknown(0),
        }
    }
}

/// A representation of a single DHCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DhcpOption<'a> {
    EndOfList,
    Pad,
    MessageType(MessageType),
    RequestedIp(Ipv4Address),
    ClientIdentifier(EthernetAddress),
    ServerIdentifier(Ipv4Address),
    Router(Ipv4Address),
    SubnetMask(Ipv4Address),
    IpLeaseTime(u32),
    Other { kind: u8, data: &'a [u8] }
}

impl<'a> DhcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], DhcpOption<'a>)> {
        // See https://tools.ietf.org/html/rfc2132 for all possible DHCP options.

        let (skip_len, option);
        match *buffer.get(0).ok_or(Error::Truncated)? {
            field::OPT_END => {
                skip_len = 1;
                option = DhcpOption::EndOfList;
            }
            field::OPT_PAD => {
                skip_len = 1;
                option = DhcpOption::Pad;
            }
            kind => {
                let length = *buffer.get(1).ok_or(Error::Truncated)? as usize;
                skip_len = length + 2;
                let data = buffer.get(2..skip_len).ok_or(Error::Truncated)?;
                match (kind, length) {
                    (field::OPT_END, _) |
                    (field::OPT_PAD, _) =>
                        unreachable!(),
                    (field::OPT_DHCP_MESSAGE_TYPE, 1) => {
                        option = DhcpOption::MessageType(MessageType::from(data[0]));
                    },
                    (field::OPT_REQUESTED_IP, 4) => {
                        option = DhcpOption::RequestedIp(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_CLIENT_ID, 7) => {
                        let hardware_type = Hardware::from(u16::from(data[0]));
                        if hardware_type != Hardware::Ethernet {
                            return Err(Error::Unrecognized);
                        }
                        option = DhcpOption::ClientIdentifier(EthernetAddress::from_bytes(&data[1..]));
                    }
                    (field::OPT_SERVER_IDENTIFIER, 4) => {
                        option = DhcpOption::ServerIdentifier(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_ROUTER, 4) => {
                        option = DhcpOption::Router(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_SUBNET_MASK, 4) => {
                        option = DhcpOption::SubnetMask(Ipv4Address::from_bytes(data));
                    }
                    (_, _) => {
                        option = DhcpOption::Other { kind: kind, data: data };
                    }
                }
            }
        }
        Ok((&buffer[skip_len..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &DhcpOption::EndOfList => 1,
            &DhcpOption::Pad => 1,
            &DhcpOption::MessageType(_) => 3,
            &DhcpOption::ClientIdentifier(eth_addr) => {
                3 + eth_addr.as_bytes().len()
            }
            &DhcpOption::RequestedIp(ip) |
            &DhcpOption::ServerIdentifier(ip) |
            &DhcpOption::Router(ip) |
            &DhcpOption::SubnetMask(ip) => {
                2 + ip.as_bytes().len()
            },
            &DhcpOption::IpLeaseTime(_) => 2 + 4,
            &DhcpOption::Other { data, .. } => 2 + data.len()
        }
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let skip_length;
        match self {
            &DhcpOption::EndOfList => {
                skip_length = 1;
                buffer[0] = field::OPT_END;
            }
            &DhcpOption::Pad => {
                skip_length = 1;
                buffer[0] = field::OPT_PAD;
            }
            _ => {
                skip_length = self.buffer_len();
                buffer[1] = (skip_length - 2) as u8;
                match self {
                    &DhcpOption::EndOfList | &DhcpOption::Pad => unreachable!(),
                    &DhcpOption::MessageType(value) => {
                        buffer[0] = field::OPT_DHCP_MESSAGE_TYPE;
                        buffer[2] = value.into();
                    }
                    &DhcpOption::ClientIdentifier(eth_addr) => {
                        buffer[0] = field::OPT_CLIENT_ID;
                        buffer[2] = u16::from(Hardware::Ethernet) as u8;
                        buffer[3..9].copy_from_slice(eth_addr.as_bytes());
                    }
                    &DhcpOption::RequestedIp(ip)  => {
                        buffer[0] = field::OPT_REQUESTED_IP;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    &DhcpOption::ServerIdentifier(ip)  => {
                        buffer[0] = field::OPT_SERVER_IDENTIFIER;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    &DhcpOption::Router(ip)  => {
                        buffer[0] = field::OPT_ROUTER;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    &DhcpOption::SubnetMask(mask)  => {
                        buffer[0] = field::OPT_SUBNET_MASK;
                        buffer[2..6].copy_from_slice(mask.as_bytes());
                    }
                    &DhcpOption::IpLeaseTime(value) => {
                        buffer[0] = field::OPT_IP_LEASE_TIME;
                        NetworkEndian::write_u32(&mut buffer[2..6], value);
                    }
                    &DhcpOption::Other { kind, data: provided } => {
                        buffer[0] = kind;
                        buffer[2..skip_length].copy_from_slice(provided);
                    }
                }
            }
        }
        &mut buffer[skip_length..]
    }
}

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

pub(crate) mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use wire::field::*;

    pub const OP: usize = 0;
    pub const HTYPE: usize = 1;
    pub const HLEN: usize = 2;
    pub const HOPS: usize = 3;
    pub const XID: Field = 4..8;
    pub const SECS: Field = 8..10;
    pub const FLAGS: Field = 10..12;
    pub const CIADDR: Field = 12..16;
    pub const YIADDR: Field = 16..20;
    pub const SIADDR: Field = 20..24;
    pub const GIADDR: Field = 24..28;
    pub const CHADDR: Field = 28..34;
    pub const SNAME: Field = 34..108;
    pub const FILE: Field = 108..236;
    pub const MAGIC_NUMBER: Field = 236..240;
    pub const OPTIONS: Rest = 240..;

    // Vendor Extensions
    pub const OPT_END: u8 = 255;
    pub const OPT_PAD: u8 = 0;
    pub const OPT_SUBNET_MASK: u8 = 1;
    pub const OPT_TIME_OFFSET: u8 = 2;
    pub const OPT_ROUTER: u8 = 3;
    pub const OPT_TIME_SERVER: u8 = 4;
    pub const OPT_NAME_SERVER: u8 = 5;
    pub const OPT_DOMAIN_NAME_SERVER: u8 = 6;
    pub const OPT_LOG_SERVER: u8 = 7;
    pub const OPT_COOKIE_SERVER: u8 = 8;
    pub const OPT_LPR_SERVER: u8 = 9;
    pub const OPT_IMPRESS_SERVER: u8 = 10;
    pub const OPT_RESOURCE_LOCATION_SERVER: u8 = 11;
    pub const OPT_HOST_NAME: u8 = 12;
    pub const OPT_BOOT_FILE_SIZE: u8 = 13;
    pub const OPT_MERIT_DUMP: u8 = 14;
    pub const OPT_DOMAIN_NAME: u8 = 15;
    pub const OPT_SWAP_SERVER: u8 = 16;
    pub const OPT_ROOT_PATH: u8 = 17;
    pub const OPT_EXTENSIONS_PATH: u8 = 18;

    // IP Layer Parameters per Host
    pub const OPT_IP_FORWARDING: u8 = 19;
    pub const OPT_NON_LOCAL_SOURCE_ROUTING: u8 = 20;
    pub const OPT_POLICY_FILTER: u8 = 21;
    pub const OPT_MAX_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
    pub const OPT_DEFAULT_TTL: u8 = 23;
    pub const OPT_PATH_MTU_AGING_TIMEOUT: u8 = 24;
    pub const OPT_PATH_MTU_PLATEU_TABLE: u8 = 25;

    // IP Layer Parameters per Interface
    pub const OPT_INTERFACE_MTU: u8 = 26;
    pub const OPT_ALL_SUBNETS_ARE_LOCAL: u8 = 27;
    pub const OPT_BROADCAST_ADDRESS: u8 = 28;
    pub const OPT_PERFORM_MASK_DISCOVERY: u8 = 29;
    pub const OPT_MASK_SUPPLIER: u8 = 30;
    pub const OPT_PERFORM_ROUTER_DISCOVERY: u8 = 31;
    pub const OPT_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
    pub const OPT_STATIC_ROUTE: u8 = 33;

    // Link Layer Parameters per Interface
    pub const OPT_TRAILER_ENCAPSULATION: u8 = 34;
    pub const OPT_ARP_CACHE_TIMEOUT: u8 = 35;
    pub const OPT_ETHERNET_ENCAPSULATION: u8 = 36;

    // TCP Parameters
    pub const OPT_TCP_DEFAULT_TTL: u8 = 37;
    pub const OPT_TCP_KEEPALIVE_INTERVAL: u8 = 38;
    pub const OPT_TCP_KEEPALIVE_GARBAGE: u8 = 39;

    // Application and Service Parameters
    pub const OPT_NIS_DOMAIN: u8 = 40;
    pub const OPT_NIS_SERVERS: u8 = 41;
    pub const OPT_NTP_SERVERS: u8 = 42;
    pub const OPT_VENDOR_SPECIFIC_INFO: u8 = 43;
    pub const OPT_NETBIOS_NAME_SERVER: u8 = 44;
    pub const OPT_NETBIOS_DISTRIBUTION_SERVER: u8 = 45;
    pub const OPT_NETBIOS_NODE_TYPE: u8 = 46;
    pub const OPT_NETBIOS_SCOPE: u8 = 47;
    pub const OPT_X_WINDOW_FONT_SERVER: u8 = 48;
    pub const OPT_X_WINDOW_DISPLAY_MANAGER: u8 = 49;
    pub const OPT_NIS_PLUS_DOMAIN: u8 = 64;
    pub const OPT_NIS_PLUS_SERVERS: u8 = 65;
    pub const OPT_MOBILE_IP_HOME_AGENT: u8 = 68;
    pub const OPT_SMTP_SERVER: u8 = 69;
    pub const OPT_POP3_SERVER: u8 = 70;
    pub const OPT_NNTP_SERVER: u8 = 71;
    pub const OPT_WWW_SERVER: u8 = 72;
    pub const OPT_FINGER_SERVER: u8 = 73;
    pub const OPT_IRC_SERVER: u8 = 74;
    pub const OPT_STREETTALK_SERVER: u8 = 75;
    pub const OPT_STDA_SERVER: u8 = 76;

    // DHCP Extensions
    pub const OPT_REQUESTED_IP: u8 = 50;
    pub const OPT_IP_LEASE_TIME: u8 = 51;
    pub const OPT_OPTION_OVERLOAD: u8 = 52;
    pub const OPT_TFTP_SERVER_NAME: u8 = 66;
    pub const OPT_BOOTFILE_NAME: u8 = 67;
    pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
    pub const OPT_SERVER_IDENTIFIER: u8 = 54;
    pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
    pub const OPT_MESSAGE: u8 = 56;
    pub const OPT_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
    pub const OPT_RENEWAL_TIME_VALUE: u8 = 58;
    pub const OPT_REBINDING_TIME_VALUE: u8 = 59;
    pub const OPT_VENDOR_CLASS_ID: u8 = 60;
    pub const OPT_CLIENT_ID: u8 = 61;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with DHCP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::MAGIC_NUMBER.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns the operation code of this packet.
    pub fn opcode(&self) -> OpCode {
        let data = self.buffer.as_ref();
        OpCode::from(data[field::OP])
    }

    /// Returns the hardware protocol type (e.g. ethernet).
    pub fn hardware_type(&self) -> Hardware {
        let data = self.buffer.as_ref();
        Hardware::from(u16::from(data[field::HTYPE]))
    }

    /// Returns the length of a hardware address in bytes (e.g. 6 for ethernet).
    pub fn hardware_len(&self) -> u8 {
        self.buffer.as_ref()[field::HLEN]
    }

    /// Returns the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn transaction_id(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::XID];
        NetworkEndian::read_u32(field)
    }

    /// Returns the hardware address of the client (called `chaddr` in the specification).
    ///
    /// Only ethernet is supported by `smoltcp`, so this functions returns
    /// an `EthernetAddress`.
    pub fn client_hardware_address(&self) -> EthernetAddress {
        let field = &self.buffer.as_ref()[field::CHADDR];
        EthernetAddress::from_bytes(field)
    }

    /// Returns the value of the `hops` field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn hops(&self) -> u8 {
        self.buffer.as_ref()[field::HOPS]
    }

    /// Returns the value of the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn secs(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::SECS];
        NetworkEndian::read_u16(field)
    }

    /// Returns the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn magic_number(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::MAGIC_NUMBER];
        NetworkEndian::read_u32(field)
    }

    /// Returns the Ipv4 address of the client, zero if not set.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn client_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::CIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `yiaddr` field, zero if not set.
    pub fn your_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::YIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `siaddr` field, zero if not set.
    pub fn server_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::SIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `giaddr` field, zero if not set.
    pub fn relay_agent_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::GIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns true if the broadcast flag is set.
    pub fn broadcast_flag(&self) -> bool {
        let field = &self.buffer.as_ref()[field::FLAGS];
        NetworkEndian::read_u16(field) & 0b1 == 0b1
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> Result<&'a [u8]> {
        let data = self.buffer.as_ref();
        data.get(field::OPTIONS).ok_or(Error::Malformed)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the optional `sname` (“server name”) and `file` (“boot file name”) fields to zero.
    ///
    /// The fields are not commonly used, so we set their value always to zero. **This method
    /// must be called when creating a packet, otherwise the emitted values for these fields
    /// are undefined!**
    pub fn set_sname_and_boot_file_to_zero(&mut self) {
        let data = self.buffer.as_mut();
        for byte in &mut data[field::SNAME] {
            *byte = 0;
        }
        for byte in &mut data[field::FILE] {
            *byte = 0;
        }
    }

    /// Sets the `OpCode` for the packet.
    pub fn set_opcode(&mut self, value: OpCode) {
        let data = self.buffer.as_mut();
        data[field::OP] = value.into();
    }

    /// Sets the hardware address type (only ethernet is supported).
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let data = self.buffer.as_mut();
        let number: u16 = value.into();
        assert!(number <= u16::from(u8::max_value())); // TODO: Replace with TryFrom when it's stable
        data[field::HTYPE] = number as u8;
    }

    /// Sets the hardware address length.
    ///
    /// Only ethernet is supported, so this field should be set to the value `6`.
    pub fn set_hardware_len(&mut self, value: u8) {
        self.buffer.as_mut()[field::HLEN] = value;
    }

    /// Sets the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn set_transaction_id(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::XID];
        NetworkEndian::write_u32(field, value)
    }

    /// Sets the ethernet address of the client.
    ///
    /// Sets the `chaddr` field.
    pub fn set_client_hardware_address(&mut self, value: EthernetAddress) {
        let field = &mut self.buffer.as_mut()[field::CHADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the hops field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn set_hops(&mut self, value: u8) {
        self.buffer.as_mut()[field::HOPS] = value;
    }

    /// Sets the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn set_secs(&mut self, value: u16) {
        let field = &mut self.buffer.as_mut()[field::SECS];
        NetworkEndian::write_u16(field, value);
    }

    /// Sets the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn set_magic_number(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::MAGIC_NUMBER];
        NetworkEndian::write_u32(field, value);
    }

    /// Sets the Ipv4 address of the client.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn set_client_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::CIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `yiaddr` field.
    pub fn set_your_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::YIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `siaddr` field.
    pub fn set_server_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::SIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `giaddr` field.
    pub fn set_relay_agent_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::GIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the broadcast flag to the specified value.
    pub fn set_broadcast_flag(&mut self, value: bool) {
        let field = &mut self.buffer.as_mut()[field::FLAGS];
        NetworkEndian::write_u16(field, if value { 1 } else { 0 });
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> Result<&mut [u8]> {
        let data = self.buffer.as_mut();
        data.get_mut(field::OPTIONS).ok_or(Error::Truncated)
    }
}

/// A high-level representation of a Dynamic Host Configuration Protocol packet.
///
/// DHCP messages have the following layout (see [RFC 2131](https://tools.ietf.org/html/rfc2131)
/// for details):
///
/// ```no_rust
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | message_type  | htype (N/A)   |   hlen (N/A)  |   hops        |
/// +---------------+---------------+---------------+---------------+
/// |                       transaction_id                          |
/// +-------------------------------+-------------------------------+
/// |           secs                |           flags               |
/// +-------------------------------+-------------------------------+
/// |                           client_ip                           |
/// +---------------------------------------------------------------+
/// |                            your_ip                            |
/// +---------------------------------------------------------------+
/// |                           server_ip                           |
/// +---------------------------------------------------------------+
/// |                        relay_agent_ip                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                    client_hardware_address                    |
/// |                                                               |
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          sname  (N/A)                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          file    (N/A)                        |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          options                              |
/// +---------------------------------------------------------------+
/// ```
///
/// It is assumed that the access layer is Ethernet, so `htype` (the field representing the
/// hardware address type) is always set to `1`, and `hlen` (which represents the hardware address
/// length) is set to `6`.
///
/// The `options` field has a variable length.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    /// This field is also known as `op` in the RFC. It indicates the type of DHCP message this
    /// packet represents.
    pub message_type: MessageType,
    /// This field is also known as `xid` in the RFC. It is a random number chosen by the client,
    /// used by the client and server to associate messages and responses between a client and a
    /// server.
    pub transaction_id: u32,
    /// This field is also known as `chaddr` in the RFC and for networks where the access layer is
    /// ethernet, it is the client MAC address.
    pub client_hardware_address: EthernetAddress,
    /// This field is also known as `ciaddr` in the RFC. It is only filled in if client is in
    /// BOUND, RENEW or REBINDING state and can respond to ARP requests.
    pub client_ip: Ipv4Address,
    /// This field is also known as `yiaddr` in the RFC.
    pub your_ip: Ipv4Address,
    /// This field is also known as `siaddr` in the RFC. It may be set by the server in DHCPOFFER
    /// and DHCPACK messages, and represent the address of the next server to use in bootstrap.
    pub server_ip: Ipv4Address,
    /// Default gateway
    pub router: Option<Ipv4Address>,
    /// This field comes from a corresponding DhcpOption.
    pub subnet_mask: Option<Ipv4Address>,
    /// This field is also known as `giaddr` in the RFC. In order to allow DHCP clients on subnets
    /// not directly served by DHCP servers to communicate with DHCP servers, DHCP relay agents can
    /// be installed on these subnets. The DHCP client broadcasts on the local link; the relay
    /// agent receives the broadcast and transmits it to one or more DHCP servers using unicast.
    /// The relay agent stores its own IP address in the `relay_agent_ip` field of the DHCP packet.
    /// The DHCP server uses the `relay_agent_ip` to determine the subnet on which the relay agent
    /// received the broadcast, and allocates an IP address on that subnet. When the DHCP server
    /// replies to the client, it sends the reply to the `relay_agent_ip` address, again using
    /// unicast. The relay agent then retransmits the response on the local network
    pub relay_agent_ip: Ipv4Address,
    /// Broadcast flags. It can be set in DHCPDISCOVER, DHCPINFORM and DHCPREQUEST message if the
    /// client requires the response to be broadcasted.
    pub broadcast: bool,
    /// The "requested IP address" option. It can be used by clients in DHCPREQUEST or DHCPDISCOVER
    /// messages, or by servers in DHCPDECLINE messages.
    pub requested_ip: Option<Ipv4Address>,
    /// The "client identifier" option.
    ///
    /// The 'client identifier' is an opaque key, not to be interpreted by the server; for example,
    /// the 'client identifier' may contain a hardware address, identical to the contents of the
    /// 'chaddr' field, or it may contain another type of identifier, such as a DNS name.  The
    /// 'client identifier' chosen by a DHCP client MUST be unique to that client within the subnet
    /// to which the client is attached. If the client uses a 'client identifier' in one message,
    /// it MUST use that same identifier in all subsequent messages, to ensure that all servers
    /// correctly identify the client.
    pub client_identifier: Option<EthernetAddress>,
    /// The "server identifier" option. It is used both to identify a DHCP server
    /// in a DHCP message and as a destination address from clients to servers.
    pub server_identifier: Option<Ipv4Address>,
    /// The parameter request list informs the server about which configuration parameters
    /// the client is interested in.
    pub parameter_request_list: Option<&'a [u8]>,
    /// DNS servers
    pub dns_servers: Option<[Option<Ipv4Address>; 3]>,
    /// IP Address Lease Time
    pub ip_lease_time: Option<u32>,
}

impl<'a> Default for Repr<'a> {
    fn default() -> Self {
        Self {
            message_type: MessageType::Unknown(0),
            transaction_id: 0,
            client_hardware_address: Default::default(),
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: false,
            requested_ip: None,
            client_identifier: None,
            server_identifier: None,
            parameter_request_list: None,
            dns_servers: None,
            ip_lease_time: None,
        }
    }
 }

impl<'a> Repr<'a> {
    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let mut len = field::OPTIONS.start;
        // message type and end-of-options options
        len += 3 + 1;
        if self.requested_ip.is_some() { len += 6; }
        if self.client_identifier.is_some() { len += 9; }
        if self.server_identifier.is_some() { len += 6; }
        if self.subnet_mask.is_some() { len += 6; }
        if let Some(value) = self.router {
            len += DhcpOption::Router(value).buffer_len();
        }
        if let Some(value) = self.ip_lease_time {
            len += DhcpOption::IpLeaseTime(value).buffer_len();
        }
        if let Some(list) = self.parameter_request_list { len += list.len() + 2; }
        if let Some(servers) = self.dns_servers {
            len += servers.iter().filter(|s| s.is_some()).count() * 4 + 2;
        }

        len
    }

    /// Parse a DHCP packet and return a high-level representation.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Self>
            where T: AsRef<[u8]> + ?Sized {

        let transaction_id = packet.transaction_id();
        let client_hardware_address = packet.client_hardware_address();
        let client_ip = packet.client_ip();
        let your_ip = packet.your_ip();
        let server_ip = packet.server_ip();
        let relay_agent_ip = packet.relay_agent_ip();

        // only ethernet is supported right now
        match packet.hardware_type() {
            Hardware::Ethernet => {
                if packet.hardware_len() != 6 {
                    return Err(Error::Malformed);
                }
            }
            Hardware::Unknown(_) => return Err(Error::Unrecognized), // unimplemented
        }

        if packet.magic_number() != DHCP_MAGIC_NUMBER {
            return Err(Error::Malformed);
        }

        let mut message_type = Err(Error::Malformed);
        let mut requested_ip = None;
        let mut client_identifier = None;
        let mut server_identifier = None;
        let mut router = None;
        let mut subnet_mask = None;
        let mut parameter_request_list = None;
        let mut dns_servers = None;
        let mut ip_lease_time = None;

        let mut options = packet.options()?;
        while options.len() > 0 {
            let (next_options, option) = DhcpOption::parse(options)?;
            match option {
                DhcpOption::EndOfList => break,
                DhcpOption::Pad => {},
                DhcpOption::MessageType(value) => {
                    if value.opcode() == packet.opcode() {
                        message_type = Ok(value);
                    }
                },
                DhcpOption::RequestedIp(ip) => {
                    requested_ip = Some(ip);
                }
                DhcpOption::ClientIdentifier(eth_addr) => {
                    client_identifier = Some(eth_addr);
                }
                DhcpOption::ServerIdentifier(ip) => {
                    server_identifier = Some(ip);
                }
                DhcpOption::Router(ip) => {
                    router = Some(ip);
                }
                DhcpOption::SubnetMask(mask) => {
                    subnet_mask = Some(mask);
                }
                DhcpOption::IpLeaseTime(value) => {
                    ip_lease_time = Some(value);
                }
                DhcpOption::Other {kind: field::OPT_PARAMETER_REQUEST_LIST, data} => {
                    parameter_request_list = Some(data);
                }
                DhcpOption::Other {kind: field::OPT_DOMAIN_NAME_SERVER, data} => {
                    let mut dns_servers_inner = [None; 3];
                    for i in 0.. {
                        let offset = 4 * i;
                        let end = offset + 4;
                        if end > data.len() { break }
                        dns_servers_inner[i] = Some(Ipv4Address::from_bytes(&data[offset..end]));
                    }
                    dns_servers = Some(dns_servers_inner);
                }
                DhcpOption::Other {..} => {}
            }
            options = next_options;
        }

        let broadcast = packet.broadcast_flag();

        Ok(Repr {
            transaction_id, client_hardware_address, client_ip, your_ip, server_ip, relay_agent_ip,
            broadcast, requested_ip, server_identifier, router,
            subnet_mask, client_identifier, parameter_request_list, dns_servers, ip_lease_time,
            message_type: message_type?,
        })
    }

    /// Emit a high-level representation into a Dynamic Host
    /// Configuration Protocol packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>) -> Result<()>
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        packet.set_sname_and_boot_file_to_zero();
        packet.set_opcode(self.message_type.opcode());
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_hardware_len(6);
        packet.set_transaction_id(self.transaction_id);
        packet.set_client_hardware_address(self.client_hardware_address);
        packet.set_hops(0);
        packet.set_secs(0); // TODO
        packet.set_magic_number(0x63825363);
        packet.set_client_ip(self.client_ip);
        packet.set_your_ip(self.your_ip);
        packet.set_server_ip(self.server_ip);
        packet.set_relay_agent_ip(self.relay_agent_ip);
        packet.set_broadcast_flag(self.broadcast);

        {
            let mut options = packet.options_mut()?;
            let tmp = options; options = DhcpOption::MessageType(self.message_type).emit(tmp);
            if let Some(eth_addr) = self.client_identifier {
                let tmp = options; options = DhcpOption::ClientIdentifier(eth_addr).emit(tmp);
            }
            if let Some(ip) = self.server_identifier {
                let tmp = options; options = DhcpOption::ServerIdentifier(ip).emit(tmp);
            }
            if let Some(ip) = self.router {
                let tmp = options; options = DhcpOption::Router(ip).emit(tmp);
            }
            if let Some(ip) = self.subnet_mask {
                let tmp = options; options = DhcpOption::SubnetMask(ip).emit(tmp);
            }
            if let Some(ip) = self.requested_ip {
                let tmp = options; options = DhcpOption::RequestedIp(ip).emit(tmp);
            }
            if let Some(list) = self.parameter_request_list {
                let option = DhcpOption::Other{ kind: field::OPT_PARAMETER_REQUEST_LIST, data: list };
                let tmp = options; options = option.emit(tmp);
            }
            if let Some(dns_servers) = self.dns_servers {
                let mut data: [u8; 3 * 4] = Default::default();
                let mut i = 0;
                while i < dns_servers.len() {
                    if let Some(dns_server) = dns_servers[i] {
                        data[i * 4..(i + 1) * 4].copy_from_slice(dns_server.as_bytes());
                    } else {
                        break;
                    }
                    i += 1;
                }
                let option = DhcpOption::Other {
                    kind: field::OPT_DOMAIN_NAME_SERVER,
                    data: &data[0..i * 4],
                };
                let tmp = options;
                options = option.emit(tmp);
            }
            if let Some(value) = self.ip_lease_time {
                let tmp = options;
                options = DhcpOption::IpLeaseTime(value).emit(tmp);
            }
            DhcpOption::EndOfList.emit(options);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use wire::Ipv4Address;
    use super::*;

    const MAGIC_COOKIE: u32 = 0x63825363;

    static DISCOVER_BYTES: &[u8] = &[
        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x82, 0x01,
        0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x32, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x37, 0x04, 0x01, 0x03, 0x06, 0x2a, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const IP_NULL: Ipv4Address = Ipv4Address([0, 0, 0, 0]);
    const CLIENT_MAC: EthernetAddress = EthernetAddress([0x0, 0x0b, 0x82, 0x01, 0xfc, 0x42]);

    #[test]
    fn test_deconstruct_discover() {
        let packet = Packet::new_unchecked(DISCOVER_BYTES);
        assert_eq!(packet.magic_number(), MAGIC_COOKIE);
        assert_eq!(packet.opcode(), OpCode::Request);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.hops(), 0);
        assert_eq!(packet.transaction_id(), 0x3d1d);
        assert_eq!(packet.secs(), 0);
        assert_eq!(packet.client_ip(), IP_NULL);
        assert_eq!(packet.your_ip(), IP_NULL);
        assert_eq!(packet.server_ip(), IP_NULL);
        assert_eq!(packet.relay_agent_ip(), IP_NULL);
        assert_eq!(packet.client_hardware_address(), CLIENT_MAC);
        let options = packet.options().unwrap();
        assert_eq!(options.len(), 3 + 9 + 6 + 6 + 1 + 7);

        let (options, message_type) = DhcpOption::parse(options).unwrap();
        assert_eq!(message_type, DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(options.len(), 9 + 6 + 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::ClientIdentifier(CLIENT_MAC));
        assert_eq!(options.len(), 6 + 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::RequestedIp(IP_NULL));
        assert_eq!(options.len(), 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::Other {
            kind: field::OPT_PARAMETER_REQUEST_LIST, data: &[1, 3, 6, 42]
        });
        assert_eq!(options.len(), 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::EndOfList);
        assert_eq!(options.len(), 7); // padding
    }

    #[test]
    fn test_construct_discover() {
        let mut bytes = vec![0xa5; 272];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_magic_number(MAGIC_COOKIE);
        packet.set_sname_and_boot_file_to_zero();
        packet.set_opcode(OpCode::Request);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_hardware_len(6);
        packet.set_hops(0);
        packet.set_transaction_id(0x3d1d);
        packet.set_secs(0);
        packet.set_broadcast_flag(false);
        packet.set_client_ip(IP_NULL);
        packet.set_your_ip(IP_NULL);
        packet.set_server_ip(IP_NULL);
        packet.set_relay_agent_ip(IP_NULL);
        packet.set_client_hardware_address(CLIENT_MAC);

        {
            let mut options = packet.options_mut().unwrap();
            let tmp = options; options = DhcpOption::MessageType(MessageType::Discover).emit(tmp);
            let tmp = options; options = DhcpOption::ClientIdentifier(CLIENT_MAC).emit(tmp);
            let tmp = options; options = DhcpOption::RequestedIp(IP_NULL).emit(tmp);
            let option = DhcpOption::Other {
                kind: field::OPT_PARAMETER_REQUEST_LIST, data: &[1, 3, 6, 42],
            };
            let tmp = options; options = option.emit(tmp);
            DhcpOption::EndOfList.emit(options);
        }

        let packet = &mut packet.into_inner()[..];
        for byte in &mut packet[265..272] {
            *byte = 0; // padding bytes
        }

        assert_eq!(packet, DISCOVER_BYTES);
    }

    fn discover_repr() -> Repr<'static> {
        Repr {
            message_type: MessageType::Discover,
            transaction_id: 0x3d1d,
            client_hardware_address: CLIENT_MAC,
            client_ip: IP_NULL,
            your_ip: IP_NULL,
            server_ip: IP_NULL,
            router: None,
            subnet_mask: None,
            relay_agent_ip: IP_NULL,
            broadcast: false,
            requested_ip: Some(IP_NULL),
            client_identifier: Some(CLIENT_MAC),
            server_identifier: None,
            parameter_request_list: Some(&[1, 3, 6, 42]),
            dns_servers: None,
        }
    }

    #[test]
    fn test_parse_discover() {
        let packet = Packet::new_unchecked(DISCOVER_BYTES);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, discover_repr());
    }

    #[test]
    fn test_emit_discover() {
        let repr = discover_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet).unwrap();
        let packet = &packet.into_inner()[..];
        let packet_len = packet.len();
        assert_eq!(packet, &DISCOVER_BYTES[..packet_len]);
        for byte in &DISCOVER_BYTES[packet_len..] {
            assert_eq!(*byte, 0); // padding bytes
        }
    }

    #[test]
    fn test_emit_dhcp_option() {
        static DATA: &[u8] = &[1, 3, 6];
        let mut bytes = vec![0xa5; 5];
        let dhcp_option = DhcpOption::Other {
            kind: field::OPT_PARAMETER_REQUEST_LIST,
            data: DATA,
        };
        {
            let rest = dhcp_option.emit(&mut bytes);
            assert_eq!(rest.len(), 0);
        }
        assert_eq!(&bytes[0..2], &[field::OPT_PARAMETER_REQUEST_LIST, DATA.len() as u8]);
        assert_eq!(&bytes[2..], DATA);
    }
}
