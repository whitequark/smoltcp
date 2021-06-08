#![allow(unused)]

pub const SIOCGIFMTU:   libc::c_ulong = 0x8921;
pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
pub const ETH_P_ALL:    libc::c_short = 0x0003;
pub const ETH_P_IEEE802154: libc::c_short = 0x00F6;

pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;
pub const IFF_TUN:      libc::c_int   = 0x0001;
pub const IFF_TAP:      libc::c_int   = 0x0002;
pub const IFF_NO_PI:    libc::c_int   = 0x1000;
