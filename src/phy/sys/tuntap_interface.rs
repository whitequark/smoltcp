use std::io;
use std::os::unix::io::{RawFd, AsRawFd};
use super::*;
use crate::{phy::Medium, wire::EthernetFrame};

#[derive(Debug)]
pub struct TunTapInterfaceDesc {
    lower: libc::c_int,
    ifreq: ifreq,
    medium: Medium,
}

impl AsRawFd for TunTapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl TunTapInterfaceDesc {
    pub fn new(name: &str, medium: Medium) -> io::Result<TunTapInterfaceDesc> {
        let lower = unsafe {
            let lower = libc::open("/dev/net/tun\0".as_ptr() as *const libc::c_char,
                                   libc::O_RDWR | libc::O_NONBLOCK);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        Ok(TunTapInterfaceDesc {
            lower,
            ifreq: ifreq_for(name),
            medium,
        })
    }

    pub fn attach_interface(&mut self) -> io::Result<()> {
        let mode = match self.medium {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => imp::IFF_TUN,
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => imp::IFF_TAP,
            #[cfg(feature = "medium-sixlowpan")]
            Medium::Sixlowpan => todo!(),
        };
        self.ifreq.ifr_data = mode | imp::IFF_NO_PI;
        ifreq_ioctl(self.lower, &mut self.ifreq, imp::TUNSETIFF).map(|_| ())
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        let lower = unsafe {
            let lower = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        let ip_mtu = ifreq_ioctl(lower, &mut self.ifreq, imp::SIOCGIFMTU).map(|mtu| mtu as usize);

        unsafe { libc::close(lower); }

        // Propagate error after close, to ensure we always close.
        let ip_mtu = ip_mtu?;

        // SIOCGIFMTU returns the IP MTU (typically 1500 bytes.)
        // smoltcp counts the entire Ethernet packet in the MTU, so add the Ethernet header size to it.
        let mtu = match self.medium {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => ip_mtu,
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => ip_mtu + EthernetFrame::<&[u8]>::header_len(),
            #[cfg(feature = "medium-sixlowpan")]
            Medium::Sixlowpan => todo!(),
        };

        Ok(mtu)
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::read(self.lower, buffer.as_mut_ptr() as *mut libc::c_void,
                                 buffer.len());
            if len == -1 { return Err(io::Error::last_os_error()) }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::write(self.lower, buffer.as_ptr() as *const libc::c_void,
                                  buffer.len());
            if len == -1 { Err(io::Error::last_os_error()).unwrap() }
            Ok(len as usize)
        }
    }
}

impl Drop for TunTapInterfaceDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}
