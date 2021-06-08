use std::{mem, io};
use std::os::unix::io::{RawFd, AsRawFd};
use super::*;

#[derive(Debug)]
pub struct RawSocketDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

impl AsRawFd for RawSocketDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl RawSocketDesc {
    pub fn new(name: &str) -> io::Result<RawSocketDesc> {
        let lower = unsafe {
            #[cfg(feature = "medium-sixlowpan")]
            let protocol = imp::ETH_P_IEEE802154;

            #[cfg(feature = "medium-ethernet")]
            let protocol = imp::ETH_P_ALL;

            let lower = libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                                     protocol.to_be() as i32);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        Ok(RawSocketDesc {
            lower: lower,
            ifreq: ifreq_for(name)
        })
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        ifreq_ioctl(self.lower, &mut self.ifreq, imp::SIOCGIFMTU).map(|mtu| mtu as usize)
    }

    pub fn bind_interface(&mut self) -> io::Result<()> {
        #[cfg(feature = "medium-sixlowpan")]
        let protocol = imp::ETH_P_IEEE802154;

        #[cfg(feature = "medium-ethernet")]
        let protocol = imp::ETH_P_ALL;

        let sockaddr = libc::sockaddr_ll {
            sll_family:   libc::AF_PACKET as u16,
            sll_protocol: protocol.to_be() as u16,
            sll_ifindex:  ifreq_ioctl(self.lower, &mut self.ifreq, imp::SIOCGIFINDEX)?,
            sll_hatype:   1,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0; 8]
        };

        unsafe {
            let res = libc::bind(self.lower,
                                 &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                                 mem::size_of::<libc::sockaddr_ll>() as u32);
            if res == -1 { return Err(io::Error::last_os_error()) }
        }

        Ok(())
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(self.lower, buffer.as_mut_ptr() as *mut libc::c_void,
                                 buffer.len(), 0);
            if len == -1 { return Err(io::Error::last_os_error()) }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::send(self.lower, buffer.as_ptr() as *const libc::c_void,
                                 buffer.len(), 0);
            if len == -1 { Err(io::Error::last_os_error()).unwrap() }
            Ok(len as usize)
        }
    }
}

impl Drop for RawSocketDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}
