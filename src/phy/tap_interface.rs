use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use Result;
use phy::{self, sys, DeviceCapabilities, Device, ETHERNET_HAEDER_MAX_LEN};
use time::Instant;

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  Rc<RefCell<sys::TapInterfaceDesc>>,
    mtu:    usize
}

impl AsRawFd for TapInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl TapInterface {
    /// Attaches to a TAP interface called `name`, or creates it if it does not exist.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str) -> io::Result<TapInterface> {
        let mut lower = sys::TapInterfaceDesc::new(name)?;
        lower.attach_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(TapInterface {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu + ETHERNET_HAEDER_MAX_LEN
        })
    }
}

impl<'a> Device<'a> for TapInterface {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken { lower: self.lower.clone() };
                Some((rx, tx))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                None
            }
            Err(err) => panic!("{}", err)
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&[u8]) -> Result<R>
    {
        f(&self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<sys::TapInterfaceDesc>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.send(&buffer[..]).unwrap();
        result
    }
}
