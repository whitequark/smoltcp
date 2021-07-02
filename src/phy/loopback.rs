#[cfg(not(feature = "rust-1_28"))]
use alloc::collections::VecDeque;
use alloc::vec::Vec;
#[cfg(feature = "rust-1_28")]
use alloc::VecDeque;

use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;
use crate::Result;

/// A loopback device.
#[derive(Debug)]
pub struct Loopback {
    queue: Option<VecDeque<Vec<u8>>>,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: Medium) -> Loopback {
        Loopback {
            queue: None,
            medium,
        }
    }
}

impl<'a> Device<'a> for Loopback {
    type RxToken = RxToken;
    type TxToken = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.queue {
            Some(ref mut queue) => queue.pop_front().map(move |buffer| {
                let rx = RxToken { buffer };
                let tx = TxToken { queue: queue };
                (rx, tx)
            }),
            None => None,
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        match self.queue {
            Some(ref mut queue) => Some(TxToken { queue: queue }),
            None => None,
        }
    }

    fn up(&'a mut self) -> Result<()> {
        self.queue = Some(VecDeque::new());
        Ok(())
    }

    fn down(&'a mut self) -> Result<()> {
        self.queue = None;
        Ok(())
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        f(&mut self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
