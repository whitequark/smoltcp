use core::fmt;

use crate::{Result, wire::pretty_print::{PrettyIndent, PrettyPrint}};
use crate::phy::{self, DeviceCapabilities, Device, Medium};
use crate::time::Instant;

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: for<'a> Device<'a>> {
    inner:  D,
    writer: fn(Instant, Packet),
}

impl<D: for<'a> Device<'a>> Tracer<D> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: Instant, packet: Packet)) -> Tracer<D> {
        Tracer { inner, writer }
    }

    /// Get a reference to the underlying device.
    ///
    /// Even if the device offers reading through a standard reference, it is inadvisable to
    /// directly read from the device as doing so will circumvent the tracing.
    pub fn get_ref(&self) -> &D {
        &self.inner
    }

    /// Get a mutable reference to the underlying device.
    ///
    /// It is inadvisable to directly read from the device as doing so will circumvent the tracing.
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<'a, D> Device<'a> for Tracer<D>
    where D: for<'b> Device<'b>,
{
    type RxToken = RxToken<<D as Device<'a>>::RxToken>;
    type TxToken = TxToken<<D as Device<'a>>::TxToken>;

    fn capabilities(&self) -> DeviceCapabilities { self.inner.capabilities() }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let &mut Self { ref mut inner, writer, .. } = self;
        let medium = inner.capabilities().medium;
        inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken { token: rx_token, writer, medium };
            let tx = TxToken { token: tx_token, writer, medium };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut inner, writer } = self;
        let medium = inner.capabilities().medium;
        inner.transmit().map(|tx_token| {
            TxToken { token: tx_token, medium, writer }
        })
    }
}

#[doc(hidden)]
pub struct RxToken<Rx: phy::RxToken> {
    token:     Rx,
    writer:    fn(Instant, Packet),
    medium:    Medium,
}

impl<Rx: phy::RxToken> phy::RxToken for RxToken<Rx> {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let Self { token, writer, medium } = self;
        token.consume(timestamp, |buffer| {
            writer(timestamp, Packet{
                buffer,
                medium,
                prefix: "<- ",
            });
            f(buffer)
        })
    }
}

#[doc(hidden)]
pub struct TxToken<Tx: phy::TxToken> {
    token:     Tx,
    writer:    fn(Instant, Packet),
    medium:    Medium,
}

impl<Tx: phy::TxToken> phy::TxToken for TxToken<Tx> {
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let Self { token, writer, medium } = self;
        token.consume(timestamp, len, |buffer| {
            let result = f(buffer);
            writer(timestamp, Packet{
                buffer,
                medium,
                prefix: "-> ",
            });
            result
        })
    }
}

pub struct Packet<'a> {
    buffer: &'a [u8],
    medium: Medium,
    prefix: &'static str,
}

impl<'a> fmt::Display for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut indent = PrettyIndent::new(self.prefix);
        match self.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => crate::wire::EthernetFrame::<&'static [u8]>::pretty_print(&self.buffer, f, &mut indent),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => match crate::wire::IpVersion::of_packet(&self.buffer) {
                #[cfg(feature = "proto-ipv4")]
                Ok(crate::wire::IpVersion::Ipv4) => crate::wire::Ipv4Packet::<&'static [u8]>::pretty_print(&self.buffer, f, &mut indent),
                #[cfg(feature = "proto-ipv6")]
                Ok(crate::wire::IpVersion::Ipv6) => crate::wire::Ipv6Packet::<&'static [u8]>::pretty_print(&self.buffer, f, &mut indent),
                _ => f.write_str("unrecognized IP version")
            }
            #[cfg(feature = "medium-sixlowpan")]
            Medium::Sixlowpan => todo!(),
        }
    }
}