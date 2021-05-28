/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
mod neighbor;
mod route;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-sixlowpan"))]
mod interface;

#[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
pub use self::neighbor::Neighbor as Neighbor;
#[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
pub(crate) use self::neighbor::Answer as NeighborAnswer;
#[cfg(any(feature = "medium-ethernet", feature = "medium-sixlowpan"))]
pub use self::neighbor::Cache as NeighborCache;
pub use self::route::{Route, Routes};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-sixlowpan"))]
pub use self::interface::{Interface, InterfaceBuilder};
