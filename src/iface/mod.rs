/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(feature = "medium-ethernet")]
mod neighbor;
mod route;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-sixlowpan"))]
mod interface;

#[cfg(feature = "medium-ethernet")]
pub use self::neighbor::Neighbor as Neighbor;
#[cfg(feature = "medium-ethernet")]
pub(crate) use self::neighbor::Answer as NeighborAnswer;
#[cfg(feature = "medium-ethernet")]
pub use self::neighbor::Cache as NeighborCache;
pub use self::route::{Route, Routes};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-sixlowpan"))]
pub use self::interface::{Interface, InterfaceBuilder};
