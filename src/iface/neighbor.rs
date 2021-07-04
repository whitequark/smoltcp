// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use managed::ManagedMap;

use crate::time::{Duration, Instant};
use crate::wire::{EthernetAddress, IpAddress};

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbor {
    hardware_addr: EthernetAddress,
    expires_at: Instant,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(EthernetAddress),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A neighbor cache backed by a map.
///
/// # Examples
///
/// On systems with heap, this cache can be created with:
///
/// ```rust
/// use std::collections::BTreeMap;
/// use smoltcp::iface::NeighborCache;
/// let mut neighbor_cache = NeighborCache::new(BTreeMap::new());
/// ```
///
/// On systems without heap, use:
///
/// ```rust
/// use smoltcp::iface::NeighborCache;
/// let mut neighbor_cache_storage = [None; 8];
/// let mut neighbor_cache = NeighborCache::new(&mut neighbor_cache_storage[..]);
/// ```
#[derive(Debug)]
pub struct Cache<'a> {
    storage: ManagedMap<'a, IpAddress, Neighbor>,
    silent_until: Instant,
    gc_threshold: usize,
}

impl<'a> Cache<'a> {
    /// Minimum delay between discovery requests, in milliseconds.
    pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);

    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis( 60_000);

    /// Default number of entries in the cache before GC kicks in
    pub(crate) const GC_THRESHOLD: usize = 1024;

    /// Create a cache. The backing storage is cleared upon creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new<T>(storage: T) -> Cache<'a>
    where
        T: Into<ManagedMap<'a, IpAddress, Neighbor>>,
    {
        Cache::new_with_limit(storage, Cache::GC_THRESHOLD)
    }

    pub fn new_with_limit<T>(storage: T, gc_threshold: usize) -> Cache<'a>
    where
        T: Into<ManagedMap<'a, IpAddress, Neighbor>>,
    {
        let mut storage = storage.into();
        storage.clear();

        Cache {
            storage,
            gc_threshold,
            silent_until: Instant::from_millis(0),
        }
    }

    pub fn fill(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: EthernetAddress,
        timestamp: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        #[cfg(any(feature = "std", feature = "alloc"))]
        let current_storage_size = self.storage.len();

        match self.storage {
            ManagedMap::Borrowed(_) => (),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedMap::Owned(ref mut map) => {
                if current_storage_size >= self.gc_threshold {
                    let new_btree_map = map
                        .iter_mut()
                        .map(|(key, value)| (*key, *value))
                        .filter(|(_, v)| timestamp < v.expires_at)
                        .collect();

                    *map = new_btree_map;
                }
            }
        };
        let neighbor = Neighbor {
            expires_at: timestamp + Self::ENTRY_LIFETIME,
            hardware_addr,
        };
        match self.storage.insert(protocol_addr, neighbor) {
            Ok(Some(old_neighbor)) => {
                if old_neighbor.hardware_addr != hardware_addr {
                    net_trace!(
                        "replaced {} => {} (was {})",
                        protocol_addr,
                        hardware_addr,
                        old_neighbor.hardware_addr
                    );
                }
            }
            Ok(None) => {
                net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
            }
            Err((protocol_addr, neighbor)) => {
                // If we're going down this branch, it means that a fixed-size cache storage
                // is full, and we need to evict an entry.
                let old_protocol_addr = match self.storage {
                    ManagedMap::Borrowed(ref mut pairs) => {
                        pairs
                            .iter()
                            .min_by_key(|pair_opt| {
                                let (_protocol_addr, neighbor) = pair_opt.unwrap();
                                neighbor.expires_at
                            })
                            .expect("empty neighbor cache storage") // unwraps min_by_key
                            .unwrap() // unwraps pair
                            .0
                    }
                    // Owned maps can extend themselves.
                    #[cfg(any(feature = "std", feature = "alloc"))]
                    ManagedMap::Owned(_) => unreachable!(),
                };

                let _old_neighbor = self.storage.remove(&old_protocol_addr).unwrap();
                match self.storage.insert(protocol_addr, neighbor) {
                    Ok(None) => {
                        net_trace!(
                            "filled {} => {} (evicted {} => {})",
                            protocol_addr,
                            hardware_addr,
                            old_protocol_addr,
                            _old_neighbor.hardware_addr
                        );
                    }
                    // We've covered everything else above.
                    _ => unreachable!(),
                }
            }
        }
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        if protocol_addr.is_broadcast() {
            return Answer::Found(EthernetAddress::BROADCAST);
        }

        if let Some(&Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get(protocol_addr)
        {
            if timestamp < expires_at {
                return Answer::Found(hardware_addr);
            }
        }

        if timestamp < self.silent_until {
            Answer::RateLimited
        } else {
            Answer::NotFound
        }
    }

    pub(crate) fn limit_rate(&mut self, timestamp: Instant) {
        self.silent_until = timestamp + Self::SILENT_TIME;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::ip::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};
    use std::collections::BTreeMap;

    const HADDR_A: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);
    const HADDR_B: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 2]);
    const HADDR_C: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 3]);
    const HADDR_D: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 4]);

    #[test]
    fn test_fill() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0))
                .found(),
            false
        );
        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_2, Instant::from_millis(0))
                .found(),
            false
        );

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_2, Instant::from_millis(0))
                .found(),
            false
        );
        assert_eq!(
            cache
                .lookup(
                    &MOCK_IP_ADDR_1,
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
            false
        );

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_2, Instant::from_millis(0))
                .found(),
            false
        );
    }

    #[test]
    fn test_expire() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert_eq!(
            cache
                .lookup(
                    &MOCK_IP_ADDR_1,
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
            false
        );
    }

    #[test]
    fn test_replace() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1, HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_cache_gc() {
        let mut cache = Cache::new_with_limit(BTreeMap::new(), 2);
        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2, HADDR_B, Instant::from_millis(50));
        // Adding third item after the expiration of the previous
        // two should garbage collect
        cache.fill(
            MOCK_IP_ADDR_3,
            HADDR_C,
            Instant::from_millis(50) + Cache::ENTRY_LIFETIME * 2,
        );

        assert_eq!(cache.storage.len(), 1);
        assert_eq!(
            cache.lookup(
                &MOCK_IP_ADDR_3,
                Instant::from_millis(50) + Cache::ENTRY_LIFETIME * 2
            ),
            Answer::Found(HADDR_C)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2, HADDR_B, Instant::from_millis(50));
        cache.fill(MOCK_IP_ADDR_3, HADDR_C, Instant::from_millis(200));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2, Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_4, Instant::from_millis(1000))
                .found(),
            false
        );

        cache.fill(MOCK_IP_ADDR_4, HADDR_D, Instant::from_millis(300));
        assert_eq!(
            cache
                .lookup(&MOCK_IP_ADDR_2, Instant::from_millis(1000))
                .found(),
            false
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4, Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_hush() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1, Instant::from_millis(2000)),
            Answer::NotFound
        );
    }
}
