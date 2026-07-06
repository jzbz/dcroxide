// SPDX-License-Identifier: ISC
//! Generic, near O(1) LRU data structures with optional time-based
//! expiration support (dcrd `container/lru`).

// Bounded bookkeeping arithmetic mirrors Go; the time arithmetic uses
// explicit wrapping operations where Go could wrap.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;

/// The minimum interval between expiration scans, in nanoseconds
/// (dcrd `expireScanInterval`, 30 seconds).
const EXPIRE_SCAN_INTERVAL: i64 = 30_000_000_000;

/// A clock returning the current time as Unix nanoseconds (dcrd's
/// `nowFn`, injectable so tests can control expiration).
pub type Clock = Rc<dyn Fn() -> i64>;

/// The system clock.
fn system_clock() -> Clock {
    Rc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or_default()
    })
}

/// An element in the linked list used to house the KV pairs and
/// associated expiration data (dcrd `element`); the list is realized
/// as indexes into an arena with index 0 as the root sentinel.
struct Element<K, V> {
    key: Option<K>,
    value: Option<V>,
    expires_after: i64,
    prev: usize,
    next: usize,
}

/// A least recently used map limited to a maximum number of items
/// with eviction of the least recently used entry when the limit is
/// exceeded (dcrd `Map`).
///
/// It also supports optional item expiration after a configurable
/// time to live (TTL) with periodic lazy removal: expired items may
/// physically remain in the map until the next expiration scan is
/// triggered by [`put`](Map::put) or [`put_with_ttl`](Map::put_with_ttl),
/// however, they will no longer publicly appear as members.
/// [`evict_expired_now`](Map::evict_expired_now) immediately removes
/// all items that are marked expired.
///
/// Expiration TTLs are relative to the time an item is added or
/// updated; accessing items does not extend the TTL.
pub struct Map<K, V> {
    now_fn: Clock,
    limit: u32,
    ttl: i64,

    items: HashMap<K, usize>,
    arena: Vec<Element<K, V>>,
    // Cache of reusable old elements (dcrd `elems`).
    free: Vec<usize>,

    // Used to optimize out expiration scans when there is no default
    // TTL and there have never been any items with a TTL.
    probably_has_timeouts: bool,

    next_expire_scan: i64,

    // The total number of hits and misses used to measure the overall
    // hit ratio.
    hits: u64,
    misses: u64,
}

impl<K: Eq + Hash + Clone, V: Clone> Map<K, V> {
    /// An initialized and empty LRU map where no items will expire by
    /// default (dcrd `NewMap`).  The provided limit is the maximum
    /// number of items the map will hold before it evicts least
    /// recently used items to make room for new items.
    pub fn new(limit: u32) -> Map<K, V> {
        Map::new_with_clock(limit, system_clock())
    }

    /// [`new`](Map::new) with an injectable clock; exposed so tests
    /// can control expiration deterministically.
    #[doc(hidden)]
    pub fn new_with_clock(limit: u32, now_fn: Clock) -> Map<K, V> {
        let mut arena = Vec::with_capacity(limit as usize + 1);
        arena.push(Element {
            key: None,
            value: None,
            expires_after: 0,
            prev: 0,
            next: 0,
        });
        Map {
            now_fn,
            limit,
            ttl: 0,
            items: HashMap::with_capacity(limit as usize),
            arena,
            free: Vec::with_capacity(limit as usize),
            probably_has_timeouts: false,
            next_expire_scan: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// An initialized and empty LRU map where the provided non-zero
    /// time to live (TTL, in nanoseconds) is applied to all items by
    /// default (dcrd `NewMapWithDefaultTTL`).  A TTL of zero disables
    /// item expiration by default and is equivalent to
    /// [`new`](Map::new).
    pub fn new_with_default_ttl(limit: u32, ttl: i64) -> Map<K, V> {
        Map::new_with_default_ttl_and_clock(limit, ttl, system_clock())
    }

    /// [`new_with_default_ttl`](Map::new_with_default_ttl) with an
    /// injectable clock; exposed so tests can control expiration
    /// deterministically.
    #[doc(hidden)]
    pub fn new_with_default_ttl_and_clock(limit: u32, ttl: i64, now_fn: Clock) -> Map<K, V> {
        let mut m = Map::new_with_clock(limit, now_fn);
        m.ttl = ttl;
        m.probably_has_timeouts = ttl > 0;
        m.next_expire_scan = (m.now_fn)().wrapping_add(EXPIRE_SCAN_INTERVAL);
        m
    }

    /// Remove the passed element from the internal list (dcrd
    /// `removeElem`).
    fn remove_elem(&mut self, idx: usize) {
        let (prev, next) = (self.arena[idx].prev, self.arena[idx].next);
        self.arena[prev].next = next;
        self.arena[next].prev = prev;
        self.arena[idx].next = 0;
        self.arena[idx].prev = 0;
    }

    /// Insert the passed element at the front of the internal list
    /// (dcrd `insertElemFront`).
    fn insert_elem_front(&mut self, idx: usize) {
        let old_front = self.arena[0].next;
        self.arena[idx].prev = 0;
        self.arena[idx].next = old_front;
        self.arena[0].next = idx;
        self.arena[old_front].prev = idx;
    }

    /// Move the passed element to the front of the internal list
    /// (dcrd `moveElemToFront`).
    fn move_elem_to_front(&mut self, idx: usize) {
        // Nothing to do when the element is already at the front of
        // the list.
        if self.arena[0].next == idx {
            return;
        }

        self.remove_elem(idx);
        self.insert_elem_front(idx);
    }

    /// Remove the provided element from the internal list, delete it
    /// from the map, and return it to the reusable element cache
    /// (dcrd `deleteElem`).
    fn delete_elem(&mut self, key: &K, idx: usize) {
        self.remove_elem(idx);
        self.items.remove(key);
        self.arena[idx].key = None; // Prevent potential memleak.
        self.arena[idx].value = None; // Prevent potential memleak.
        self.free.push(idx);
    }

    /// Whether expiration is enabled and the provided element has
    /// expired (dcrd `isElemExpired`).
    fn is_elem_expired(&self, idx: usize, now: i64) -> bool {
        self.probably_has_timeouts && now > self.arena[idx].expires_after
    }

    /// Scan through all items in the map, remove any that have
    /// expired, and update the minimum time the next expire scan can
    /// take place (dcrd `removeExpired`).
    fn remove_expired(&mut self, now: i64) -> u32 {
        let mut num_evicted = 0u32;
        let expired: Vec<(K, usize)> = self
            .items
            .iter()
            .filter(|(_, idx)| now > self.arena[**idx].expires_after)
            .map(|(key, idx)| (key.clone(), *idx))
            .collect();
        for (key, idx) in expired {
            self.delete_elem(&key, idx);
            num_evicted = num_evicted.wrapping_add(1);
        }

        // Set next expiration scan to occur after the scan interval.
        self.next_expire_scan = now.wrapping_add(EXPIRE_SCAN_INTERVAL);
        num_evicted
    }

    /// The core shared logic of [`put`](Map::put) and
    /// [`put_with_ttl`](Map::put_with_ttl) (dcrd `put`); MUST only be
    /// called with a non-zero limit.
    fn put_internal(&mut self, key: K, value: V, now: i64, ttl: i64) -> u32 {
        // Treat zero TTLs as 100 years in the future in order to
        // allow individual elements to effectively have expiration
        // disabled without needing to store an additional byte in
        // every element.
        let ttl = if ttl == 0 {
            const ONE_HUNDRED_YEARS: i64 = 3_600 * 24 * 365 * 100 * 1_000_000_000;
            ONE_HUNDRED_YEARS
        } else {
            ttl
        };

        // When the entry already exists move it to the front of the
        // list thereby marking it most recently used.
        if let Some(&idx) = self.items.get(&key) {
            self.arena[idx].value = Some(value);
            self.arena[idx].expires_after = now.wrapping_add(ttl);
            self.move_elem_to_front(idx);
            return 0;
        }

        // Evict the least recently used entry (back of the list) if
        // the new entry would exceed the size limit.  Also reuse the
        // node so a new one doesn't have to be allocated.
        if self.items.len() as u32 + 1 > self.limit {
            // Evict least recently used item.
            let idx = self.arena[0].prev;
            let old_key = self.arena[idx].key.take().expect("evicted element key");
            self.items.remove(&old_key);

            // Reuse the list element of the item that was just
            // evicted for the new item.
            self.arena[idx].key = Some(key.clone());
            self.arena[idx].value = Some(value);
            self.arena[idx].expires_after = now.wrapping_add(ttl);
            self.move_elem_to_front(idx);
            self.items.insert(key, idx);
            return 1;
        }

        // The limit hasn't been reached yet, so just add the new
        // item.  Reuse old list elements when possible.
        let idx = match self.free.pop() {
            Some(idx) => {
                self.arena[idx].key = Some(key.clone());
                self.arena[idx].value = Some(value);
                idx
            }
            None => {
                self.arena.push(Element {
                    key: Some(key.clone()),
                    value: Some(value),
                    expires_after: 0,
                    prev: 0,
                    next: 0,
                });
                self.arena.len() - 1
            }
        };
        self.arena[idx].expires_after = now.wrapping_add(ttl);
        self.insert_elem_front(idx);
        self.items.insert(key, idx);
        0
    }

    /// Either add the passed key/value pair when an item for that key
    /// does not already exist or update the existing item for the
    /// given key to the passed value and arrange for the item to
    /// expire after the configured default TTL, if any (dcrd `Put`).
    /// The associated item becomes the most recently used item, and
    /// the least recently used item is evicted when adding a new item
    /// would exceed the max limit.
    ///
    /// It returns the number of evicted items which includes any
    /// items that were evicted due to being marked expired.
    pub fn put(&mut self, key: K, value: V) -> u32 {
        // Nothing can be added when the limit is zero.
        if self.limit == 0 {
            return 0;
        }

        // Scan through the items and remove any that are expired when
        // expiration is enabled and the scan interval has elapsed.
        // This is done for efficiency so the scan only happens
        // periodically instead of on every put.
        let now = (self.now_fn)();
        let mut num_evicted = 0u32;
        if self.probably_has_timeouts && now > self.next_expire_scan {
            num_evicted = self.remove_expired(now);
        }

        num_evicted.wrapping_add(self.put_internal(key, value, now, self.ttl))
    }

    /// [`put`](Map::put) with the provided time to live in
    /// nanoseconds (dcrd `PutWithTTL`).  A TTL of zero will disable
    /// expiration for the item, which can be useful when the map was
    /// configured with a default expiration TTL.
    pub fn put_with_ttl(&mut self, key: K, value: V, ttl: i64) -> u32 {
        // Nothing can be added when the limit is zero.
        if self.limit == 0 {
            return 0;
        }

        // Enable item expiration when not already done and the passed
        // TTL is non-zero.  Note that this being true also implies
        // there is no default TTL configured since item expiration
        // would already be marked active in that case.
        //
        // Otherwise, scan through the items and remove any that are
        // expired when item expiration was already enabled and the
        // scan interval has elapsed.
        let now = (self.now_fn)();
        let mut num_evicted = 0u32;
        if !self.probably_has_timeouts && ttl > 0 {
            self.probably_has_timeouts = true;
            self.next_expire_scan = now.wrapping_add(EXPIRE_SCAN_INTERVAL);
        } else if self.probably_has_timeouts && now > self.next_expire_scan {
            num_evicted = self.remove_expired(now);
        }

        num_evicted.wrapping_add(self.put_internal(key, value, now, ttl))
    }

    /// The value associated with the passed key if it is a member,
    /// modifying its priority to be the most recently used item (dcrd
    /// `Get`).  The expiration time for the item is not modified.
    /// The hit ratio is updated accordingly.
    ///
    /// See [`peek`](Map::peek) for a variant that does not modify the
    /// priority or update the hit ratio.
    pub fn get(&mut self, key: &K) -> Option<V> {
        let now = (self.now_fn)();
        match self.items.get(key) {
            Some(&idx) if !self.is_elem_expired(idx, now) => {
                self.hits = self.hits.wrapping_add(1);
                self.move_elem_to_front(idx);
                self.arena[idx].value.clone()
            }
            _ => {
                self.misses = self.misses.wrapping_add(1);
                None
            }
        }
    }

    /// Whether or not the passed item is a member (dcrd `Exists`).
    /// The priority and expiration time for the item are not
    /// modified.  It does not affect the hit ratio.
    pub fn exists(&self, key: &K) -> bool {
        match self.items.get(key) {
            Some(&idx) => !self.is_elem_expired(idx, (self.now_fn)()),
            None => false,
        }
    }

    /// The associated value of the passed key if it is a member,
    /// without modifying any priority or the hit ratio (dcrd `Peek`).
    pub fn peek(&self, key: &K) -> Option<V> {
        match self.items.get(key) {
            Some(&idx) if !self.is_elem_expired(idx, (self.now_fn)()) => {
                self.arena[idx].value.clone()
            }
            _ => None,
        }
    }

    /// The number of items in the map (dcrd `Len`).
    pub fn len(&self) -> u32 {
        self.items.len() as u32
    }

    /// Whether the map holds no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Delete the item associated with the passed key if it exists
    /// (dcrd `Delete`).
    pub fn delete(&mut self, key: &K) {
        if let Some(&idx) = self.items.get(key) {
            let key = key.clone();
            self.delete_elem(&key, idx);
        }
    }

    /// Immediately remove all items that are marked expired without
    /// waiting for the next expiration scan and return the number of
    /// items that were removed (dcrd `EvictExpiredNow`).
    pub fn evict_expired_now(&mut self) -> u32 {
        if !self.probably_has_timeouts {
            return 0;
        }

        self.remove_expired((self.now_fn)())
    }

    /// Remove all items and reset the hit ratio (dcrd `Clear`).
    pub fn clear(&mut self) {
        let keys: Vec<(K, usize)> = self
            .items
            .iter()
            .map(|(key, &idx)| (key.clone(), idx))
            .collect();
        for (key, idx) in keys {
            self.delete_elem(&key, idx);
        }
        self.arena[0].prev = 0;
        self.arena[0].next = 0;
        self.probably_has_timeouts = self.ttl > 0;
        self.next_expire_scan = (self.now_fn)().wrapping_add(EXPIRE_SCAN_INTERVAL);
        self.hits = 0;
        self.misses = 0;
    }

    /// A vector of unexpired keys ordered from least recently used to
    /// most recently used (dcrd `Keys`).  The priority and expiration
    /// times for the items are not modified.
    pub fn keys(&self) -> Vec<K> {
        let mut keys = Vec::with_capacity(self.items.len());
        let now = (self.now_fn)();
        let mut idx = self.arena[0].prev;
        while idx != 0 {
            if !self.is_elem_expired(idx, now) {
                keys.push(self.arena[idx].key.clone().expect("listed element key"));
            }
            idx = self.arena[idx].prev;
        }
        keys
    }

    /// A vector of unexpired values ordered from least recently used
    /// to most recently used (dcrd `Values`).  The priority and
    /// expiration times for the items are not modified.
    pub fn values(&self) -> Vec<V> {
        let mut values = Vec::with_capacity(self.items.len());
        let now = (self.now_fn)();
        let mut idx = self.arena[0].prev;
        while idx != 0 {
            if !self.is_elem_expired(idx, now) {
                values.push(self.arena[idx].value.clone().expect("listed element value"));
            }
            idx = self.arena[idx].prev;
        }
        values
    }

    /// The percentage of lookups via [`get`](Map::get) that resulted
    /// in a successful hit (dcrd `HitRatio`).
    pub fn hit_ratio(&self) -> f64 {
        let total_lookups = self.hits.wrapping_add(self.misses);
        if total_lookups == 0 {
            return 100.0;
        }

        self.hits as f64 / total_lookups as f64 * 100.0
    }
}

/// A least recently used set limited to a maximum number of items
/// with eviction of the least recently used entry when the limit is
/// exceeded, with the same optional expiration support as [`Map`]
/// (dcrd `Set`).
pub struct Set<T> {
    m: Map<T, ()>,
}

impl<T: Eq + Hash + Clone> Set<T> {
    /// An initialized and empty LRU set where no items will expire by
    /// default (dcrd `NewSet`).
    pub fn new(limit: u32) -> Set<T> {
        Set { m: Map::new(limit) }
    }

    /// [`new`](Set::new) with an injectable clock; exposed so tests
    /// can control expiration deterministically.
    #[doc(hidden)]
    pub fn new_with_clock(limit: u32, now_fn: Clock) -> Set<T> {
        Set {
            m: Map::new_with_clock(limit, now_fn),
        }
    }

    /// An initialized and empty LRU set where the provided non-zero
    /// time to live (TTL, in nanoseconds) is applied to all items by
    /// default (dcrd `NewSetWithDefaultTTL`).
    pub fn new_with_default_ttl(limit: u32, ttl: i64) -> Set<T> {
        Set {
            m: Map::new_with_default_ttl(limit, ttl),
        }
    }

    /// [`new_with_default_ttl`](Set::new_with_default_ttl) with an
    /// injectable clock; exposed so tests can control expiration
    /// deterministically.
    #[doc(hidden)]
    pub fn new_with_default_ttl_and_clock(limit: u32, ttl: i64, now_fn: Clock) -> Set<T> {
        Set {
            m: Map::new_with_default_ttl_and_clock(limit, ttl, now_fn),
        }
    }

    /// Either add the passed item when it does not already exist or
    /// refresh the existing item and arrange for it to expire after
    /// the configured default TTL, if any (dcrd `Put`).  The item
    /// becomes the most recently used item.
    pub fn put(&mut self, item: T) -> u32 {
        self.m.put(item, ())
    }

    /// [`put`](Set::put) with the provided time to live in
    /// nanoseconds (dcrd `PutWithTTL`).  A TTL of zero will disable
    /// expiration for the item.
    pub fn put_with_ttl(&mut self, item: T, ttl: i64) -> u32 {
        self.m.put_with_ttl(item, (), ttl)
    }

    /// Whether or not the passed item is a member, modifying its
    /// priority to be the most recently used item when it is (dcrd
    /// `Contains`).  The hit ratio is updated accordingly.
    pub fn contains(&mut self, item: &T) -> bool {
        self.m.get(item).is_some()
    }

    /// Whether or not the passed item is a member without modifying
    /// its priority or the hit ratio (dcrd `Exists`).
    pub fn exists(&self, item: &T) -> bool {
        self.m.exists(item)
    }

    /// The number of items in the set (dcrd `Len`).
    pub fn len(&self) -> u32 {
        self.m.len()
    }

    /// Whether the set holds no items.
    pub fn is_empty(&self) -> bool {
        self.m.is_empty()
    }

    /// Delete the passed item if it exists (dcrd `Delete`).
    pub fn delete(&mut self, item: &T) {
        self.m.delete(item)
    }

    /// Immediately remove all items that are marked expired and
    /// return the number of items that were removed (dcrd
    /// `EvictExpiredNow`).
    pub fn evict_expired_now(&mut self) -> u32 {
        self.m.evict_expired_now()
    }

    /// Remove all items and reset the hit ratio (dcrd `Clear`).
    pub fn clear(&mut self) {
        self.m.clear()
    }

    /// A vector of unexpired items ordered from least recently used
    /// to most recently used (dcrd `Items`).
    pub fn items(&self) -> Vec<T> {
        self.m.keys()
    }

    /// The percentage of lookups via [`contains`](Set::contains) that
    /// resulted in a successful hit (dcrd `HitRatio`).
    pub fn hit_ratio(&self) -> f64 {
        self.m.hit_ratio()
    }
}
