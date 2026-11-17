//! A cache of the BLS signature checks that passed, behind the
//! `signature_cache` feature: the same design as `ic-certificate-verification`'s.
//!
//! A canister signature from an application subnet takes two BLS checks: the
//! root key's over the subnet's delegation, then the subnet key's over the
//! certificate. The first is the same for every certificate the subnet
//! mints, and a signature presented again repeats both, so recording each
//! check that passed spares a verifier nearly all of them. An entry is a
//! SHA-256 over the check's inputs (public key, signature, message), and only
//! a check that passed is ever inserted, so a hit answers exactly as checking
//! again would.
//!
//! In a canister the cache lives in the heap: an update call's insert stays
//! for later calls, while a query's is discarded with the rest of its state.

use lru::LruCache;
use sha2::{Digest, Sha256};
use std::sync::{LazyLock, Mutex};

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) struct SignatureCacheEntry {
    hash: [u8; 32],
}

impl SignatureCacheEntry {
    /// Hashes a check's inputs. The key and signature are fixed-length for
    /// BLS, and the message comes last, so plain concatenation is
    /// unambiguous.
    pub(crate) fn new(pk: &[u8], sig: &[u8], msg: &[u8]) -> Self {
        let mut sha256 = Sha256::new();
        sha256.update(pk);
        sha256.update(sig);
        sha256.update(msg);
        Self {
            hash: sha256.finalize().into(),
        }
    }
}

/// A size-bounded cache of BLS checks that passed.
pub(crate) struct SignatureCache {
    // Unbounded to `lru`, and held to `max_size` by `insert`: a bounded
    // `LruCache` allocates its whole table up front, which every user would
    // pay on first touch whether or not the cache ever fills.
    cache: Mutex<LruCache<SignatureCacheEntry, ()>>,
    max_size: usize,
}

static GLOBAL_SIGNATURE_CACHE: LazyLock<SignatureCache> =
    LazyLock::new(|| SignatureCache::new(SignatureCache::SIZE_OF_GLOBAL_CACHE));

impl SignatureCache {
    /// `ic-certificate-verification`'s size: about 6 MB when full.
    pub const SIZE_OF_GLOBAL_CACHE: usize = 100_000;

    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::unbounded()),
            max_size,
        }
    }

    pub(crate) fn global() -> &'static Self {
        &GLOBAL_SIGNATURE_CACHE
    }

    /// Whether a check with these inputs passed before. A hit makes the
    /// entry the most recently used.
    pub(crate) fn contains(&self, entry: &SignatureCacheEntry) -> bool {
        self.lock().get(entry).is_some()
    }

    /// Records a check that passed. Only ever called after one has.
    pub(crate) fn insert(&self, entry: SignatureCacheEntry) {
        let mut cache = self.lock();
        cache.put(entry, ());
        while cache.len() > self.max_size {
            cache.pop_lru();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruCache<SignatureCacheEntry, ()>> {
        // A panic while the lock is held leaves only a set of hashes, each
        // either fully inserted or not, so the cache stays usable.
        self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> SignatureCacheEntry {
        SignatureCacheEntry::new(&[n; 96], &[n; 48], &[n; 32])
    }

    #[test]
    fn an_inserted_entry_is_found_and_others_are_not() {
        let cache = SignatureCache::new(10);
        cache.insert(entry(1));
        assert!(cache.contains(&entry(1)));
        assert!(!cache.contains(&entry(2)));
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_at_the_limit() {
        let cache = SignatureCache::new(2);
        cache.insert(entry(1));
        cache.insert(entry(2));
        // A hit makes 1 the most recent, so 2 is the one to go.
        assert!(cache.contains(&entry(1)));
        cache.insert(entry(3));
        assert!(cache.contains(&entry(1)));
        assert!(!cache.contains(&entry(2)));
        assert!(cache.contains(&entry(3)));
    }

    #[test]
    fn the_inputs_are_all_part_of_the_entry() {
        let base = SignatureCacheEntry::new(&[1; 96], &[2; 48], b"message");
        assert_ne!(base, SignatureCacheEntry::new(&[9; 96], &[2; 48], b"message"));
        assert_ne!(base, SignatureCacheEntry::new(&[1; 96], &[9; 48], b"message"));
        assert_ne!(base, SignatureCacheEntry::new(&[1; 96], &[2; 48], b"other"));
    }
}
