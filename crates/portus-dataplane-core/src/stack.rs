//! A slot for a network stack's view of a core object.
//!
//! The core stores TLS material as DER bytes. A stack usually wants it in its
//! own type (a certificate store, a peer identity) and must not rebuild that
//! per request, so core objects that are looked up on the request path carry
//! a [`StackCache`]: the adapter fills it on first use and reads it after.
//! One value per object; the type is whatever the stack stores.

use std::any::Any;
use std::sync::{Arc, OnceLock};

#[derive(Default)]
pub struct StackCache(OnceLock<Arc<dyn Any + Send + Sync>>);

impl StackCache {
    /// The cached `T`, built with `init` on first call. A second stack asking
    /// for a different `T` on the same object is a programming error and panics:
    /// one binary runs one stack.
    pub fn get_or_init<T, F>(&self, init: F) -> Arc<T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        let any = self.0.get_or_init(|| Arc::new(init()) as Arc<dyn Any + Send + Sync>);
        Arc::clone(any)
            .downcast::<T>()
            .unwrap_or_else(|_| panic!("stack cache holds a {:?}, not a {}", any.type_id(), std::any::type_name::<T>()))
    }
}

impl std::fmt::Debug for StackCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.get().is_some() { "StackCache(filled)" } else { "StackCache(empty)" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn builds_once_and_hands_out_the_same_value() {
        let cache = StackCache::default();
        let builds = AtomicUsize::new(0);
        let a = cache.get_or_init(|| {
            builds.fetch_add(1, Ordering::Relaxed);
            vec![1u8, 2, 3]
        });
        let b = cache.get_or_init(|| {
            builds.fetch_add(1, Ordering::Relaxed);
            vec![9u8]
        });
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(*a, vec![1, 2, 3]);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[should_panic(expected = "stack cache holds")]
    fn a_second_type_is_a_programming_error() {
        let cache = StackCache::default();
        let _ = cache.get_or_init(|| 7u32);
        let _ = cache.get_or_init(String::new);
    }
}
