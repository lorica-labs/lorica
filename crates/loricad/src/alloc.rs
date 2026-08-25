//! A counting global allocator, which is assertion 6.
//!
//! Twenty lines rather than `assert_no_alloc`, which has had no release since 2021 and
//! this project aims at being auditable.
//!
//! It counts always rather than only while armed. A flag would have to be set and
//! cleared around the region under test, and a region that forgets to clear it stops
//! counting for the rest of the process — a guard that silently switches itself off. Two
//! reads and a subtraction have no such state.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering},
};

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Allocations since the process started.
///
/// `Relaxed` throughout: the count is a total, nothing else is ordered against it, and a
/// fence on every allocation would cost more than the thing being measured.
pub fn allocations() -> u64 {
    ALLOCATIONS.load(Ordering::Relaxed)
}

pub struct Counting;

// SAFETY: every method forwards to System with the layout it was given and returns
// exactly what System returned, so the contract of the trait is System's contract.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    /// Forwarded rather than left to the default implementation, which would allocate,
    /// copy and free, and so count as one allocation while doing the work of two.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    /// A reallocation is counted: growing a buffer inside the tick is exactly the thing
    /// assertion 6 exists to catch, and it is invisible if only fresh allocations count.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
