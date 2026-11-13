//! Memory of the Fake-IP table: 100 000 names must stay under 50 MB, the
//! Network Extension's whole budget on iOS. A counting allocator measures the
//! heap this test binary holds.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::IpAddr;
use std::sync::atomic::{AtomicIsize, Ordering};

use engine_embedded::config::FakeIpConfig;
use engine_embedded::fake_ip::FakeIpPool;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const NAMES: usize = 100_000;
const BUDGET_BYTES: isize = 50 * 1024 * 1024;

/// A name of typical length (about 30 bytes, longer than most hosts).
fn name(i: usize) -> String {
    format!("cdn-{i:06}.edge-{}.example-service.com", i % 97)
}

#[test]
fn one_hundred_thousand_names_stay_under_50_mb() {
    let before = LIVE.load(Ordering::Relaxed);
    let pool = FakeIpPool::from_config(&FakeIpConfig {
        enabled: true,
        max_entries: NAMES,
        ..FakeIpConfig::default()
    })
    .unwrap()
    .unwrap();
    let mut first = None;
    for i in 0..NAMES {
        let address = pool.assign(&name(i));
        first.get_or_insert(address);
    }
    let used = LIVE.load(Ordering::Relaxed) - before;
    let stats = pool.stats();
    println!(
        "fake-ip: {} names use {:.1} MiB ({} bytes per name)",
        stats.entries,
        used as f64 / (1024.0 * 1024.0),
        used / NAMES as isize
    );
    assert_eq!(stats.entries, NAMES as u64);
    assert_eq!(stats.recycled, 0);
    assert!(used < BUDGET_BYTES, "{used} bytes for {NAMES} names");

    // Every name still maps back, and the table holds no more once full.
    let first = IpAddr::V4(first.unwrap());
    assert_eq!(pool.lookup(first).as_deref(), Some(name(0).as_str()));
    let full = LIVE.load(Ordering::Relaxed);
    for i in NAMES..NAMES + 10_000 {
        pool.assign(&name(i));
    }
    let stats = pool.stats();
    assert_eq!(stats.entries, NAMES as u64);
    assert_eq!(stats.recycled, 10_000);
    // Recycling swaps names of the same length: no growth beyond noise.
    assert!(LIVE.load(Ordering::Relaxed) - full < 1024 * 1024);
}
