//! Tiny non-cryptographic PRNG for the ClientHello split point.
//!
//! The split only needs an unpredictable-ish size in a small range; this avoids
//! pulling in the `rand` crate (and its weight) for a single `randint`.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static STATE: Cell<u64> = Cell::new(seed());
}

fn seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    // Mix in the thread identity so two threads seeded in the same nanosecond
    // don't share a stream.
    let tid = std::thread::current().id();
    let mut x = nanos ^ (format!("{tid:?}").len() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    if x == 0 {
        x = 0x9E3779B97F4A7C15;
    }
    x
}

fn next_u64() -> u64 {
    STATE.with(|s| {
        // xorshift64*
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        x.wrapping_mul(0x2545F4914F6CDD1D)
    })
}

/// Uniform-ish integer in `[min, max]` (inclusive). Returns `min` if `min >= max`.
pub fn range_inclusive(min: usize, max: usize) -> usize {
    if min >= max {
        return min;
    }
    let span = (max - min + 1) as u64;
    min + (next_u64() % span) as usize
}
