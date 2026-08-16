//! Tiny deterministic PRNG shared by mock sources and test fixtures.

/// xorshift64*: cheap, deterministic, good enough for synthetic frames.
pub(crate) fn shift_xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}
