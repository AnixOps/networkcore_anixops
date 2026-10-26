//! v6 `default` mode protocol profile (spec §7.4): parameters derived from
//! the PSK, the salt block, padding content, the padding/ciphertext mix and
//! the sender's frame sizing. Both ends compute the same profile once per PSK.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

const G: u64 = 0x9e37_79b9_7f4a_7c15;
const SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const HS: u64 = 0x7053;
const MIXHS: u64 = 0x51a7;
const CHUNK0: u64 = 0xf17c;
const EXTRA: u64 = 0x2da;

/// Seq used for the salt block filler.
const SALT_FILL_SEQ: u64 = 0xFFFF_FFFF;

/// Frame header (7) plus its tag (16).
const HEADER_OVERHEAD: u64 = 23;

/// Appendix A.
const TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn fold(y: u64) -> u64 {
    (y ^ (y >> 32)) & 0xffff_ffff
}

fn prf32(ns: u64, label: u64, a: u64, b: u64) -> u64 {
    fold(mix64(
        ns ^ b
            .wrapping_mul(0x5899_65cc_7537_4cc3)
            .wrapping_add(0x33a2_13ec_50ff_e2e9)
            ^ label.wrapping_mul(G)
            ^ a.wrapping_mul(0xe703_7ed1_a0b4_28db)
                .wrapping_add(0x8f39_07f7_b2b8_0c35),
    ))
}

fn pick(raw: u64, lo: u64, hi: u64) -> u64 {
    lo + raw % (hi - lo + 1)
}

/// The namespace values of one PSK (spec §7.4.2).
#[derive(Clone, Copy)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

impl Namespaces {
    fn new(psk: &[u8]) -> Self {
        let secret = Blake2b::<U32>::new()
            .chain_update(SEED)
            .chain_update(psk)
            .finalize();
        let word = |i: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&secret[i * 8..i * 8 + 8]);
            u64::from_le_bytes(raw)
        };
        let (s0, s1, s2, s3) = (word(0), word(1), word(2), word(3));
        let ns = |label: u64, seed: u64| {
            mix64(
                label.wrapping_mul(0xd6e8_feb8_6659_fd93)
                    ^ seed.wrapping_add(0xa076_1d64_78bd_642f)
                    ^ s0
                    ^ s1.wrapping_add(G)
                    ^ s2.rotate_left(17)
                    ^ s3.rotate_right(11),
            )
        };
        Self {
            profile: ns(5, 0xb46c_2e7d_9a15_38f1),
            prefix: ns(0, 0x5d92_17c0_83e6_4ab9),
            motif: ns(2, 0xa71f_0c54_d839_6e2b),
            salt: ns(3, 0x3e8a_91b5_2740_f6cd),
            mix: ns(16, 0xc9f4_260b_7d1e_835a),
            chunk: ns(21, 0x62d0_b5e1_9c4a_783f),
            write: ns(28, 0x917b_3c48_e6a2_05d4),
        }
    }

    /// `ns(label)`: the namespace a PRF label belongs to.
    fn of(&self, label: u64) -> u64 {
        match label {
            0 | 1 | 14 | 15 | 33 | 34 => self.prefix,
            2 => self.motif,
            3 | 16..=20 => self.mix,
            21..=26 | 38 | 39 => self.chunk,
            28..=32 | 35..=37 => self.write,
            _ => self.profile,
        }
    }
}

/// Deterministic per-PSK parameters of the v6 `default` mode.
pub struct Profile {
    ns: Namespaces,
    pad_min: u64,
    pad_max: u64,
    salt_prefix_len: u64,
    salt_block_len: u64,
    prefix_min: u64,
    prefix_max: u64,
    chunk_initial: u64,
    first_record_cap: u64,
    chunk_max: u64,
    generator: u64,
    pad_count: u64,
    pad_interval: u64,
    small_limit: u64,
    bit_min: u64,
    bit_max: u64,
    mix_mode: u64,
    mix_rounds: u64,
    mix_stride: u64,
    mix_offset_base: u64,
    mix_block: u64,
    chunk_policy: u64,
    chunk_step: u64,
    chunk_jitter: u64,
    idle_reset_secs: u64,
    write_policy: u64,
    write_first: u64,
    write_jitter: u64,
    write_jitter_pct: u64,
    g: [u64; 7],
    chunk_buckets: [u64; 8],
    write_buckets: [u64; 8],
    write_seq: [u64; 8],
    /// Where salt byte `i` sits in the salt block, and its mask.
    salt_perm: Vec<usize>,
    salt_mask: [u8; 16],
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derived from the PSK: print nothing.
        f.write_str("Profile { .. }")
    }
}

impl Profile {
    pub fn new(psk: &[u8]) -> Self {
        let ns = Namespaces::new(psk);
        let s = |label: u64, domain: u64| prf32(ns.of(label), label, 0, domain);

        let pad_min = pick(s(7, 0), 0x18, 0xa0);
        let pad_max = (pad_min + pick(s(8, 0), 0xa0, 0x3c0)).min(EXTRA);
        let mut hs_prefix_min = pick(s(14, HS), 0x10, 0x60);
        let hs_prefix_max = (hs_prefix_min + pick(s(15, HS), 0x10, 0xa0)).min(0x80);
        hs_prefix_min = hs_prefix_min.min(hs_prefix_max);
        let salt_prefix_len = pick(s(33, HS), hs_prefix_min, hs_prefix_max);
        let salt_block_len = 16 + salt_prefix_len;
        let hs_mix_rounds = pick(s(17, MIXHS), 1, 4);
        let hs_mix_stride = pick(s(18, MIXHS), 0x11, 0xfb);
        let mut prefix_min = pick(s(14, 0), 0x08, 0x50);
        let prefix_max = (prefix_min + pick(s(15, 0), 0x10, 0xa0)).min(0x80);
        prefix_min = prefix_min.min(prefix_max);
        let chunk_initial = pick(s(22, 0), 0x200, 0x5b4).clamp(0x60, 0x5b4);
        let first_record_cap = pick(s(22, CHUNK0), 0x100, 0x300)
            .min(chunk_initial.min(0x300))
            .max(0x100);
        let chunk_max = pick(s(23, 0), 0x2000, 0x3fff).max(chunk_initial);
        let generator = s(6, 0) & 3;
        let pad_count = pick(s(9, 0), 2, 8);
        let pad_interval = pick(s(10, 0), 2, 0x0b);
        let small_limit = pick(s(11, 0), 0x60, 0x300);
        let bit_min = pick(s(12, 0), 0x18, 0x29);
        let bit_max = pick(s(13, 0), 0x3a, 0x4c);
        let mix_mode = s(16, 0) % 3;
        let mix_rounds = pick(s(17, 0), 1, 3);
        let mix_stride = pick(s(18, 0), 2, 13);
        let mix_offset_base = pick(s(19, 0), 0, 15);
        let mix_block = pick(s(20, 0), 8, 0x40);
        let chunk_policy = s(21, 0) % 3;
        let chunk_step = pick(s(24, 0), 0x400, 0x1000).min(0xb68);
        let chunk_jitter = pick(s(25, 0), 0x10, 0xc0).min(0xb6);
        let idle_reset_secs = pick(s(27, 0), 0x0c, 0x5a);
        let write_policy = s(28, 0) % 3;
        let write_first = pick(s(29, 0), 4, 8);
        let write_jitter = pick(s(32, 0), 0x08, 0x60);
        let write_jitter_pct = pick(s(28, 0x504c), 8, 0x30);
        let g = [
            0,
            pick(s(6, 1), 0x18, 0x80),
            pick(s(6, 2), 0x10, 0x60),
            pick(s(6, 3), 0x10, 0x60),
            pick(s(6, 4), 0x00, 0x09),
            pick(s(6, 5), 0x01, 0x08),
            pick(s(6, 6), 0x07, 0x17),
        ];
        let mut chunk_buckets = [0u64; 8];
        let mut write_buckets = [0u64; 8];
        let mut write_seq = [0u64; 8];
        for i in 0..8u64 {
            chunk_buckets[i as usize] = pick(s(26, i), 0x1000, chunk_max);
            write_buckets[i as usize] = pick(s(30, i), 0x140, 0x5b4);
            write_seq[i as usize] = pick(s(31, i), 0x168, 0x5b4);
        }

        // Salt block permutation and masks (§7.4.4).
        let len = salt_block_len as usize;
        let sp = |d: u64, i: u64| {
            fold(mix64(
                i.wrapping_mul(0x5899_65cc_7537_4cc3)
                    .wrapping_add(0x33a2_13ec_50ff_e2e9)
                    ^ (ns.salt ^ 0xdaa6_6d2c_7ddf_743f)
                    ^ d.wrapping_mul(0xe703_7ed1_a0b4_28db)
                        .wrapping_add(0x8f39_07f7_b2b8_0c35),
            ))
        };
        let mut perm: Vec<usize> = (0..len).collect();
        for round in 0..hs_mix_rounds.max(1) {
            let d = MIXHS + round;
            for i in 0..len {
                let j = i + (sp(d, i as u64) % (len - i) as u64) as usize;
                perm.swap(i, j);
            }
        }
        let mut salt_mask = [0u8; 16];
        for (i, mask) in salt_mask.iter_mut().enumerate() {
            let i = i as u64;
            *mask = ((i * hs_mix_stride) % 256) as u8 ^ (prf32(ns.salt, 2, MIXHS, i) as u8);
        }

        Self {
            ns,
            pad_min,
            pad_max,
            salt_prefix_len,
            salt_block_len,
            prefix_min,
            prefix_max,
            chunk_initial,
            first_record_cap,
            chunk_max,
            generator,
            pad_count,
            pad_interval,
            small_limit,
            bit_min,
            bit_max,
            mix_mode,
            mix_rounds,
            mix_stride,
            mix_offset_base,
            mix_block,
            chunk_policy,
            chunk_step,
            chunk_jitter,
            idle_reset_secs,
            write_policy,
            write_first,
            write_jitter,
            write_jitter_pct,
            g,
            chunk_buckets,
            write_buckets,
            write_seq,
            salt_perm: perm,
            salt_mask,
        }
    }

    fn prf(&self, label: u64, a: u64, b: u64) -> u64 {
        prf32(self.ns.of(label), label, a, b)
    }

    fn prf_bytes(&self, label: u64, a: u64, n: usize) -> Vec<u8> {
        let mut state = self.ns.of(label)
            ^ a.wrapping_mul(0xd6e8_feb8_6659_fd93)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ label.wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (n as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            state = state.wrapping_add(G);
            let word = mix64(state).to_le_bytes();
            let take = (n - out.len()).min(8);
            out.extend_from_slice(&word[..take]);
        }
        out
    }

    pub(crate) fn salt_block_len(&self) -> usize {
        self.salt_block_len as usize
    }

    pub(crate) fn idle_reset_secs(&self) -> u64 {
        self.idle_reset_secs
    }

    /// Salt block carrying `salt` (§7.4.4).
    pub(crate) fn salt_block(&self, salt: &[u8; 16]) -> Vec<u8> {
        let mut block = self.fill(SALT_FILL_SEQ, self.salt_block_len());
        for (i, byte) in salt.iter().enumerate() {
            block[self.salt_perm[i]] = self.salt_mask[i] ^ byte;
        }
        block
    }

    pub(crate) fn salt_from_block(&self, block: &[u8]) -> [u8; 16] {
        let mut salt = [0u8; 16];
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = self.salt_mask[i] ^ block[self.salt_perm[i]];
        }
        salt
    }

    /// Length of the plaintext prefix in front of frame `seq`.
    pub(crate) fn prefix_len(&self, seq: u64) -> usize {
        pick(self.prf(33, seq, 0), self.prefix_min, self.prefix_max) as usize
    }

    /// Padding and prefix content (§7.4.6).
    pub(crate) fn fill(&self, seq: u64, n: usize) -> Vec<u8> {
        let mut out = self.prf_bytes(0, seq, n);
        let g = &self.g;
        match self.generator {
            0 => {
                let bit_count = pick(self.prf(1, seq, 0), self.bit_min, self.bit_max);
                let scaled = bit_count * 8;
                let row = (if scaled <= 0x31 {
                    1
                } else if scaled > 0x2ed {
                    7
                } else {
                    (scaled + 0x32) / 100
                }) as usize;
                for (i, byte) in out.iter_mut().enumerate() {
                    let v = *byte;
                    let raw = v.wrapping_add(i as u8);
                    let t = TABLE[row * 16 + ((raw ^ v) & 0x0f) as usize];
                    *byte = t.rotate_left(u32::from((raw ^ (v >> 4)) & 7));
                }
            }
            1 => {
                let total = g[1] + g[2] + g[3];
                for (i, byte) in out.iter_mut().enumerate() {
                    let v = *byte;
                    let b = u64::from(v) % total;
                    *byte = if b < g[1] {
                        pick(u64::from(v.wrapping_add(i as u8)), 0x20, 0x7e) as u8
                    } else if b < g[1] + g[2] {
                        pick(u64::from(v ^ i as u8), 0x80, 0xbf) as u8
                    } else {
                        pick(
                            u64::from(v.wrapping_add(i.wrapping_mul(7) as u8)),
                            0xc0,
                            0xff,
                        ) as u8
                    };
                }
            }
            2 => {
                for (i, byte) in out.iter_mut().enumerate() {
                    let v = u64::from(*byte);
                    let i = i as u64;
                    let low = ((v & 0x0f) + g[4] + (i & 1)) % 10;
                    let high = (v + ((i & 3) << 4) + 0x30) & 0xf0;
                    *byte = (high | low) as u8;
                }
            }
            _ => {
                let motif = self.prf_bytes(2, seq, 32);
                let motif_len = match 4 * g[5] {
                    0 => 4,
                    len => len as usize,
                };
                let period = g[6].max(5) as usize;
                let (mut bo, mut mo) = (0usize, 0usize);
                for (i, byte) in out.iter_mut().enumerate() {
                    let v = *byte;
                    *byte = if bo < period - 3 {
                        (((g[5] + 3) * i as u64) % 256) as u8 ^ motif[mo % 32]
                    } else if bo < period - 1 {
                        0x30 | (v % 10)
                    } else {
                        v
                    };
                    bo = (bo + 1) % period;
                    mo = (mo + 1) % motif_len;
                }
            }
        }
        out
    }

    /// Swaps padding and ciphertext bytes of frame `seq` (§7.4.7). It is an
    /// involution: the receiver runs it again to undo it.
    pub(crate) fn mix(&self, seq: u64, padding: &mut [u8], ciphertext: &mut [u8]) {
        let n = padding.len().min(ciphertext.len());
        if n == 0 {
            return;
        }
        let swap_strided =
            |padding: &mut [u8], ciphertext: &mut [u8], stride: usize, off: usize| {
                if stride == 1 {
                    padding[..n].swap_with_slice(&mut ciphertext[..n]);
                    return;
                }
                let mut k = off;
                while k < n {
                    std::mem::swap(&mut padding[k], &mut ciphertext[k]);
                    k += stride;
                }
            };
        for round in 0..self.mix_rounds {
            let stride = (self.mix_stride + round % 3).max(1);
            match self.mix_mode {
                0 => {
                    let off = self.mix_offset_base % stride;
                    swap_strided(
                        &mut *padding,
                        &mut *ciphertext,
                        stride as usize,
                        off as usize,
                    );
                }
                1 => {
                    let block = self.mix_block as usize;
                    let mut off = (round as usize & 1) * block;
                    while off + block <= n {
                        padding[off..off + block]
                            .swap_with_slice(&mut ciphertext[off..off + block]);
                        off += 2 * block;
                    }
                }
                _ => {
                    let off = (self.prf(3, seq, round) + self.mix_offset_base) % stride;
                    swap_strided(
                        &mut *padding,
                        &mut *ciphertext,
                        stride as usize,
                        off as usize,
                    );
                }
            }
        }
    }

    /// Payload limit of the next frame; advances the sender state (§7.4.8).
    pub(crate) fn next_limit(&self, state: &mut SenderState, seq: u64, idle: bool) -> usize {
        if idle || state.chunk_size == 0 {
            state.chunk_size = self.chunk_initial;
        }
        let chunk_size = state.chunk_size;
        let mut limit = match self.chunk_policy {
            0 => chunk_size,
            1 => self.chunk_buckets[(self.prf(38, seq, chunk_size) % 8) as usize],
            _ => {
                let j = self.prf(39, seq, chunk_size) % (2 * self.chunk_jitter + 1);
                (chunk_size + j).saturating_sub(self.chunk_jitter)
            }
        };
        limit = limit.clamp(0x40, self.chunk_max);
        if seq == 0 {
            limit = limit.min(self.first_record_cap);
        }
        state.chunk_size = (chunk_size + self.chunk_step).min(self.chunk_max);
        limit.clamp(1, 0xFFFF) as usize
    }

    /// Padding length of frame `seq` with `n` payload bytes and a `pre`-byte
    /// prefix; `first` adds the salt block.
    pub(crate) fn padding_len(&self, seq: u64, n: usize, pre: usize, first: bool) -> usize {
        let n = n as u64;
        let pre = pre as u64;
        let mut p = if seq < self.pad_count
            || (n > 0 && n <= self.small_limit)
            || seq.is_multiple_of(self.pad_interval)
        {
            pick(self.prf(34, seq, n), self.pad_min, self.pad_max)
        } else {
            0
        };
        let tag = if n > 0 { 16 } else { 0 };
        let total = if first { self.salt_block_len } else { 0 };
        let frame = total + pre + HEADER_OVERHEAD + p + n + tag;
        let target = self.write_target(seq, frame);
        if target > frame {
            p += (target - frame).min(EXTRA);
        }
        if first {
            let base = if n > 0 { n + 0x37 } else { n + 0x27 };
            let threshold = (base * 25).div_ceil(75).max(0xc0);
            if self.salt_prefix_len + pre + p < threshold {
                let t = (threshold - self.salt_prefix_len - pre).min(self.pad_max + EXTRA);
                if t <= 0xfffe {
                    p = t;
                }
            }
        }
        p.min(0xFFFF) as usize
    }

    fn write_target(&self, seq: u64, frame: u64) -> u64 {
        if frame > 0x5b3 {
            return frame.min(0xFFFF);
        }
        let mut t = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[(self.prf(35, seq, frame) % 8) as usize]
        };
        if self.write_policy == 2 {
            let j = self.prf(36, seq, 0) % (2 * self.write_jitter + 1);
            t = (t + j).saturating_sub(self.write_jitter).max(1);
        }
        let spread = EXTRA.min(frame * self.write_jitter_pct / 100);
        if self.prf(35, seq, spread) & 1 == 0 {
            t = (t + spread).min(0xFFFF);
        } else if t > spread / 2 {
            t -= spread / 2;
        }
        while frame > t {
            let mut next = self.write_buckets[(self.prf(37, seq, t) % 8) as usize];
            if next <= t {
                next = t + self.pad_max;
                if next > 0xFFFF {
                    return 0xFFFF;
                }
            }
            t = next;
        }
        t
    }
}

/// Sender frame-sizing state of one direction (`chunkSize` in §7.4.8).
#[derive(Default)]
pub(crate) struct SenderState {
    chunk_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_deterministic_and_within_ranges() {
        let a = Profile::new(b"an interop test psk");
        let b = Profile::new(b"an interop test psk");
        let c = Profile::new(b"another psk value");
        assert_eq!(a.salt_perm, b.salt_perm);
        assert_eq!(a.fill(3, 40), b.fill(3, 40));
        assert_ne!(
            (a.salt_perm.clone(), a.fill(3, 40)),
            (c.salt_perm.clone(), c.fill(3, 40))
        );
        for p in [&a, &c] {
            assert!((0x18..=EXTRA).contains(&p.pad_min));
            assert!(p.pad_max <= EXTRA);
            assert!((16 + 0x10..=16 + 0x80).contains(&p.salt_block_len));
            assert!(p.prefix_min <= p.prefix_max && p.prefix_max <= 0x80);
            assert!(p.first_record_cap >= 0x100 && p.first_record_cap <= 0x300);
            assert!(p.chunk_max >= p.chunk_initial);
            assert!(p.generator < 4 && p.mix_mode < 3);
            let mut sorted = p.salt_perm.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..p.salt_block_len()).collect::<Vec<_>>());
        }
    }

    #[test]
    fn salt_block_round_trips() {
        for psk in [&b"0123456789ab"[..], b"another longer pre-shared key"] {
            let profile = Profile::new(psk);
            let salt: [u8; 16] = core::array::from_fn(|i| (i * 17 + 5) as u8);
            let block = profile.salt_block(&salt);
            assert_eq!(block.len(), profile.salt_block_len());
            assert_eq!(profile.salt_from_block(&block), salt);
        }
    }

    #[test]
    fn mix_is_an_involution_for_every_mode() {
        let mut profile = Profile::new(b"mix test psk");
        for mode in 0..3 {
            profile.mix_mode = mode;
            for (pad_len, ct_len) in [(0, 30), (5, 30), (300, 120), (64, 64), (700, 1500)] {
                let pad: Vec<u8> = (0..pad_len).map(|i| i as u8).collect();
                let ct: Vec<u8> = (0..ct_len).map(|i| (i as u8) ^ 0xa5).collect();
                let (mut p, mut c) = (pad.clone(), ct.clone());
                profile.mix(9, &mut p, &mut c);
                profile.mix(9, &mut p, &mut c);
                assert_eq!((p, c), (pad, ct));
            }
        }
    }

    #[test]
    fn every_generator_fills_the_requested_length() {
        let mut profile = Profile::new(b"generator test psk");
        for generator in 0..4 {
            profile.generator = generator;
            for n in [0, 1, 7, 64, 900] {
                assert_eq!(profile.fill(4, n).len(), n);
            }
        }
    }

    #[test]
    fn frame_sizes_stay_in_bounds() {
        let profile = Profile::new(b"sizing test psk");
        let mut state = SenderState::default();
        let first = profile.next_limit(&mut state, 0, true);
        assert!(first as u64 <= profile.first_record_cap);
        for seq in 1..50 {
            let limit = profile.next_limit(&mut state, seq, false);
            assert!((1..=0xFFFF).contains(&limit));
        }
        for seq in 0..50 {
            for n in [0, 1, 100, 1400, 0x3fff] {
                let pre = profile.prefix_len(seq);
                assert!(pre as u64 >= profile.prefix_min && pre as u64 <= profile.prefix_max);
                assert!(profile.padding_len(seq, n, pre, seq == 0) <= 0xFFFF);
            }
        }
    }
}
