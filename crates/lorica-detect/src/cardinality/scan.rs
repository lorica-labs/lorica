//! One reduction over the per-prefix slots, in four instruction sets.
//!
//! **The asymmetry this file exists to exploit.** The kernel side has no vector unit — eBPF
//! has no SIMD instructions and no way to reach one — so everything it can do to a thousand
//! counters is a thousand times what it does to one. The agent runs on the same processor
//! with AVX-512 or NEON sitting idle. So the division is not an implementation detail: the
//! kernel counts and samples, and the whole-map arithmetic happens up here, once a tick, in
//! vector registers.
//!
//! **The alternative that was rejected, with its number.** Writing the scalar loop and
//! letting LLVM vectorise it. [`fold`] *is* that loop, compiled at `opt-level = 3`, and
//! `benches/scan.rs` measures it over 1024 slots at **657.9 and 788.7 ns** across two runs,
//! against **245.0 to 270.8 ns** for the hand-written AVX2 path and **132.5 to 160.1 ns**
//! for AVX-512 — 2.7x to 2.9x, and 4.9x both times. What the compiler will not do is the
//! saturating subtract, the unsigned compare and the unsigned maximum in vector registers,
//! because below AVX-512 `u64` has no unsigned compare at all: it sees `saturating_sub` and
//! a `>` on `u64` and leaves both scalar. The bias trick the AVX2 path carries is a rewrite
//! the compiler is not entitled to make. Both runs are on an AMD Ryzen 9 7900X, which is a
//! development host and not this project's measurement machine; the spread between them is
//! why two runs are quoted rather than one.
//!
//! **Why a value and not a `cfg`.** [`Isa`] is a parameter of [`reduce_with`], so the
//! fallback is a path a test can enter on the machine it is running on. A dispatch hidden
//! inside a `#[cfg]` would make the AVX2 and scalar paths unreachable on any host with
//! AVX-512, which is how a fallback rots: compiled on every push, executed on none.

/// What one pass over the slots answers.
///
/// Three numbers and not a per-slot output, because the decision above needs the shape of
/// the distribution and not its contents: how many prefixes are moving, whether any single
/// one is moving enough to be named, and what they add up to. A per-slot result would be a
/// second buffer the size of the map for a caller that reduces it again.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Reduction {
    /// Slots whose delta reached the floor.
    pub active: u32,
    /// The largest single delta.
    pub hottest: u64,
    /// Every delta added up.
    ///
    /// Wrapping, in every path including the scalar reference. AVX-512 is the only one of
    /// the four with a saturating 64-bit add, so a saturating total would be a number the
    /// paths could legitimately disagree on — and the equivalence between them is worth
    /// more than a saturation that only a corrupt read reaches. The width is the guard:
    /// 1024 slots would each have to carry 2^54 hits in one tick to wrap this.
    pub total: u64,
}

/// Which instruction set a reduction was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Isa {
    /// The reference. Defines the correct answer; the other three are checked against it.
    Scalar,
    Avx512,
    Avx2,
    Neon,
}

impl Isa {
    /// Widest first, which is the order [`Self::detect`] walks.
    pub const ALL: [Isa; 4] = [Isa::Avx512, Isa::Avx2, Isa::Neon, Isa::Scalar];

    /// The widest path this processor can run.
    pub fn detect() -> Self {
        Self::ALL
            .into_iter()
            .find(|isa| isa.available())
            .unwrap_or(Isa::Scalar)
    }

    /// Whether this path answers on this processor.
    ///
    /// Defined as the path itself answering on an empty input rather than as a second copy
    /// of the feature detection. Two copies of a detection are two things to keep in step,
    /// and the one a caller can see is not the one that decides.
    pub fn available(self) -> bool {
        reduce_with(self, &[], &[], 1).is_some()
    }

    pub const fn name(self) -> &'static str {
        match self {
            Isa::Scalar => "scalar",
            Isa::Avx512 => "avx512",
            Isa::Avx2 => "avx2",
            Isa::Neon => "neon",
        }
    }
}

/// One pass over the slots on the widest path this processor has.
pub fn reduce(cur: &[u64], prev: &[u64], floor: u64) -> Reduction {
    reduce_with(Isa::detect(), cur, prev, floor)
        .unwrap_or_else(|| reduce_with(Isa::Scalar, cur, prev, floor).unwrap_or_default())
}

/// One pass on a named path, or `None` when this processor cannot run it.
///
/// `None` and not a silent fall back to the scalar path: a test that forces AVX2 has to be
/// able to tell "AVX2 agreed" from "AVX2 was not there and the scalar path answered
/// instead", and a function that quietly substitutes one for the other makes the
/// equivalence test pass on a machine that never ran a vector instruction.
///
/// `floor` is raised to one. A floor of zero would count every slot in the map as active,
/// including the ones that have never been touched.
pub fn reduce_with(isa: Isa, cur: &[u64], prev: &[u64], floor: u64) -> Option<Reduction> {
    let n = cur.len().min(prev.len());
    let (cur, prev) = (&cur[..n], &prev[..n]);
    let floor = floor.max(1);
    match isa {
        Isa::Scalar => {
            let mut out = Reduction::default();
            fold(&mut out, cur, prev, floor);
            Some(out)
        }
        Isa::Avx512 => avx512_reduce(cur, prev, floor),
        Isa::Avx2 => avx2_reduce(cur, prev, floor),
        Isa::Neon => neon_reduce(cur, prev, floor),
    }
}

/// The reference arithmetic, and the tail of all three vector loops.
///
/// One function for both jobs on purpose: a separate tail would be a fourth expression of
/// the same three operations, and the remainder of a vector loop is exactly where a
/// second expression of it would go wrong unwitnessed.
fn fold(out: &mut Reduction, cur: &[u64], prev: &[u64], floor: u64) {
    for (c, p) in cur.iter().zip(prev.iter()) {
        let d = c.saturating_sub(*p);
        if d >= floor {
            out.active += 1;
        }
        if d > out.hottest {
            out.hottest = d;
        }
        out.total = out.total.wrapping_add(d);
    }
}

/// AVX2 has no unsigned 64-bit compare — `_mm256_cmpgt_epi64` is signed — and a counter
/// above `2^63` would compare the wrong way round. Flipping the sign bit maps the unsigned
/// order onto the signed one exactly, for every input, which is what lets this path agree
/// with [`fold`] on the whole `u64` range instead of on the range someone assumed counters
/// stay inside.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2(cur: &[u64], prev: &[u64], floor: u64) -> Reduction {
    use core::arch::x86_64::{
        _mm256_add_epi64, _mm256_andnot_si256, _mm256_blendv_epi8, _mm256_cmpgt_epi64,
        _mm256_loadu_si256, _mm256_set1_epi64x, _mm256_setzero_si256, _mm256_storeu_si256,
        _mm256_sub_epi64, _mm256_xor_si256,
    };

    const LANES: usize = 4;

    let bias = _mm256_set1_epi64x(i64::MIN);
    // `d > floor - 1` is `d >= floor` for unsigned `d`, and `floor` is never zero.
    let gate = _mm256_xor_si256(_mm256_set1_epi64x((floor - 1) as i64), bias);
    let mut active = _mm256_setzero_si256();
    let mut total = _mm256_setzero_si256();
    let mut hot = _mm256_setzero_si256();

    let chunks = cur.len() / LANES;
    for i in 0..chunks {
        let at = i * LANES;
        // SAFETY: `at + LANES <= chunks * LANES <= cur.len()`, and `prev` was trimmed to
        // `cur.len()` by `reduce_with`. Both are unaligned loads, so the pointers carry no
        // alignment precondition beyond that of `u64`, which the slices already hold.
        let (c, p) = unsafe {
            (
                _mm256_loadu_si256(cur.as_ptr().add(at).cast()),
                _mm256_loadu_si256(prev.as_ptr().add(at).cast()),
            )
        };
        let borrow = _mm256_cmpgt_epi64(_mm256_xor_si256(p, bias), _mm256_xor_si256(c, bias));
        // `saturating_sub`: the lanes where `prev` exceeded `cur` are zeroed rather than
        // wrapped, which is what the reference does and what a counter map that was reset
        // under the reader produces.
        let d = _mm256_andnot_si256(borrow, _mm256_sub_epi64(c, p));
        let db = _mm256_xor_si256(d, bias);
        // A matching lane is all ones, so subtracting the mask adds one to the lane.
        active = _mm256_sub_epi64(active, _mm256_cmpgt_epi64(db, gate));
        total = _mm256_add_epi64(total, d);
        hot = _mm256_blendv_epi8(hot, d, _mm256_cmpgt_epi64(db, _mm256_xor_si256(hot, bias)));
    }

    // Stored rather than reduced with a shuffle sequence, and stored three times rather
    // than through one closure: a closure inside a `#[target_feature]` function does not
    // inherit the feature, so the intrinsic inside it would be compiled for the baseline.
    let mut lanes = [0u64; LANES];
    // SAFETY: `lanes` holds exactly `LANES` u64, which is the width of one store, and the
    // store is unaligned. The same holds for the two below.
    unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), active) };
    let active = lanes.iter().sum::<u64>() as u32;
    // SAFETY: as above.
    unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), total) };
    let total = lanes.iter().fold(0u64, |a, b| a.wrapping_add(*b));
    // SAFETY: as above.
    unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), hot) };
    let hottest = lanes.iter().copied().max().unwrap_or(0);

    let mut out = Reduction {
        active,
        hottest,
        total,
    };
    let done = chunks * LANES;
    fold(&mut out, &cur[done..], &prev[done..], floor);
    out
}

/// AVX-512 is the only one of the three with the operations this reduction actually wants:
/// `_mm512_cmpge_epu64_mask` compares unsigned without the bias trick, and
/// `_mm512_max_epu64` is one instruction where AVX2 needs a compare and a blend.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn avx512(cur: &[u64], prev: &[u64], floor: u64) -> Reduction {
    use core::arch::x86_64::{
        _mm512_add_epi64, _mm512_cmpge_epu64_mask, _mm512_loadu_si512, _mm512_maskz_sub_epi64,
        _mm512_max_epu64, _mm512_set1_epi64, _mm512_setzero_si512, _mm512_storeu_si512,
    };

    const LANES: usize = 8;

    let gate = _mm512_set1_epi64(floor as i64);
    let mut active = 0u32;
    let mut total = _mm512_setzero_si512();
    let mut hot = _mm512_setzero_si512();

    let chunks = cur.len() / LANES;
    for i in 0..chunks {
        let at = i * LANES;
        // SAFETY: `at + LANES <= chunks * LANES <= cur.len()`, and `prev` was trimmed to
        // `cur.len()` by `reduce_with`. Both loads are unaligned.
        let (c, p) = unsafe {
            (
                _mm512_loadu_si512(cur.as_ptr().add(at).cast()),
                _mm512_loadu_si512(prev.as_ptr().add(at).cast()),
            )
        };
        let d = _mm512_maskz_sub_epi64(_mm512_cmpge_epu64_mask(c, p), c, p);
        active += _mm512_cmpge_epu64_mask(d, gate).count_ones();
        total = _mm512_add_epi64(total, d);
        hot = _mm512_max_epu64(hot, d);
    }

    let mut lanes = [0u64; LANES];
    // SAFETY: `lanes` holds exactly `LANES` u64, which is the width of one store, and the
    // store is unaligned. The same holds for the one below.
    unsafe { _mm512_storeu_si512(lanes.as_mut_ptr().cast(), total) };
    let total = lanes.iter().fold(0u64, |a, b| a.wrapping_add(*b));
    // SAFETY: as above.
    unsafe { _mm512_storeu_si512(lanes.as_mut_ptr().cast(), hot) };
    let hottest = lanes.iter().copied().max().unwrap_or(0);

    let mut out = Reduction {
        active,
        hottest,
        total,
    };
    let done = chunks * LANES;
    fold(&mut out, &cur[done..], &prev[done..], floor);
    out
}

/// AArch64 NEON, where the register holds two lanes rather than four or eight — and where
/// the unsigned compares AVX2 lacks are all present, so no bias trick is needed.
///
/// `#[target_feature(enable = "neon")]` even though NEON is baseline on every `aarch64`
/// target, because the compiler does not accept that as a reason: "the neon target feature
/// being enabled in the build configuration does not remove the requirement to list it in
/// `#[target_feature]`". This function was written without the attribute and would not have
/// compiled for any ARM host — `cargo clippy --target aarch64-unknown-linux-gnu` is what
/// found that on an x86 development machine, and it is the only thing that can.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon(cur: &[u64], prev: &[u64], floor: u64) -> Reduction {
    use core::arch::aarch64::{
        vaddq_u64, vandq_u64, vbslq_u64, vcgeq_u64, vcgtq_u64, vdupq_n_u64, vgetq_lane_u64,
        vld1q_u64, vsubq_u64,
    };

    const LANES: usize = 2;

    let gate = vdupq_n_u64(floor);
    let one = vdupq_n_u64(1);
    let mut active = vdupq_n_u64(0);
    let mut total = vdupq_n_u64(0);
    let mut hot = vdupq_n_u64(0);

    let chunks = cur.len() / LANES;
    for i in 0..chunks {
        let at = i * LANES;
        // SAFETY: `at + LANES <= chunks * LANES <= cur.len()`, and `prev` was trimmed to
        // `cur.len()` by `reduce_with`. `vld1q_u64` reads two u64 from a `*const u64`,
        // whose alignment the slice already holds.
        let (c, p) = unsafe {
            (
                vld1q_u64(cur.as_ptr().add(at)),
                vld1q_u64(prev.as_ptr().add(at)),
            )
        };
        // `saturating_sub`: all-ones where `cur >= prev`, so the and keeps the difference
        // there and zeroes it everywhere else.
        let d = vandq_u64(vsubq_u64(c, p), vcgeq_u64(c, p));
        active = vaddq_u64(active, vandq_u64(vcgeq_u64(d, gate), one));
        total = vaddq_u64(total, d);
        hot = vbslq_u64(vcgtq_u64(d, hot), d, hot);
    }

    // Extracted lane by lane rather than through a closure: a closure inside a
    // `#[target_feature]` function does not inherit the feature.
    let mut out = Reduction {
        active: vgetq_lane_u64::<0>(active).wrapping_add(vgetq_lane_u64::<1>(active)) as u32,
        hottest: vgetq_lane_u64::<0>(hot).max(vgetq_lane_u64::<1>(hot)),
        total: vgetq_lane_u64::<0>(total).wrapping_add(vgetq_lane_u64::<1>(total)),
    };
    let done = chunks * LANES;
    fold(&mut out, &cur[done..], &prev[done..], floor);
    out
}

fn avx2_reduce(cur: &[u64], prev: &[u64], floor: u64) -> Option<Reduction> {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: the branch is the precondition. `avx2` is the only feature the function
        // enables and it was just detected on the processor this thread runs on.
        return Some(unsafe { avx2(cur, prev, floor) });
    }
    let _ = (cur, prev, floor);
    None
}

fn avx512_reduce(cur: &[u64], prev: &[u64], floor: u64) -> Option<Reduction> {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx512f") {
        // SAFETY: the branch is the precondition. `avx512f` is the only feature the
        // function enables and it was just detected on this processor.
        return Some(unsafe { avx512(cur, prev, floor) });
    }
    let _ = (cur, prev, floor);
    None
}

fn neon_reduce(cur: &[u64], prev: &[u64], floor: u64) -> Option<Reduction> {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: the branch is the precondition. `neon` is the only feature the function
        // enables, and it was just detected — detected rather than assumed from the target,
        // so this reads the same as the two x86 paths above.
        return Some(unsafe { neon(cur, prev, floor) });
    }
    let _ = (cur, prev, floor);
    None
}
