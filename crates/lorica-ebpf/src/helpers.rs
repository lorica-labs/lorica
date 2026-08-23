//! Every helper call of the data path goes through this module.
//!
//! Two reasons, both structural. The static call budget is auditable by reading one
//! file instead of grepping the pipeline. And each wrapper is `#[inline(never)]`, so
//! it is a single call site rather than one per caller: inlining the counter bump
//! would multiply its map lookup by the number of stages that count.
//!
//! These wrappers keep `#[inline(never)]` unconditionally, unlike the parsers and the
//! stages, which carry it only under the `profiling` feature. Here it is not
//! instrumentation: the static call budget is a count of the calls present in the
//! object, and inlining a wrapper would multiply its call by the number of callers.

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_FIB_LOOKUP_SKIP_NEIGH, bpf_fib_lookup as FibParams},
    helpers::{bpf_fib_lookup, bpf_jiffies64, bpf_ktime_get_ns},
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use lorica_common::{Bucket, Charge, CounterId, Family, LpmValue, PacketView, Rate};

use crate::maps::{BUCKET_BANK, COUNTERS, UNIFIED_LIST};

/// A packet is one host, so the lookup asks for the full width of the key and the trie
/// answers with the longest entry that covers it. Precedence is the specificity of the
/// address, and nothing in this program compares prefix lengths to obtain it.
const HOST_PREFIX_BITS: u32 = 128;

/// What the instrumented build counts. Kinds, not call sites: the budget of the
/// design is expressed as lookups and helpers, so that is what a test asserts.
#[cfg(feature = "count-helpers")]
#[derive(Clone, Copy)]
pub enum HelperKind {
    MapLookup = 0,
    /// Counted although the verifier inlines the fast-path clock into a load: what the
    /// budget is about is how many times a packet reads the clock, which is the number a
    /// stage can get wrong.
    ClockRead = 1,
    /// Neither of the two above, and the reason it needs a kind of its own: it is the most
    /// expensive call in the program by a factor of five, so a budget that folded it into
    /// the map lookups would hide the one number worth watching.
    FibLookup = 2,
}

#[cfg(feature = "count-helpers")]
impl HelperKind {
    pub const COUNT: u32 = 3;
}

/// Counting is itself a map lookup, so it must not count itself, and the probe write
/// of the parse tests must not count either. Otherwise the instrumented figure would
/// measure the instrumentation.
#[cfg(feature = "count-helpers")]
#[inline(always)]
fn observe(kind: HelperKind) {
    if let Some(slot) = crate::maps::HELPER_COUNTS.get_ptr_mut(kind as u32) {
        // SAFETY: the pointer comes from a successful per-CPU lookup.
        unsafe { *slot += 1 }
    }
}

/// The clock of the packet path. Read once per packet in `stage::run` and passed down;
/// reading it again in a stage would double the one clock read the budget allows.
///
/// `bpf_jiffies64` and not `bpf_ktime_get_ns`, because the nanoseconds were measured: the
/// helper call cost 54 ns of the 243 ns a legitimate UDP packet spent above the harness
/// floor, 22 % of the whole program, at an IPC of 0.7 where the rest of the program runs
/// at 2.1 — a serialising timestamp counter read. The verifier inlines this one into a
/// load of the kernel's jiffy counter, so what is left is a memory reference. The unit
/// that costs nothing is the unit the deadlines are written in.
#[inline(never)]
pub fn now_jiffies() -> u64 {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::ClockRead);
    // SAFETY: no argument, no pointer, and the helper exists since 5.5, well below the
    // 6.8 floor of the project.
    unsafe { bpf_jiffies64() }
}

/// Nanoseconds, for a path that is not the packet path: an event timestamp an operator
/// reads, or a measurement of the program itself. A jiffy is 1 to 4 ms wide, which is
/// coarser than anything worth timing inside one program run.
//
// `expect` and not `allow`: the day a path off the fast path reads this, the expectation
// goes unfulfilled and the build says so, which removes the attribute instead of leaving
// it to be noticed.
#[expect(dead_code)]
#[inline(never)]
pub fn now_ns() -> u64 {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::ClockRead);
    // SAFETY: no argument, no pointer, available on every kernel at and above the
    // floor.
    unsafe { bpf_ktime_get_ns() }
}

/// The one map lookup that serves every counter in the program.
///
/// Takes an index rather than a [`CounterId`] because the slots above the named ones
/// belong to individual entries of the unified list, and an entry knows its own index
/// and not a name.
#[inline(never)]
pub fn bump_at(index: u32) {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::MapLookup);
    if let Some(slot) = COUNTERS.get_ptr_mut(index) {
        // SAFETY: the pointer comes from a successful per-CPU lookup, so it is valid
        // for the duration of this program run and not shared with another CPU.
        unsafe { *slot += 1 }
    }
}

/// Inlined on purpose: it resolves a name to an index and calls the one wrapper, so
/// every counter in the program still goes through a single call site.
#[inline(always)]
pub fn bump(id: CounterId) {
    bump_at(id.index());
}

/// The one lookup of the unified list.
///
/// It lives here rather than in the stage for the same reason as the counter bump: the
/// static budget has to be readable in one file, and the instrumented count has to see
/// every call. A lookup issued straight from the stage would be invisible to both.
#[inline(never)]
pub fn list_lookup(src: &[u8; 16]) -> Option<LpmValue> {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::MapLookup);
    UNIFIED_LIST.get(Key::new(HOST_PREFIX_BITS, *src)).copied()
}

/// The address family as the kernel socket API numbers it, which is what
/// `bpf_fib_lookup` reads out of the first byte of its parameter block.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// What the reverse-path lookup answered.
///
/// Two values because the classification of stage 5 needs both, and because the helper
/// writes the interface it resolved over the one it was given: reading `ifindex` after the
/// call is the only way to learn where the route back leaves from.
#[derive(Clone, Copy)]
pub struct FibAnswer {
    /// A `BPF_FIB_LKUP_RET_*` code, or a negative errno widened, which is the helper
    /// refusing the call rather than answering it.
    pub code: u32,
    pub ifindex: u32,
}

/// The reverse-path lookup: the source of the packet asked as if it were a destination.
///
/// Here rather than in the stage for the same reason as the list lookup, and with more at
/// stake. It is by a wide margin the most expensive call in the program — arming stage 5
/// takes the legitimate path from 86 ns to 226 ns above the `XDP_PASS` floor, so **+140 ns
/// for this one call and the counter that follows it**, against 9 ns for a lookup in a
/// near-empty LPM trie. So both the static audit and the instrumented count have to see
/// it, and a call issued straight from the stage would be invisible to both.
///
/// An earlier fixture in C priced the same helper at 48 ns and that figure is wrong by
/// about a factor of three; the number above is the one measured on this wrapper, on the
/// real pipeline, twice.
///
/// `SKIP_NEIGH` because the only thing wanted here is the egress interface: without it the
/// helper goes on to walk the neighbour table to fill in two MAC addresses this stage
/// throws away, and on a host that really routes that is work on top of the 140 ns. The
/// flag arrived in 6.7 and the floor of the lab is 6.8; below 6.7 the kernel rejects the
/// flag word outright and the stage reads the negative return as an answer it cannot use,
/// which passes the packet — the same direction the criterion takes when it disarms.
///
/// Not `DIRECT`: that flag skips the routing rules, and on a host whose reverse path is
/// defined by a rule the rules are precisely the question being asked.
#[inline(never)]
pub fn fib_reverse_path(ctx: &XdpContext, view: &PacketView, ingress: u32) -> FibAnswer {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::FibLookup);

    // Sixty-four bytes of stack, and they live in this frame rather than in the caller's:
    // `#[inline(never)]` is what keeps the pipeline frame from swelling by the size of a
    // parameter block only one stage ever fills in.
    // SAFETY: every field is an integer or an array of integers, so the all-zero pattern
    // is a valid value, and zeroing is required — the helper reads the fields the family
    // selects and would otherwise read whatever the frame held.
    let mut params: FibParams = unsafe { core::mem::zeroed() };
    params.ifindex = ingress;
    match view.family() {
        Family::V4 => {
            params.family = AF_INET;
            // The parser stores v4 in the v4-mapped form, so the address is the last four
            // bytes. `from_ne_bytes` keeps them in the order they arrived in, which is the
            // network order the field is declared in.
            params.__bindgen_anon_4.ipv4_dst =
                u32::from_ne_bytes([view.src[12], view.src[13], view.src[14], view.src[15]]);
        }
        Family::V6 => {
            params.family = AF_INET6;
            params.__bindgen_anon_4.ipv6_dst = [
                u32::from_ne_bytes([view.src[0], view.src[1], view.src[2], view.src[3]]),
                u32::from_ne_bytes([view.src[4], view.src[5], view.src[6], view.src[7]]),
                u32::from_ne_bytes([view.src[8], view.src[9], view.src[10], view.src[11]]),
                u32::from_ne_bytes([view.src[12], view.src[13], view.src[14], view.src[15]]),
            ];
        }
    }

    // `tot_len` is left at zero on purpose: a non-zero one turns the lookup into an MTU
    // check too, which is a second question and a longer path.
    //
    // SAFETY: `params` is a live object of exactly the type the helper reads, the length
    // is its own size rather than a constant that could drift from it, and `ctx` is the
    // context this program was entered with.
    let code = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            &mut params,
            core::mem::size_of::<FibParams>() as i32,
            BPF_FIB_LOOKUP_SKIP_NEIGH,
        )
    };

    FibAnswer {
        code: code as u32,
        ifindex: params.ifindex,
    }
}

/// The one lookup of the bucket bank, drain and charge included.
///
/// It lives here for the same reason as the list lookup: a map lookup issued straight from
/// a stage is invisible to the instrumented counter and to the static audit, which is a
/// mistake this program has already paid for once. A bank lookup is counted as a
/// [`HelperKind::MapLookup`] and not as a kind of its own.
///
/// The update happens here rather than being handed back as a pointer because a
/// `PTR_TO_MAP_VALUE` returned from a bpf-to-bpf subprogram is not something to bet the
/// floor kernel on, and the arithmetic itself is `lorica_common::Bucket::charge` either
/// way. A missing slot answers `Within`: no bank is not a reason to refuse a packet.
#[inline(never)]
pub fn bank_charge(index: u32, rate: Rate, now: u64, size: u32) -> Charge {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::MapLookup);
    match BUCKET_BANK.get_ptr_mut(index) {
        // SAFETY: the pointer comes from a successful lookup, and `BankSlot` is `repr(C)`
        // with the bucket as its only field, so the value starts where the slot does.
        //
        // The four accesses are volatile, which is what pins [`stall`] between the load and
        // the store: nothing else in the language orders an unrelated side effect against a
        // plain load and a plain store the optimiser is free to move it across. The words
        // are also genuinely shared with every other CPU, so a volatile read and a volatile
        // write are the honest spelling of the update either way.
        Some(slot) => unsafe {
            let mut bucket = Bucket {
                level: core::ptr::read_volatile(&raw const (*slot).bucket.level),
                last_tick: core::ptr::read_volatile(&raw const (*slot).bucket.last_tick),
            };
            stall();
            let verdict = bucket.charge(rate, now, size);
            core::ptr::write_volatile(&raw mut (*slot).bucket.level, bucket.level);
            core::ptr::write_volatile(&raw mut (*slot).bucket.last_tick, bucket.last_tick);
            verdict
        },
        None => Charge::Within,
    }
}

/// Widens the window [`bank_charge`] holds a bucket open for, by as many reads of one
/// read-only word as `BUCKET_STALL` names, so the leak of the bank can be measured as a
/// function of that width rather than at the single width the program happens to have.
///
/// Zero in every load that is not a measurement, and zero means absent rather than cheap:
/// the verifier constant-folds the `.rodata` word and removes the loop before the JIT sees
/// it, the same way it removes an unarmed signature vector.
///
/// **Why this shape and not another.** The dead work has to survive the optimiser, has to
/// sit between the load and the store, and has to cost nothing but time. A volatile read is
/// the only construct that gets all three: it may not be deleted for having an unused
/// result, it may not be hoisted out of the loop, and it may not be reordered against the
/// volatile accesses of the bucket around it. An arithmetic chain would have needed its
/// result to reach the verdict in order to survive, which would have changed the verdict.
/// It is deliberately not a division — this program carries none, `helper_budget` asserts
/// that, and a division inside the window would confound the length of the window with the
/// cost of what fills it. And the word it reads is a line of this program's own `.rodata`
/// that no other CPU wants, so what the loop adds is window and not coherence traffic.
#[inline(always)]
fn stall() {
    for _ in 0..crate::settings::bucket_stall() {
        crate::settings::bucket_stall();
    }
}

/// Publishes the parsed view for the encapsulation tests. Deliberately outside the
/// helper accounting: it does not exist in a build without the feature.
#[cfg(feature = "parse-probe")]
#[inline(never)]
pub fn probe(view: &lorica_common::PacketView) {
    if let Some(slot) = crate::maps::PARSE_PROBE.get_ptr_mut(0) {
        // The two packet pointers are cleared first: the verifier refuses a store of a
        // pointer into a map value, and their values would mean nothing to a reader in
        // userspace anyway.
        let mut copy = *view;
        copy.data = 0;
        copy.data_end = 0;
        // SAFETY: the pointer comes from a successful per-CPU lookup.
        unsafe { *slot = copy }
    }
}
