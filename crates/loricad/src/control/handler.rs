//! The commands past `status`, and the only state a client is allowed to move.
//!
//! **`rules` walks the trie instead of reading the agent's own record, and the record is 1
//! key long.** The agent already remembers the single key its last applied rung wrote —
//! `standing` in `main` — so answering from that record would cost no syscall and would
//! read identically on a healthy agent. It would also be unfalsifiable. The one thing
//! `rules` exists to establish is that no active entry lacks a deadline, and the entry that
//! breaks it is by definition one [`apply`](crate::enforce::apply) did not write: a future
//! configuration path, a bug, a direct `lpm::load`. Those are exactly the entries a 1-key
//! record does not contain. `tests/control.rs` puts a `Deadline::never()` entry into the
//! trie behind `apply`'s back and asserts `rules` reports it, and that case is only
//! writable because this reads the map.
//!
//! **What the walk costs, and the ceiling it has.** `BPF_MAP_GET_NEXT_KEY` plus one lookup
//! per entry, so 2 syscalls per entry and no batching — an `LPM_TRIE` has no
//! `BPF_MAP_LOOKUP_BATCH` in the kernel, which is why the batch reader this crate already
//! owns is for `COUNTERS` and not for this. At the list size the agent writes into that is
//! a handful of syscalls per operator command, on a path no packet is waiting on. It is the
//! wrong shape for a list of a hundred thousand operator rules, and the answer then is a
//! bounded page rather than a whole list; nothing reloads such a list yet, so there is
//! nothing here to page.
//!
//! **`arm` asks `parse_options`' condition rather than repeating it.** See
//! [`arming_allowed`]: one predicate, one message, two callers.

use std::{collections::VecDeque, fmt::Write as _, net::Ipv6Addr};

use aya::{
    Ebpf,
    maps::{MapData, lpm_trie::LpmTrie},
};
use lorica_common::{CounterId, LpmKey, LpmValue, V4_MAPPED_PREFIX_BITS};
use lorica_detect::snapshot::NAMED_SLOTS;
use lorica_policy::Mode;

use super::{Snapshot, quote};
use crate::{attach::Attachment, enforce::withdraw};

/// The unified list, by the name `lorica-ebpf` declares it under.
const LIST: &str = "UNIFIED_LIST";

/// Transitions kept for `tiers`.
///
/// Bounded because a flapping agent transitions all day and an unbounded history is a leak
/// with a nice name on it. 64 is enough to see a whole escalation and its descent several
/// times over, and the count of every transition ever is reported next to the list so a
/// reader can tell the list was cut. The deque is built at this capacity and never grows
/// past it, which is what makes [`Tiers::note`] callable from the tick: the tick allocates
/// nothing, and a `Vec` that doubled would allocate on the transition.
const KEPT: usize = 64;

/// The mutable half of the control plane: what a command may read, and what it may change.
///
/// Every field is a borrow of a local of the agent's loop rather than a copy of one. A
/// second copy of `mode` would be a second answer to "is this agent armed", and the two
/// would be read by different code.
pub struct Control<'a> {
    pub mode: &'a mut Mode,
    /// The key the last applied rung wrote, so `disarm` can take it back out instead of
    /// leaving it to its deadline.
    pub standing: &'a mut Option<LpmKey>,
    /// Entries withdrawn. `disarm` adds to it, because a withdrawal it made is the same
    /// event as a withdrawal the descent made and an operator counting them should not have
    /// to know which path removed what.
    pub pulled: &'a mut u64,
    pub written: u64,
    pub withheld: u64,
    pub stages: &'a [u64; NAMED_SLOTS],
    pub tiers: &'a Tiers,
    /// The interface the program is on, if it is on one. Borrowed like `mode`, for the same
    /// reason: a copy would be a second answer to whether this agent is in the packet path,
    /// and the two would be read by different code.
    pub attached: &'a mut Option<Attachment>,
    /// The loaded program: for the one thing a borrowed descriptor cannot do, name a map,
    /// and for the one thing a shared borrow cannot do, attach.
    pub ebpf: &'a mut Ebpf,
}

/// One move of the ladder, as the tick saw it.
pub struct Transition {
    tick: u64,
    from: u8,
    to: u8,
}

/// The rungs the ladder has stood on, oldest kept first.
///
/// Recorded here and not read out of [`Engine`](lorica_detect::Engine), which counts its
/// transitions but keeps none: `Metrics::transitions` is a number and a history is a list.
/// `total` below is that same count kept locally, so the list and the count come from one
/// place and cannot disagree the way two counters of the same thing do.
pub struct Tiers {
    seen: VecDeque<Transition>,
    rung: u8,
    total: u64,
}

impl Default for Tiers {
    fn default() -> Self {
        Self {
            seen: VecDeque::with_capacity(KEPT),
            rung: 0,
            total: 0,
        }
    }
}

impl Tiers {
    /// Records `rung` if the ladder actually moved. Called every tick, and it allocates
    /// nothing: the deque is at capacity from the start and the oldest entry leaves before
    /// a new one arrives.
    pub fn note(&mut self, tick: u64, rung: u8) {
        if rung == self.rung {
            return;
        }
        if self.seen.len() == KEPT {
            self.seen.pop_front();
        }
        self.seen.push_back(Transition {
            tick,
            from: self.rung,
            to: rung,
        });
        self.rung = rung;
        self.total += 1;
    }

    pub fn rung(&self) -> u8 {
        self.rung
    }
}

/// Whether this agent has anywhere to count a refusal, which is the whole precondition of
/// arming.
///
/// Refused rather than aliased. Every entry the ladder writes points at a counter slot, and
/// the slots below [`CounterId::COUNT`] belong to the named counters: an armed agent with no
/// room above them would charge its own refusals to a stage counter and then read them back
/// as evidence for the next rung.
///
/// One predicate and one message, for two callers. `parse_options` asks it of `--mode
/// armed` at startup and [`arm`] asks it of a socket at runtime. A restated condition is
/// how a guard comes to hold on one path and not on the other, and the runtime path is the
/// one nobody reads a usage string before using.
pub fn arming_allowed(counter_slots: u32) -> Result<(), String> {
    if counter_slots > CounterId::COUNT {
        return Ok(());
    }
    Err(format!(
        "arming needs at least one counter slot above the {} named counters and this agent \
         has {counter_slots}: start it with --counters {} or more",
        CounterId::COUNT,
        CounterId::COUNT + 1
    ))
}

/// A refusal, in the one shape every caller can rely on. The message is escaped once, as a
/// whole, because part of it is a string a client sent.
pub(super) fn error(message: &str) -> String {
    format!("{{\"error\": {}}}\n", quote(message))
}

/// The word for a mode, and the same two words the configuration file uses.
///
/// A third vocabulary, and the reason it is acceptable is that `tests/control.rs` asserts
/// each word parses back through `Mode`'s own `FromStr`. That is the property that matters:
/// a mode `status` reports has to be a mode something can be set to.
pub(super) fn word(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "observe",
        Mode::Armed => "armed",
    }
}

/// The slot count as the guard needs it.
///
/// [`Snapshot`] carries it as a `usize` because it is read off the sweep, and it started
/// life as the `u32` size of a map. The saturation is therefore unreachable, and it is here
/// instead of a cast that would wrap in the permissive direction.
fn slots(snapshot: &Snapshot) -> u32 {
    u32::try_from(snapshot.counter_slots).unwrap_or(u32::MAX)
}

/// An address and its prefix length, in the notation an operator would type.
///
/// The v4-mapped range is rendered as IPv4 because that is how it was written: the unified
/// key puts IPv4 behind `::ffff:0:0/96`, and reporting `::ffff:198.51.100.7/128` for an
/// entry an operator asked for on `198.51.100.7/32` is the same number in a spelling nobody
/// can grep for.
pub(super) fn prefix(addr: [u8; 16], prefix_len: u32) -> String {
    let v6 = Ipv6Addr::from(addr);
    match v6.to_ipv4_mapped() {
        Some(v4) if prefix_len >= V4_MAPPED_PREFIX_BITS => {
            format!("{v4}/{}", prefix_len - V4_MAPPED_PREFIX_BITS)
        }
        _ => format!("{v6}/{prefix_len}"),
    }
}

/// `LpmValue` as aya's typed reader needs it.
///
/// The newtype exists only to carry the `Pod` bound: `lorica-common` is shared with the
/// eBPF crate and does not depend on aya, so it cannot state it itself.
#[derive(Clone, Copy)]
struct PodValue(LpmValue);

// SAFETY: LpmValue is Copy and 'static, and it is the value type UNIFIED_LIST is declared
// with in lorica-ebpf, so the kernel's value size is this size.
unsafe impl aya::Pod for PodValue {}

/// The ladder's history.
pub(super) fn tiers_json(control: &Control<'_>) -> String {
    let mut out = String::with_capacity(256 + control.tiers.seen.len() * 48);
    out.push_str("{\n");
    let _ = writeln!(out, "  \"rung\": {},", control.tiers.rung);
    let _ = writeln!(out, "  \"transitions\": {},", control.tiers.total);
    let _ = writeln!(out, "  \"kept\": {KEPT},");
    out.push_str("  \"history\": [\n");
    let last = control.tiers.seen.len();
    for (index, moved) in control.tiers.seen.iter().enumerate() {
        let comma = if index + 1 == last { "" } else { "," };
        let _ = writeln!(
            out,
            "    {{\"tick\": {}, \"from\": {}, \"to\": {}}}{comma}",
            moved.tick, moved.from, moved.to
        );
    }
    out.push_str("  ]\n}\n");
    out
}

/// Every entry the unified list is carrying, with the deadline it carries.
///
/// One entry per line, and `expires` is rendered for every one of them including the entries
/// that never expire. Leaving those out would make the answer look correct and make the
/// assertion in `tests/control.rs` unfailable, which are the same mistake.
pub(super) fn rules_json(snapshot: &Snapshot, control: &Control<'_>) -> String {
    let Some(map) = (*control.ebpf).map(LIST) else {
        return error(&format!("no {LIST} map in the loaded object"));
    };
    let list: LpmTrie<&MapData, [u8; 16], PodValue> = match LpmTrie::try_from(map) {
        Ok(list) => list,
        Err(err) => return error(&format!("{LIST} is not an LPM trie: {err}")),
    };

    // Collected before anything is rendered, so a walk that fails half way answers one
    // error rather than a truncated list a reader would take for the whole list.
    let mut entries = Vec::new();
    for found in list.iter() {
        match found {
            Ok((key, value)) => entries.push((key, value.0)),
            Err(err) => return error(&format!("walking {LIST} failed: {err}")),
        }
    }

    let now = snapshot.clock.jiffies;
    let hz = u64::from(snapshot.clock.hz).max(1);
    let mut out = String::with_capacity(256 + entries.len() * 160);
    out.push_str("{\n");
    let _ = writeln!(out, "  \"count\": {},", entries.len());
    let _ = writeln!(out, "  \"jiffies\": {now},");
    let _ = writeln!(out, "  \"kernel_hz\": {},", snapshot.clock.hz);
    out.push_str("  \"entries\": [\n");
    for (index, (key, value)) in entries.iter().enumerate() {
        let comma = if index + 1 == entries.len() { "" } else { "," };
        // Rendered as null and not as a large number, because a "584 million years"
        // remainder is a sentinel dressed up as a measurement.
        let left = if value.deadline.is_never() {
            "null".to_owned()
        } else {
            (value.deadline.0.saturating_sub(now) / hz).to_string()
        };
        let _ = writeln!(
            out,
            "    {{\"prefix\": {}, \"action\": {}, \"counter_slot\": {}, \
             \"deadline_jiffies\": {}, \"expires\": {}, \"expires_in_secs\": {left}}}{comma}",
            quote(&prefix(key.data(), key.prefix_len())),
            quote(&format!("{:?}", value.action)),
            value.counter_idx,
            value.deadline.0,
            !value.deadline.is_never(),
        );
    }
    out.push_str("  ]\n}\n");
    out
}

/// Arms the agent, if it has a slot to count refusals in.
pub(super) fn arm(snapshot: &Snapshot, control: &mut Control<'_>) -> String {
    if let Err(why) = arming_allowed(slots(snapshot)) {
        return error(&why);
    }
    *control.mode = Mode::Armed;
    format!(
        "{{\"mode\": {}, \"note\": {}}}\n",
        quote(word(Mode::Armed)),
        quote(
            "the next tick writes what the ladder is already deciding; nothing is written by \
             this command"
        )
    )
}

/// Puts the mode back and takes out what arming wrote.
///
/// The deadline would remove the entry eventually, and that is the objection rather than
/// the answer: an operator who disarms and then watches traffic still being dropped for the
/// rest of a ten-minute TTL has been told the agent is off while it is not.
///
/// Only the key the agent itself wrote is withdrawn. The list is shared with whatever else
/// ever writes into it, and a `disarm` that emptied it would be a command that removes an
/// operator's own entries.
pub(super) fn disarm(control: &mut Control<'_>) -> String {
    *control.mode = Mode::Observe;
    let Some(key) = control.standing.take() else {
        return format!(
            "{{\"mode\": {}, \"withdrawn\": null}}\n",
            quote(word(Mode::Observe))
        );
    };
    let Some(list) = lorica_dataplane::maps::fd(&*control.ebpf, LIST) else {
        // The mode is already back, which is the half that matters; the key stays recorded
        // so the descent can still take it out.
        *control.standing = Some(key);
        return error(&format!(
            "the mode is back to {} but {LIST} could not be named, so {} is still refused \
             until its deadline",
            word(Mode::Observe),
            prefix(key.addr, key.prefix_len)
        ));
    };
    if let Err(err) = withdraw(list, key) {
        *control.standing = Some(key);
        return error(&format!(
            "the mode is back to {} but withdrawing {} failed: {err}",
            word(Mode::Observe),
            prefix(key.addr, key.prefix_len)
        ));
    }
    *control.pulled += 1;
    format!(
        "{{\"mode\": {}, \"withdrawn\": {}}}\n",
        quote(word(Mode::Observe)),
        quote(&prefix(key.addr, key.prefix_len))
    )
}

/// Puts the program on an interface, and leaves it there.
///
/// The note in the answer is the attach tax, and it is in the answer rather than only in the
/// documentation because this command is the one place an operator can turn it on without
/// having read anything: `--iface` is typed next to a usage line, `attach` is typed into a
/// running agent. See [`crate::attach`] for where the two numbers come from.
///
/// Refusing a second attach rather than moving the program is the same argument
/// [`AttachError::Occupied`](lorica_dataplane::loader::AttachError) makes about somebody
/// else's program: a move that succeeds leaves the first interface unprotected without
/// anyone asking for that, and it would be reported as a success.
pub(super) fn attach(control: &mut Control<'_>, iface: &str) -> String {
    if iface.is_empty() {
        return error("attach needs an interface name: `attach <iface>`");
    }
    if let Some(held) = control.attached.as_ref() {
        return error(&format!(
            "already attached to {}; this agent holds one program and the XDP hook takes one \
             program per interface, so detach first",
            held.iface()
        ));
    }
    match crate::attach::attach(control.ebpf, iface) {
        Ok(held) => {
            let answer = format!(
                "{{\"attached\": true, \"interface\": {}, \"note\": {}}}\n",
                quote(held.iface()),
                quote(
                    "every received packet goes through the program from now on: 58 % off the \
                     receive throughput and 57 % onto the application p99, measured on virtio, \
                     whether or not anything is attacking"
                )
            );
            *control.attached = Some(held);
            answer
        }
        Err(why) => error(&why),
    }
}

/// Takes the program back off the interface.
///
/// The interface is named in the answer, and it is read out of the [`Attachment`] before the
/// detach consumes it — an operator who detaches has to be told what stopped being filtered,
/// and after the call there is nothing left to ask.
pub(super) fn detach(control: &mut Control<'_>) -> String {
    let Some(held) = control.attached.take() else {
        return error("not attached to anything, so there is nothing to detach");
    };
    let iface = held.iface().to_owned();
    match crate::attach::detach(control.ebpf, held) {
        Ok(()) => format!(
            "{{\"attached\": false, \"interface\": {}}}\n",
            quote(&iface)
        ),
        Err(why) => error(&why),
    }
}

/// There is nothing to re-read yet, and saying so is the whole command.
///
/// `main` loads the object, the compiled-in default settings and the whole signature
/// catalogue, and reads no policy file. A `reload` that answered success would be reporting
/// a re-read that did not happen, which is worse than not having the command: an operator
/// would conclude their edited file is in force.
pub(super) fn reload() -> String {
    error(
        "reload has no source to read: this agent takes its settings from the loaded object \
         and reads no configuration file, so there is nothing to re-read",
    )
}
