//! Three lines an incident, and a `u64` that ties them together.
//!
//! **Why a field and not a span.** A span is the idiomatic answer and it is the wrong one
//! here: it allocates under `Registry`, this binary is built `panic = "abort"`, and the tick
//! is asserted at zero allocations by a counting global allocator. An `attack_id` on three
//! events costs the same as any other `u64` field — nothing after the formatter's buffer has
//! warmed — and reconstructs the incident with `journalctl -u loricad | grep attack_id=…`.
//! It is a grep and not a journald field match, because a text layer on stderr arrives as
//! `MESSAGE` and journald indexes no field this process did not send natively.
//!
//! **Why three and not one per rung change.** An incident that climbs from `Mark` to
//! `DropBroad` crosses four rungs and can oscillate across the hysteresis for as long as the
//! attack lasts, so a line per rung change makes the line count a function of how the attack
//! moves — which is the property this whole module exists not to have. The rung is on each of
//! the three lines, and everything between them is in the aggregate line.
//!
//! **What the third line carries and why it is not derivable from the first two.** Duration
//! and volume. An operator reading the detection line does not yet know either, and a reader
//! joining two lines by timestamp gets the duration wrong by up to one tick period and the
//! volume not at all, because the counter totals are not on the detection line.

use std::hash::{BuildHasher, RandomState};

use lorica_detect::{Decision, Reason, Snapshot, Tier};
use tracing::info;

/// The incident in force, or none.
#[derive(Default)]
pub struct Incident {
    /// Drawn once per process. The `attack_id` has to be unguessable across restarts so two
    /// runs of the agent cannot hand an operator the same id for different incidents; it does
    /// not have to be unpredictable to an attacker, because nothing rests on it.
    keys: RandomState,
    active: Option<Active>,
}

struct Active {
    id: u64,
    started_ns: u64,
    /// Stage events accounted when the incident opened, so the third line can carry a delta.
    events: u64,
    /// `acted` when the incident opened. A rise above it is mitigation becoming a rule.
    acted: u64,
    applied: bool,
}

impl Incident {
    /// The transition this tick, if there was one. Returns the lines emitted: zero or one.
    pub fn observe(&mut self, snapshot: &Snapshot, decision: &Decision, acted: u64) -> u64 {
        let events = stage_events(snapshot);

        let Some(active) = &mut self.active else {
            if decision.tier() == Tier::Observe {
                return 0;
            }
            let id = self.keys.hash_one((snapshot.seq, snapshot.at_ns));
            self.active = Some(Active {
                id,
                started_ns: snapshot.at_ns,
                events,
                acted,
                applied: false,
            });
            info!(
                attack_id = id,
                tick_seq = snapshot.seq,
                rung = decision.tier().rung(),
                reason = ground(decision.reason()),
                "detected"
            );
            return 1;
        };

        if decision.tier() == Tier::Observe {
            let (id, started_ns, opened_at) = (active.id, active.started_ns, active.events);
            self.active = None;
            info!(
                attack_id = id,
                tick_seq = snapshot.seq,
                duration_ms = snapshot.at_ns.saturating_sub(started_ns) / 1_000_000,
                events = events.saturating_sub(opened_at),
                "cleared"
            );
            return 1;
        }

        if !active.applied && acted > active.acted {
            active.applied = true;
            info!(
                attack_id = active.id,
                tick_seq = snapshot.seq,
                rung = decision.tier().rung(),
                // Jiffies, which is what the map entry was written with. Converting it to a
                // wall clock here would need the measured `CONFIG_HZ`, and a deadline
                // reprinted in a unit the kernel does not use is a number nobody can check
                // against the map.
                deadline = decision.deadline().0,
                "mitigating"
            );
            return 1;
        }

        0
    }
}

/// The ground of the decision, as a fixed string.
///
/// A name and not `?reason`: the `Debug` of a `Confirmed` carries an `LpmKey` and the one of a
/// `Saturation` two bit rates, so the line length would depend on which rung is in force —
/// and a formatter buffer that has to grow is an allocation in the tick.
const fn ground(reason: &Reason) -> &'static str {
    match reason {
        Reason::Quiet => "quiet",
        Reason::Pressure { .. } => "pressure",
        Reason::Confirmed { .. } => "confirmed",
        Reason::Saturation { .. } => "saturation",
    }
}

/// Stage events accounted since the agent started.
///
/// The sum over the named counters, which counts one packet once per stage it reached: it is
/// the same quantity the `stage_events` metric family exposes, and it is a volume rather than
/// a packet count. Named `events` on the line for that reason.
fn stage_events(snapshot: &Snapshot) -> u64 {
    snapshot
        .counters
        .named()
        .iter()
        .fold(0u64, |total, slot| total.wrapping_add(*slot))
}
