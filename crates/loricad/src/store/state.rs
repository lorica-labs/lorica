//! The mitigation state, and the one number that decides what persisting it costs.
//!
//! **`fsync` per tick is the trap of this project, and it dwarfs the choice of engine.**
//! Measured on carapace-dev, release, ext4, redb 2.6.3: a `Durability::None` commit costs
//! 45.4 us at the p50 and a `Durability::Immediate` one costs 3487 us, a factor of 77 on the
//! same code with one flag changed. No engine choice is worth a factor of 77, so the number
//! that decides whether the agent is a source of jitter is [`State::harden_every`] and not
//! the name of the library. redb is here for the reasons of a distant second place: one
//! thread, no C dependency, a few MiB of RSS, and a `Database::create` measured in tens of
//! microseconds.
//!
//! The figures this was written against were 7 us and 1448 us. Neither reproduced on
//! carapace-dev; the floor of a redb 2.6.3 write transaction there was 23 us with the
//! database on tmpfs, and the durable side is whatever the disk charges for an `fsync`, which
//! fio put at 3.16 ms on the measurement VM. The ratio survives, the absolute numbers do not.
//!
//! **redb 4.2.0 changed the cost structure, and it refuted the reason the cadence had.** The
//! numbers above and every cadence figure that used to be in this tree came from 2.6.3, where
//! each `Durability::None` commit pinned a parent state that only a durable commit cleared:
//! the cheap commit got more expensive the longer hardening was deferred, and the durable one
//! paid for the whole backlog. Re-measured across cadences on the same machine, before and
//! after the upgrade — DESKTOP-EDSDEFV, WSL2, ext4, release, 10 000 commits per cadence, from
//! `tests/store.rs::the_cost_per_write_is_dominated_past_ten_writes_a_commit`:
//!
//! | writes per durable commit | non-durable p50, 2.6.3 → 4.2.0 | durable p50, 2.6.3 → 4.2.0 |
//! |---|---|---|
//! | 2 | 33.0 → 10.4 us | 1373.6 → 1425.6 us |
//! | 10 | 17.7 → 4.0 us | 1773.9 → 1446.8 us |
//! | 100 | 20.4 → 3.7 us | 3155.2 → 1462.2 us |
//! | never | 36.3 → 3.7 us | — |
//!
//! Two things moved. The cheap commit is **4.4x faster** at the shipped cadence, against the
//! "about twice as fast" the 4.2.0 release notes claim. And the backlog stopped being paid
//! for: under 2.6.3 the durable commit grew 1373 → 1773 → 3155 us as the cadence lengthened,
//! under 4.2.0 it is flat at 1425 → 1447 → 1462, which is one `fsync` and nothing else. The
//! non-durable side went flat with it.
//!
//! So the argument that a cadence past about ten writes was **strictly dominated** — a higher
//! cost per write *and* a wider window of loss — does not hold on 4.2.0. Cost per write now
//! falls monotonically as the cadence lengthens (163.7 us at 10, 21.7 at 100, 4.0 at never),
//! because a longer cadence adds one fixed `fsync` and nothing else. The cadence is therefore
//! chosen on the loss window alone; see [`State::DEFAULT_HARDEN_EVERY`].
//!
//! Absolutes are this machine's, whose `fsync` is 1.45 ms against the 3.16 ms fio put on the
//! measurement VM. **The lab re-run is what re-baselines them**; what transfers between
//! machines is the two structural facts above, which are ratios.
//!
//! **A non-durable commit is still a commit.** `Durability::None` does not mean "maybe
//! written": the write transaction is atomic either way, and a crash rolls the database
//! back to the last *durable* commit rather than leaving a torn one. What the cadence
//! trades away is how many ticks of history a crash costs, never the integrity of the
//! base. `crash_between_durable_commits_leaves_a_consistent_base` is the assertion.
//!
//! **A tier change hardens regardless of the cadence.** The tick count is telemetry and
//! losing thirty seconds of it costs nothing; the tier is the fact the agent has to agree
//! with the kernel about after a restart, so it is the one write that pays for an `fsync`.
//!
//! No `compact()` is called, and that is deliberate rather than pending. Under 2.6.3 every
//! `Durability::None` commit registered a live read transaction on the parent state so redb
//! could roll back to it, and only a durable commit cleared them; `compact()` refused while
//! one existed and blamed "a transaction still in progress" that the caller never opened.
//! 4.2.0 reclaims space with savepoints alive, so that particular refusal is gone — and the
//! reason to leave compaction out is now the only one that was ever load-bearing: a state of
//! three keys rewritten in place has nothing to compact.

use std::path::Path;

use anyhow::{Context, Result, bail};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};

/// One table, three keys, `u64` values. No serialisation format, so no version of one to
/// migrate: a key this file stops writing is a key the next version stops reading.
const STATE: TableDefinition<&str, u64> = TableDefinition::new("mitigation");

const TIER: &str = "tier";
const TICKS: &str = "ticks";

/// How far the mitigation has escalated.
///
/// Three values because the agent has three postures and not because a scale was wanted:
/// the program is loaded but not attached by default — which is what the attach-tax
/// measurement forced — attached when detection says so, and enforcing only when the
/// operator has turned enforcement on. Anything finer belongs to whoever decides the
/// escalation, not to whoever writes it down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Tier {
    Detached = 0,
    Attached = 1,
    Enforcing = 2,
}

impl Tier {
    /// Parses a persisted discriminant. `None` rather than a transmute, and `None` rather
    /// than a default: a value this build does not know came from a newer agent, and
    /// silently reading it as `Detached` would detach a host that is under attack.
    pub const fn from_u64(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Detached),
            1 => Some(Self::Attached),
            2 => Some(Self::Enforcing),
            _ => None,
        }
    }
}

impl State {
    /// Ticks between two durable commits, unless a caller says otherwise: **one second of a
    /// 10 Hz agent**.
    ///
    /// **It is a choice about the loss window, and on redb 4.2 that is the only axis left.**
    /// On 2.6.3 there was a second one: a longer cadence made the cheap commit slower and the
    /// durable one pay for the whole backlog, so past about ten writes a commit the curve was
    /// strictly dominated — worse cost *and* worse window — and ten was where the two met.
    /// 4.2.0 flattened both halves, so cost per write now falls all the way to "never harden"
    /// and nothing but the window argues for a bound. The module header carries the
    /// before-and-after table and
    /// `tests/store.rs::the_cost_per_write_is_dominated_past_ten_writes_a_commit` is what
    /// re-measures it — including on the machine where it matters, which is not the one that
    /// produced those numbers.
    ///
    /// So ten survives its own justification changing, and what it costs is one `fsync` a
    /// second: 1.45 ms of the 1 000 available on the machine measured, 0.15 % of a core, and
    /// 163.7 us per write against the 4.0 us of never hardening at all.
    ///
    /// What one second of loss costs: the tick count, which is telemetry. The tier is the one
    /// fact the agent has to agree with the kernel about after a restart, and a tier change
    /// hardens regardless of this number — which is why a wider window is cheap here and
    /// would not be if the tier rode on the cadence.
    pub const DEFAULT_HARDEN_EVERY: u64 = 10;
}

pub struct State {
    db: Database,
    tier: Tier,
    ticks: u64,
    /// Ticks between two durable commits. At 10 Hz, [`State::DEFAULT_HARDEN_EVERY`] is one
    /// second of tick history at risk and one `fsync` a second; 1 is the trap named at the
    /// top of this file and is accepted only because refusing it would hide it.
    harden_every: u64,
    since_harden: u64,
    hardenings: u64,
}

impl State {
    /// Opens or creates the database and reads back the tier it was left at.
    ///
    /// The table is created under `Durability::Immediate`, so a fresh database has a
    /// durable commit to roll back to before the first tick ever runs. Without one, the
    /// crash the cadence is measured against would have nothing to return to.
    pub fn open(path: &Path, harden_every: u64) -> Result<Self> {
        if harden_every == 0 {
            bail!(
                "harden_every 0 would never issue a durable commit, so a crash would lose all of it"
            );
        }
        let db = Database::create(path)
            .with_context(|| format!("cannot open the state database at {}", path.display()))?;

        let mut txn = db
            .begin_write()
            .context("cannot begin the opening transaction")?;
        // Fallible since redb 4: the only way it refuses is a durability *reduced* below
        // Immediate inside a transaction that touched a persistent savepoint. This file
        // creates no savepoint — the module header says why — and this call raises the
        // durability rather than reducing it, so the error is unreachable and is propagated
        // instead of asserted away.
        txn.set_durability(Durability::Immediate)
            .context("cannot make the opening transaction durable")?;
        txn.open_table(STATE)
            .context("cannot create the mitigation table")?;
        txn.commit()
            .context("cannot commit the opening transaction")?;

        let read = db.begin_read().context("cannot read the state back")?;
        let table = read
            .open_table(STATE)
            .context("the mitigation table is missing right after being created")?;
        let raw_tier = table.get(TIER).context("cannot read the tier")?;
        let tier = match raw_tier {
            Some(value) => {
                let raw = value.value();
                Tier::from_u64(raw)
                    .with_context(|| format!("{raw} is not a tier this build knows"))?
            }
            None => Tier::Detached,
        };
        let ticks = table
            .get(TICKS)
            .context("cannot read the tick count")?
            .map_or(0, |value| value.value());
        drop(table);
        drop(read);

        Ok(Self {
            db,
            tier,
            ticks,
            harden_every,
            since_harden: 0,
            hardenings: 0,
        })
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Durable commits this process has made. Not persisted: it says what the cadence did,
    /// which is a question about this run and not about the database.
    pub fn hardenings(&self) -> u64 {
        self.hardenings
    }

    /// Writes one tick.
    ///
    /// Durable when the tier moved or when the cadence is due, non-durable otherwise. The
    /// tier is compared before it is stored, so the transition itself is what triggers the
    /// `fsync` and the ticks that follow at the same tier do not.
    pub fn record(&mut self, tier: Tier) -> Result<()> {
        let changed = tier != self.tier;
        let durable = changed || self.since_harden + 1 >= self.harden_every;
        let ticks = self.ticks + 1;

        let mut txn = self
            .db
            .begin_write()
            .context("cannot begin the tick write")?;
        txn.set_durability(if durable {
            Durability::Immediate
        } else {
            Durability::None
        })
        .context("cannot set the durability of the tick write")?;
        {
            let mut table = txn
                .open_table(STATE)
                .context("cannot open the mitigation table")?;
            // The tier is written only when it moves, so the ordinary tick is one insert and
            // not two. It is in the same transaction as the tick count, so the two can never
            // be read out of step.
            if changed {
                table
                    .insert(TIER, tier as u64)
                    .context("cannot write the tier")?;
            }
            table
                .insert(TICKS, ticks)
                .context("cannot write the tick count")?;
        }
        txn.commit().context("cannot commit the tick")?;

        self.tier = tier;
        self.ticks = ticks;
        if durable {
            self.hardenings += 1;
            self.since_harden = 0;
        } else {
            self.since_harden += 1;
        }
        Ok(())
    }
}
