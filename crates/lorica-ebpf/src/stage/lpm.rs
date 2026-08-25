//! Stage 3. One list, one lookup: the allow list and the block list are the same trie
//! and the value carries the verdict.
//!
//! Precedence is the specificity of the address, which is what the trie returns. The
//! scope lives in the value rather than in the key because an LPM_TRIE matches only
//! the leading bits of its key, so a protocol and a port in the key would forbid any
//! generic entry.
//!
//! **What is left for it now that `blocklist` runs first.** The two flat tables next door
//! resolve every IPv4 prefix, at 4 MiB and 16 MiB fixed and one access for the common case;
//! the trie is 198 MiB and 414 ns at a million entries, which is what moved the operator
//! blocklist out of it. What the trie still does better than any snapshot is the thing a
//! snapshot cannot do at all: a per-entry deadline and a single-entry update. So this stage
//! now serves IPv6, and the exact keys the detection loop writes with a TTL — and a
//! configuration carrying neither loses the stage entirely, because
//! [`settings::blocklist_trie`] is a `.rodata` word the verifier folds and the branch below
//! is then not in the JITed program at all.

use lorica_common::{Action, CounterId, PacketView};

use crate::{helpers, settings, stage::Outcome};

#[inline(never)]
pub fn run(view: &PacketView, now: u64) -> Outcome {
    // First, and before the lookup, because that is the point: a cleared word takes
    // everything below out of the program rather than skipping it at run time.
    if !settings::blocklist_trie() {
        return Outcome::Continue;
    }

    let Some(value) = helpers::list_lookup(&view.src) else {
        return Outcome::Continue;
    };

    // Checked before the scope, and for every action rather than only for the drops. An
    // entry past its deadline has nothing to say about this packet at all, so calling it
    // a scope miss would report the wrong thing; and an allow that outlives its deadline
    // is a permanent exemption nobody decided, which is the direction that costs more.
    //
    // The entry is left where it is. Removal belongs to the agent, and the whole reason
    // the comparison happens here is that the agent may be dead.
    if value.deadline.expired(now) {
        helpers::bump(CounterId::LpmExpired);
        return Outcome::Continue;
    }

    // An entry that does not cover this protocol and port has nothing to say about
    // this packet. Counting the miss matters: an allow entry whose scope keeps missing
    // is either a misconfiguration or somebody probing around it.
    if !value.applies_to(view.proto, view.dport) {
        helpers::bump(CounterId::LpmScopeMiss);
        return Outcome::Continue;
    }

    match value.action {
        Action::Allow => {
            // Counted per entry, not globally. A flow that leaves the pipeline without
            // leaving a trace is exactly what a forged allow-listed source looks like:
            // without this counter the bypass is undetectable by construction.
            helpers::bump_at(value.counter_idx);
            Outcome::Pass
        }
        Action::Drop => {
            helpers::bump(CounterId::LpmDropHit);
            Outcome::Drop
        }
        // Rate limiting and marking are verdicts the later stages own. Reaching them
        // here would mean this stage had decided something it does not implement.
        Action::Continue | Action::RateLimit | Action::Mark => Outcome::Continue,
    }
}
