//! Stage 3. One list, one lookup: the allow list and the block list are the same trie
//! and the value carries the verdict.
//!
//! Precedence is the specificity of the address, which is what the trie returns. The
//! scope lives in the value rather than in the key because an LPM_TRIE matches only
//! the leading bits of its key, so a protocol and a port in the key would forbid any
//! generic entry.

use carapace_common::{Action, CounterId, PacketView};

use crate::{helpers, stage::Outcome};

#[inline(never)]
pub fn run(view: &PacketView, _now_ns: u64) -> Outcome {
    let Some(value) = helpers::list_lookup(&view.src) else {
        return Outcome::Continue;
    };

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
