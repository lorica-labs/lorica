//! Configuration into map entries, with every refusal happening here rather than at
//! run time.
//!
//! A rule the data path cannot honour is a rule the operator has to hear about while
//! reading the file, not one that quietly does nothing under attack.

pub mod bogon;
pub mod bogon_table;
pub mod lpm;
pub mod service;
pub mod signature;

use std::collections::BTreeMap;

use lorica_common::{
    Action, Clock, CounterId, Deadline, LpmKey, LpmValue, SCOPE_MAX, V4_MAPPED_PREFIX_BITS, setting,
};

use crate::{
    config::{ActionName, Config},
    profile::{MapSizes, MemlockModel, ProfileKind},
};

/// Everything the loader needs, and nothing it has to interpret further.
#[derive(Debug)]
pub struct Compiled {
    pub profile: ProfileKind,
    pub settings: u32,
    /// The vectors stage 6 is loaded with, one bit per row of the catalogue. Patched into
    /// the program like the settings word, and the rows it leaves out are removed from the
    /// program by the verifier rather than skipped at run time.
    pub signature_vectors: u32,
    pub entries: Vec<(LpmKey, LpmValue)>,
    /// The rules that go into the two flat tables instead of the trie, as
    /// `(address, prefix length, verdict)` — the shape
    /// [`blocklist::build`](crate::blocklist::build) takes.
    ///
    /// **What qualifies, and why it is exactly this.** The flat tables answer an IPv4 address
    /// in one memory access and carry eight bits a slot: a verdict, a probe length and a
    /// fingerprint. They have no room for a scope, no room for a deadline, and no counter
    /// index. So a rule goes here when it needs none of the three — IPv4, `deny`, no scope, no
    /// `ttl_secs` — and stays in the trie otherwise. An `allow` never qualifies, because an
    /// unscoped allow is refused outright a few lines below and a scoped one needs the scope.
    ///
    /// That is not a subset chosen to be easy. It is the shape a blocklist has: a large list
    /// of addresses to refuse, permanently, whatever they are talking to. The trie costs 414
    /// ns on the legitimate path once an operator fills it, and these two tables were built to
    /// take that traffic off it.
    ///
    /// **A rule gives up nothing observable by qualifying**, which is worth checking rather
    /// than assuming: the trie counts a *drop* through the shared `LpmDropHit` and only an
    /// *allow* through a per-entry slot. An allow never qualifies here, so nothing that moves
    /// had a counter of its own to lose, and stage 3 bumps `LpmDropHit` from either table.
    /// Per-entry counting was never available at the size these tables exist for anyway: a
    /// million entries is a million slots times every processor.
    pub flat: Vec<(u32, u32, Action)>,
    /// The bogon entries, which go into the same map behind the same lookup. They are
    /// kept apart from the operator entries because they are not the operator's: they
    /// share one counter slot instead of owning one each, and what the file asked for
    /// stays readable without subtracting a generated table from it.
    pub bogons: Vec<(LpmKey, LpmValue)>,
    pub sizes: MapSizes,
    pub warnings: Vec<Warning>,
}

/// Something the operator probably did not mean, which is still theirs to decide.
#[derive(Debug, PartialEq, Eq)]
pub enum Warning {
    /// A forged source address costs an attacker nothing on UDP, so an allow entry
    /// scoped to UDP is a hole anybody can walk through by writing the right address
    /// in a header. It is a refusal in no configuration language: an operator behind
    /// a filtered transit link has every right to it.
    AllowOnUdp { prefix: String, scope: String },
}

/// Spelled out rather than left to `Debug`, because the only thing that reads a warning is a
/// human at a prompt and `AllowOnUdp { prefix: "10.0.0.0/8", scope: "udp:53" }` is a struct
/// where a sentence belongs.
impl core::fmt::Display for Warning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AllowOnUdp { prefix, scope } => write!(
                f,
                "{prefix} is allowed on {scope}, and a forged source costs an attacker nothing                  on UDP: anyone who writes that address in a header walks through this rule"
            ),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error(
        "{name} is not a vector of the signature catalogue; the names are the signature \
         counters without their prefix, and accepting a misspelt one would leave that \
         vector out of the loaded program with nothing to read about it"
    )]
    UnknownSignatureVector { name: String },

    #[error("{spec} is not an address or a prefix")]
    BadPrefix { spec: String },

    #[error("{spec} declares a {declared}-bit prefix, and the family has {width} bits")]
    PrefixTooLong {
        spec: String,
        declared: u32,
        width: u32,
    },

    #[error(
        "{spec} has bits set outside its prefix; write the network address, because \
         masking it here would accept the line and mean something else"
    )]
    PrefixHasHostBits { spec: String },

    #[error("{spec} resolves to {resolved}, which is not a scope: {kind:?}")]
    BadScope {
        spec: String,
        resolved: String,
        kind: service::BadScope,
    },

    #[error(
        "{prefix} appears more than once; merge the rules into one with several \
         scopes, because two entries on the same prefix leave the trie with no answer \
         and picking one silently is a false positive nobody can see"
    )]
    DuplicatePrefix { prefix: String },

    #[error(
        "{prefix} is one of the built-in bogon prefixes, so the rule lands on the trie \
         key the built-in entry already holds, and there the trie has no answer; drop \
         the rule if it says the same thing, or write a longer prefix if it is an \
         exception, because a longer prefix is what the trie prefers"
    )]
    BogonPrefix { prefix: String },

    #[error(
        "the allow rule on {prefix} has no scope, which makes it a bare source \
         address and a total bypass on UDP; give it a protocol and a port range"
    )]
    UnscopedAllow { prefix: String },

    #[error(
        "{prefix} carries {count} scopes and the limit is {SCOPE_MAX}; split the \
         prefix, because an unbounded scope list costs helper calls and register \
         pressure in the data path for a case nobody has"
    )]
    TooManyScopes { prefix: String, count: usize },

    #[error(
        "the {profile} profile budgets {budget} bytes of locked kernel memory and \
         this configuration needs {needed}; the design does not fit in the machine, \
         and it is better to know here"
    )]
    MemlockExceeded {
        profile: ProfileKind,
        needed: u64,
        budget: u64,
    },
}

/// `clock` is the kernel's jiffy counter — one reading of it and the rate it ticks at —
/// passed in rather than read here: the deadlines this produces are compared against that
/// counter in the data path, and a function that reads a clock cannot be tested against a
/// table of expectations. The rate comes with the reading because measuring it is the
/// agent's job, and it is measured, never assumed.
pub fn compile(
    config: &Config,
    clock: Clock,
    model: MemlockModel,
) -> Result<Compiled, CompileError> {
    let mut entries: Vec<(LpmKey, LpmValue)> = Vec::with_capacity(config.rules.len());
    let mut flat: Vec<(u32, u32, Action)> = Vec::new();

    // **Which prefixes the trie will hold, decided before a single rule is placed.** Stage 3
    // reads the flat tables first and the trie only for what they had no verdict for, so a
    // prefix in the flat tables answers before any longer prefix in the trie is ever
    // consulted. A `/24` deny placed flat would therefore refuse the address a `/32` allow in
    // the trie was written to permit — precedence by specificity, silently inverted, on the
    // one pair of rules an operator writes precisely because they expect the longer to win.
    //
    // So a rule may only go flat when nothing longer inside it stays behind. This is that set:
    // every rule the flat tables cannot hold, and every bogon, because those are in the trie
    // too.
    let trie_only = trie_only_prefixes(config)?;
    let mut seen: BTreeMap<(u32, [u8; 16]), ()> = BTreeMap::new();
    let mut warnings = Vec::new();

    for rule in &config.rules {
        let key = lpm::parse_prefix(&rule.prefix)?;
        let prefix = lpm::describe(&key);

        if seen.insert((key.prefix_len, key.addr), ()).is_some() {
            return Err(CompileError::DuplicatePrefix { prefix });
        }

        let action = match rule.action {
            ActionName::Allow => Action::Allow,
            ActionName::Deny => Action::Drop,
        };

        if rule.scopes.len() > SCOPE_MAX {
            return Err(CompileError::TooManyScopes {
                prefix,
                count: rule.scopes.len(),
            });
        }
        if action == Action::Allow && rule.scopes.is_empty() {
            return Err(CompileError::UnscopedAllow { prefix });
        }

        // The flat tables first, because a rule that belongs there consumes no list slot and
        // no counter slot and the sizes below are computed from what is left.
        if let Some(flat_rule) = flat_candidate(&key, action, rule)
            && !trie_only.iter().any(|inner| contains(&key, inner))
        {
            flat.push(flat_rule);
            continue;
        }

        let mut value = LpmValue::zeroed();
        value.action = action;
        value.priority = rule.priority;
        // One counter slot per entry, above the named ones. A single global counter
        // would say that some allow-listed source left the pipeline, which is not the
        // question an operator asks after a bypass.
        //
        // Indexed by position in `entries` and not by position in the file, because the rules
        // that went to the flat tables are not here: numbering by file position would leave a
        // hole per flat rule in a map the profile sized exactly.
        value.counter_idx = CounterId::COUNT + entries.len() as u32;
        value.deadline = match rule.ttl_secs {
            // Only a mitigation entry is required to expire. An operator rule is
            // allowed to last as long as the file it is written in.
            None => Deadline::never(),
            Some(secs) => clock.deadline(secs),
        };

        for (index, spec) in rule.scopes.iter().enumerate() {
            let scope = service::resolve(spec, &config.services)?;
            if action == Action::Allow && scope.proto == service::IPPROTO_UDP {
                warnings.push(Warning::AllowOnUdp {
                    prefix: prefix.clone(),
                    scope: spec.clone(),
                });
            }
            value.scopes[index] = scope;
        }
        value.scope_len = rule.scopes.len() as u8;

        entries.push((key, value));
    }

    // The bogons join the same list. A rule on a prefix the table already holds is
    // refused for the reason two rules on one prefix are refused: the trie keys on the
    // prefix alone, so one of the two entries would win by nothing an operator can read.
    let mut bogons = Vec::with_capacity(bogon_table::BOGONS.len());
    for (key, value) in bogon::entries() {
        if seen.insert((key.prefix_len, key.addr), ()).is_some() {
            return Err(CompileError::BogonPrefix {
                prefix: lpm::describe(&key),
            });
        }
        bogons.push((key, value));
    }

    let reserve = config
        .mitigation_reserve
        .unwrap_or_else(|| config.profile.default_mitigation_reserve());
    let unified_list_entries = ((entries.len() + bogons.len()) as u32).saturating_add(reserve);
    let sizes = MapSizes {
        unified_list_entries,
        // The named counters, then one slot per entry the list can hold.
        counter_entries: CounterId::COUNT.saturating_add(unified_list_entries),
        bank_buckets: lorica_common::DEFAULT_BANK_BUCKETS,
    };

    let needed = sizes.memlock_bytes(model);
    let budget = config.profile.memlock_budget();
    if needed > budget {
        return Err(CompileError::MemlockExceeded {
            profile: config.profile,
            needed,
            budget,
        });
    }

    Ok(Compiled {
        profile: config.profile,
        settings: settings_word(&config.settings),
        signature_vectors: signature::vectors_word(config.signatures.as_deref())?,
        entries,
        flat,
        bogons,
        sizes,
        warnings,
    })
}

/// Every prefix the trie will hold: the rules the flat tables cannot take, and the bogons.
///
/// Parsed here and again in the loop below, which is one wasted parse per rule at compile time
/// and buys the thing that matters: the placement of a rule can depend on the whole
/// configuration rather than only on the rules before it in the file. A rule's table would
/// otherwise depend on where in the file it was written, which is the property this compiler
/// most insists it does not have.
fn trie_only_prefixes(config: &Config) -> Result<Vec<LpmKey>, CompileError> {
    let mut keys: Vec<LpmKey> = bogon::entries().map(|(key, _)| key).collect();
    for rule in &config.rules {
        let key = lpm::parse_prefix(&rule.prefix)?;
        let action = match rule.action {
            ActionName::Allow => Action::Allow,
            ActionName::Deny => Action::Drop,
        };
        if flat_candidate(&key, action, rule).is_none() {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Whether `inner` is a strictly longer prefix inside `outer`.
///
/// Equal prefixes are not contained: two rules on one prefix are already a refusal, and a
/// bogon on the same prefix as a rule is another. What this asks about is nesting.
fn contains(outer: &LpmKey, inner: &LpmKey) -> bool {
    if inner.prefix_len <= outer.prefix_len {
        return false;
    }
    let bits = outer.prefix_len as usize;
    let whole = bits / 8;
    if outer.addr[..whole] != inner.addr[..whole] {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    outer.addr[whole] & mask == inner.addr[whole] & mask
}

/// The flat form of a rule that belongs in the two tables, or `None` if it belongs in the trie.
///
/// One place, and a total function of the rule, so that "which table holds this" is answerable
/// by reading one predicate rather than by tracing two branches of a loop.
fn flat_candidate(
    key: &LpmKey,
    action: Action,
    rule: &crate::config::Rule,
) -> Option<(u32, u32, Action)> {
    // IPv4 only. The parser stores it v4-mapped, so a prefix inside IPv4 space is one at or
    // past the mapped prefix, and its length in IPv4 terms is what is left after it.
    let len = key.prefix_len.checked_sub(V4_MAPPED_PREFIX_BITS)?;
    if action != Action::Drop || !rule.scopes.is_empty() || rule.ttl_secs.is_some() {
        return None;
    }
    let addr = u32::from_be_bytes([key.addr[12], key.addr[13], key.addr[14], key.addr[15]]);
    Some((addr, len, action))
}

fn settings_word(settings: &crate::config::Settings) -> u32 {
    let mut word = 0;
    if settings.accept_ip_options {
        word |= setting::ACCEPT_IP_OPTIONS;
    }
    if settings.drop_icmp_echo {
        word |= setting::DROP_ICMP_ECHO;
    }
    if settings.drop_icmp_other {
        word |= setting::DROP_ICMP_OTHER;
    }
    if settings.allow_later_fragments {
        word |= setting::ALLOW_LATER_FRAGMENTS;
    }
    if settings.enforce_signatures {
        word |= setting::ENFORCE_SIGNATURES;
    }
    if settings.enforce_buckets {
        word |= setting::ENFORCE_BUCKETS;
    }
    word
}
